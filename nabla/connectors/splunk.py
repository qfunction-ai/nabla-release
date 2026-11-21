"""Splunk connector — fetch logs from Splunk via REST API.

Uses httpx directly (not splunk-sdk) to avoid heavy dependencies.
Auth: bearer token (preferred) or username/password (session key).

The user provides the full SPL search string per log type. The search
string must output fields matching Nabla's canonical schema (see
CANONICAL_SCHEMA below). This avoids hardcoded field mappings and
lets the user tailor queries to their specific Splunk deployment.

Optional: include ``{watchlist_clause}`` in the search string to have
Nabla inject watchlist filters (user/host/IP) at runtime.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from nabla.connectors.base import CANONICAL_SCHEMA, ConnectorConfig, Watchlist
from nabla.log import get_logger

logger = get_logger("connectors.splunk")


@dataclass
class SplunkConfig(ConnectorConfig):
    """Splunk-specific connector configuration.

    Attributes:
        host: Splunk REST API URL (e.g. https://splunk.example.com:8089).
        token: Bearer token (preferred auth method).
        username: Username for session key auth.
        password: Password for session key auth.
        credentials_path: Path to JSON file with {token, username, password}.
        verify_ssl: Whether to verify TLS certificates.
        validate_url: Whether to run SSRF validation on the host URL.
        query_map: Mapping of log type → user-provided SPL search string.
            Each query must output fields matching CANONICAL_SCHEMA.
            Optional ``{watchlist_clause}`` placeholder gets replaced
            with watchlist filters at runtime.
        queries_path: Path to JSON file with query_map (alternative to
            env vars for long queries). Format: {"auth": "search ...", ...}
        max_results: Maximum number of results per search.
    """
    host: str = ""
    token: str = ""
    username: str = ""
    password: str = ""
    credentials_path: str = ""
    verify_ssl: bool = True
    validate_url: bool = True
    query_map: dict[str, str] = field(default_factory=dict)
    queries_path: str = ""
    max_results: int = 10000

    def __post_init__(self) -> None:
        """Load credentials and queries from files if paths are set."""
        from nabla.connectors.base import apply_credentials, load_queries_from_file
        apply_credentials(self.credentials_path, "Splunk", self, {
            "token": "token", "username": "username", "password": "password",
        })
        load_queries_from_file(self.queries_path, "Splunk", self.query_map)


class SplunkConnector:
    """Fetch logs from Splunk via the REST API.

    The user provides search strings per log type that output fields
    matching Nabla's canonical schema. The connector authenticates,
    executes the search, and validates the output.
    """

    def __init__(self, config: SplunkConfig) -> None:
        self.config = config
        self._session_key: str | None = None
        self._original_hostname: str = ""

        if not self.config.verify_ssl:
            from nabla.connectors.base import warn_ssl_disabled
            warn_ssl_disabled("Splunk", self.config.host)

    def _get_auth_header(self) -> dict[str, str]:
        """Get the Authorization header. Uses token if available, otherwise session key."""
        if self.config.token:
            return {"Authorization": f"Bearer {self.config.token}"}
        if self._session_key:
            return {"Authorization": f"Splunk {self._session_key}"}
        return {}

    def _authenticate(self, client: httpx.Client, original_hostname: str = "") -> None:
        """Authenticate with username/password to get a session key.

        When original_hostname is provided, SSRF redirect validation is
        applied to each redirect hop.
        """
        if self.config.token:
            return  # Token auth, no login needed

        if not self.config.username or not self.config.password:
            raise ValueError("Splunk auth requires either a token or username/password")

        logger.info("Authenticating to Splunk as %s", self.config.username)
        resp = client.post(
            "/services/auth/login",
            data={"username": self.config.username, "password": self.config.password},
        )
        resp = self._follow_redirects(client, resp, original_hostname)
        resp.raise_for_status()

        # Parse session key from XML response
        import defusedxml.ElementTree as ET
        root = ET.fromstring(resp.text)

        # Try multiple XML formats:
        # 1. Namespace-aware: <s:key name="sessionKey"> (Splunk REST API with namespace)
        ns = {"s": "http://dev.splunk.com/ns/rest"}
        session_elem = root.find(".//s:key[@name='sessionKey']", ns)
        if session_elem is not None and session_elem.text:
            self._session_key = session_elem.text
        else:
            # 2. Direct element: <sessionKey>...</sessionKey> (simple auth response)
            session_elem = root.find(".//sessionKey")
            if session_elem is not None and session_elem.text:
                self._session_key = session_elem.text
            else:
                # 3. Attribute-based: any element with name="sessionKey"
                for elem in root.iter():
                    if elem.get("name") == "sessionKey" and elem.text:
                        self._session_key = elem.text
                        break
                if not self._session_key:
                    raise ValueError("Could not extract session key from Splunk login response")

        logger.info("Splunk session key obtained")

    def _follow_redirects(
        self,
        client: httpx.Client,
        response: httpx.Response,
        original_hostname: str = "",
        max_redirects: int = 5,
    ) -> httpx.Response:
        """Manually follow HTTP redirects with SSRF validation on each hop."""
        from nabla.ssrf import follow_redirects_safe
        return follow_redirects_safe(
            client, response,
            original_hostname=original_hostname or self._original_hostname,
            max_redirects=max_redirects,
            caller_name="Splunk",
        )

    def _request(
        self,
        client: httpx.Client,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Make an HTTP request with SSRF-aware redirect following."""
        resp = client.request(method, url, **kwargs)
        return self._follow_redirects(client, resp)

    def _execute_search_validated(
        self,
        client: httpx.Client,
        query: str,
        since: str | None = None,
        until: str | None = None,
        original_hostname: str = "",
    ) -> list[dict[str, Any]]:
        """Execute a Splunk search with SSRF redirect validation."""
        try:
            return self._execute_search(client, query, since=since, until=until)
        except httpx.RedirectStatusError as e:
            if original_hostname:
                from nabla.ssrf import validate_redirect_url
                location = e.response.headers.get("location", "")
                if location:
                    is_valid, err = validate_redirect_url(location, original_hostname)
                    if not is_valid:
                        raise ValueError(f"Splunk search redirect blocked: {err}")
            raise

    @staticmethod
    def _spl_escape(value: str) -> str:
        """Escape a value for safe inclusion in SPL double-quoted strings."""
        from nabla.connectors.base import escape_query_value
        return escape_query_value(value)

    # Watchlist field map for Splunk queries
    _WATCHLIST_FIELD_MAP = {"user": "user", "host": "host", "ip": ["src_ip", "client_ip"]}

    def _build_watchlist_clause(self, watchlist: Watchlist) -> str:
        """Build an SPL filter clause from the watchlist."""
        from nabla.connectors.base import build_watchlist_clause
        return build_watchlist_clause(watchlist, self._WATCHLIST_FIELD_MAP, "Splunk")

    def _resolve_query(self, log_type: str, watchlist: Watchlist) -> str:
        """Resolve the search string for a log type, injecting watchlist filters."""
        from nabla.connectors.base import resolve_query
        return resolve_query(
            log_type, watchlist, self.config.query_map, "Splunk",
            self._WATCHLIST_FIELD_MAP,
        )

    @staticmethod
    def _minimal_normalize(raw: dict[str, Any], log_type: str) -> dict[str, Any]:
        """Apply minimal normalization to a raw Splunk result.

        The user's search string should already output canonical field names.
        This only handles:
        - _time (epoch float) → timestamp (ISO string) — Splunk-specific format
        - Adding the ``type`` field from the requested log_type
        - Dropping _raw (too large for archival memory)
        """
        normalized: dict[str, Any] = {"type": log_type}

        # Timestamp — convert _time (epoch or ISO) to ISO string
        ts = raw.get("_time") or raw.get("timestamp")
        if isinstance(ts, (int, float)):
            normalized["timestamp"] = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        elif isinstance(ts, str) and ts:
            normalized["timestamp"] = ts
        else:
            normalized["timestamp"] = ""  # R6-14/CLOCK Rule 2: absent means absent — never "now" (a wall stamp moved the data clock during backfills)

        # N-6/R-8 (round 7): emit the native ID BEFORE dropping the
        # internals. _cd is unique only WITHIN a bucket, so the composite
        # _bkt~_cd is the real identity — without it every Splunk event
        # fell to the field-hash ID and overlapping pulls could not dedup
        # on the source's own key.
        bkt, cd = raw.get("_bkt"), raw.get("_cd")
        if bkt is not None and cd is not None and not normalized.get("event_record_id"):
            normalized["event_record_id"] = f"{bkt}~{cd}"

        # Copy all other fields as-is (user's query already renamed them)
        for key, value in raw.items():
            if key in ("_time", "_raw", "_cd", "_si", "_bkt", "_serial", "splunk_server", "linecount"):
                continue  # Drop Splunk internal fields
            if key not in normalized:
                normalized[key] = value

        return normalized

    @staticmethod
    def _validate_output(logs: list[dict[str, Any]], log_type: str) -> None:
        """Validate fetched logs against the canonical schema."""
        from nabla.connectors.base import validate_output
        validate_output(logs, log_type, "Splunk", strict=True)

    def _execute_search(
        self, client: httpx.Client, query: str,
        since: str | None = None, until: str | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a Splunk search and return results.

        Uses the export endpoint with streaming (it keeps the connection open).
        Falls back to async job + polling for large result sets.

        Args:
            client: Authenticated httpx client.
            query: SPL query string.
            since: ISO timestamp for earliest_time.
            until: ISO timestamp for latest_time.
        """
        logger.debug("Executing SPL: %s", query[:200])

        # Build search parameters — time range goes as API params, not in the query string
        search_params: dict[str, Any] = {"search": query, "output_mode": "json"}
        if since:
            search_params["earliest_time"] = since
        if until:
            search_params["latest_time"] = until
        if self.config.max_results:
            search_params["count"] = self.config.max_results

        # Try export endpoint first (faster, for smaller result sets)
        try:
            results = []
            max_count = self.config.max_results or 0
            with client.stream(
                "POST",
                "/services/search/jobs/export",
                data=search_params,
                timeout=httpx.Timeout(120.0, connect=30.0),
            ) as resp:
                resp.raise_for_status()
                # Read the streaming response with a time limit
                deadline = time.monotonic() + 90  # Max 90 seconds for streaming
                buf = ""
                for chunk in resp.iter_bytes():
                    if time.monotonic() > deadline:
                        logger.warning("Export endpoint streaming timeout, truncating results")
                        break
                    buf += chunk.decode("utf-8", errors="replace")
                    # Process complete lines
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            if "result" in obj:
                                results.append(obj["result"])
                                if max_count and len(results) >= max_count:
                                    break
                        except json.JSONDecodeError:
                            pass  # silent by design: unparseable splunk response JSON (2026-09 sweep)
                    if max_count and len(results) >= max_count:
                        break
            return results
        except httpx.HTTPStatusError as e:
            if e.response.status_code != 503:
                raise
            logger.debug("Export endpoint returned 503, falling back to async job")

        # Fallback: async job
        return self._async_search(client, query, since, until)

    def _async_search(
        self, client: httpx.Client, query: str,
        since: str | None = None, until: str | None = None,
    ) -> list[dict[str, Any]]:
        """Run an async search job and poll for results."""
        # Create job
        job_data: dict[str, Any] = {"search": query, "exec_mode": "blocking"}
        if since:
            job_data["earliest_time"] = since
        if until:
            job_data["latest_time"] = until

        resp = client.post(
            "/services/search/jobs",
            data=job_data,
            timeout=120.0,
        )
        resp.raise_for_status()

        # Extract SID from XML response
        import defusedxml.ElementTree as ET
        root = ET.fromstring(resp.text)
        sid = None
        for elem in root.iter():
            if elem.tag.endswith("sid") and elem.text:
                sid = elem.text
                break
        if not sid:
            raise ValueError("Could not extract search job SID from Splunk response")

        logger.debug("Created search job: %s", sid)

        # Poll until done
        for _ in range(120):  # Max 10 minutes
            resp = client.get(
                f"/services/search/jobs/{sid}",
                timeout=10.0,
            )
            resp.raise_for_status()
            if '"DONE"' in resp.text or 'dispatchState">DONE' in resp.text:
                break
            time.sleep(5)
        else:
            raise TimeoutError(f"Search job {sid} did not complete in time")

        # Get results
        resp = client.get(
            f"/services/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": self.config.max_results},
            timeout=60.0,
        )
        resp.raise_for_status()

        # Cancel the job
        try:
            client.post(f"/services/search/jobs/{sid}/control", data={"action": "cancel"})
        except Exception as e:
            logger.warning("splunk connector failed (non-fatal): %s", e, exc_info=True)

        return self._parse_job_results(resp.text)

    def _parse_export_results(self, text: str) -> list[dict[str, Any]]:
        """Parse results from the export endpoint (JSON stream)."""
        results = []
        for line in text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, dict) and "result" in data:
                    results.append(data["result"])
                elif isinstance(data, dict) and "_time" in data:
                    results.append(data)
            except json.JSONDecodeError:
                pass  # silent by design: unparseable splunk result row (2026-09 sweep)
        return results

    def _parse_job_results(self, text: str) -> list[dict[str, Any]]:
        """Parse results from the job results endpoint."""
        try:
            data = json.loads(text)
            if isinstance(data, dict) and "results" in data:
                return data["results"]
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass  # silent by design: unparseable splunk response JSON (2026-09 sweep)
        return []

    def fetch_logs(
        self,
        watchlist: Watchlist,
        log_type: str,
        since: str | None,
        until: str | None,
    ) -> list[dict[str, Any]]:
        """Fetch logs from Splunk for the given type.

        Args:
            watchlist: Entities to target (used for ``{watchlist_clause}`` injection).
            log_type: One of "auth", "network", "dns", "endpoint".
            since: ISO timestamp for incremental ingestion.
            until: ISO timestamp for upper bound.

        Returns:
            List of log dicts in Nabla's canonical format.
        """
        if not self.config.host:
            raise ValueError("Splunk host not configured (set NABLA_SPLUNK_HOST)")

        # SSRF validation — block private IPs and localhost
        parsed_host = self.config.host
        original_ips: set[str] = set()
        if self.config.validate_url:
            from nabla.connectors.base import validate_host_ssrf
            original_ips, hostname = validate_host_ssrf(parsed_host)
            self._original_hostname = hostname

        query = self.config.query_map.get(log_type, "")
        if not query:
            logger.info("No Splunk query configured for log type '%s', skipping", log_type)
            return []

        if watchlist.is_empty:
            logger.info("Watchlist is empty — no watchlist filter will be applied")

        query = self._resolve_query(log_type, watchlist)

        # Build a validated httpx client that checks redirect targets
        # against SSRF rules. This prevents redirect-based SSRF where the
        # initial request goes to a valid host but the server redirects
        # to an internal address.
        #
        # We use follow_redirects=False and manually follow redirects
        # with SSRF validation on each hop. This is the safest approach
        # since httpx doesn't provide a redirect-validation hook.
        _original_hostname = ""
        if self.config.validate_url:
            from urllib.parse import urlparse as _urlparse
            _original_hostname = _urlparse(parsed_host).hostname or ""

        with httpx.Client(
            base_url=self.config.host,
            verify=self.config.verify_ssl,
            timeout=httpx.Timeout(120.0, connect=30.0),
            follow_redirects=False,
        ) as client:
            # R6-13 (round 6, D11): validation BEFORE credentials leave the
            # building — the old order authenticated first, so a
            # rebinding/validation failure had already leaked the token.
            # Honors the documented validate_url=False test escape.
            if getattr(self.config, "validate_url", True):
                from nabla.ssrf import validate_connector_url as _vcu
                _ok, _err = _vcu(str(self.config.host))
                if not _ok:
                    raise ValueError(f"Splunk host failed SSRF re-validation: {_err}")
            # Authenticate if needed (Splunk auth endpoint may redirect)
            self._authenticate(client, _original_hostname)

            # DNS rebinding check: re-resolve hostname after first request
            if original_ips and _original_hostname:
                from nabla.ssrf import verify_dns_stability
                is_stable, err = verify_dns_stability(_original_hostname, original_ips)
                if not is_stable:
                    raise ValueError(f"Splunk DNS rebinding detected: {err}")

            # Execute search with redirect validation
            raw_results = self._execute_search_validated(
                client, query, since=since, until=until,
                original_hostname=_original_hostname,
            )

        # Minimal normalization (user's query already renamed fields)
        logs = [self._minimal_normalize(r, log_type) for r in raw_results]

        # Validate output against canonical schema
        self._validate_output(logs, log_type)

        logger.info("Fetched %d %s logs from Splunk", len(logs), log_type)
        return logs

    def available_log_types(self) -> list[str]:
        """Return log types that have a configured Splunk query."""
        return [lt for lt, q in self.config.query_map.items() if q]
