"""SumoLogic connector — fetch logs from SumoLogic via Search Job API.

Uses httpx directly to avoid heavy dependencies.
Auth: accessId + accessKey (HTTP Basic Auth).

The user provides the full SumoLogic query string per log type. The query
must output fields matching Nabla's canonical schema (see CANONICAL_SCHEMA
below). This avoids hardcoded field mappings and lets the user tailor
queries to their specific SumoLogic deployment.

Optional: include ``{watchlist_clause}`` in the query string to have
Nabla inject watchlist filters (user/host/IP) at runtime.

Search Job API (v2) flow:
1. POST /v2/search/jobs  →  get job ID
2. Poll GET /v2/search/jobs/{id}  →  wait for DONE GATHERING RESULTS
3. GET /v2/search/jobs/{id}/messages?offset=0&limit=N  →  page results
4. DELETE /v2/search/jobs/{id}  →  clean up

Note: The v1 Search Job API requires an Enterprise-tier account. The v2
API is available on all account types and uses epoch milliseconds for
time ranges instead of ISO strings.

Rate limits: 4 req/sec per user, 10 concurrent per access key,
200 active jobs per org. 429 responses trigger exponential backoff.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from nabla.connectors.base import CANONICAL_SCHEMA, ConnectorConfig, Watchlist
from nabla.log import get_logger

logger = get_logger("connectors.sumologic")

# SumoLogic internal fields to drop from normalized output
_DROP_FIELDS = frozenset({
    "_messageid", "_sourceid", "_receipttime", "_collectorId",
    "_blockid", "_size", "_format", "_messagecount", "_raw",
    "_collector", "_source",
})

# Search job states that indicate completion
_DONE_STATES = frozenset({
    "DONE GATHERING RESULTS",
    "DONE GATHERING HISTOGRAM",
    "CANCELLED",
})

# Max page size for message retrieval (SumoLogic limit)
_MAX_PAGE_SIZE = 10_000


@dataclass
class SumoConfig(ConnectorConfig):
    """SumoLogic-specific connector configuration.

    Attributes:
        host: SumoLogic API endpoint URL (e.g. https://api.sumologic.com/api).
        access_id: Access ID for HTTP Basic Auth.
        access_key: Access Key for HTTP Basic Auth.
        credentials_path: Path to JSON file with {access_id, access_key}.
        verify_ssl: Whether to verify TLS certificates.
        validate_url: Whether to run SSRF validation on the host URL.
        query_map: Mapping of log type → user-provided SumoLogic query string.
            Each query must output fields matching CANONICAL_SCHEMA.
            Optional ``{watchlist_clause}`` placeholder gets replaced
            with watchlist filters at runtime.
        queries_path: Path to JSON file with query_map (alternative to
            env vars for long queries). Format: {"auth": "...", ...}
        max_results: Maximum number of results per search.
        poll_interval: Seconds between status polls while waiting for job completion.
        poll_timeout: Maximum seconds to wait for a search job to complete.
    """
    host: str = ""
    access_id: str = ""
    access_key: str = ""
    credentials_path: str = ""
    verify_ssl: bool = True
    validate_url: bool = True
    query_map: dict[str, str] = field(default_factory=dict)
    queries_path: str = ""
    max_results: int = 10_000
    poll_interval: float = 5.0
    poll_timeout: float = 300.0

    def __post_init__(self) -> None:
        """Load credentials and queries from files if paths are set."""
        from nabla.connectors.base import apply_credentials, load_queries_from_file
        apply_credentials(self.credentials_path, "SumoLogic", self, {
            "access_id": "access_id", "access_key": "access_key",
        })
        load_queries_from_file(self.queries_path, "SumoLogic", self.query_map)


class SumoLogicConnector:
    """Fetch logs from SumoLogic via the Search Job API.

    The user provides query strings per log type that output fields
    matching Nabla's canonical schema. The connector authenticates,
    executes the search job, polls for completion, pages through
    messages, and cleans up.
    """

    def __init__(self, config: SumoConfig) -> None:
        self.config = config
        self._original_hostname: str = ""

        if not self.config.verify_ssl:
            from nabla.connectors.base import warn_ssl_disabled
            warn_ssl_disabled("SumoLogic", self.config.host)

    def _follow_redirects(
        self,
        client: httpx.Client,
        response: httpx.Response,
        max_redirects: int = 5,
    ) -> httpx.Response:
        """Manually follow HTTP redirects with SSRF validation on each hop."""
        from nabla.ssrf import follow_redirects_safe
        return follow_redirects_safe(
            client, response,
            original_hostname=self._original_hostname,
            max_redirects=max_redirects,
            caller_name="SumoLogic",
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

    @staticmethod
    def _escape_query_value(value: str) -> str:
        """Escape a value for safe inclusion in SumoLogic double-quoted strings."""
        from nabla.connectors.base import escape_query_value
        return escape_query_value(value)

    # Watchlist field map for SumoLogic queries
    _WATCHLIST_FIELD_MAP = {"user": "user", "host": "_sourceHost", "ip": "_sourceIP"}

    def _build_watchlist_clause(self, watchlist: Watchlist) -> str:
        """Build a SumoLogic filter clause from the watchlist."""
        from nabla.connectors.base import build_watchlist_clause
        return build_watchlist_clause(watchlist, self._WATCHLIST_FIELD_MAP, "SumoLogic")

    def _resolve_query(self, log_type: str, watchlist: Watchlist) -> str:
        """Resolve the query string for a log type, injecting watchlist filters."""
        from nabla.connectors.base import resolve_query
        return resolve_query(
            log_type, watchlist, self.config.query_map, "SumoLogic",
            self._WATCHLIST_FIELD_MAP,
        )

    # Windows Security Event ID → canonical action mapping
    _WIN_EVENT_ACTIONS: dict[int, str] = {
        4624: "login",
        4625: "login_failed",
        4634: "logoff",
        4647: "logoff",
        4648: "login_explicit",
        4662: "object_access",
        4672: "special_privileges",
        4720: "account_created",
        4732: "group_modified",
        4738: "group_modified",
        4768: "kerberos_tgranted",
        4769: "kerberos_trequested",
        4776: "credential_validation",
        4798: "group_enumerated",
        4799: "group_membership",
        4907: "audit_policy_change",
        5058: "key_operation",
        5059: "key_operation",
        5061: "key_operation",
        5379: "credential_read",
    }

    @classmethod
    def _normalize_windows_event(cls, event: dict[str, Any], log_type: str) -> dict[str, Any]:
        """Normalize a Windows Security Event JSON to Nabla's canonical schema.

        Handles the structured JSON format from SumoLogic's Windows event
        collection (OTel/Sysmon). Extracts fields from event_data and
        rendering_info into canonical field names.

        Args:
            event: Parsed JSON from the _raw field.
            log_type: The requested log type (auth, endpoint, etc.).

        Returns:
            Dict with canonical field names.
        """
        normalized: dict[str, Any] = {"type": log_type}

        # Timestamp from system_time
        system_time = event.get("system_time", "")
        if system_time:
            normalized["timestamp"] = system_time
        else:
            normalized["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Host from computer field
        computer = event.get("computer", "")
        if computer:
            # Strip domain suffix (e.g. EC2AMAZ-OCPNFK9.qfunction.ai → EC2AMAZ-OCPNFK9)
            normalized["host"] = computer.split(".")[0] if "." in computer else computer

        # Event ID and action
        eid = 0
        event_id_obj = event.get("event_id", {})
        if isinstance(event_id_obj, dict):
            eid = event_id_obj.get("id", 0)
        elif isinstance(event_id_obj, (int, float)):
            eid = int(event_id_obj)

        if eid:
            normalized["event_code"] = str(eid)
            normalized["action"] = cls._WIN_EVENT_ACTIONS.get(eid, f"event_{eid}")

        # Extract user from event_data
        event_data = event.get("event_data", {})
        if isinstance(event_data, dict):
            # TargetUserName is the primary user in auth events
            user = event_data.get("TargetUserName") or event_data.get("SubjectUserName") or event_data.get("User", "")
            if user:
                # Strip domain prefix (QFUNCTION\\admin → admin)
                if "\\" in user:
                    user = user.split("\\")[-1]
                # Skip machine accounts (ending in $)
                if not user.endswith("$"):
                    normalized["user"] = user

            # Source IP for logon events
            ip = event_data.get("IpAddress") or event_data.get("SourceAddress", "")
            if ip:
                normalized["source_ip"] = ip

            # Logon type
            logon_type = event_data.get("LogonType", "")
            if logon_type:
                normalized["logon_type"] = logon_type

        # For endpoint events, extract process info from Sysmon-style data
        if log_type == "endpoint":
            image = event_data.get("Image", "")
            if image:
                normalized["process"] = image.split("\\")[-1]
                normalized["command_line"] = image

            parent = event_data.get("ParentImage", "")
            if parent:
                normalized["parent_process"] = parent.split("\\")[-1]

            cmd = event_data.get("CommandLine", "")
            if cmd:
                normalized["command_line"] = cmd

        # Keywords (Audit Success / Audit Failure)
        keywords = event.get("keywords", [])
        if isinstance(keywords, list) and keywords:
            normalized["result"] = keywords[0]  # e.g. "Audit Success"

        # Store the original message for context
        message = event.get("message", "")
        if message:
            # Truncate long messages
            normalized["details"] = message[:500]

        return normalized

    # Regex patterns for parsing Linux Sysmon XML events from syslog lines
    _XML_EVENT_ID_RE = re.compile(r"<EventID>(\d+)</EventID>")
    _XML_SYSTEM_TIME_RE = re.compile(r'SystemTime="([^"]+)"')
    _XML_COMPUTER_RE = re.compile(r"<Computer>([^<]+)</Computer>")
    _XML_DATA_RE = re.compile(r'<Data Name="([^"]+)">([^<]*)</Data>')

    # Linux Sysmon Event ID → canonical action mapping
    _LINUX_SYSMON_ACTIONS: dict[int, str] = {
        1: "process_create",
        2: "file_create_time",
        3: "network_connect",
        5: "process_terminate",
        6: "driver_load",
        7: "image_load",
        8: "remote_thread",
        10: "process_access",
        11: "file_create",
        12: "registry_add_delete",
        13: "registry_set",
        17: "pipe_event",
        22: "dns_query",
        23: "file_delete",
        25: "process_tampering",
        26: "file_delete_detected",
    }

    @classmethod
    def _normalize_linux_sysmon_xml(cls, raw_text: str, log_type: str) -> dict[str, Any]:
        """Normalize a Linux Sysmon XML event (wrapped in syslog) to canonical schema.

        Linux Sysmon events arrive as syslog lines containing XML:
            Apr 30 19:51:24 hostname sysmon[pid]: <Event>...</Event>

        The XML uses <Data Name="FieldName">Value</Data> pairs inside
        <EventData>. We parse with regex (not XML parser) to avoid
        dependency on defusedxml and handle the syslog prefix.

        Args:
            raw_text: The raw _raw field from SumoLogic.
            log_type: The requested log type (endpoint, network, dns).

        Returns:
            Dict with canonical field names.
        """
        normalized: dict[str, Any] = {"type": log_type}

        # Extract event ID
        eid_match = cls._XML_EVENT_ID_RE.search(raw_text)
        eid = int(eid_match.group(1)) if eid_match else 0
        if eid:
            normalized["event_code"] = str(eid)
            normalized["action"] = cls._LINUX_SYSMON_ACTIONS.get(eid, f"event_{eid}")

        # Extract timestamp from SystemTime
        ts_match = cls._XML_SYSTEM_TIME_RE.search(raw_text)
        if ts_match:
            normalized["timestamp"] = ts_match.group(1)
        else:
            normalized["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Extract computer (host)
        comp_match = cls._XML_COMPUTER_RE.search(raw_text)
        if comp_match:
            computer = comp_match.group(1)
            # Strip domain suffix
            normalized["host"] = computer.split(".")[0] if "." in computer else computer

        # Extract all Data Name/Value pairs
        event_data = {}
        for m in cls._XML_DATA_RE.finditer(raw_text):
            event_data[m.group(1)] = m.group(2)

        # Map to canonical fields based on event type
        if eid == 1:  # Process Create
            image = event_data.get("Image", "")
            if image:
                normalized["process"] = image.rsplit("/", 1)[-1]
            cmd = event_data.get("CommandLine", "")
            if cmd:
                normalized["command_line"] = cmd
            user = event_data.get("User", "")
            if user:
                normalized["user"] = user
            parent = event_data.get("ParentImage", "")
            if parent:
                normalized["parent_process"] = parent.rsplit("/", 1)[-1]
            integrity = event_data.get("IntegrityLevel", "")
            if integrity and integrity != "no level":
                normalized["integrity_level"] = integrity
            hashes = event_data.get("Hashes", "")
            if hashes:
                normalized["hashes"] = hashes

        elif eid == 3:  # Network Connect
            src_ip = event_data.get("SourceIp", "")
            if src_ip:
                normalized["src_ip"] = src_ip
            dst_ip = event_data.get("DestinationIp", "")
            if dst_ip:
                normalized["dst_ip"] = dst_ip
            dst_port = event_data.get("DestinationPort", "")
            if dst_port:
                normalized["dest_port"] = dst_port
            src_port = event_data.get("SourcePort", "")
            if src_port:
                normalized["src_port"] = src_port
            protocol = event_data.get("Protocol", "")
            if protocol:
                normalized["protocol"] = protocol
            image = event_data.get("Image", "")
            if image:
                normalized["process"] = image.rsplit("/", 1)[-1]
            user = event_data.get("User", "")
            if user:
                normalized["user"] = user

        elif eid == 5:  # Process Terminate
            image = event_data.get("Image", "")
            if image:
                normalized["process"] = image.rsplit("/", 1)[-1]
            user = event_data.get("User", "")
            if user:
                normalized["user"] = user

        elif eid == 22:  # DNS Query
            query_name = event_data.get("QueryName", "")
            if query_name:
                normalized["domain"] = query_name
            image = event_data.get("Image", "")
            if image:
                normalized["process"] = image.rsplit("/", 1)[-1]
            user = event_data.get("User", "")
            if user:
                normalized["user"] = user
            query_results = event_data.get("QueryResults", "")
            if query_results:
                normalized["query_results"] = query_results

        # Store all event_data for context
        if event_data:
            # Keep a subset of useful fields as details
            detail_keys = [k for k in event_data if k not in
                           ("RuleName", "UtcTime", "ProcessGuid", "LogonGuid")]
            details = {k: event_data[k][:200] for k in detail_keys[:10]}
            if details:
                normalized["details"] = json.dumps(details, default=str)[:500]

        return normalized

    @classmethod
    def _minimal_normalize(cls, raw: dict[str, Any], log_type: str) -> dict[str, Any]:
        """Apply minimal normalization to a raw SumoLogic message.

        If the _raw field contains JSON, attempts to parse it and apply
        structured normalization (e.g. Windows Security Events). Otherwise
        falls back to field-by-field mapping.

        This handles:
        - _raw JSON parsing → structured normalization
        - _messagetime (epoch ms) → timestamp (ISO string)
        - _sourceHost → host
        - _sourceCategory → source
        - Adding the ``type`` field from the requested log_type
        - Dropping SumoLogic internal fields
        """
        # Try to parse _raw as JSON for structured events
        raw_text = raw.get("_raw", "")
        if isinstance(raw_text, str) and raw_text.startswith("{"):
            try:
                event = json.loads(raw_text)
                if isinstance(event, dict) and ("event_id" in event or "event_data" in event):
                    # Windows Security Event or Sysmon event
                    return cls._normalize_windows_event(event, log_type)
            except (json.JSONDecodeError, ValueError):
                pass  # silent by design: not valid JSON, falls through to field mapping (2026-09 sweep)

        # Try to parse Linux Sysmon XML events (syslog-wrapped XML)
        if isinstance(raw_text, str) and "<Event>" in raw_text and "<EventID>" in raw_text:
            return cls._normalize_linux_sysmon_xml(raw_text, log_type)

        normalized: dict[str, Any] = {"type": log_type}

        # Timestamp — convert _messagetime (epoch ms) to ISO string
        ts = raw.get("_messagetime") or raw.get("timestamp")
        if isinstance(ts, (int, float)):
            # SumoLogic uses milliseconds since epoch
            normalized["timestamp"] = datetime.fromtimestamp(
                ts / 1000.0, tz=timezone.utc,
            ).isoformat()
        elif isinstance(ts, str) and ts:
            normalized["timestamp"] = ts
        else:
            normalized["timestamp"] = datetime.now(timezone.utc).isoformat()

        # Map SumoLogic metadata fields to canonical names
        if "_sourceHost" in raw and "host" not in raw:
            normalized["host"] = raw["_sourceHost"]
        if "_sourceCategory" in raw and "source" not in raw:
            normalized["source"] = raw["_sourceCategory"]

        # Copy all other fields as-is (user's query already renamed them)
        for key, value in raw.items():
            if key in _DROP_FIELDS:
                continue
            if key not in normalized:
                normalized[key] = value

        return normalized

    @staticmethod
    def _validate_output(logs: list[dict[str, Any]], log_type: str) -> None:
        """Validate fetched logs against the canonical schema."""
        from nabla.connectors.base import validate_output
        validate_output(logs, log_type, "SumoLogic", strict=False)

    def _create_search_job(
        self,
        client: httpx.Client,
        query: str,
        from_ts: str | None = None,
        to_ts: str | None = None,
    ) -> str:
        """Create a SumoLogic search job and return the job ID.

        Uses the v2 Search Job API which accepts epoch milliseconds
        for time ranges and is available on all account tiers (v1
        requires Enterprise).

        Args:
            client: Authenticated httpx client.
            query: SumoLogic query string.
            from_ts: ISO timestamp for start of time range.
            to_ts: ISO timestamp for end of time range.

        Returns:
            The search job ID string.

        Raises:
            ValueError: If the job ID cannot be extracted from the response.
        """
        from datetime import timedelta

        now = datetime.now(timezone.utc)
        from_dt = datetime.fromisoformat(from_ts) if from_ts else (now - timedelta(hours=1))
        to_dt = datetime.fromisoformat(to_ts) if to_ts else now

        # v2 API requires epoch milliseconds
        from_ms = int(from_dt.timestamp() * 1000)
        to_ms = int(to_dt.timestamp() * 1000)

        body: dict[str, Any] = {
            "query": query,
            "from": from_ms,
            "to": to_ms,
            "timeZone": "UTC",
        }

        logger.debug("Creating search job: %s", query[:200])
        resp = self._request(
            client, "POST",
            "/v2/search/jobs",
            json=body,
            timeout=httpx.Timeout(30.0, connect=10.0),
        )
        resp.raise_for_status()

        data = resp.json()
        job_id = data.get("id")
        if not job_id:
            raise ValueError(f"Could not extract search job ID from SumoLogic response: {data}")

        logger.info("Created search job: %s", job_id)
        return job_id

    def _poll_search_job(self, client: httpx.Client, job_id: str) -> dict[str, Any]:
        """Poll a search job until it completes.

        Keeps the session alive by polling every poll_interval seconds.
        Raises TimeoutError if the job doesn't complete within poll_timeout.

        Args:
            client: Authenticated httpx client (with cookie jar).
            job_id: The search job ID to poll.

        Returns:
            The final job status JSON.

        Raises:
            TimeoutError: If the job doesn't complete within poll_timeout.
        """
        deadline = time.monotonic() + self.config.poll_timeout
        while time.monotonic() < deadline:
            resp = self._request(
                client, "GET",
                f"/v2/search/jobs/{job_id}",
                timeout=httpx.Timeout(10.0, connect=5.0),
            )
            resp.raise_for_status()

            data = resp.json()
            state = data.get("state", "")
            message_count = data.get("messageCount", 0)

            if state in _DONE_STATES:
                logger.info(
                    "Search job %s completed: state=%s, messages=%d",
                    job_id, state, message_count,
                )
                return data

            if state == "CANCELLED":
                raise ValueError(f"Search job {job_id} was cancelled")

            logger.debug(
                "Search job %s: state=%s, messages=%d — polling...",
                job_id, state, message_count,
            )
            time.sleep(self.config.poll_interval)

        raise TimeoutError(
            f"Search job {job_id} did not complete within {self.config.poll_timeout}s"
        )

    def _fetch_messages(
        self,
        client: httpx.Client,
        job_id: str,
        message_count: int,
    ) -> list[dict[str, Any]]:
        """Page through all messages from a completed search job.

        Args:
            client: Authenticated httpx client (with cookie jar).
            job_id: The completed search job ID.
            message_count: Total number of messages available.

        Returns:
            List of raw message dicts.
        """
        if message_count == 0:
            return []

        max_results = min(message_count, self.config.max_results)
        results: list[dict[str, Any]] = []
        offset = 0

        while offset < max_results:
            limit = min(_MAX_PAGE_SIZE, max_results - offset)
            resp = self._request(
                client, "GET",
                f"/v2/search/jobs/{job_id}/messages",
                params={"offset": offset, "limit": limit},
                timeout=httpx.Timeout(60.0, connect=10.0),
            )
            resp.raise_for_status()

            data = resp.json()
            messages = data.get("messages", [])

            if not messages:
                break

            # SumoLogic messages are in {"map": {...}} format
            for msg in messages:
                msg_map = msg.get("map", msg)
                results.append(msg_map)

            offset += len(messages)

            if len(messages) < limit:
                break  # No more messages available

        logger.info(
            "Fetched %d/%d messages from search job %s",
            len(results), message_count, job_id,
        )
        return results

    def _delete_search_job(self, client: httpx.Client, job_id: str) -> None:
        """Delete a search job to free up the concurrent job limit.

        Non-fatal on failure — jobs time out after 8 hours anyway.
        """
        try:
            self._request(
                client, "DELETE",
                f"/v2/search/jobs/{job_id}",
                timeout=httpx.Timeout(10.0, connect=5.0),
            )
            logger.debug("Deleted search job %s", job_id)
        except Exception as e:
            logger.debug("Failed to delete search job %s (non-fatal): %s", job_id, e)

    def fetch_logs(
        self,
        watchlist: Watchlist,
        log_type: str,
        since: str | None,
        until: str | None,
    ) -> list[dict[str, Any]]:
        """Fetch logs from SumoLogic for the given type.

        Args:
            watchlist: Entities to target (used for ``{watchlist_clause}`` injection).
            log_type: One of "auth", "network", "dns", "endpoint".
            since: ISO timestamp for incremental ingestion.
            until: ISO timestamp for upper bound.

        Returns:
            List of log dicts in Nabla's canonical format.
        """
        if not self.config.host:
            raise ValueError("SumoLogic host not configured (set NABLA_SUMOLOGIC_HOST)")

        if not self.config.access_id or not self.config.access_key:
            raise ValueError(
                "SumoLogic auth requires access_id and access_key "
                "(set NABLA_SUMOLOGIC_ACCESS_ID and NABLA_SUMOLOGIC_ACCESS_KEY)"
            )

        # SSRF validation — block private IPs and localhost
        original_ips: set[str] = set()
        if self.config.validate_url:
            from nabla.connectors.base import validate_host_ssrf
            original_ips, hostname = validate_host_ssrf(self.config.host)
            self._original_hostname = hostname

        query = self.config.query_map.get(log_type, "")
        if not query:
            logger.info("No SumoLogic query configured for log type '%s', skipping", log_type)
            return []

        if watchlist.is_empty:
            logger.info("Watchlist is empty — no watchlist filter will be applied")

        query = self._resolve_query(log_type, watchlist)

        # Parse original hostname for SSRF redirect validation
        if self.config.validate_url:
            from urllib.parse import urlparse as _urlparse
            self._original_hostname = _urlparse(self.config.host).hostname or ""

        # Build httpx client with Basic Auth and cookie jar for session routing.
        # SumoLogic routes requests to the correct backend server based on
        # session cookies — without cookies, follow-up requests may hit the
        # wrong server and return 404 or 500.
        #
        # We use follow_redirects=False and manually follow redirects
        # with SSRF validation on each hop. This prevents redirect-based
        # SSRF where the initial request goes to a valid host but the
        # server redirects to an internal address.
        with httpx.Client(
            base_url=self.config.host,
            auth=(self.config.access_id, self.config.access_key),
            verify=self.config.verify_ssl,
            timeout=httpx.Timeout(120.0, connect=30.0),
            follow_redirects=False,
        ) as client:
            # Create search job
            job_id = self._create_search_job(client, query, from_ts=since, to_ts=until)

            # DNS rebinding check: re-resolve hostname after first request
            if original_ips and self._original_hostname:
                from nabla.ssrf import verify_dns_stability
                is_stable, err = verify_dns_stability(self._original_hostname, original_ips)
                if not is_stable:
                    # Clean up the job before raising
                    try:
                        self._delete_search_job(client, job_id)
                    except Exception as e:
                        logger.warning("sumologic connector failed (non-fatal): %s", e, exc_info=True)
                    raise ValueError(f"SumoLogic DNS rebinding detected: {err}")

            try:
                # Poll until done
                status = self._poll_search_job(client, job_id)
                message_count = status.get("messageCount", 0)

                # Fetch messages
                raw_messages = self._fetch_messages(client, job_id, message_count)
            finally:
                # Always clean up the search job
                self._delete_search_job(client, job_id)

        # Normalize to canonical schema
        logs = [self._minimal_normalize(m, log_type) for m in raw_messages]

        # Validate output
        self._validate_output(logs, log_type)

        logger.info("Fetched %d %s logs from SumoLogic", len(logs), log_type)
        return logs

    def available_log_types(self) -> list[str]:
        """Return log types that have a configured SumoLogic query."""
        return [lt for lt, q in self.config.query_map.items() if q]
