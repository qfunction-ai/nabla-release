"""Nabla configuration via environment variables."""

import logging
import os

from pydantic_settings import BaseSettings

logger = logging.getLogger("nabla.config")


class Settings(BaseSettings):
    """Application settings loaded from NABLA_* environment variables."""

    # ── Letta server ──────────────────────────────────────────
    letta_base_url: str = "http://localhost:8284"
    letta_api_key: str = ""  # If set, passed to Letta client for API authentication
    tool_letta_url: str = ""  # Override for cross-agent tool access

    # ── Authentication ────────────────────────────────────────
    setup_token: str = ""  # If set, all /api/* endpoints require this token
    dev_mode: bool = False  # Allow open access when no token is set (local dev only)

    # ── Web server ────────────────────────────────────────────
    web_host: str = "0.0.0.0"
    web_port: int = 8000
    # R6-11 (round 6): who the backend trusts for X-Forwarded-For —
    # nginx's fixed compose IP by default; do NOT widen to the network
    forwarded_allow_ips: str = "172.28.0.2"

    # ── Model configuration ───────────────────────────────────
    llm_model: str = "ollama/gemma4:26b"
    embedding_model: str = "embeddinggemma:latest"
    # Embedding endpoint — must be reachable from INSIDE the Letta container
    # Use host.docker.internal when Letta runs in Docker
    embedding_endpoint: str = "http://host.docker.internal:11434/v1"

    # ── Ollama (advisory — set on the Ollama host, not here) ──
    ollama_keep_alive: str = "24h"
    ollama_context_length: int = 32768
    ollama_flash_attention: bool = True
    ollama_max_loaded_models: int = 2

    # ── Letta workarounds ─────────────────────────────────────
    letta_max_context_window: int = 32768
    letta_compaction_model: str = ""  # If set, overrides compaction model to match Ollama model

    # ── Data directory ────────────────────────────────────────
    data_dir: str = "/data"

    # ── Auth (login plan 2026-09-01) ──────────────────────────
    jwt_expire_minutes: int = 10080  # 7 days; cookie max_age derives from this

    @property
    def users_file(self) -> str:
        """Path to the user accounts store."""
        return self._data_path("users.json")

    @property
    def jwt_secret_file(self) -> str:
        """Path to the JWT signing secret (generated on first boot)."""
        return self._data_path("jwt_secret")

    def _data_path(self, filename: str) -> str:
        """Join data_dir with a filename."""
        return os.path.join(self.data_dir, filename)

    @property
    def effective_tool_url(self) -> str:
        """URL tools use to connect to Letta (for cross-agent archival reads)."""
        return self.tool_letta_url or self.letta_base_url

    # ── Data file paths (auto-generated from _DATA_FILES dict) ───
    @property
    def runs_file(self) -> str:
        """Path to the pipeline run history file."""
        return self._data_path("runs.json")

    @property
    def rl_state_file(self) -> str:
        """Path to the RL agent state file."""
        return self._data_path("rl_state.json")

    @property
    def gcn_lof_model_file(self) -> str:
        """Path to the GCN-LOF model weights file."""
        return self._data_path("gcn_lof_model.json")

    @property
    def entity_profiles_file(self) -> str:
        """Path to the entity baseline profiles file."""
        return self._data_path("entity_profiles.json")

    @property
    def system_state_file(self) -> str:
        """Path to the system phase state file."""
        return self._data_path("system_state.json")

    @property
    def incidents_file(self) -> str:
        """Path to the incident persistence file."""
        return self._data_path("incidents.json")

    @property
    def siem_logs_file(self) -> str:
        """Path to the SIEM log storage file (JSONL)."""
        return self._data_path("siem_logs.jsonl")

    @property
    def baseline_snapshots_file(self) -> str:
        """Path to the baseline snapshot storage file (JSONL)."""
        return self._data_path("baseline_snapshots.jsonl")

    @property
    def entity_risk_scores_file(self) -> str:
        """Path to the entity risk scores file."""
        return self._data_path("entity_risk_scores.json")

    # ── Watchlist ──────────────────────────────────────────────
    watchlist_path: str = ""  # If empty, defaults to data_dir/watchlists.json

    @property
    def effective_watchlist_path(self) -> str:
        """Path to the watchlist file."""
        return self.watchlist_path or self._data_path("watchlists.json")

    # ── Environment context ───────────────────────────────────
    env_context_path: str = ""  # If empty, defaults to data_dir/environment_context.json

    @property
    def effective_env_context_path(self) -> str:
        """Path to the environment context JSON file."""
        return self.env_context_path or self._data_path("environment_context.json")

    # ── Ingestion ──────────────────────────────────────────────
    ingestion_source: str = "auto"
    ingestion_state_path: str = ""  # If empty, defaults to data_dir/ingestion_state.json

    @property
    def effective_ingestion_state_path(self) -> str:
        """Path to the ingestion state file."""
        return self.ingestion_state_path or self._data_path("ingestion_state.json")

    # ── Scheduler ──────────────────────────────────────────────
    schedule_enabled: bool = False
    schedule_interval_minutes: int = 5
    schedule_log_types: str = "all"
    schedule_log_count: int = 50

    # ── Operational limits ─────────────────────────────────────
    passage_limit: int = 50
    agent_list_limit: int = 100
    max_file_entries: int = 100_000  # Max log entries from file upload

    # ── Entity baseline ────────────────────────────────────────
    entity_warmup_observations: int = 3  # Min runs before entity-specific baselines
    new_account_grace_days: int = 30  # Days after creation before z-score detection
    baseline_days: int = 21  # Days of SIEM ingestion before full detection; 0 to skip

    # ── Risk scoring ────────────────────────────────────────────
    risk_score_decay_half_life_hours: float = 24.0  # Hours for anomaly contribution to halve
    risk_score_max_anomalies: int = 20  # Max contributing anomalies retained per entity
    risk_score_investigation_cutoff: float = 50.0  # Score above which entities are auto-prioritized

    # ── Peer groups ─────────────────────────────────────────────
    peer_group_recompute_interval: int = 10  # Minimum pipeline runs between re-clustering

    # ── Account classification (N9: reachable in Docker, was raw env) ──
    machine_accounts: str = ""  # comma-separated extra machine accounts (excluded from baselining)
    human_accounts: str = ""  # comma-separated accounts forced back into baselining (override wins)
    operator: str = ""  # audit-trail identity for operator-triggered runs

    # ── Exfiltration detection ──────────────────────────────────
    sanctioned_services: str = ""  # R14: comma-separated domain suffixes (tenant-level preferred)
    timezone: str = "UTC"  # R17: site timezone for hour-based detectors (IANA name)
    exfil_volume_sigma: float = 3.0  # Z-score threshold for volume anomaly
    exfil_dns_entropy_threshold: float = 3.5  # Shannon entropy threshold for DNS tunneling
    exfil_staging_window_minutes: int = 30  # Window for staging pattern detection

    # ── LOLBIN database integrity pins (N14: was raw env) ──────
    lolbas_sha256: str = ""  # expected SHA256 of the LOLBAS download (empty = warn + verify-skip)
    gtfobins_sha256: str = ""  # expected SHA256 of the GTFOBins download

    # ── Splunk connector ───────────────────────────────────────
    splunk_host: str = ""  # e.g. https://splunk.example.com:8089
    splunk_token: str = ""  # Bearer token (preferred)
    splunk_username: str = ""  # Username/password fallback
    splunk_password: str = ""
    splunk_credentials_path: str = ""  # File path for Splunk credentials (overrides env vars)
    splunk_verify_ssl: bool = True
    splunk_validate_url: bool = True  # SSRF validation on splunk_host (disable for test hostnames)
    splunk_auth_query: str = ""  # SPL search string for auth logs
    splunk_network_query: str = ""  # SPL search string for network logs
    splunk_dns_query: str = ""  # SPL search string for DNS logs
    splunk_endpoint_query: str = ""  # SPL search string for endpoint logs
    splunk_queries_path: str = ""  # Path to JSON file with all queries (alternative to env vars)
    splunk_max_results: int = 10000  # Max results per search

    @property
    def splunk_query_map(self) -> dict[str, str]:
        """Map log type to user-provided SPL search string."""
        return {
            "auth": self.splunk_auth_query,
            "network": self.splunk_network_query,
            "dns": self.splunk_dns_query,
            "endpoint": self.splunk_endpoint_query,
        }

    def splunk_config(self):
        """Construct a SplunkConfig from settings for the pipeline."""
        from nabla.connectors.splunk import SplunkConfig
        return SplunkConfig(
            host=self.splunk_host,
            token=self.splunk_token,
            username=self.splunk_username,
            password=self.splunk_password,
            credentials_path=self.splunk_credentials_path,
            verify_ssl=self.splunk_verify_ssl,
            validate_url=self.splunk_validate_url,
            query_map=self.splunk_query_map,
            queries_path=self.splunk_queries_path,
            max_results=self.splunk_max_results,
        )

    # ── SumoLogic connector ────────────────────────────────────
    sumologic_host: str = ""  # e.g. https://api.sumologic.com/api
    sumologic_access_id: str = ""
    sumologic_access_key: str = ""
    sumologic_credentials_path: str = ""  # File path for SumoLogic credentials (overrides env vars)
    sumologic_verify_ssl: bool = True
    sumologic_validate_url: bool = True  # SSRF validation on sumologic_host
    sumologic_auth_query: str = ""  # SumoLogic query string for auth logs
    sumologic_network_query: str = ""  # SumoLogic query string for network logs
    sumologic_dns_query: str = ""  # SumoLogic query string for DNS logs
    sumologic_endpoint_query: str = ""  # SumoLogic query string for endpoint logs
    sumologic_queries_path: str = ""  # Path to JSON file with all queries
    sumologic_max_results: int = 10_000  # Max results per search
    sumologic_poll_interval: float = 5.0  # Seconds between status polls
    sumologic_poll_timeout: float = 300.0  # Max seconds to wait for job completion

    @property
    def sumologic_query_map(self) -> dict[str, str]:
        """Map log type to user-provided SumoLogic query string."""
        return {
            "auth": self.sumologic_auth_query,
            "network": self.sumologic_network_query,
            "dns": self.sumologic_dns_query,
            "endpoint": self.sumologic_endpoint_query,
        }

    def sumologic_config(self):
        """Construct a SumoConfig from settings for the pipeline."""
        from nabla.connectors.sumologic import SumoConfig
        return SumoConfig(
            host=self.sumologic_host,
            access_id=self.sumologic_access_id,
            access_key=self.sumologic_access_key,
            credentials_path=self.sumologic_credentials_path,
            verify_ssl=self.sumologic_verify_ssl,
            validate_url=self.sumologic_validate_url,
            query_map=self.sumologic_query_map,
            queries_path=self.sumologic_queries_path,
            max_results=self.sumologic_max_results,
            poll_interval=self.sumologic_poll_interval,
            poll_timeout=self.sumologic_poll_timeout,
        )

    # ── Credential warning ─────────────────────────────────────
    def model_post_init(self, __context: object) -> None:
        """Warn when sensitive credentials are set via environment variables."""
        if (self.splunk_token or self.splunk_password) and not self.splunk_credentials_path:
            logger.warning(
                "Splunk credentials are set via NABLA_SPLUNK_* env vars. "
                "These are visible in /proc/PID/environ and docker inspect. "
                "Use NABLA_SPLUNK_CREDENTIALS_PATH (a file with mode 0600) instead."
            )
        if (self.sumologic_access_id or self.sumologic_access_key) and not self.sumologic_credentials_path:
            logger.warning(
                "SumoLogic credentials are set via NABLA_SUMOLOGIC_* env vars. "
                "These are visible in /proc/PID/environ and docker inspect. "
                "Use NABLA_SUMOLOGIC_CREDENTIALS_PATH (a file with mode 0600) instead."
            )

    model_config = {"env_prefix": "NABLA_"}


_settings: Settings | None = None


def get_settings() -> Settings:
    """Return cached settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
        logger.debug("Settings loaded: letta_base_url=%s, llm_model=%s", _settings.letta_base_url, _settings.llm_model)
    return _settings
