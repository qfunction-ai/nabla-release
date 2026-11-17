"""Pipeline package — multi-agent UEBA pipeline orchestration.

Re-exports all public names for backward compatibility.
`from nabla.pipeline import run_pipeline` still works.
"""

from nabla.pipeline.orchestration import run_pipeline
from nabla.pipeline.status import get_status
from nabla.pipeline.helpers import (
    _extract_assistant_message,
    _read_supervisor_blocks,
    _resolve_log_types,
    _extract_count,
    _read_baseline_host_procs,
    _extract_host_processes_from_entries,
    _resolve_source,
    _filter_watchlist_by_groups,
    LOG_TYPES,
)
from nabla.pipeline.env_context import (
    _load_environment_context,
    _auto_detect_network_ranges,
    _auto_detect_new_accounts,
    _format_env_context_block,
)
