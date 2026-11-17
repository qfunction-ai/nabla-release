"""Export and import Nabla learned state.

Bundles all durable state files into a single JSON for portability
across teardown/bootstrap cycles. Shared memory blocks are not included —
they're regenerated on the next pipeline run.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nabla.log import get_logger
from nabla.utils import get_allowed_dirs, path_is_allowed

logger = get_logger("export")

EXPORT_VERSION = 1


def _validate_path(file_path: str, must_exist: bool = False) -> None:
    """Validate a file path is within allowed directories.

    Prevents path traversal attacks (e.g., writing to /etc/cron.d/).

    Args:
        file_path: The file path to validate.
        must_exist: If True, the file must exist.

    Raises:
        ValueError: If the path is outside allowed directories.
        FileNotFoundError: If must_exist and the file doesn't exist.
    """
    path = Path(file_path).resolve()

    if must_exist and not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not path_is_allowed(path):
        raise ValueError(
            f"Path '{file_path}' is outside allowed directories. "
            f"Export/import paths must be under /data or /tmp."
        )


# State files to include in export, keyed by section name.
# Values are filenames relative to data_dir.
STATE_FILES: dict[str, str] = {
    "entity_profiles": "entity_profiles.json",
    "rl_state": "rl_state.json",
    "gcn_lof_model": "gcn_lof_model.json",
    "environment_context": "environment_context.json",
    "watchlists": "watchlists.json",
    "runs": "runs.json",
    "ingestion_state": "ingestion_state.json",
    "system_state": "system_state.json",
    "incidents": "incidents.json",
    "siem_logs": "siem_logs.jsonl",
    "baseline_snapshots": "baseline_snapshots.jsonl",
}


def export_state(data_dir: str, output_path: str) -> dict[str, Any]:
    """Read all state files and write a single export JSON.

    Args:
        data_dir: Path to the data directory containing state files.
        output_path: Path to write the export JSON.

    Returns:
        Summary dict with counts of exported/skipped files.
    """
    _validate_path(output_path)

    state: dict[str, Any] = {}
    exported: list[str] = []
    skipped: list[str] = []

    for section, filename in STATE_FILES.items():
        filepath = os.path.join(data_dir, filename)
        if os.path.exists(filepath):
            try:
                if filename.endswith(".jsonl"):
                    # JSONL files: read as list of JSON objects
                    lines = []
                    with open(filepath, "r") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                lines.append(json.loads(line))
                    state[section] = lines
                else:
                    with open(filepath, "r") as f:
                        state[section] = json.load(f)
                exported.append(section)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to read %s: %s — skipping", filepath, e)
                skipped.append(section)
        else:
            logger.info("State file not found: %s — skipping", filepath)
            skipped.append(section)

    export_data = {
        "version": EXPORT_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "state": state,
    }

    from nabla.persistence import atomic_write_json
    atomic_write_json(output_path, export_data)

    summary = {"exported": exported, "skipped": skipped, "output_path": output_path}
    logger.info(
        "Exported %d/%d state files to %s (skipped: %s)",
        len(exported), len(STATE_FILES), output_path,
        ", ".join(skipped) if skipped else "none",
    )
    return summary


def _validate_export(data: dict[str, Any]) -> None:
    """Validate export JSON structure.

    Raises:
        ValueError: If the export is invalid.
    """
    if "version" not in data:
        raise ValueError("Invalid export: missing 'version' field")
    if data["version"] != EXPORT_VERSION:
        raise ValueError(
            f"Unsupported export version: {data['version']} "
            f"(expected {EXPORT_VERSION})"
        )
    if "state" not in data:
        raise ValueError("Invalid export: missing 'state' field")
    if not isinstance(data["state"], dict):
        raise ValueError("Invalid export: 'state' must be a dict")


def _backup_file(filepath: str) -> str | None:
    """Create a .bak backup of a file. Returns backup path or None if no file exists."""
    if not os.path.exists(filepath):
        return None
    backup_path = filepath + ".bak"
    shutil.copy2(filepath, backup_path)
    return backup_path


def _merge_dicts(existing: Any, imported: Any) -> Any:
    """Deep-merge two dicts. Imported values override existing on conflict."""
    if not isinstance(existing, dict) or not isinstance(imported, dict):
        return imported
    merged = dict(existing)
    for key, value in imported.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def _merge_runs(existing: list[dict], imported: list[dict]) -> list[dict]:
    """Merge run histories, deduplicating by run_id."""
    existing_ids = {r.get("run_id") for r in existing}
    merged = list(existing)
    for run in imported:
        if run.get("run_id") not in existing_ids:
            merged.append(run)
    return merged


def _merge_incidents(existing: list[dict], imported: list[dict]) -> list[dict]:
    """Merge incident lists, deduplicating by incident_id.

    When the same incident_id exists in both, keep the one with the
    newer updated_at timestamp (it has the latest status/notes).
    """
    by_id: dict[str, dict] = {}
    for inc in existing:
        by_id[inc.get("incident_id", "")] = inc
    for inc in imported:
        iid = inc.get("incident_id", "")
        if iid not in by_id:
            by_id[iid] = inc
        else:
            # Keep the one with the newer updated_at
            existing_ts = by_id[iid].get("updated_at", "")
            imported_ts = inc.get("updated_at", "")
            if imported_ts > existing_ts:
                by_id[iid] = inc
    return list(by_id.values())


def _merge_ingestion_state(existing: dict, imported: dict) -> dict:
    """Merge ingestion states, keeping the latest timestamps."""
    merged = dict(existing)
    for connector, imported_entry in imported.items():
        if connector not in merged:
            merged[connector] = imported_entry
            continue
        existing_entry = merged[connector]
        # Keep the later last_ingestion timestamp
        existing_ts = existing_entry.get("last_ingestion", "")
        imported_ts = imported_entry.get("last_ingestion", "")
        if imported_ts > existing_ts:
            merged[connector] = imported_entry
        # Merge per-type timestamps similarly
        if "log_types" in imported_entry:
            if "log_types" not in merged[connector]:
                merged[connector]["log_types"] = {}
            for lt, lt_data in imported_entry["log_types"].items():
                if lt not in merged[connector]["log_types"]:
                    merged[connector]["log_types"][lt] = lt_data
                else:
                    existing_lt_ts = merged[connector]["log_types"][lt].get("last_ingestion", "")
                    imported_lt_ts = lt_data.get("last_ingestion", "")
                    if imported_lt_ts > existing_lt_ts:
                        merged[connector]["log_types"][lt] = lt_data
    return merged


def import_state(
    input_path: str,
    data_dir: str,
    merge: bool = False,
) -> dict[str, Any]:
    """Read export JSON and write state files to data_dir.

    Args:
        input_path: Path to the export JSON file.
        data_dir: Path to the data directory to write state files.
        merge: If True, merge imported state with existing. If False, overwrite.

    Returns:
        Summary dict with counts of imported/skipped/restored files.

    Raises:
        ValueError: If the export file is invalid or path is outside allowed dirs.
        FileNotFoundError: If the export file doesn't exist.
    """
    _validate_path(input_path, must_exist=True)

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Export file not found: {input_path}")

    with open(input_path, "r") as f:
        data = json.load(f)

    _validate_export(data)

    state = data["state"]
    imported: list[str] = []
    skipped: list[str] = []
    backups: list[str] = []

    os.makedirs(data_dir, exist_ok=True)

    for section, filename in STATE_FILES.items():
        if section not in state:
            logger.info("Section '%s' not in export — skipping", section)
            skipped.append(section)
            continue

        filepath = os.path.join(data_dir, filename)
        imported_data = state[section]

        # Backup existing file before overwriting
        backup_path = _backup_file(filepath)
        if backup_path:
            backups.append(backup_path)

        if merge and os.path.exists(filepath):
            try:
                if filename.endswith(".jsonl"):
                    # JSONL files: read existing lines
                    existing_lines = []
                    with open(filepath, "r") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                existing_lines.append(json.loads(line))
                    imported_data = _merge_jsonl(section, existing_lines, imported_data)
                else:
                    with open(filepath, "r") as f:
                        existing_data = json.load(f)
                    imported_data = _merge_section(section, existing_data, imported_data)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(
                    "Failed to read existing %s for merge: %s — using imported data",
                    filepath, e,
                )

        if filename.endswith(".jsonl"):
            # Write JSONL files as line-delimited JSON
            try:
                lines = imported_data if isinstance(imported_data, list) else [imported_data]
                with open(filepath, "w") as f:
                    for line_data in lines:
                        f.write(json.dumps(line_data, default=str) + "\n")
                imported.append(section)
            except OSError as e:
                logger.error("Failed to write %s: %s", filepath, e)
                skipped.append(section)
        else:
            from nabla.persistence import atomic_write_json
            try:
                atomic_write_json(filepath, imported_data)
                imported.append(section)
            except OSError as e:
                logger.error("Failed to write %s: %s", filepath, e)
                skipped.append(section)

    summary = {
        "imported": imported,
        "skipped": skipped,
        "backups": backups,
        "merge": merge,
    }
    logger.info(
        "Imported %d/%d state files to %s (merge=%s, skipped: %s)",
        len(imported), len(STATE_FILES), data_dir, merge,
        ", ".join(skipped) if skipped else "none",
    )
    return summary


def _merge_jsonl(section: str, existing: list[dict], imported: list[dict]) -> list[dict]:
    """Merge JSONL files — append imported lines to existing.

    JSONL files are append-only logs, so merge means concatenation.
    For baseline_snapshots, deduplicate by timestamp (keep latest).
    For siem_logs, just append (each ingestion batch is unique).
    """
    if section == "baseline_snapshots":
        # Deduplicate by timestamp — keep the latest snapshot per timestamp
        by_ts: dict[str, dict] = {}
        for entry in existing:
            ts = entry.get("timestamp", "")
            by_ts[ts] = entry
        for entry in imported:
            ts = entry.get("timestamp", "")
            by_ts[ts] = entry
        return sorted(by_ts.values(), key=lambda e: e.get("timestamp", ""))

    # For siem_logs and other JSONL — just concatenate
    return existing + imported


def _merge_section(
    section: str, existing: Any, imported: Any,
) -> Any:
    """Section-specific merge logic.

    Args:
        section: State section name (e.g., 'entity_profiles', 'runs').
        existing: Existing data loaded from disk.
        imported: Imported data from export file.

    Returns:
        Merged data.
    """
    if section == "runs":
        # Runs is a list — deduplicate by run_id
        existing_list = existing if isinstance(existing, list) else []
        imported_list = imported if isinstance(imported, list) else []
        return _merge_runs(existing_list, imported_list)

    if section == "ingestion_state":
        # Ingestion state — keep latest timestamps
        existing_dict = existing if isinstance(existing, dict) else {}
        imported_dict = imported if isinstance(imported, dict) else {}
        return _merge_ingestion_state(existing_dict, imported_dict)

    if section == "gcn_lof_model":
        # Model weights can't be meaningfully merged — imported wins
        return imported

    if section == "system_state":
        # System state: keep the more advanced phase (detection > baseline)
        # and the earlier first_ingestion_at
        existing_dict = existing if isinstance(existing, dict) else {}
        imported_dict = imported if isinstance(imported, dict) else {}
        merged = dict(existing_dict)
        merged.update(imported_dict)
        # If either is in detection, keep detection
        if existing_dict.get("phase") == "detection" or imported_dict.get("phase") == "detection":
            merged["phase"] = "detection"
        # Keep the earlier first_ingestion_at
        existing_first = existing_dict.get("first_ingestion_at")
        imported_first = imported_dict.get("first_ingestion_at")
        if existing_first and imported_first:
            merged["first_ingestion_at"] = min(existing_first, imported_first)
        elif existing_first:
            merged["first_ingestion_at"] = existing_first
        return merged

    if section == "incidents":
        # Incidents is a list — deduplicate by incident_id, keep newer updated_at
        existing_list = existing if isinstance(existing, list) else []
        imported_list = imported if isinstance(imported, list) else []
        return _merge_incidents(existing_list, imported_list)

    # For all other sections (entity_profiles, rl_state,
    # environment_context, watchlists) — deep merge with imported
    # values overriding existing on conflict
    if isinstance(existing, dict) and isinstance(imported, dict):
        return _merge_dicts(existing, imported)

    return imported
