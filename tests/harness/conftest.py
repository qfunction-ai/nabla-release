"""Harness fixtures: a lightweight in-process pipeline driver.

Runs the REAL pipeline stages (ingest→detect→risk) in-process against the
population data, on the scheduler-shaped path (graph layers ENABLED — that
is where R3's flag rate manifests). No Letta server needed: the supervisor
step is stubbed only where it purely formats narrative; everything
deterministic runs for real.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


class FakeBlocks:
    """Blocks stub for run_detection's lolbin read."""

    def __init__(self):
        self._vals = {"lolbin_db": ""}

    def list(self, label, limit=100):
        label = label if isinstance(label, str) else label
        return []


def drive_pipeline(entries, tmp_path, monkeypatch, detection_phase="detection",
                  run_graph=True):
    """Run ingestion+detection+risk in-process; return (detection_result, risk_store, runs).

    The scheduler-shaped path: skip_graph=False (graph layers ON).
    """
    import numpy as np

    # Settings pointed at tmp
    from nabla.config import Settings
    s = Settings(
        data_dir=str(tmp_path), letta_base_url="http://x", embedding_endpoint="http://x",
        splunk_host="", sumologic_host="", splunk_validate_url=False,
        sumologic_validate_url=False,
    )
    monkeypatch.setattr("nabla.config.get_settings", lambda: s)

    # Ingestion: parse+normalize the entries (file path, no truncation)
    from nabla.pipeline.ingestion import IngestionResult
    ing = IngestionResult()
    ing.entries = entries
    ing.total_ingested = len(entries)

    # Detection: the real run_detection minus the Letta client reads
    from nabla.pipeline import detection as pdet

    class _Agents:
        class blocks:
            @staticmethod
            def update(agent_id, block_label, value):
                return None
            @staticmethod
            def list(label, limit=100):
                return []

        @staticmethod
        def blocks_list(label, limit=100):
            return []

    class _Client:
        agents = _Agents()

    # Patch the block reads. Q-1: the lolbin block must be POPULATED —
    # an empty block now raises `lolbin_index_not_loaded` (detection on
    # fallback data must say so), which would trip the harness's
    # no-degradations assertions. The harness runs the production-shaped
    # "db" state.
    _LOLBIN_BLOCK = (
        "=== WINDOWS LOLBINS ===\n"
        "certutil | Download, Encode | T1105, T1140\n"
        "mshta | Execute | T1218\n"
        "=== UNIX GTFOBINS ===\n"
        "curl | Read | T1105\n"
    )
    monkeypatch.setattr(pdet, "_read_supervisor_blocks",
                        lambda client, agent_id, *labels: {
                            l: (_LOLBIN_BLOCK if l == "lolbin_db" else "")
                            for l in labels})

    # Force detection phase (the course/demo path — fresh instances start
    # baseline and entity detectors are phase-suppressed; the harness tests
    # the DETECTION-phase behavior where the findings live)
    import json as _json
    state_path = tmp_path / "system_state.json"
    if not state_path.exists():
        state_path.write_text(_json.dumps({"phase": "detection"}))
    monkeypatch.setattr("nabla.system_state.load_system_state",
                        lambda p: {"phase": "detection", "data_newest_ts": None})

    from nabla.connectors.base import Watchlist
    # F3/F4: collect detector degradations. Detectors swallow their own
    # exceptions by design, so a detector can fail on every single run and
    # the run still looks clean — exfil_volume did exactly that for a whole
    # round. Collecting here makes the failure visible to the assertions.
    from nabla.degradations import collect_degradations
    degradations: list[str] = []
    with collect_degradations(degradations):
        result = pdet.run_detection(
            _Client(), {"supervisor": "agent-harness"}, s, entries,
            Watchlist(), siem_entries_ingested=len(entries),
            effective_source="file", skip_graph=not run_graph,
        )

    # Absorption (the orchestration step the harness must exercise): group
    # entries by entity and update profiles — WITHOUT this, profiles never
    # warm in-harness and every entity detector stays cold
    from nabla.baselines import group_entries_by_entity
    if result.entity_profiles is not None:
        groups = group_entries_by_entity(entries)
        for (etype, eid), gentries in groups.items():
            if etype == "user":
                result.entity_profiles.update_user(eid, gentries)
            elif etype == "host":
                result.entity_profiles.update_host(eid, gentries)
            elif etype == "ip":
                result.entity_profiles.update_ip(eid, gentries)
        result.entity_profiles.save()  # the orchestration step the harness skipped twice

    # Risk: real scoring against the tmp store.
    # N2 (round 4): the data clock tracks the SIMULATED event time — the
    # newest ingested entry's stamp — exactly what the real pipeline's data
    # clock does. The old wall-now mock made August-stamped anomalies decay
    # to zero (~0.5^99 days), and the only reason attack separation held was
    # a decay-immortal empty-ts anomaly — the harness was leaning on the N2.3
    # bug. Absent stamps stay absent: the fallback is SIM time, never wall.
    from nabla import risk
    sim_now = max((e.get("timestamp", "") for e in entries), default="")
    sim_dt = None
    if sim_now:
        from nabla.utils import parse_iso_timestamp
        sim_dt = parse_iso_timestamp(sim_now)
    _clock = sim_dt or datetime.now(timezone.utc)
    monkeypatch.setattr(risk, "_data_clock", lambda: _clock)
    etm = {}
    if result.entity_profiles is not None:
        for eid in result.entity_profiles.users:
            etm[eid] = "user"
        # Mirror orchestration.py's entity_type_map exactly: hosts and IPs
        # are typed too. The harness omitted them, so host-keyed entities
        # fell into compute_risk_scores' "user" default — a shape the real
        # pipeline never produces (round-5 Phase 0: host-side assertions
        # need honest typing).
        for eid in result.entity_profiles.hosts:
            etm[eid] = "host"
        for eid in result.entity_profiles.ips:
            etm[eid] = "ip"
    try:
        store = risk.compute_risk_scores(
            result.anomalies, etm,
            temporal_chains=result.temporal_chains or [],
            half_life_hours=24.0,
        )
        risk_error = None
    except Exception as e:
        store = None
        risk_error = f"{type(e).__name__}: {e}"

    return {
        "detection": result,
        "risk_store": store,
        "risk_error": risk_error,
        "degradations": degradations,
    }
