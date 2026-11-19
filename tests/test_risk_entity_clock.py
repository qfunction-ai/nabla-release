"""N2.2 (round 4): each entity's risk decays against ITS OWN clock.

R12's per-batch reference (max(data clock, newest anomaly IN THE BATCH))
is one clock for every entity: a batch on recent data ages every entity
from an older dataset — the reviewer's verified scenario (c): a replay
batch for alice, then one synthetic run for a DIFFERENT user, zeroes
alice's replayed score.

The fix: EntityRiskScore persists its own data_clock (the newest stamp
it was scored against); each entity's reference is the max of its
persisted clock and its own batch anomalies' stamps. Dormant entities
keep their score until their own stream advances — documented,
intended (a dormant entity's score reflects its last known activity).
"""

from __future__ import annotations

import json

import pytest


def _anom(aid: str, entity: str, ts: str, severity: str = "high") -> dict:
    return {
        "anomaly_id": aid, "entity": entity, "detection_method": "entity_z_score",
        "severity": severity, "confidence": 0.9, "raw_score": 2.4, "timestamp": ts,
    }


@pytest.fixture
def isolated_settings(tmp_path, monkeypatch):
    import json as _json
    import types
    # system_state with a data clock AT the replay window — the honest
    # sim condition (the pipeline's data clock = newest ingested event).
    # Without it _data_clock falls back to wall-now and August anomalies
    # legitimately decay to zero (live-mode semantics, not the replay bug).
    state = {"phase": "detection", "data_newest_ts": "2026-08-12T03:00:00+00:00"}
    (tmp_path / "system_state.json").write_text(_json.dumps(state))
    s = types.SimpleNamespace(
        entity_risk_scores_file=str(tmp_path / "risk.json"),
        system_state_file=str(tmp_path / "system_state.json"),
        data_dir=str(tmp_path),  # detect_exfiltration's calibration read
        machine_accounts="",  # N9: utils classification reads these
        human_accounts="",
    )
    (tmp_path / "feedback").mkdir(exist_ok=True)
    monkeypatch.setattr("nabla.config.get_settings", lambda: s)
    return s


class TestPerEntityReferenceClock:
    def test_a_replayed_batch_keeps_its_score(self, isolated_settings):
        """Reviewer scenario (a): three high August anomalies against an
        August data clock keep a substantial score (regression guard for
        the batch-max rule that already handles this)."""
        from nabla import risk
        anoms = [_anom(f"a{i}", "alice", f"2026-08-1{i}T03:00:00Z") for i in (0, 1, 2)]
        store = risk.compute_risk_scores(anoms, {"alice": "user"})
        score = store.get("alice").overall
        assert score > 10.0, f"replayed batch scored only {score} — should be substantial"

    def test_b_later_batch_for_another_user_preserves_the_replayed_score(self, isolated_settings):
        """Reviewer scenario (c): replay for alice (August), then a batch
        for BOB stamped months later. Alice's score must persist — bob's
        newer data must not age her anomalies. RED under the global clock."""
        from nabla import risk
        august = [_anom(f"a{i}", "alice", f"2026-08-1{i}T03:00:00Z") for i in (0, 1, 2)]
        store1 = risk.compute_risk_scores(august, {"alice": "user"})
        before = store1.get("alice").overall
        assert before > 10.0

        # bob's later run — a different entity, October stamps
        october = [_anom("b1", "bob", "2026-10-15T09:00:00Z"),
                   _anom("b2", "bob", "2026-10-15T10:00:00Z")]
        store2 = risk.compute_risk_scores(october, {"alice": "user", "bob": "user"})
        after = store2.get("alice").overall
        assert after >= before * 0.9, (
            f"alice's score collapsed {before:.1f} -> {after:.1f} on bob's later "
            f"batch — the reference clock is global, not per-entity (N2.2)"
        )

    def test_c_exfil_on_old_data_does_not_collapse_the_score(self, isolated_settings):
        """Reviewer scenario (b): the replay batch plus an exfil anomaly
        CONSTRUCTED from the same old data — with event-time stamps (N2.1)
        the clock stays in August and the score stands."""
        from nabla import risk
        from nabla.exfiltration import detect_exfiltration
        august_events = [{
            "timestamp": f"2026-08-10T03:{m:02d}:00Z", "log_type": "dns",
            "user": "alice", "query": "a" * 60 + ".evil.example",
            "query_type": "TXT", "action": "dns_query", "source_ip": "203.0.113.5",
            "dest_ip": "", "host": "H", "process": "", "command_line": "",
            "event_code": "",
        } for m in range(10)]
        exfil = detect_exfiltration(august_events)
        assert exfil, "setup: expected an exfil anomaly"

        anoms = [_anom(f"a{i}", "alice", f"2026-08-1{i}T03:00:00Z") for i in (0, 1, 2)]
        store = risk.compute_risk_scores(anoms + exfil, {"alice": "user"})
        score = store.get("alice").overall
        assert score > 10.0, (
            f"score collapsed to {score} with an event-time exfil anomaly in the "
            f"batch — the stamps must not move alice's clock to wall-now"
        )

    def test_data_clock_persisted_and_advances(self, isolated_settings):
        """The per-entity clock survives save/load and advances with the
        entity's own stamps."""
        from nabla import risk
        from nabla.risk import EntityRiskStore
        store1 = risk.compute_risk_scores(
            [_anom("a1", "alice", "2026-08-10T03:00:00Z")], {"alice": "user"})
        store2 = EntityRiskStore(isolated_settings.entity_risk_scores_file)
        a = store2.get("alice")
        assert a is not None
        persisted = getattr(a, "data_clock", "")
        # cold start floors at the dataset's data clock (2026-08-12, the
        # state file) — R12's synthetic-then-replay guard; the entity's own
        # stamps then ADVANCE it beyond that
        assert persisted.startswith("2026-08-12"), (
            f"per-entity data_clock not persisted/floored (got {persisted!r}) — N2.2"
        )

        # a later alice batch advances her clock
        risk.compute_risk_scores(
            [_anom("a2", "alice", "2026-09-01T05:00:00Z")], {"alice": "user"})
        store3 = EntityRiskStore(isolated_settings.entity_risk_scores_file)
        assert store3.get("alice").data_clock.startswith("2026-09-01")
