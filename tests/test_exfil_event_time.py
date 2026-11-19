"""N2.1 (round 4): exfiltration anomalies must carry EVENT time, not wall time.

All five exfil sub-detectors stamped `"timestamp": datetime.now(...)`, so any
exfil anomaly in a replay batch pushed the risk reference clock to today and
decayed every replayed anomaly in the batch to months-old — the reviewer's
verified table: score 26.9 with three replayed anomalies, 6.0 (all pruned)
with one wall-clock exfil anomaly added.

Also N2.3 (final-review REQUIRED 2): empty-timestamp anomalies are
decay-IMMORTAL in risk.py (`decay = ... if ts else 1.0` at :560/:621) —
never pruned, resurrected at full weight. Absent must mean absent.
"""

from __future__ import annotations

import json

import pytest

from nabla.exfiltration import detect_exfiltration


def _dns_entry(ts: str, user: str = "eve", q: str = "a" * 60 + ".evil.example") -> dict:
    return {
        "timestamp": ts, "log_type": "dns", "user": user,
        "query": q, "query_type": "TXT", "action": "dns_query",
        "source_ip": "203.0.113.5", "dest_ip": "", "host": "H", "process": "",
        "command_line": "", "event_code": "",
    }


class TestExfilStampsUseEventTime:
    @pytest.fixture(autouse=True)
    def _isolated_settings(self, tmp_path, monkeypatch):
        """detect_exfiltration touches bandit/RL state writes; point them
        at a writable tmp dir so the assertion under test is the only
        thing that can fail."""
        import types
        s = types.SimpleNamespace(
            entity_risk_scores_file=str(tmp_path / "r.json"),
            rl_state_file=str(tmp_path / "rl.json"),
            data_dir=str(tmp_path),
            system_state_file=str(tmp_path / "no-state.json"),
            machine_accounts="",  # N9: utils classification reads these
            human_accounts="",
        )
        monkeypatch.setattr("nabla.config.get_settings", lambda: s)
        (tmp_path / "feedback").mkdir(exist_ok=True)

    def test_dns_tunneling_carries_event_timestamp(self):
        """A DNS-tunneling anomaly fired on August data must be stamped with
        the August event time — not the wall clock of the detecting run.
        RED today: the stamp is datetime.now()."""
        entries = [_dns_entry("2026-08-10T03:00:00Z") for _ in range(10)]
        anomalies = detect_exfiltration(entries)
        tun = [a for a in anomalies if a.get("detection_method") == "dns_tunneling"]
        assert tun, "setup: dns_tunneling should fire on 10 long TXT queries"
        for a in tun:
            assert a.get("timestamp", "").startswith("2026-08-10"), (
                f"exfil anomaly stamped with wall clock: {a.get('timestamp')!r} "
                f"(event time was 2026-08-10T03:00:00Z)"
            )

    def test_no_exfil_anomaly_is_wall_clock_stamped(self, tmp_path, monkeypatch):
        """Broad form: every anomaly from any exfil sub-detector fires with
        a timestamp within the events' time span, on data a month old."""
        import types
        s = types.SimpleNamespace(
            entity_risk_scores_file=str(tmp_path / "r.json"),
            rl_state_file=str(tmp_path / "rl.json"),
            data_dir=str(tmp_path),
            system_state_file=str(tmp_path / "no-state.json"),
            machine_accounts="",  # N9: utils classification reads these
            human_accounts="",
        )
        monkeypatch.setattr("nabla.config.get_settings", lambda: s)
        (tmp_path / "feedback").mkdir(exist_ok=True)

        entries = [_dns_entry(f"2026-08-10T03:{m:02d}:00Z") for m in range(10)]
        # add a network connect for the destination/volume sub-detectors
        entries += [{
            "timestamp": "2026-08-10T03:30:00Z", "log_type": "network",
            "user": "eve", "action": "network_connect",
            "source_ip": "10.0.0.1", "dest_ip": "198.51.100.9",
            "dest_port": 443, "bytes": 50_000_000, "host": "H",
            "process": "", "command_line": "", "event_code": "", "query": "",
            "query_type": "",
        } for _ in range(5)]
        anomalies = detect_exfiltration(entries)
        assert anomalies, "setup: expected some exfil anomalies"
        for a in anomalies:
            ts = a.get("timestamp", "")
            assert ts.startswith("2026-08-10"), (
                f"{a.get('detection_method')} stamped {ts!r} — wall clock, not event time"
            )


class TestEmptyTimestampsAreAbsentInRisk:
    """N2.3: absent means absent — no contribution, no retention, no
    immortality. RED today: decay guards give empty-ts anomalies 1.0
    forever (risk.py:560/:621)."""

    def _make(self, ts: str | None, severity: str = "high") -> dict:
        a = {
            "anomaly_id": f"n2-{ts or 'empty'}", "entity": "alice",
            "detection_method": "entity_z_score", "severity": severity,
            "confidence": 0.9, "raw_score": 2.4,
        }
        if ts is not None:
            a["timestamp"] = ts
        return a

    def test_empty_ts_anomaly_contributes_nothing(self, tmp_path, monkeypatch):
        import os
        from nabla import risk
        s = type("S", (), {})()
        s.entity_risk_scores_file = str(tmp_path / "risk.json")
        s.system_state_file = str(tmp_path / "no-state.json")
        s.machine_accounts = ""  # N9: utils classification reads these
        s.human_accounts = ""
        monkeypatch.setattr("nabla.config.get_settings", lambda: s)

        # one healthy anomaly with a real August timestamp, one with none
        store = risk.compute_risk_scores(
            [self._make("2026-08-10T03:00:00Z"), self._make(None)],
            {"alice": "user"},
        )
        score = store.get("alice")
        # the healthy anomaly alone defines the expected score
        store_ref = risk.compute_risk_scores(
            [self._make("2026-08-10T03:00:00Z")], {"alice": "user"})
        ref = store_ref.get("alice")
        assert score.overall == ref.overall, (
            f"empty-ts anomaly changed the score ({score.overall} vs {ref.overall}) "
            f"— it must contribute nothing"
        )

    def test_empty_ts_anomaly_does_not_survive_retention(self, tmp_path, monkeypatch):
        """The zombie witness: an empty-ts anomaly in the retained set must
        be dropped, not resurrected at full weight forever."""
        from nabla import risk
        s = type("S", (), {})()
        s.entity_risk_scores_file = str(tmp_path / "risk.json")
        s.system_state_file = str(tmp_path / "no-state.json")
        s.machine_accounts = ""  # N9: utils classification reads these
        s.human_accounts = ""
        monkeypatch.setattr("nabla.config.get_settings", lambda: s)

        # seed the store with an empty-ts retained anomaly by hand — the
        # REAL on-disk shape ({"entities": {...}}; a bare dict loads as
        # nothing, which is how the first version of this test lied)
        import json
        path = str(tmp_path / "risk.json")
        seeded = {"entities": {"alice": {
            "entity_id": "alice", "entity_type": "user", "overall": 50.0,
            "peak": 50.0, "categories": {"account_compromise": 50.0}, "trend": 0.0,
            "last_updated": "2026-08-10T00:00:00Z",
            "contributing_anomalies": [
                {"anomaly_id": "zombie", "entity": "alice",
                 "detection_method": "entity_z_score", "severity": "high",
                 "confidence": 0.9, "raw_score": 2.4, "timestamp": "",
                 "base_contribution": 40.0, "contribution": 40.0,
                 "categories": ["account_compromise"]},
            ],
        }}}
        with open(path, "w") as fh:
            json.dump(seeded, fh)

        # a later run for a DIFFERENT entity — recompute-from-retained fires
        store = risk.compute_risk_scores(
            [{"anomaly_id": "b1", "entity": "bob", "detection_method": "entity_z_score",
              "severity": "low", "confidence": 0.5, "raw_score": 1.0,
              "timestamp": "2026-09-01T00:00:00Z"}],
            {"alice": "user", "bob": "user"},
        )
        alice = store.get("alice")
        ids = [a.get("anomaly_id") for a in (alice.contributing_anomalies or [])]
        assert "zombie" not in ids, (
            f"empty-ts anomaly survived retention at contribution "
            f"{[a.get('contribution') for a in alice.contributing_anomalies]} — "
            f"decay-immortal (risk.py:560/:621)"
        )
        assert alice.overall < 50.0, "zombie kept the score at full weight"
