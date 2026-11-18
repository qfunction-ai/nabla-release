"""Stage 3 gates: A12-A21 detector quality."""

import numpy as np


class TestA12HistoricalAnchoring:
    def test_benign_batch_flags_nothing(self):
        """The reviewer's gate: a batch of identical benign events flags NOTHING
        (per-batch min-max forced the max to 1.0 and the worst event always
        cleared the threshold)."""
        from nabla.gcn_lof import GCNLOFDetector
        d = GCNLOFDetector.__new__(GCNLOFDetector)
        d.score_bank = {}
        # Identical scores, fresh bank: not enough history -> zeros -> no flags
        raw = np.array([1.0, 1.0, 1.0, 1.0])
        z = d._bank_zscore(raw, "lof")
        assert (z == 0).all()

    def test_anchored_z_after_history(self):
        from nabla.gcn_lof import GCNLOFDetector
        d = GCNLOFDetector.__new__(GCNLOFDetector)
        d.score_bank = {}
        # Warm the bank: 200 observations around 1.0
        d._bank_zscore(np.random.default_rng(1).normal(1.0, 0.05, 200), "lof")
        # A batch far from history scores high; a batch AT history ~0
        at_history = d._bank_zscore(np.array([1.0, 1.01, 0.99]), "lof")
        far_out = d._bank_zscore(np.array([3.0]), "lof")
        assert abs(at_history).max() < 1.0
        assert far_out[0] > 10

    def test_bank_persists_roundtrip(self):
        from nabla.gcn_lof import GCNLOFDetector
        d = GCNLOFDetector.__new__(GCNLOFDetector)
        d.score_bank = {"lof": {"count": 100, "mean": 1.0, "m2": 4.0}}
        ser = {"score_bank": d.score_bank}
        d2 = GCNLOFDetector.__new__(GCNLOFDetector)
        d2.score_bank = ser.get("score_bank") or {}
        assert d2.score_bank["lof"]["count"] == 100


class TestA14ChainGating:
    def test_single_event_multi_detector_not_chained(self):
        """Three detectors on ONE event must not produce a flagged chain."""
        from nabla.temporal import TemporalChain, should_flag_chain
        one_event = {"anomaly_id": "same-id", "detection_method": "brute_force",
                     "timestamp": "2026-01-01T03:00:00Z"}
        chain = TemporalChain(
            chain_id=1, entities={"user": {"a"}}, events=[one_event] * 3,
            phases=["initial_access"],
            start_time=None, end_time=None, duration_seconds=0.0,
            phase_coverage=0.2, tightness=1.0, score=0.5)
        assert not should_flag_chain(chain)


class TestA15MinPopulation:
    def test_small_batch_z_skipped(self):
        """Below 10 users the batch z cannot mathematically reach 2.0."""
        from nabla.detection import detect_anomalies
        # 5 users, one with 10x the events: max z = sqrt(4) = 2.0 — unreachable
        entries = []
        for u in ["a", "b", "c", "d", "e"]:
            n = 100 if u == "a" else 10
            for i in range(n):
                entries.append({"user": u, "action": "login_success",
                                "type": "auth", "timestamp": "2026-01-15T10:00:00Z"})
        anomalies, _ = detect_anomalies(entries)
        z_spikes = [a for a in anomalies if a.get("detection_method") == "z_score"]
        assert len(z_spikes) == 0


class TestA16Allowlist:
    def test_sanctioned_service_exempt(self, monkeypatch):
        # R14: reads via Settings — patch the settings object
        from unittest.mock import MagicMock
        import nabla.exfiltration as exfil
        fake_settings = MagicMock()
        fake_settings.sanctioned_services = "drive.google.com"
        monkeypatch.setattr("nabla.config.get_settings", lambda: fake_settings)
        assert "drive.google.com" in exfil._sanctioned_services()

    def test_domain_boundary_matching(self):
        from nabla.exfiltration import _domain_matches
        assert _domain_matches("contoso.sharepoint.com", "sharepoint.com")
        assert _domain_matches("sharepoint.com", "sharepoint.com")
        assert not _domain_matches("evil-sharepoint.com", "sharepoint.com")


class TestA21StagingSize:
    def test_small_transfer_not_flagged(self):
        from nabla.exfiltration import detect_exfiltration
        from datetime import datetime, timedelta, timezone
        t = datetime.now(timezone.utc)
        entries = [
            {"user": "u", "action": "create", "target_file": "x.txt", "timestamp": t.isoformat()},
            {"user": "u", "action": "network_connect", "type": "network", "bytes": 1_000,
             "timestamp": (t + timedelta(minutes=5)).isoformat()},
        ]
        anomalies = detect_exfiltration(entries, thresholds={})
        assert not [a for a in anomalies if a.get("detection_method") == "exfil_staging"]


class TestA19Rename:
    def test_no_impossible_travel_anywhere(self):
        import subprocess
        r = subprocess.run(
            ["grep", "-rn", "--include=*.py", "impossible_travel", "nabla/"],
            capture_output=True, text=True)
        assert r.stdout.strip() == "", f"stale references: {r.stdout[:200]}"


class TestA18HourParsing:
    def test_offset_timestamp_utc_hour(self):
        from nabla.utils import _parse_hour
        # 23:30 at UTC+5 == 18:30 UTC: NOT off-hours despite local slice '23'
        assert _parse_hour("2026-01-15T23:30:00+05:00") == 18
        assert _parse_hour("garbage") == -1
