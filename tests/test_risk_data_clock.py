"""A7 remediation: risk decay/stamps/trend on the data clock.

Gates (remediation plan phase 1 + review REQUIRED 1):
- Week-old replayed data produces non-trivial scores (was: ~0.8%).
- The replay-after-live sequence produces sane mixed-clock-free trend/last_updated.
- Unparseable timestamps are 'time unknown' (zero age), not maximum age.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from nabla.config import Settings

ANOMALY = {
    "entity": "alice",
    "type": "brute_force_attempt",
    "detection_method": "brute_force",
    "severity": "medium",
    "confidence": 0.8,
    "categories": ["account_compromise"],
}


def _write_state(tmp_path: Path, newest: str) -> None:
    (tmp_path / "system_state.json").write_text(json.dumps({"data_newest_ts": newest}))


def _settings(tmp_path):
    return Settings(
        data_dir=str(tmp_path), letta_base_url="http://x", embedding_endpoint="http://x",
        splunk_host="", sumologic_host="", splunk_validate_url=False, sumologic_validate_url=False,
    )


def test_week_old_replay_produces_nontrivial_scores(tmp_path, monkeypatch):
    """THE course gate: replayed historical data must score."""
    s = _settings(tmp_path)
    monkeypatch.setattr("nabla.config.get_settings", lambda: s)
    from nabla import risk

    week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    _write_state(tmp_path, week_ago)
    store = risk.compute_risk_scores(
        [{**ANOMALY, "timestamp": week_ago}],
        entity_type_map={"alice": "user"}, half_life_hours=24.0)
    score = store.scores["alice"].overall
    assert score > 3.0, f"week-old replay scored {score} - decay still wall-clocked (undecayed ceiling is 4.0; wall-clock bug scores ~0.03)"


def test_replay_after_live_no_mixed_clock_artifacts(tmp_path, monkeypatch):
    """Review REQUIRED 1 gate: live-scored entity, then older data ingested -
    trend and last_updated must stay sane (no wall/data mixing)."""
    s = _settings(tmp_path)
    monkeypatch.setattr("nabla.config.get_settings", lambda: s)
    from nabla import risk

    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    _write_state(tmp_path, yesterday)
    risk.compute_risk_scores(
        [{**ANOMALY, "timestamp": yesterday}],
        entity_type_map={"alice": "user"}, half_life_hours=24.0)

    older = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    _write_state(tmp_path, older)
    store2 = risk.compute_risk_scores(
        [{**ANOMALY, "timestamp": older}],
        entity_type_map={"alice": "user"}, half_life_hours=24.0)
    sc = store2.scores["alice"]
    assert abs(sc.trend) < 100.0, f"trend insane: {sc.trend}"
    lu = datetime.fromisoformat(sc.last_updated.replace("Z", "+00:00"))
    assert lu < datetime.now(timezone.utc) - timedelta(days=5), "last_updated wall-clocked"


def test_unparseable_timestamp_is_time_unknown(tmp_path, monkeypatch):
    """Not 999-hours-old: zero age against the reference."""
    s = _settings(tmp_path)
    monkeypatch.setattr("nabla.config.get_settings", lambda: s)
    from nabla import risk

    _write_state(tmp_path, datetime.now(timezone.utc).isoformat())
    store = risk.compute_risk_scores(
        [{**ANOMALY, "timestamp": "garbage"}],
        entity_type_map={"alice": "user"}, half_life_hours=24.0)
    assert store.scores["alice"].overall > 3.0, "unparseable ts zeroed the contribution"


def test_live_ingestion_tracks_wall_clock(tmp_path, monkeypatch):
    """Fresh data now: data clock ~= wall clock, legacy behavior."""
    s = _settings(tmp_path)
    monkeypatch.setattr("nabla.config.get_settings", lambda: s)
    from nabla import risk

    now_iso = datetime.now(timezone.utc).isoformat()
    _write_state(tmp_path, now_iso)
    store = risk.compute_risk_scores(
        [{**ANOMALY, "timestamp": now_iso}],
        entity_type_map={"alice": "user"}, half_life_hours=24.0)
    assert store.scores["alice"].overall > 3.0


def test_risk_accumulates_across_runs(tmp_path, monkeypatch):
    """A6 gate: one medium anomaly per run x 5 runs ends higher than after run 1."""
    s = _settings(tmp_path)
    monkeypatch.setattr("nabla.config.get_settings", lambda: s)
    from nabla import risk

    _write_state(tmp_path, datetime.now(timezone.utc).isoformat())
    scores = []
    for run in range(5):
        ts = (datetime.now(timezone.utc) - timedelta(minutes=5 * run)).isoformat()
        store = risk.compute_risk_scores(
            [{**ANOMALY, "timestamp": ts, "detection_method": f"method_{run}"}],
            entity_type_map={"alice": "user"}, half_life_hours=24.0)
        scores.append(store.scores["alice"].overall)
    assert scores[-1] > scores[0], f"no accumulation: {scores}"
    assert len(store.scores["alice"].contributing_anomalies) == 5


def test_bandit_weight_applied(tmp_path, monkeypatch):
    """A5 gate: a method with strong confirmation history gets weight > 1.0."""
    s = _settings(tmp_path)
    monkeypatch.setattr("nabla.config.get_settings", lambda: s)
    from nabla import risk
    from nabla.rl.bandit import DetectionMethodBandit

    _write_state(tmp_path, datetime.now(timezone.utc).isoformat())
    bandit = DetectionMethodBandit.__new__(DetectionMethodBandit)
    bandit.methods = ["brute_force"]
    bandit.alpha = {"brute_force": 10.0}
    bandit.beta = {"brute_force": 1.0}
    w = risk._get_bandit_weights(bandit)
    assert w["brute_force"] > 1.0, f"confirmed method not boosted: {w}"


class TestR1R2Round3:
    def test_real_id_anomalies_flow_through_risk(self, tmp_path, monkeypatch):
        """R1 (round 3): anomalies carrying stamped IDs must not crash risk."""
        s = _settings(tmp_path)
        monkeypatch.setattr("nabla.config.get_settings", lambda: s)
        from nabla import risk

        monkeypatch.setattr(risk, "_data_clock", lambda: datetime.now(timezone.utc))
        # First run: seeds the retained store
        anom1 = {**ANOMALY, "anomaly_id": "abc123def456ghi7", "timestamp": datetime.now(timezone.utc).isoformat()}
        store = risk.compute_risk_scores([anom1], {"alice": "user"}, half_life_hours=24.0)
        assert store.scores["alice"].overall > 3.0  # would have raised ValueError pre-fix

    def test_single_decay_not_compounding(self, tmp_path, monkeypatch):
        """R2 (round 3): retained contributions decay ONCE per run from base.

        5-minute runs over 2 hours: the first anomaly's contribution must
        match base * 0.5^(age/half_life) within tolerance — the old code
        compounded decay per run (~2h effective memory).
        """
        s = _settings(tmp_path)
        monkeypatch.setattr("nabla.config.get_settings", lambda: s)
        from nabla import risk
        from datetime import timedelta

        start = datetime.now(timezone.utc)
        monkeypatch.setattr(risk, "_data_clock", lambda: start)  # fixed clock for determinism

        anom1 = {**ANOMALY, "anomaly_id": "seed-anom", "severity": "high",
                 "confidence": 1.0, "timestamp": start.isoformat()}
        store1 = risk.compute_risk_scores([anom1], {"alice": "user"}, half_life_hours=24.0)
        base = store1.scores["alice"].contributing_anomalies[0].get("base_contribution")

        # 24 subsequent 5-min runs, each with a DIFFERENT anomaly (so alice keeps
        # being scored) — clock advancing 5 min per run
        t = start
        for i in range(24):
            t = t + timedelta(minutes=5)
            monkeypatch.setattr(risk, "_data_clock", lambda tt=t: tt)
            other = {**ANOMALY, "anomaly_id": f"other-{i}", "entity": "bob",
                     "timestamp": t.isoformat()}
            risk.compute_risk_scores([other], {"alice": "user", "bob": "user"}, half_life_hours=24.0)

        # alice's seed anomaly: age = 2h; single decay => base * 0.5^(2/24)
        monkeypatch.setattr(risk, "_data_clock", lambda tt=t: tt)
        storeN = risk.compute_risk_scores(
            [{**ANOMALY, "anomaly_id": "final", "entity": "carol", "timestamp": t.isoformat()}],
            {"alice": "user", "bob": "user", "carol": "user"}, half_life_hours=24.0)
        alice = storeN.scores.get("alice")
        seed = [a for a in alice.contributing_anomalies if a.get("anomaly_id") == "seed-anom"]
        assert seed, f"seed anomaly pruned early (R2 compounding): {[a.get('anomaly_id') for a in alice.contributing_anomalies]}"
        expected = base * 0.5 ** (2.0 / 24.0)
        actual = seed[0].get("contribution", 0.0)
        assert abs(actual - expected) < 0.05 * base, (
            f"contribution {actual} vs single-decay {expected:.3f} (base {base})")


class TestR12BothOrders:
    def test_synthetic_then_replay_both_alive(self, tmp_path, monkeypatch):
        """REQUIRED 1's harness case: BOTH course orders score non-trivially."""
        s = _settings(tmp_path)
        monkeypatch.setattr("nabla.config.get_settings", lambda: s)
        from nabla import risk
        import json as J
        from datetime import datetime, timedelta, timezone

        # SIEM replay stamps August; the persisted clock sits at Aug-end
        state = tmp_path / "system_state.json"
        aug_end = "2026-08-31T23:59:00Z"
        state.write_text(J.dumps({"data_newest_ts": aug_end}))

        # Order 1: synthetic run (wall-now stamps) AFTER the replay
        now_anom = {**ANOMALY, "anomaly_id": "synth-1",
                    "timestamp": datetime.now(timezone.utc).isoformat()}
        st1 = risk.compute_risk_scores([now_anom], {"alice": "user"}, half_life_hours=24.0)
        assert st1.scores["alice"].overall > 3.0, "synthetic-after-replay died (the A7 disease)"

        # Order 2: replay-stamped attack. The clock sits at Aug-31 (the
        # replay's own newest); the attack batch's newest is Aug-30 22:00 ->
        # per-batch ref = Aug-31 -> ~26h age -> ~1.9 of 4.0 base. That IS
        # the honest decay (one day older than the newest data). The case
        # the per-batch fix guards: a synthetic run CANNOT advance the
        # reference (risk never persists it), so the Nov-18-wall-now
        # poisoning the review feared cannot happen. Assert the bounded
        # decay — and that it's decay-from-OWN-time, not 80-day zeroing:
        aug_anom = {**ANOMALY, "anomaly_id": "atk-1", "entity": "bob",
                    "timestamp": "2026-08-30T22:00:00Z"}
        st2 = risk.compute_risk_scores([aug_anom], {"alice": "user", "bob": "user"},
                                       half_life_hours=24.0)
        bob = st2.scores["bob"].overall
        assert bob > 1.0, f"replay zeroed ({bob}) — 80-day disease, not 1-day decay"
        assert bob < 4.0, f"decay not applied ({bob})"
