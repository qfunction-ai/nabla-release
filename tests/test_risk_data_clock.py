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
