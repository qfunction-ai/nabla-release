"""Phase 3 (round 4): N3, N5, N6 — quarantine wiring and the bandit reset.

N3: held baseline data is lost on a false-positive disposition —
    apply_pending mutates a store nobody saves, and the 5-batch cap is
    25 minutes at the 5-minute schedule while the hold lasts 7 days.
    Fix shape (reviewer's + STRONG 2): approve_pending moves batches to
    an approved list; the NEXT pipeline run drains ALL approved entities
    at start, inside its load-save window; the cap becomes span/count
    based.

N5: any anomaly quarantines its entity; a TP freezes the baseline
    forever. Fix shape: severity gate {high, critical} OR method in an
    explicit QUARANTINE_HOLD_METHODS set (the medium-ceiling families);
    TP holds 14 data-clock days then auto-releases (Decision 1);
    TTL-release APPLIES held data (final-review REQUIRED 1, Decision:
    self-healing over permanent re-flag loops).

N6: reset_poisoned_bandit has zero production callers. Fix shape:
    schema-gated reset in DetectionMethodBandit.load() — pre-schema
    state files yield uniform priors IN THE RISK COMPUTATION, written
    atomically.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


@pytest.fixture
def env(tmp_path, monkeypatch):
    import types
    # sim data clock inside the data window — the honest condition (the
    # span cap and hold TTLs are data-clock based; a wall-now clock makes
    # August-stamped batches look months old and drops them at write time)
    state = {"phase": "detection", "data_newest_ts": "2026-08-10T00:00:00+00:00"}
    (tmp_path / "system_state.json").write_text(json.dumps(state))
    s = types.SimpleNamespace(
        data_dir=str(tmp_path),
        entity_profiles_file=str(tmp_path / "profiles.json"),
        system_state_file=str(tmp_path / "system_state.json"),
        rl_state_file=str(tmp_path / "rl_state.json"),
        entity_warmup_observations=3,
    )
    monkeypatch.setattr("nabla.config.get_settings", lambda: s)
    return tmp_path


def _entries(hours: list[int], day: int = 9, user: str = "casey", per_hour: int = 8) -> list[dict]:
    out = []
    for h in hours:
        for k in range(per_hour):
            out.append({
                "timestamp": f"2026-08-{day:02d}T{h:02d}:{k * 7 % 60:02d}:00Z",
                "log_type": "auth", "user": user, "action": "login_success",
            })
    return out


class TestN3HeldDataSurvivesFPDisposition:
    def _hold_a_batch(self, env, user="casey"):
        from nabla.baselines import flag_quarantine, hold_pending, EntityProfileStore
        flag_quarantine([user])
        batch = _entries([14, 15])
        hold_pending(user, batch)
        return batch

    def test_fp_disposition_approves_and_next_run_applies(self, env, monkeypatch):
        """The N3 witness: hold -> FP disposition -> NEXT pipeline run ->
        the on-disk profile shows the held observations. RED today (the
        applied data is discarded — no save; and the API path can't apply
        at all under the new design)."""
        from nabla.baselines import (EntityProfileStore, apply_disposition_to_quarantine,
                                     approve_pending)
        self._hold_a_batch(env)

        # the API-path disposition: approves; writes NO profiles
        apply_disposition_to_quarantine("casey", "false_positive")

        # the next pipeline run drains approved batches into the profile
        store = EntityProfileStore(str(env / "profiles.json"))
        from nabla.baselines import drain_approved_pending
        applied = drain_approved_pending(store)
        store.save()
        # CLOCK-SPEC Rule 6 / T-1 (round 6): drains apply PER MERGED HOUR —
        # this hold spans hours 14 and 15, so two complete-hour applications
        # is the correct count (the old batch-count assertion measured
        # fragments; a 5-min schedule batch is not an hour)
        assert applied == 2, f"approved hours not drained ({applied})"

        reloaded = EntityProfileStore(str(env / "profiles.json"))
        p = reloaded.get_user("casey")
        assert p is not None and p.observation_count >= 1, (
            "held data never reached the on-disk profile — N3: the FP verdict was discarded"
        )
        assert 14 in p.hour_histogram or 14 in p.typical_hours.to_list() if hasattr(p.typical_hours, "to_list") else True

    def test_quiet_entity_drains_at_next_run_not_on_activity(self, env):
        """STRONG 2: approved batches drain at pipeline START for ALL
        approved entities — an entity that goes quiet after its FP
        disposition must not silently lose its verdict past the cap."""
        from nabla.baselines import (EntityProfileStore, flag_quarantine,
                                     hold_pending, approve_pending, drain_approved_pending)
        # casey: held + approved. dana (quiet after disposition): held + approved.
        for u in ("casey", "dana"):
            flag_quarantine([u])
            hold_pending(u, _entries([10], user=u))
            approve_pending(u)

        store = EntityProfileStore(str(env / "profiles.json"))
        applied = drain_approved_pending(store)  # no activity for dana — still drains
        store.save()
        assert applied == 2, (
            f"drain skipped a quiet entity ({applied}/2) — the verdict leaks (STRONG 2)"
        )

    def test_pending_cap_is_span_and_count_based(self, env):
        """The 5-batch cap is 25 minutes at the default schedule while the
        hold lasts 7 days. The cap becomes 7 data-clock days or 5,000
        events per entity, whichever first."""
        from nabla.baselines import flag_quarantine, hold_pending, _load_pending
        flag_quarantine(["casey"])
        # six SMALL batches in one hour — all must survive (old cap: 5)
        for i in range(6):
            hold_pending("casey", _entries([9 + i // 6], per_hour=1))
        pend = _load_pending()
        assert len(pend.get("casey", [])) == 6, (
            f"count-based cap dropped same-hour batches: {len(pend.get('casey', []))}"
        )
        # a batch older than 7 data-clock days is dropped at write time
        old = _entries([3], day=1, per_hour=4)
        hold_pending("casey", old)
        pend = _load_pending()
        stamps = [e["timestamp"] for b in pend["casey"] for e in b]
        assert all(s >= "2026-08-08" for s in stamps), (
            "span cap did not drop a >7-day-old batch (7 data-clock-day span)"
        )


class TestN5QuarantineTrigger:
    def _anom(self, method="entity_off_hours", severity="medium", user="riley"):
        return {"detection_method": method, "severity": severity, "user": user,
                "entity": user, "anomaly_id": f"a-{method}-{severity}"}

    def test_medium_off_hours_on_hold_list_does_quarantine(self):
        """The round-1 REQUIRED 1 positive path: a MEDIUM entity_off_hours
        anomaly (hold list) DOES quarantine. RED today? No — today
        EVERYTHING quarantines; this is the witness that the fix must keep
        true while the negative path below becomes true."""
        from nabla.pipeline.orchestration import _quarantine_flagged_entities
        flagged = _quarantine_flagged_entities([self._anom("entity_off_hours", "medium")])
        assert flagged == {"riley"}, f"hold-list medium must quarantine, got {flagged}"

    def test_medium_statistical_noise_does_not_quarantine(self):
        """The negative path: a medium z_score (NOT on the hold list) must
        NOT quarantine. RED today (everything flags)."""
        from nabla.pipeline.orchestration import _quarantine_flagged_entities
        flagged = _quarantine_flagged_entities([self._anom("z_score", "medium")])
        assert flagged == set(), (
            f"medium statistical noise quarantined: {flagged} — the freeze-a-baseline-"
            f"per-flag noise N5 exists to kill"
        )

    def test_low_anything_does_not_quarantine(self):
        """Low severity, non-hold-list methods stay quiet. (Hold-list
        methods gate regardless of severity by design — their ceiling IS
        medium; a 'low off-hours' would still be the only signal for that
        attack class.)"""
        from nabla.pipeline.orchestration import _quarantine_flagged_entities
        flagged = _quarantine_flagged_entities([
            self._anom("z_score", "low"), self._anom("entity_z_score", "low"),
            self._anom("multi_ip", "low"),
        ])
        assert flagged == set()

    def test_high_severity_quarantines_regardless_of_method(self):
        from nabla.pipeline.orchestration import _quarantine_flagged_entities
        flagged = _quarantine_flagged_entities([self._anom("z_score", "high")])
        assert flagged == {"riley"}

    def test_tp_holds_14_data_clock_days_then_releases(self, env, monkeypatch):
        """Decision 1: TP = discard pending + hold 14 data-clock days, then
        auto-release (a remediated account resumes learning; indefinite
        freeze is the R6 half N5 closes). RED today (indefinite=True)."""
        from nabla.baselines import (flag_quarantine, hold_quarantine,
                                     discard_pending, _is_quarantined)
        import nabla.baselines as B

        state = {"phase": "detection", "data_newest_ts": "2026-08-10T00:00:00+00:00"}
        (env / "system_state.json").write_text(json.dumps(state))

        flag_quarantine(["riley"], data_clock=datetime(2026, 8, 10, tzinfo=timezone.utc))
        hold_quarantine("riley")  # the TP disposition
        discard_pending("riley")

        assert _is_quarantined("riley") is True

        # 14 data-clock days pass (advance the state's newest)
        state["data_newest_ts"] = "2026-08-24T00:00:00+00:00"
        (env / "system_state.json").write_text(json.dumps(state))
        assert _is_quarantined("riley") is False, (
            "TP hold never expires — the baseline freezes forever (N5)"
        )

    def test_ttl_release_applies_held_data(self, env, monkeypatch):
        """Final-review REQUIRED 1: a no-disposition TTL expiry treats held
        data as normal (release AND apply) — the self-healing choice."""
        from nabla.baselines import (flag_quarantine, hold_pending, _is_quarantined,
                                     EntityProfileStore, drain_released_pending)
        import nabla.baselines as B

        state = {"phase": "detection", "data_newest_ts": "2026-08-10T00:00:00+00:00"}
        (env / "system_state.json").write_text(json.dumps(state))

        flag_quarantine(["riley"], data_clock=datetime(2026, 8, 10, tzinfo=timezone.utc))
        hold_pending("riley", _entries([22], user="riley"))

        # 8 data-clock days pass: TTL (7d) expires
        state["data_newest_ts"] = "2026-08-18T00:00:00+00:00"
        (env / "system_state.json").write_text(json.dumps(state))
        assert _is_quarantined("riley") is False

        store = EntityProfileStore(str(env / "profiles.json"))
        applied = drain_released_pending(store)
        store.save()
        assert applied >= 1, "TTL expiry did not route held data to apply (REQUIRED 1: APPLY)"
        re = EntityProfileStore(str(env / "profiles.json"))
        assert re.get_user("riley").observation_count >= 1


class TestN6BanditReset:
    def test_pre_schema_state_loads_uniform_and_risk_uses_it(self, env, monkeypatch):
        """N6: a pre-schema bandit state (poisoned alpha/beta from the
        deleted text parser) loads as uniform priors, AND the risk
        computation actually sees uniform (not just the file)."""
        import types
        # a poisoned pre-schema state file
        poisoned = {
            "bandit": {"alpha": {"failed_login_ratio": 99.0}, "beta": {"failed_login_ratio": 1.0}}
        }
        (env / "rl_state.json").write_text(json.dumps(poisoned))

        s = types.SimpleNamespace(
            data_dir=str(env),
            rl_state_file=str(env / "rl_state.json"),
            entity_risk_scores_file=str(env / "risk.json"),
            system_state_file=str(env / "system_state.json"),
        )
        monkeypatch.setattr("nabla.config.get_settings", lambda: s)

        from nabla.rl.bandit import DetectionMethodBandit
        b = DetectionMethodBandit.load(str(env / "rl_state.json"))
        means = b.get_means()  # deterministic; get_weights SAMPLES
        assert means.get("failed_login_ratio", 0.5) == pytest.approx(0.5), (
            f"poisoned priors survived the load: {means} — N6 (schema gate missing)"
        )
        # written back with the schema marker, atomically
        on_disk = json.loads((env / "rl_state.json").read_text())
        assert on_disk.get("schema") == 2, f"schema marker not stamped: {on_disk.keys()}"

    def test_post_schema_state_is_left_alone(self, env, monkeypatch):
        """Learned post-reset state (schema 2) must NOT be reset again."""
        learned = {
            "schema": 2,
            "bandit": {"alpha": {"failed_login_ratio": 8.0}, "beta": {"failed_login_ratio": 2.0}},
        }
        (env / "rl_state.json").write_text(json.dumps(learned))
        from nabla.rl.bandit import DetectionMethodBandit
        b = DetectionMethodBandit.load(str(env / "rl_state.json"))
        means = b.get_means()
        bf = means.get("failed_login_ratio", 0.5)
        assert bf != pytest.approx(0.5), (
            f"schema-2 state was reset — the gate doesn't gate (brute_force mean={bf})"
        )
