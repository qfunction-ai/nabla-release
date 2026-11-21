"""N-3 / R-3 / R-4 / R-11 (round 7): the quarantine drains must commit
AFTER the profile store save, selectively, per batch.

The shipped orchestration cleared approved.json BEFORE the profile save
(orchestration.py:313 vs :327 — the comment said AFTER): a crash in
between lost the analyst's verdict for good. The TTL drain had the same
disease one file over — it popped pending.json and saved it inside the
drain, before the profile store persisted. And the replay guard
fingerprinted the WHOLE approval set, so a new approval arriving between
crash and restart changed the fingerprint and re-applied everything.

New contract:
- hold assigns a per-batch uid at HOLD time (R-4)
- drains apply through update_user, record applied uids on the profile,
  and rewrite NOTHING (R-3)
- commit_drain_after_save (called after the profile save) removes ONLY
  the drained batches — a verdict arriving mid-run survives (R-11)
- crash before the commit: per-batch uids make the replay a no-op
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

T0 = datetime(2026, 8, 16, 0, 0, tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _entries(hours, user="alice", day=0):
    out = []
    for h in hours:
        out.append({
            "user": user, "action": "process_create",
            "timestamp": _iso(T0 + timedelta(days=day, hours=h)),
            "event_id": f"ev-{user}-{day}-{h}",
            "process_name": "pw.exe", "command_line": "x",
        })
    return out


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NABLA_DATA_DIR", str(tmp_path))
    import nabla.config as config_mod
    config_mod._settings = None
    # Pin the data clock to T0: hold_pending's 7-day span cap drops
    # batches older than data-clock-now (fresh env = wall clock).
    import nabla.baselines as B
    monkeypatch.setattr(B, "_data_clock_now", lambda: T0)
    yield tmp_path
    config_mod._settings = None


def _approved(env) -> dict:
    p = env / "baseline_approved.json"
    return json.loads(p.read_text()) if p.exists() else {}


def _pending(env) -> dict:
    p = env / "baseline_pending.json"
    return json.loads(p.read_text()) if p.exists() else {}


def _new_store():
    from nabla.config import get_settings
    from nabla.baselines import EntityProfileStore
    return EntityProfileStore(get_settings().entity_profiles_file)


class TestApprovedDrainCommit:
    def test_crash_before_save_keeps_verdict(self, env):
        """The round-6 bug, witnessed: the orchestration cleared
        approved.json BEFORE the profile save. A crash between the two
        lost the analyst's verdict for good. The new contract: nothing
        is removed until commit_drain_after_save runs post-save."""
        import nabla.baselines as B

        B.hold_pending("alice", _entries([3]))
        assert B.approve_pending("alice") == 1

        store = _new_store()
        applied = B.drain_approved_pending(store)
        assert applied, "drain applied nothing"
        # CRASH: profile store never saved, commit never runs.
        # Desired: the verdict is still in approved.json.
        assert "alice" in _approved(env), (
            "approved.json was emptied before the profile save — "
            "a crash here loses the analyst's verdict (N-3)")

    def test_replay_after_save_is_noop_and_commits(self, env):
        import nabla.baselines as B

        B.hold_pending("alice", _entries([3]))
        B.approve_pending("alice")
        store = _new_store()
        applied1 = B.drain_approved_pending(store)
        assert applied1
        store.save()
        # crash AFTER save, BEFORE commit: uids persisted with the store
        assert "alice" in _approved(env)

        # replay: a fresh run drains again (nothing new), saves, commits
        store2 = _new_store()
        calls = []
        orig = store2.update_user
        store2.update_user = lambda *a, **k: (calls.append(a), orig(*a, **k))[1]
        applied2 = B.drain_approved_pending(store2)
        store2.save()
        B.commit_drain_after_save(applied2)
        assert calls == [], "crash replay re-applied drained batches"
        assert "alice" not in _approved(env), "commit left drained batches"

    def test_midrun_arrival_survives_commit(self, env):
        """R-11: an analyst approves ANOTHER batch while the pipeline is
        mid-run (between drain and commit). The commit removes only what
        the drain processed — the new verdict survives and applies on
        the next run, exactly once."""
        import nabla.baselines as B

        B.hold_pending("alice", _entries([3]))
        B.approve_pending("alice")
        store = _new_store()
        applied = B.drain_approved_pending(store)
        store.save()

        # mid-run: a second batch is held and approved
        B.hold_pending("alice", _entries([5]))
        assert B.approve_pending("alice") == 1

        B.commit_drain_after_save(applied)
        remaining = _approved(env).get("alice", [])
        assert len(remaining) == 1, (
            f"commit wiped the mid-run verdict: {remaining!r}")

        # next run: the survivor applies exactly once
        store2 = _new_store()
        calls = []
        orig = store2.update_user
        store2.update_user = lambda *a, **k: (calls.append(a), orig(*a, **k))[1]
        applied2 = B.drain_approved_pending(store2)
        store2.save()
        B.commit_drain_after_save(applied2)
        assert len(applied2.get("alice", [])) == 1
        assert len(calls) == 1, f"survivor applied {len(calls)} times"
        assert "alice" not in _approved(env)

    def test_batch_uids_assigned_at_hold_time(self, env):
        """R-4: identity is per batch and assigned at HOLD time — two
        holds of identical content are two batches with two uids (a
        whole-set fingerprint would re-apply the set when a new batch
        joins it)."""
        import nabla.baselines as B

        B.hold_pending("alice", _entries([3]))
        B.hold_pending("alice", _entries([3]))  # duplicate content
        pend = B._load_pending()
        uids = [B._batch_uid("alice", b) for b in pend["alice"]]
        assert len(uids) == 2 and uids[0] != uids[1], (
            f"hold did not assign per-batch uids: {uids!r}")

        B.approve_pending("alice")
        store = _new_store()
        applied = B.drain_approved_pending(store)
        store.save()
        B.commit_drain_after_save(applied)
        assert len(applied["alice"]) == 2
        assert "alice" not in _approved(env)


class TestTtlReleaseCommit:
    def _arm(self, env, ttl_expired=True):
        import nabla.baselines as B
        since = T0 - timedelta(days=30 if ttl_expired else 1)
        (env / "baseline_quarantine.json").write_text(json.dumps({"alice": {
            "held": True, "since": _iso(since), "batches_held": 1,
            "indefinite": False,
        }}))
        B.hold_pending("alice", _entries([3]))

    def test_drain_does_not_rewrite_pending_before_save(self, env):
        """R-3: the TTL drain popped pending.json and saved it INSIDE the
        drain — a crash before the profile save lost the held data for
        good. New contract: the drain rewrites nothing."""
        import nabla.baselines as B
        self._arm(env)
        assert "alice" in _pending(env)

        store = _new_store()
        released, holds = B.drain_released_pending(store)
        assert released, "TTL drain released nothing"
        # CRASH: profile store never saved, commit never runs.
        assert "alice" in _pending(env), (
            "drain_released_pending rewrote pending.json before the "
            "profile store persisted — a crash here loses the held data (R-3)")

    def test_replay_is_noop_then_commit_clears(self, env):
        import nabla.baselines as B
        self._arm(env)
        store = _new_store()
        released, holds = B.drain_released_pending(store)
        store.save()
        # crash after save, before commit
        assert "alice" in _pending(env)

        store2 = _new_store()
        calls = []
        orig = store2.update_user
        store2.update_user = lambda *a, **k: (calls.append(a), orig(*a, **k))[1]
        released2, holds2 = B.drain_released_pending(store2)
        store2.save()
        B.commit_drain_after_save(None, released2, holds2)
        assert calls == [], "crash replay re-applied TTL-released batches"
        assert "alice" not in _pending(env)
        q = json.loads((env / "baseline_quarantine.json").read_text())
        assert q["alice"]["held"] is False

    def test_midrun_rehold_survives_commit(self, env):
        """The TTL release drains; detection RE-ARMS the entity later in
        the same run (new anomaly). The commit flips only the hold it
        drained — the fresh hold must survive."""
        import nabla.baselines as B
        self._arm(env)
        store = _new_store()
        released, holds = B.drain_released_pending(store)
        store.save()

        # mid-run re-arm: detection flags alice again (new since)
        B.flag_quarantine(["alice"], data_clock=T0 + timedelta(hours=1))

        B.commit_drain_after_save(None, released, holds)
        q = json.loads((env / "baseline_quarantine.json").read_text())
        assert q["alice"]["held"] is True, (
            "commit erased a hold re-armed mid-run")
        assert "alice" not in _pending(env)


class TestLegacyShapes:
    def test_legacy_bare_batches_still_drain(self, env):
        """Pre-round-7 pending/approved files carry bare entry lists —
        the drains must accept both shapes and give legacy batches a
        deterministic content uid."""
        import nabla.baselines as B
        entries = _entries([3])
        (env / "baseline_approved.json").write_text(json.dumps(
            {"alice": [entries]}))
        store = _new_store()
        applied = B.drain_approved_pending(store)
        store.save()
        B.commit_drain_after_save(applied)
        assert len(applied.get("alice", [])) == 1
        assert "alice" not in _approved(env)


class TestOrchestrationOrder:
    def test_commit_runs_after_save_in_orchestration(self):
        """N-3: the shipped orchestration called clear_approved_after_save
        BEFORE entity_profiles.save() while the comment claimed AFTER —
        code contradicting itself is how the verdict-loss bug shipped.
        Guard: the commit call must come after the save, positionally,
        and the pre-save clear must be gone entirely."""
        from pathlib import Path
        src = Path(__file__).resolve().parent.parent / "nabla" / "pipeline" / "orchestration.py"
        text = src.read_text()
        assert "clear_approved_after_save" not in text, (
            "the pre-save whole-file clear still exists in orchestration")
        i_save = text.find("detection.entity_profiles.save()")
        i_commit = text.find("commit_drain_after_save(")
        assert i_save != -1 and i_commit != -1, (
            "orchestration lost the save or the drain commit")
        assert i_save < i_commit, (
            "commit_drain_after_save runs BEFORE the profile save — "
            "a crash between them loses the analyst's verdict (N-3)")
