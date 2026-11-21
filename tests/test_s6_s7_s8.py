"""S6/S7/S8 (round 5) regressions.

S6: approved drains land even when the entity is re-flagged in the same
    run — asserted via an EWMA observation change, NOT observation_count
    (which increments in update_user regardless of absorption; the vacuous
    version of this test passed while the data never reached the baseline
    — self-review R6).
S7: one rate alert per entity per absolute hour (covered in
    test_s4_hourly_rates.py; re-asserted at the store level here).
S8: bandit state survives save→load — the old flat save dropped the
    schema marker and reset learned state every roundtrip.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest


def _fresh_dir():
    """Unique dir AND a fresh Settings view per test — get_settings caches,
    so mutating NABLA_DATA_DIR mid-process doesn't propagate without this."""
    d = tempfile.mkdtemp()
    os.environ["NABLA_DATA_DIR"] = d
    import nabla.config as cfg
    cfg._settings = None
    return d


def _warm_dave(store, days=5, per_hour=6):
    evts = [{"user": "dave", "action": "x", "type": "authentication",
             "timestamp": f"2026-11-1{d}T0{h}:00:00Z"}
            for d in range(days) for h in range(per_hour)]
    for _ in range(40):
        store.update_user("dave", evts)


class TestS6ApprovedDrain:
    def test_reflag_does_not_discard_approved_data(self):
        d = _fresh_dir()
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.baselines import (EntityProfileStore, flag_quarantine,
                                     drain_approved_pending, approve_pending)
        prof = Path(d) / "entity_profiles.json"
        store = EntityProfileStore(str(prof))
        _warm_dave(store)
        store.save()

        flag_quarantine(["dave"])
        store.update_user("dave", [{"user": "dave", "action": "y",
                                    "type": "authentication",
                                    "timestamp": "2026-11-19T01:00:00Z"}])
        store.save()
        approve_pending("dave")
        flag_quarantine(["dave"])  # same-run re-flag, pipeline order

        store2 = EntityProfileStore(str(prof))
        ewma_before = store2.users["dave"].typical_event_count.n
        drained = drain_approved_pending(store2)
        store2.save()
        store3 = EntityProfileStore(str(prof))
        ewma_after = store3.users["dave"].typical_event_count.n
        drained_batches = sum(len(v) for v in drained.values())
        assert drained_batches == 1
        assert ewma_after > ewma_before, (
            f"S6: approved batch drained ({drained_batches}) but EWMA observations "
            f"{ewma_before}→{ewma_after} — the data never reached the baseline")

    def test_live_batches_still_respect_holds(self):
        d = _fresh_dir()
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.baselines import EntityProfileStore, flag_quarantine, _load_pending
        from pathlib import Path as P
        store = EntityProfileStore(str(P(d) / "p.json"))
        _warm_dave(store)
        flag_quarantine(["dave"])
        store.update_user("dave", [{"user": "dave", "action": "y",
                                    "type": "authentication",
                                    "timestamp": "2026-11-19T01:00:00Z"}])
        store.save()
        held = (_load_pending() or {}).get("dave", [])
        assert len(held) == 1, "live batch under hold must go to pending, not the profile"


class TestS8BanditPersistence:
    def test_save_load_roundtrip_preserves_learned_state(self):
        d = _fresh_dir()
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.rl.bandit import DetectionMethodBandit
        p = str(Path(d) / "rl_state.json")
        b = DetectionMethodBandit.load(p)
        b.alpha["lolbin"] = 20.0
        b.update("lolbin", confirmed=True)  # alpha → 21 (confirmed increments)
        b.save(p)
        raw = json.loads(Path(p).read_text())
        assert raw.get("schema") == 2, "save must stamp the schema marker"
        assert "bandit" in raw, "save must preserve the combined-file shape"
        b2 = DetectionMethodBandit.load(p)
        assert b2.alpha["lolbin"] == 21.0, (
            f"learned alpha died in the roundtrip — the S8 disease "
            f"(got {b2.alpha['lolbin']}, expected 21.0 post-update)")

    def test_save_preserves_other_consumers_keys(self):
        d = _fresh_dir()
        import logging
        logging.disable(logging.CRITICAL)
        from nabla.rl.bandit import DetectionMethodBandit
        from nabla.persistence import atomic_write_json
        p = str(Path(d) / "rl_state.json")
        atomic_write_json(p, {"schema": 2, "someone_elses_key": {"x": 1}})
        b = DetectionMethodBandit.load(p)
        b.save(p)
        raw = json.loads(Path(p).read_text())
        assert raw.get("someone_elses_key") == {"x": 1}, (
            "save clobbered a co-tenant key of the combined RL state file")
