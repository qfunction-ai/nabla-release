"""N1 (round 4): the hour histogram must survive a save, and decay once.

R10 added a decayed per-hour histogram keyed by INT hours. JSON converts
int keys to strings; nothing converted them back; `_HISTOGRAM_FIELDS` was
declared and never referenced by serialization. After any reload, every
hour of a warm user's activity reads as "unusual" — the off-hours
detector fires on nearly every batch. Zero test coverage existed; this
file is why it survived to round 4.

Companion bug: decay was applied once per DISTINCT HOUR IN THE BATCH
(the decay loop nested inside the batch-hours loop), violating its own
R10 comment ("per-update is the design") — a batch spanning 3 hours
decayed existing entries by 0.99^3.
"""

from __future__ import annotations

import json

from nabla.baselines import EntityProfileStore, UserProfile
from nabla.utils import hour_is_unusual


def _entries(hours: list[int], per_hour: int = 10, day: int = 9) -> list[dict]:
    """Auth-ish entries on the given UTC hours of one day."""
    out = []
    for h in hours:
        for k in range(per_hour):
            out.append({
                "timestamp": f"2026-08-{day:02d}T{h:02d}:{k * 6:02d}:00Z",
                "log_type": "auth",
                "user": "n1user",
                "action": "login_success",
            })
    return out


class TestHistogramSurvivesSaveReload:
    def test_typical_hour_stays_typical_after_save(self, tmp_path):
        """The N1 core: 09:00-17:00 across three days of batches; hour 10
        is typical in memory and must REMAIN typical after save+reload.
        RED today: JSON stringifies the int keys, nothing converts back,
        hour_is_unusual(hist, 10) looks up int 10, misses, reads share 0.
        """
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        for day in (9, 10, 11):
            store.update_user("n1user", _entries(list(range(9, 18)), day=day))
        store.save()

        hist_before = store.get_user("n1user").hour_histogram
        assert not hour_is_unusual(hist_before, 10), "setup: hour 10 typical in memory"

        reloaded = EntityProfileStore(path)
        hist_after = reloaded.get_user("n1user").hour_histogram
        assert not hour_is_unusual(hist_after, 10), (
            f"N1: hour 10 became unusual after reload — keys are "
            f"{sorted(map(type, hist_after.keys()))} "
            f"(values: {dict(list(hist_after.items())[:3])})"
        )

    def test_keys_round_trip_as_ints(self, tmp_path):
        """Direct statement of the type contract: dict[int, float] before,
        dict[int, float] after."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        store.update_user("n1user", _entries([9, 10, 11]))
        store.save()

        raw = json.load(open(path))
        # raw on disk carries string keys (JSON) — the LOADER must repair
        reloaded = EntityProfileStore(path)
        hist = reloaded.get_user("n1user").hour_histogram
        assert hist, "histogram empty after reload"
        bad = {k: v for k, v in hist.items() if not isinstance(k, int)}
        assert not bad, f"non-int histogram keys after reload: {bad}"

    def test_round_trip_preserves_values(self, tmp_path):
        """Not just types — the counts themselves, modulo the decay that
        the intervening update applies to both sides equally here (none:
        save/load only, no update between)."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        store.update_user("n1user", _entries([9, 10, 11]))
        store.save()
        before = dict(store.get_user("n1user").hour_histogram)

        reloaded = EntityProfileStore(path)
        after = dict(reloaded.get_user("n1user").hour_histogram)
        assert after == before, f"histogram values changed across reload: {before} -> {after}"


class TestDecayOncePerUpdate:
    def test_decay_applied_exactly_once_per_update(self, tmp_path):
        """A batch spanning 3 distinct hours decays existing entries by
        exactly 0.99^1, not 0.99^3 (the loop-nesting bug)."""
        path = str(tmp_path / "profiles.json")
        store = EntityProfileStore(path)
        p = store.get_or_create_user("n1user")
        p.hour_histogram = {9: 100.0, 10: 100.0, 11: 100.0}

        store.update_user("n1user", _entries([13, 14, 15], per_hour=4))

        # existing hours decayed exactly once; batch hours added on top
        assert abs(p.hour_histogram[9] - 99.0) < 1e-9, (
            f"hour 9 decayed to {p.hour_histogram[9]} — expected one 0.99 pass (99.0); "
            f"0.99^3 would read {100.0 * 0.99 ** 3:.4f}"
        )
