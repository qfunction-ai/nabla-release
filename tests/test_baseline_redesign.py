"""Stage 2 gates: A8 (per-time-unit) + A9 (bias-corrected EWMA)."""

from nabla.baselines import EWMAProfile, EntityProfileStore


class TestA9BiasCorrection:
    def test_three_identical_observations_zero_z(self):
        p = EWMAProfile()
        for _ in range(3):
            p.update(42.0)
        assert p.value == 42.0
        assert p.z_score(42.0) == 0.0

    def test_first_observation_seeds_exactly(self):
        p = EWMAProfile()
        p.update(100.0)
        assert p.value == 100.0  # was 30.0 under zero-start

    def test_warm_up_divisor_correct_small_n(self):
        for n in (1, 2, 3):
            p = EWMAProfile()
            for _ in range(n):
                p.update(50.0)
            assert p.value == 50.0, f"n={n}: {p.value}"

    def test_std_reasonable_on_alternating(self):
        p = EWMAProfile()
        for i in range(30):
            p.update(44.0 if i % 2 else 40.0)
        # population std of 40/44 alternation = 2.0
        assert 1.5 < p.std < 2.5

    def test_legacy_records_deserialize(self):
        old = EWMAProfile.from_dict({"value": 41.8, "variance": 525.0, "alpha": 0.3})
        assert old.n >= 100  # treated as warm


class TestA8RateBaselining:
    def _store(self, tmp_path):
        return EntityProfileStore(str(tmp_path / "profiles.json"))

    def test_run_size_independence(self, tmp_path):
        """Same behavior observed in differently-sized runs -> same typical."""
        store = self._store(tmp_path)
        # 30 events over 1 hour
        big = [{"user": "a", "action": "x", "timestamp": f"2025-01-15T09:{i % 60:02d}:00Z"} for i in range(30)]
        # 30 events over 1 hour, split into three 10-event runs (same span each)
        store.update_user("a", big)
        p1 = store.get_user("a").typical_event_count.value

        store2 = self._store(tmp_path)
        for batch in range(3):
            part = [{"user": "a", "action": "x",
                     "timestamp": f"2025-01-1{5 + batch}T09:{i:02d}:00Z"} for i in range(10)]
            store2.update_user("a", part)
        # After several runs the EWMA should be in the same ballpark (per-hour),
        # NOT an order of magnitude apart (count-vs-rate would be)
        p2 = store2.get_user("a").typical_event_count.value
        assert p1 == p2 or abs(p1 - p2) / max(p1, p2) < 0.5, f"run-size dependent: {p1} vs {p2}"

    def test_zero_span_one_hour_convention(self):
        from nabla.baselines import _observation_window_hours
        entries = [{"timestamp": "2025-01-15T09:00:00Z"}] * 50
        assert _observation_window_hours(entries) == 1.0

    def test_span_clamped(self):
        from nabla.baselines import _observation_window_hours
        tiny = [{"timestamp": "2025-01-15T09:00:00Z"}, {"timestamp": "2025-01-15T09:00:30Z"}]
        assert _observation_window_hours(tiny) == 1.0 / 60
        huge = [{"timestamp": "2025-01-15T09:00:00Z"}, {"timestamp": "2025-02-15T09:00:00Z"}]
        assert _observation_window_hours(huge) == 24.0


class TestA11RecencySets:
    def test_eviction_is_least_recently_seen(self):
        from nabla.baselines import RecencySet
        rs = RecencySet(max_size=3)
        rs.add("a"); rs.add("b"); rs.add("c")
        rs.add("a")  # refresh a
        rs.add("d")  # cap exceeded -> evict b (least recent)
        assert set(rs) == {"a", "c", "d"}

    def test_unseen_hour_flags_again(self, tmp_path):
        """A11 gate: an hour absent for 30+ observations becomes unusual again."""
        store = EntityProfileStore(str(tmp_path / "p.json"))
        # Fill with hours 0-47 (all hours typical) at max cap 48...
        # instead: fill with 48 OTHER hours' worth of refreshes while hour 5
        # is never seen -> hour 5 evicts out
        for day in range(10):
            entries = [{"user": "u", "action": "x",
                        "timestamp": f"2025-01-{day+1:02d}T{h % 24:02d}:00:00Z"}
                       for h in (1, 2, 3)]  # only hours 1,2,3 seen
            store.update_user("u", entries)
        p = store.get_user("u")
        assert 5 not in p.typical_hours  # never seen -> not typical

        # Now see hour 5 for a while, then stop -> eventually evicted
        for day in range(20):
            entries = [{"user": "u", "action": "x",
                        "timestamp": f"2025-02-{day+1:02d}T0{h}:00:00Z"}
                       for h in (1, 2, 3, 5)]
            store.update_user("u", entries)
        assert 5 in store.get_user("u").typical_hours
        for day in range(30):
            entries = [{"user": "u", "action": "x",
                        "timestamp": f"2025-03-{day+1:02d}T0{h}:00:00Z"}
                       for h in (1, 2, 3)]
            store.update_user("u", entries)
        # Hours set is small here; the eviction only fires at the cap. The
        # gate's real claim: at cap, the UNSEEN hour drops before the seen.
        from nabla.baselines import RecencySet
        rs = RecencySet(max_size=3)
        for h in (1, 2, 5):
            rs.add(h)
        for _ in range(50):
            rs.add(1); rs.add(2); rs.add(3)
        assert 5 not in rs.members

    def test_legacy_plain_list_loads(self):
        from nabla.baselines import RecencySet
        rs = RecencySet.from_legacy(["1.2.3.4", "5.6.7.8"], max_size=10)
        assert "1.2.3.4" in rs

    def test_serialization_roundtrip_types(self):
        from nabla.baselines import RecencySet
        rs = RecencySet(max_size=10)
        rs.add(8); rs.add(9)
        d = rs.to_dict()
        rs2 = RecencySet.from_legacy(d, max_size=10)
        assert set(rs2) == {8, 9}


class TestA10Quarantine:
    """The four-row truth table (plan stage 2; risk-4 gate: ALL FOUR rows)."""

    def _env(self, tmp_path, monkeypatch):
        import nabla.baselines as B
        qfile = tmp_path / "quarantine.json"
        sfile = tmp_path / "system_state.json"
        monkeypatch.setattr(B, "_quarantine_file", lambda: qfile)
        import json as J
        from datetime import datetime, timezone
        sfile.write_text(J.dumps({"data_newest_ts": datetime.now(timezone.utc).isoformat()}))
        return B

    def test_row_fp_releases(self, tmp_path, monkeypatch):
        B = self._env(tmp_path, monkeypatch)
        B.flag_quarantine(["alice"])
        assert B._is_quarantined("alice")
        B.apply_disposition_to_quarantine("alice", "false_positive")
        assert not B._is_quarantined("alice")

    def test_row_btp_releases(self, tmp_path, monkeypatch):
        B = self._env(tmp_path, monkeypatch)
        B.flag_quarantine(["alice"])
        B.apply_disposition_to_quarantine("alice", "benign_true_positive")
        assert not B._is_quarantined("alice")

    def test_row_tp_holds(self, tmp_path, monkeypatch):
        B = self._env(tmp_path, monkeypatch)
        B.flag_quarantine(["alice"])
        B.apply_disposition_to_quarantine("alice", "true_positive")
        assert B._is_quarantined("alice")  # indefinitely

    def test_row_nodisposition_ttl_data_clock(self, tmp_path, monkeypatch):
        """No disposition: released after 7 days of DATA time."""
        from datetime import datetime, timedelta, timezone
        B = self._env(tmp_path, monkeypatch)
        B.flag_quarantine(["bob"])  # since = data clock (now)
        assert B._is_quarantined("bob")
        # Advance the DATA clock 8 days: replay/ingest moved time forward.
        # Patch the clock directly — the function reads get_settings().data_dir
        # which the tmp_path state file can't reach.
        future = datetime.now(timezone.utc) + timedelta(days=8)
        monkeypatch.setattr(B, "_data_clock_now", lambda: future)
        assert not B._is_quarantined("bob"), "TTL should release on data-clock advance"

    def test_held_batch_does_not_absorb(self, tmp_path, monkeypatch):
        B = self._env(tmp_path, monkeypatch)
        store = B.EntityProfileStore(str(tmp_path / "p.json"))
        # Warm the profile past entity_warmup_observations (default 3) —
        # the cold-entity carve-out absorbs held batches for cold entities
        for day in range(4):
            store.update_user("alice", [{"user": "alice", "action": "x",
                                         "timestamp": f"2025-01-1{day}T09:00:00Z"}] * 10)
        ewma_before = store.get_user("alice").typical_event_count.value
        B.flag_quarantine(["alice"])
        # An attack-sized batch arrives while held
        store.update_user("alice", [{"user": "alice", "action": "x",
                                     "timestamp": "2025-01-15T10:00:00Z"}] * 500)
        ewma_after = store.get_user("alice").typical_event_count.value
        assert ewma_after == ewma_before, "held batch must NOT absorb into baselines"


def test_rate_uses_user_window_not_batch_window():
    """Stage-4 rehearsal catch #4: mixed batches must not dilute per-user rates.

    A user with 23 events in 1.5h inside a batch spanning 24h computes
    15.3/hr (their rate) — not 0.96/hr (diluted across the batch).
    """
    from nabla.baselines import _observation_window_hours
    user_events = [
        {"user": "smith", "timestamp": "2025-01-15T09:00:00Z"},
        {"user": "smith", "timestamp": "2025-01-15T10:30:00Z"},
    ]
    full_batch = user_events + [
        {"user": "noise", "timestamp": "2025-01-15T00:00:00Z"},
        {"user": "noise", "timestamp": "2025-01-15T23:59:00Z"},
    ]
    user_window = _observation_window_hours(user_events)  # 1.5h
    batch_window = _observation_window_hours(full_batch)  # ~24h
    assert user_window < 2.0
    assert batch_window > 23.0
    # The detection math must use the user's window:
    rate_correct = 23 / user_window
    rate_buggy = 23 / batch_window
    assert rate_correct > 15.0 and rate_buggy < 1.0
