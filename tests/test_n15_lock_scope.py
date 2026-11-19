"""N15 (round 4): quarantine/pending mutations hold file_lock across the
read-modify-write cycle.

The old _save_* helpers locked only the WRITE — two processes could both
load, both mutate, one write wins (lost update: a disposition racing a
pipeline run could vanish a held batch). The witness pins the structure:
while a mutation is between its load and its save, the file lock must be
UNACQUIRABLE. flock is per open-file-description, so a second open in
this same process blocks — that makes the witness deterministic, no
timing race.
"""

import threading

import pytest


def _settings(tmp_path, monkeypatch):
    import types
    import nabla.config
    s = types.SimpleNamespace(data_dir=str(tmp_path))
    monkeypatch.setattr(nabla.config, "get_settings", lambda: s)
    return s


def _assert_lock_held_during_rmw(monkeypatch, module, load_name, trigger):
    """Patch the loader to pause mid-cycle; while paused, a competing
    file_lock on the same file must NOT acquire."""
    from nabla.persistence import file_lock

    in_rmw = threading.Event()
    release = threading.Event()
    orig_load = getattr(module, load_name)

    def slow_load():
        result = orig_load()
        in_rmw.set()
        release.wait(timeout=10)
        return result

    monkeypatch.setattr(module, load_name, slow_load)
    t = threading.Thread(target=trigger, daemon=True)
    t.start()
    assert in_rmw.wait(5), f"{trigger} never reached its load"

    acquired = []
    lock_path = str(module._quarantine_file() if "quarantine" in load_name
                    else module._pending_file())

    def try_lock():
        try:
            with file_lock(lock_path):
                acquired.append(True)
        except Exception:
            acquired.append(False)

    lt = threading.Thread(target=try_lock, daemon=True)
    lt.start()
    lt.join(1.0)
    blocked = lt.is_alive()  # still waiting on flock ⇒ lock was held
    release.set()
    t.join(10)
    lt.join(10)
    assert not t.is_alive(), f"{trigger} did not finish after release"
    assert blocked, (
        "file lock was NOT held across the read-modify-write cycle — "
        "a concurrent writer could interleave and lose the update"
    )


def test_flag_quarantine_holds_lock_across_cycle(tmp_path, monkeypatch):
    import nabla.baselines as B
    _settings(tmp_path, monkeypatch)
    _assert_lock_held_during_rmw(
        monkeypatch, B, "_load_quarantine",
        lambda: B.flag_quarantine(["alice"]),
    )


def test_hold_pending_holds_lock_across_cycle(tmp_path, monkeypatch):
    import nabla.baselines as B
    _settings(tmp_path, monkeypatch)
    entries = [{"timestamp": "2026-08-10T03:00:00Z", "user": "alice"}]
    _assert_lock_held_during_rmw(
        monkeypatch, B, "_load_pending",
        lambda: B.hold_pending("alice", entries),
    )


def test_approve_pending_holds_approved_lock(tmp_path, monkeypatch):
    """approve_pending mutates BOTH pending and approved — the approved
    file's RMW must hold its lock too."""
    import threading as _th
    from nabla.persistence import file_lock
    import nabla.baselines as B
    _settings(tmp_path, monkeypatch)

    in_rmw = _th.Event()
    release = _th.Event()
    orig = B._load_approved

    def slow_load():
        result = orig()
        in_rmw.set()
        release.wait(timeout=10)
        return result

    monkeypatch.setattr(B, "_load_approved", slow_load)
    # fresh timestamp: the N3 span cap drops batches older than 7 data-clock
    # days, and a stale one would leave approve_pending nothing to move
    from datetime import datetime, timedelta, timezone
    fresh = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    B.hold_pending("alice", [{"timestamp": fresh}])
    t = _th.Thread(target=lambda: B.approve_pending("alice"), daemon=True)
    t.start()
    assert in_rmw.wait(5)

    acquired = []

    def try_lock():
        try:
            with file_lock(str(B._approved_file())):
                acquired.append(True)
        except Exception:
            acquired.append(False)

    lt = _th.Thread(target=try_lock, daemon=True)
    lt.start()
    lt.join(1.0)
    blocked = lt.is_alive()
    release.set()
    t.join(10)
    lt.join(10)
    assert not t.is_alive()
    assert blocked, "approved-file lock not held across its RMW"


def test_bandit_save_is_atomic():
    """N15: bandit state writes via atomic_write_json (no torn state)."""
    from unittest.mock import patch
    from nabla.rl.bandit import DetectionMethodBandit

    bandit = DetectionMethodBandit()
    with patch("nabla.persistence.atomic_write_json") as m:
        bandit.save("/tmp/rl.json")
    m.assert_called_once()
