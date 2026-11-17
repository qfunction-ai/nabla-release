"""Tests for atomic file persistence."""

import json
import os
import tempfile
import threading

from nabla.persistence import atomic_write_json, file_lock


def test_atomic_write_creates_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.json")
        atomic_write_json(path, {"key": "value"})
        assert os.path.exists(path)
        with open(path) as f:
            assert json.load(f) == {"key": "value"}


def test_atomic_write_overwrites_existing():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.json")
        atomic_write_json(path, {"v": 1})
        atomic_write_json(path, {"v": 2})
        with open(path) as f:
            assert json.load(f) == {"v": 2}


def test_atomic_write_creates_parent_dirs():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "sub", "dir", "test.json")
        atomic_write_json(path, {"deep": True})
        assert os.path.exists(path)


def test_atomic_write_no_temp_left_on_failure():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.json")
        # Make the directory read-only to trigger write failure
        os.chmod(tmpdir, 0o444)
        try:
            atomic_write_json(path, {"key": "value"})
        except (OSError, PermissionError):
            pass
        finally:
            os.chmod(tmpdir, 0o755)
        # No target file should exist (write failed)
        assert not os.path.exists(path)
        # No temp files should remain
        files = os.listdir(tmpdir)
        assert len(files) == 0


def test_file_lock_prevents_concurrent_writes():
    """Two threads writing concurrently with file_lock should not lose data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "runs.json")
        # Pre-populate with a base list
        atomic_write_json(path, [])

        errors = []
        results = []

        def writer(items):
            try:
                with file_lock(path):
                    with open(path) as f:
                        runs = json.load(f)
                    runs.extend(items)
                    atomic_write_json(path, runs)
                    results.append(len(runs))
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=writer, args=(["a", "b"],))
        t2 = threading.Thread(target=writer, args=(["c", "d"],))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert not errors, f"Concurrent writes failed: {errors}"
        with open(path) as f:
            final = json.load(f)
        # Both writes should be present (no data loss)
        assert len(final) == 4, f"Expected 4 items, got {len(final)}: {final}"


def test_file_lock_creates_lock_file():
    """file_lock should create a .lock file next to the data file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "data.json")
        with file_lock(path):
            pass
        lock_path = path + ".lock"
        assert os.path.exists(lock_path)


def test_atomic_write_json_with_datetime():
    """datetime values should serialize to string via default=str and produce valid JSON."""
    from datetime import datetime

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "dt.json")
        dt = datetime(2025, 1, 15, 10, 30, 0)
        data = {"timestamp": dt, "label": "test"}
        atomic_write_json(path, data)

        with open(path) as f:
            loaded = json.load(f)

        # default=str converts datetime to its ISO string representation
        assert loaded["timestamp"] == str(dt)
        assert loaded["label"] == "test"


def test_atomic_write_json_deeply_nested_dirs():
    """Writing to a deeply nested path should create all intermediate directories."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "a", "b", "c", "d", "file.json")
        atomic_write_json(path, {"deep": True})

        assert os.path.exists(path)
        # Verify every intermediate directory was created
        assert os.path.isdir(os.path.join(tmpdir, "a"))
        assert os.path.isdir(os.path.join(tmpdir, "a", "b"))
        assert os.path.isdir(os.path.join(tmpdir, "a", "b", "c"))
        assert os.path.isdir(os.path.join(tmpdir, "a", "b", "c", "d"))

        with open(path) as f:
            assert json.load(f) == {"deep": True}


def test_file_lock_creates_parent_dir():
    """When the lock file's parent directory doesn't exist, file_lock should create it."""
    with tempfile.TemporaryDirectory() as tmpdir:
        nested_dir = os.path.join(tmpdir, "sub", "dir")
        assert not os.path.exists(nested_dir), "Precondition: dir should not exist yet"

        path = os.path.join(nested_dir, "data.json")
        with file_lock(path):
            pass

        assert os.path.isdir(nested_dir), "file_lock should create the parent directory"
        lock_path = path + ".lock"
        assert os.path.exists(lock_path), "Lock file should exist after locking"


def test_file_lock_sequential_reacquire_same_thread():
    """Acquiring the lock, releasing it, then acquiring again from the same thread should work."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "data.json")

        # First acquisition
        with file_lock(path):
            pass

        # Second acquisition after the first is released
        with file_lock(path):
            pass

        # If we get here, sequential re-acquisition works fine
        lock_path = path + ".lock"
        assert os.path.exists(lock_path)


def test_atomic_write_json_preserves_data_types():
    """All JSON-compatible types should round-trip correctly through atomic_write_json."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "types.json")
        data = {
            "int_val": 42,
            "float_val": 3.14,
            "bool_val": True,
            "none_val": None,
            "list_val": [1, "two", 3.0],
            "nested_dict": {"inner": "value", "number": 99},
        }
        atomic_write_json(path, data)

        with open(path) as f:
            loaded = json.load(f)

        assert isinstance(loaded["int_val"], int)
        assert loaded["int_val"] == 42
        assert isinstance(loaded["float_val"], float)
        assert loaded["float_val"] == 3.14
        assert isinstance(loaded["bool_val"], bool)
        assert loaded["bool_val"] is True
        assert loaded["none_val"] is None
        assert isinstance(loaded["list_val"], list)
        assert loaded["list_val"] == [1, "two", 3.0]
        assert isinstance(loaded["nested_dict"], dict)
        assert loaded["nested_dict"] == {"inner": "value", "number": 99}


def test_file_lock_with_nonexistent_directory():
    """file_lock should create the directory when the data file is in a non-existent path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        new_dir = os.path.join(tmpdir, "brand_new_dir")
        assert not os.path.exists(new_dir), "Precondition: directory should not exist"

        path = os.path.join(new_dir, "data.json")
        with file_lock(path):
            # While holding the lock, the directory should exist
            assert os.path.isdir(new_dir)

        lock_path = path + ".lock"
        assert os.path.exists(lock_path)
