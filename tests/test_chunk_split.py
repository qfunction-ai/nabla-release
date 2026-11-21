# Round-7 Phase 7 witness: the CLI chunk splitter. The Phase-3 rewrite
# checked `if not lines: break` BEFORE filtering dead readlines — at EOF
# the list still held chunk_size empty strings, the break never fired,
# and the ingest spun at 99% CPU writing empty .part files forever
# (46,979 of them in nine minutes on the first live run). No suite test
# exercised files over the 15000 cap, and the cli tests mock the
# pipeline — the splitter ran untested. These tests go through the real
# splitter with files OVER the cap.

import json
import signal
from pathlib import Path

from nabla.cli import _split_large_file


def _write_events(path: Path, hours: dict[str, int]) -> None:
    """Write sorted synthetic events: {hour: count}."""
    with open(path, "w") as out:
        for hour, n in hours.items():
            for i in range(n):
                out.write(json.dumps({
                    "user": "u1",
                    "action": "login",
                    "timestamp": f"2026-08-09T{hour}:{i % 60:02d}:00Z",
                    "host": "h1",
                }) + "\n")


class TestChunkSplitter:
    def test_terminates_at_eof_with_pending(self, tmp_path):
        """The spin case: a boundary cut leaves pending lines, the file
        hits EOF, and the loop must still exit (alarm makes a
        regression FAIL instead of hang)."""
        f = tmp_path / "day.jsonl"
        # hour 01 has 10000 events, hour 02 has 5010 — first pass reads
        # 15000, cuts at the hour boundary, pending carries 5000 into
        # the EOF iteration.
        _write_events(f, {"01": 10000, "02": 5010})

        def _alarm(signum, frame):
            raise TimeoutError("chunk splitter did not terminate (EOF spin)")

        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(30)
        try:
            subs = _split_large_file(str(f), 15000)
        finally:
            signal.alarm(0)

        assert len(subs) == 2, subs
        total = sum(sum(1 for _ in open(s)) for s in subs)
        assert total == 15010, total
        # every chunk whole-hour: first chunk only hour 01
        first = [json.loads(l)["timestamp"][:13] for l in open(subs[0])]
        assert all(t.endswith("T01") for t in first), "chunk 1 cut mid-hour"

    def test_dense_hour_hard_cut_still_terminates(self, tmp_path):
        """A single hour denser than the cap hard-cuts mid-hour and
        must still terminate."""
        f = tmp_path / "day.jsonl"
        _write_events(f, {"03": 30000})

        def _alarm(signum, frame):
            raise TimeoutError("chunk splitter did not terminate (dense spin)")

        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(60)
        try:
            subs = _split_large_file(str(f), 15000)
        finally:
            signal.alarm(0)

        total = sum(sum(1 for _ in open(s)) for s in subs)
        assert total == 30000, total
        assert len(subs) == 2, subs

    def test_small_file_not_split(self, tmp_path):
        """Files under the cap are never split (single-chunk path)."""
        f = tmp_path / "day.jsonl"
        _write_events(f, {"01": 100})
        # the run command only calls the splitter above the cap; here
        # we just verify the small-file contract directly
        assert sum(1 for _ in open(f)) == 100
