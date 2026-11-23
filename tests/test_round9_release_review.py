"""Round 9 witnesses: Q-1 (fallback-source degradation), R9-2 (run upsert).

RED-first: every test here was watched failing against pre-fix HEAD
(commit recorded in the round-9 ledger) before its fix landed.
"""

from __future__ import annotations

import json
import os

import pytest

from nabla.degradations import collect_degradations


# ---------------------------------------------------------------- Q-1

class TestLolbinFallbackDegradation:
    """Q-1: detection running on the fallback sig list must say so.

    The round-8 exit gate found production lolbin had been running on the
    9-entry FALLBACK_LOLBIN_SIGS since deployment — zero degradations fired,
    so nothing looked broken. The check keys on the parse SOURCE, never on
    the block's text (a text-marker check lies in both directions).
    """

    def _load(self, block_text):
        from nabla.pipeline.detection import _load_lolbin_sigs
        sink: list[str] = []
        with collect_degradations(sink):
            sigs = _load_lolbin_sigs(block_text)
        return sigs, sink

    def test_placeholder_block_reports_degradation(self):
        sigs, sink = self._load("LOLBIN database: not loaded")
        assert "lolbin_index_not_loaded" in sink
        assert sigs, "fallback must still arm detection"

    def test_empty_block_reports_degradation(self):
        _, sink = self._load("")
        assert "lolbin_index_not_loaded" in sink

    def test_real_block_no_degradation(self):
        block = (
            "=== WINDOWS LOLBINS ===\n"
            "certutil | Download | T1105\n"
            "mshta | Execute | T1218\n"
        )
        sigs, sink = self._load(block)
        assert sink == []
        assert sigs and sigs[0][0] == "certutil"

    def test_marker_present_but_no_sigs_still_reports(self):
        """The anti-text-marker witness: the header string exists, but the
        section is empty. A marker-presence check would say 'loaded'; the
        source check must fire because detection IS on fallback data."""
        block = "=== WINDOWS LOLBINS ===\n(no entries)\n"
        _, sink = self._load(block)
        assert "lolbin_index_not_loaded" in sink

    def test_cosmetic_format_variance_no_degradation(self):
        """A block that parses fine despite cosmetic variance must not
        fire — the degradation tracks parsed data, not exact text."""
        block = (
            "=== UNIX GTFOBINS ===\n"
            "curl | Read | T1105\n"
            "\n"
            "=== WINDOWS LOLBINS ===\n"
            "  certutil | Download | T1105  \n"
            "mshta | Execute, Encode | T1218, T1027\n"
        )
        sigs, sink = self._load(block)
        assert sink == []
        assert sigs and sigs[0][0] == "certutil"


# ---------------------------------------------------------------- R9-2

class TestRunUpsert:
    """R9-2: the pipeline saves each run twice (Step 4b pre-incident, then
    completion). save_run appended unconditionally, so every run was
    double-listed in runs.json — visible on camera in clips 5 and 10."""

    def _save_twice(self, env_data_dir):
        from nabla.history import save_run
        run = {
            "run_id": "aaaabbbbccccdddd",
            "started_at": "2026-11-23T03:00:00+00:00",
            "finished_at": None,
            "source": "file",
            "anomalies": [{"detection_method": "off_hours"}],
        }
        save_run(dict(run))
        # completion save: same run_id, completion fields present
        run["finished_at"] = "2026-11-23T03:01:00+00:00"
        run["success"] = True
        save_run(dict(run))
        return run

    def test_two_saves_one_entry_with_completion_fields(self, env_data_dir):
        self._save_twice(env_data_dir)
        from nabla.history import list_runs
        runs = list_runs(limit=20)
        matching = [r for r in runs if r.get("run_id") == "aaaabbbbccccdddd"]
        assert len(matching) == 1, (
            f"{len(matching)} entries for one run — the run list shows "
            "doubles on camera"
        )
        assert matching[0].get("finished_at") == "2026-11-23T03:01:00+00:00"
        assert matching[0].get("success") is True

    def test_legacy_duplicated_file_self_heals(self, env_data_dir):
        """Dev stacks carry legacy runs.json files with every run listed
        twice. Loading must keep the LAST entry per run_id (the completion
        record), and the next save persists the deduped state."""
        path = os.path.join(env_data_dir, "runs.json")
        with open(path, "w") as f:
            json.dump([
                {"run_id": "r1", "finished_at": None, "success": None},
                {"run_id": "r2", "finished_at": None, "success": None},
                {"run_id": "r1", "finished_at": "done-1", "success": True},
                {"run_id": "r2", "finished_at": "done-2", "success": True},
            ], f)
        from nabla.history import list_runs
        runs = list_runs(limit=20)
        assert len(runs) == 2, f"legacy dupes survive: {len(runs)} entries"
        by_id = {r["run_id"]: r for r in runs}
        assert by_id["r1"]["finished_at"] == "done-1"
        assert by_id["r2"]["finished_at"] == "done-2"

    def test_distinct_runs_both_kept(self, env_data_dir):
        from nabla.history import save_run, list_runs
        for rid in ("run-a", "run-b"):
            save_run({"run_id": rid, "started_at": "x", "finished_at": None})
        runs = list_runs(limit=20)
        ids = [r["run_id"] for r in runs]
        assert ids.count("run-a") == 1 and ids.count("run-b") == 1


# ---------------------------------------------------------------- Q-3

class TestParserResync:
    """Q-3: a mid-array syntax error must not eat the reports after it.

    The naive resync (scan to the next `,{`) lands inside the broken
    element's own claims list — a claim object is not a report, and the
    claims list's closing `]` would read as the end of the array, losing
    elements 2 and 3 again. Only a candidate that decodes AND validates
    as an IncidentReport proves a real report starts there.
    """

    @staticmethod
    def _report(entity: str) -> dict:
        return {
            "entity": entity,
            "summary": f"summary for {entity}",
            "severity": "high",
            "entities": [entity],
            "attack_techniques": ["T1105"],
            "recommended_actions": ["investigate"],
            "claims": [{"text": "claim", "evidence": [f"{entity}00000000"[:16]]}],
        }

    @staticmethod
    def _array(*elements: str) -> str:
        return "Supervisor output:\n[" + ",\n".join(elements) + "\n]\nend"

    def test_error_inside_claims_keeps_later_reports(self):
        """Element 1 has a syntax error INSIDE its claims list (two claims).
        The first `,{` after the error is claim 2's object — it must be
        skipped (does not validate as a report), and the scan must resume
        at element 2. Elements 2 and 3 valid; element 1 flagged ONCE."""
        from nabla.pipeline.structured_report import parse_reports
        el1 = (
            '{"entity": "alice", "summary": "s", "severity": "high", '
            '"claims": [{"text": "claim one", "evidence": ["aaaabbbbccccdddd"]}, '
            '{BAD-UNQUOTED "text": "claim two", "evidence": ["1111222233334444"]}]}'
        )
        import json
        el2 = json.dumps(self._report("bob"))
        el3 = json.dumps(self._report("carol"))
        meta = parse_reports(self._array(el1, el2, el3))
        assert [r["entity"] for r in meta["reports"]] == ["bob", "carol"], (
            f"later reports lost: {[r['entity'] for r in meta['reports']]}"
        )
        assert len(meta["invalid"]) == 1, (
            f"expected exactly one invalid entry for the skipped span, got "
            f"{len(meta['invalid'])}: {meta['invalid']}"
        )
        assert "alice" not in json.dumps(meta["reports"])

    def test_error_in_body_keeps_later_reports(self):
        """Syntax error in element 1's body (before claims) — same contract."""
        from nabla.pipeline.structured_report import parse_reports
        el1 = '{"entity": "alice", "summary": BAD-UNQUOTED, "severity": "high"}'
        import json
        el2 = json.dumps(self._report("bob"))
        el3 = json.dumps(self._report("carol"))
        meta = parse_reports(self._array(el1, el2, el3))
        assert [r["entity"] for r in meta["reports"]] == ["bob", "carol"]
        assert len(meta["invalid"]) == 1

    def test_truncated_tail_behavior_unchanged(self):
        """No-regression: a truncated LAST element has nothing to resync
        to — the complete elements stand and the tail is flagged (round-8
        N-3 behavior, kept)."""
        from nabla.pipeline.structured_report import parse_reports
        import json
        el1 = json.dumps(self._report("alice"))
        el2 = json.dumps(self._report("bob"))
        truncated = '{"entity": "carol", "summary": "trunc'
        meta = parse_reports(self._array(el1, el2, truncated))
        assert [r["entity"] for r in meta["reports"]] == ["alice", "bob"]
        assert meta["parse_error"], "the truncated tail must still be flagged"
        assert len(meta["invalid"]) == 0
