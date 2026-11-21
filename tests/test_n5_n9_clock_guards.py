# Round 7 Phase 4 witnesses: N-5 (span-tracker ceiling), N-6 (native
# IDs survive the connectors), N-7 (no raw [:13] hour slicing), N-9
# (one shared future ceiling).

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


class TestN5SpanTrackerCeiling:
    def test_future_stamp_does_not_poison_data_clock(self):
        # The CLI feeds RAW file timestamps to record_ingestion (its own
        # scan bypasses normalize_and_validate) — one 2099 stamp used to
        # advance data_newest_ts to 2099 (R6-1's disease through the CLI
        # path). The ceiling belongs where the data lands.
        from nabla.system_state import record_ingestion
        state = {"data_newest_ts": "2026-08-15T23:00:00+00:00"}
        out = record_ingestion(state, "sumologic",
                               entry_timestamps=["2099-01-01T00:00:00Z"])
        assert out["data_newest_ts"] == "2026-08-15T23:00:00+00:00", (
            "a future stamp advanced the data clock through the span tracker")

    def test_real_stamps_still_advance(self):
        from nabla.system_state import record_ingestion
        state = {}
        out = record_ingestion(state, "splunk",
                               entry_timestamps=["2026-08-15T03:00:00Z",
                                                 "2026-08-15T09:00:00Z"])
        assert out["data_newest_ts"].startswith("2026-08-15T09")
        assert out["data_oldest_ts"].startswith("2026-08-15T03")

    def test_mixed_batch_keeps_only_sane_stamps(self):
        from nabla.system_state import record_ingestion
        state = {}
        out = record_ingestion(state, "sumologic",
                               entry_timestamps=["2099-01-01T00:00:00Z",
                                                 "2026-08-15T05:00:00Z"])
        assert out["data_newest_ts"].startswith("2026-08-15T05"), (
            "the poisoned stamp won the max() — ceiling filter broken")

    def test_file_source_still_ignored(self):
        from nabla.system_state import record_ingestion
        state = {}
        out = record_ingestion(state, "file",
                               entry_timestamps=["2099-01-01T00:00:00Z"])
        assert "data_newest_ts" not in out


class TestN9SharedCeiling:
    def test_risk_ceiling_delegates_to_shared(self, monkeypatch):
        # risk._future_ceiling must follow the shared definition — patch
        # the clock_ingestion one and risk's must move with it (drifted
        # copies are how N-9 happened).
        import nabla.pipeline.clock_ingestion as ci
        import nabla.risk as risk
        from datetime import datetime, timedelta, timezone
        fake = datetime(2030, 1, 1, tzinfo=timezone.utc) + timedelta(hours=1)
        monkeypatch.setattr(ci, "future_ceiling", lambda: fake)
        assert risk._future_ceiling() == fake, (
            "risk._future_ceiling no longer delegates to the shared ceiling")

    def test_shared_ceiling_is_wall_plus_one_hour(self):
        from nabla.pipeline.clock_ingestion import future_ceiling
        from datetime import datetime, timedelta, timezone
        before = datetime.now(timezone.utc)
        got = future_ceiling()
        after = datetime.now(timezone.utc)
        assert before + timedelta(hours=1) <= got <= after + timedelta(hours=1)


class TestN6NativeIdsSurviveConnectors:
    def test_splunk_cd_bkt_composite(self):
        # R-8: _cd is unique only WITHIN a bucket — the composite
        # _bkt~_cd is the real identity, and it must reach the clock
        # layer's preference order as event_record_id.
        from nabla.connectors.splunk import SplunkConnector
        raw = {"_time": 1755236400.0, "_raw": "x", "_cd": "455:12",
               "_bkt": "main~455~B6E3", "_si": ["idx"],
               "user": "alice", "action": "login_success",
               "timestamp": "2026-08-15T03:00:00Z"}
        out = SplunkConnector._minimal_normalize(raw, "auth")
        assert out.get("event_record_id") == "main~455~B6E3~455:12", (
            f"splunk native id wrong: {out.get('event_record_id')}")
        assert "_cd" not in out and "_bkt" not in out

    def test_splunk_without_bucket_no_composite(self):
        from nabla.connectors.splunk import SplunkConnector
        raw = {"_time": 1755236400.0, "_raw": "x",
               "user": "alice", "action": "login_success",
               "timestamp": "2026-08-15T03:00:00Z"}
        out = SplunkConnector._minimal_normalize(raw, "auth")
        assert not out.get("event_record_id")

    def test_sumologic_message_id_field_mapping(self):
        from nabla.connectors.sumologic import SumoLogicConnector
        raw = {"_raw": "plain text", "_messageid": "abc-123",
               "_messagetime": 1755236400000,
               "user": "alice", "action": "login_success"}
        out = SumoLogicConnector._minimal_normalize(raw, "auth")
        assert out.get("message_id") == "abc-123", (
            f"sumologic dropped the native id: {out}")

    def test_sumologic_message_id_windows_json_path(self):
        # The structured early-return paths bypass the envelope — the
        # id must be stamped on them too.
        import json as _json
        from nabla.connectors.sumologic import SumoLogicConnector
        event = {"event_id": 4624,
                 "event_data": {"TargetUserName": "alice"},
                 "user": "alice", "action": "login_success"}
        raw = {"_raw": _json.dumps(event), "_messageid": "win-77",
               "_messagetime": 1755236400000}
        out = SumoLogicConnector._minimal_normalize(raw, "auth")
        assert out.get("message_id") == "win-77", (
            f"windows-json path lost the envelope id: {out}")

    def test_native_ids_reach_clock_layer_preference(self):
        # End-to-end: connector output flows through
        # normalize_and_validate and the native ID wins over the field
        # hash (Rule 0's preference order).
        from nabla.connectors.splunk import SplunkConnector
        from nabla.pipeline.clock_ingestion import normalize_and_validate
        raw = {"_time": 1755236400.0, "_raw": "x", "_cd": "455:12",
               "_bkt": "main~455~B6E3", "_si": ["idx"],
               "user": "alice", "action": "login_success",
               "timestamp": "2026-08-15T03:00:00Z"}
        out = SplunkConnector._minimal_normalize(raw, "auth")
        entries = normalize_and_validate([out], source="splunk")
        assert entries[0]["event_id"].startswith("splunk:"), (
            f"native id did not win the preference order: "
            f"{entries[0].get('event_id')}")


class TestN7NoRawHourSlicing:
    def test_no_executable_hour_slices(self):
        # R6-6's disease was two hour-key derivations that never
        # matched. Rule 5 made event_hour_key the one derivation; the
        # four surviving raw [:13] sites (detection x2, exfiltration,
        # cli chunker) are now gone. The AST walk ignores comments and
        # docstrings — any hit is executable code.
        hits = []
        for path in (REPO / "nabla").rglob("*.py"):
            if "__pycache__" in str(path):
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if (isinstance(node, ast.Subscript)
                        and isinstance(node.slice, ast.Slice)
                        and isinstance(node.slice.upper, ast.Constant)
                        and node.slice.upper.value == 13):
                    hits.append(f"{path.relative_to(REPO)}:{node.lineno}")
        assert not hits, (
            f"raw [:13] slicing in executable code — use "
            f"event_hour_key (Rule 5): {hits}")

    def test_event_hour_key_handles_offsets(self):
        from nabla.pipeline.clock_ingestion import event_hour_key
        # +05:00 offset: 08:30 local == 03:30 UTC
        assert event_hour_key(
            {"timestamp": "2026-08-16T08:30:00+05:00"}) == "2026-08-16T03"
        assert event_hour_key(
            {"timestamp": "2026-08-16T03:30:00Z"}) == "2026-08-16T03"
        assert event_hour_key({"timestamp": ""}) == ""
        assert event_hour_key({"timestamp": "garbage"}) == ""
