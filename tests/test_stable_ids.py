"""Phase 2 (remediation plan): stable anomaly_id / event_id.

Gates:
- Re-running the same batch produces IDENTICAL anomaly IDs (determinism).
- Every anomaly from detect_anomalies carries an anomaly_id.
- Same-run collisions get discriminator suffixes (unique within a run).
- Ingested entries carry event_id.
- Incidents record contributing_anomaly_ids.
"""

import json
from pathlib import Path

from nabla.detection import detect_anomalies, _stamp_anomaly_ids

ENTRIES = [
    {"user": "alice", "action": "login_success", "type": "auth",
     "timestamp": "2026-11-01T03:00:00Z", "source_ip": "9.9.9.9", "anomaly": "off_hours_login"},
    {"user": "alice", "action": "login_success", "type": "auth",
     "timestamp": "2026-11-01T03:05:00Z", "source_ip": "9.9.9.9", "anomaly": "off_hours_login"},
    {"user": "bob", "action": "login_failure", "type": "auth",
     "timestamp": "2026-11-01T03:10:00Z", "source_ip": "8.8.8.8"},
]


def test_anomaly_ids_deterministic_across_runs():
    a1, _ = detect_anomalies(json.loads(json.dumps(ENTRIES)))
    a2, _ = detect_anomalies(json.loads(json.dumps(ENTRIES)))
    ids1 = [a["anomaly_id"] for a in a1]
    ids2 = [a["anomaly_id"] for a in a2]
    assert ids1 == ids2, "same batch must produce identical IDs"
    assert all(ids1), "every anomaly carries an ID"


def test_anomaly_ids_unique_within_run():
    a, _ = detect_anomalies(ENTRIES + [
        # force a collision: identical anomaly fields on a duplicate entry
        dict(ENTRIES[0]),
    ])
    ids = [x["anomaly_id"] for x in a]
    assert len(ids) == len(set(ids)), f"IDs not unique within run: {ids}"


def test_stamp_collision_discriminator():
    anomalies = [
        {"entity": "x", "detection_method": "m", "timestamp": "t", "details": "d"},
        {"entity": "x", "detection_method": "m", "timestamp": "t", "details": "d"},
    ]
    _stamp_anomaly_ids(anomalies)
    assert anomalies[0]["anomaly_id"] != anomalies[1]["anomaly_id"]


def test_event_ids_stamped(tmp_path, monkeypatch):
    from nabla.pipeline.ingestion import run_ingestion
    f = tmp_path / "sample.jsonl"
    f.write_text("\n".join(json.dumps(e) for e in ENTRIES) + "\n")
    from nabla.config import Settings
    s = Settings(data_dir=str(tmp_path), letta_base_url="http://x", embedding_endpoint="http://x",
                 splunk_host="", sumologic_host="", splunk_validate_url=False, sumologic_validate_url=False)
    monkeypatch.setattr("nabla.config.get_settings", lambda: s)
    result = run_ingestion(None, {}, s, "auth", 100, "file", file_path=str(f), file_format="jsonl")
    assert result.entries, "no entries ingested"
    assert all("event_id" in e for e in result.entries), "event_id missing"
    ids = [e["event_id"] for e in result.entries]
    assert len(ids) == len(set(ids)), "event IDs collide on distinct events"


def test_incident_records_contributing_ids(tmp_path):
    from nabla.incidents import save_incidents, _incidents_file
    import nabla.incidents as inc
    (tmp_path / "incidents.json").write_text("[]")
    runs = tmp_path / "runs.json"
    # Minimal run record with anomalies carrying IDs
    anomaly = {"anomaly_id": "abc123", "entity": "alice", "detection_method": "brute_force",
               "severity": "high", "timestamp": "2026-11-01T03:00:00Z"}
    runs.write_text(json.dumps([{"run_id": "r-1", "anomalies": [anomaly]}]))
    monkey_path = str(tmp_path / "incidents.json")

    import unittest.mock as mock
    with mock.patch.object(inc, "_incidents_file", return_value=monkey_path), \
         mock.patch.object(inc, "_load_run_anomalies", return_value=[anomaly]):
        finding = {"entity": "alice", "entity_type": "user", "type": "brute_force",
                   "severity": "high", "confidence": 0.9, "log_types": ["auth"],
                   "mitre_attack": [], "tools_detected": None}
        n = save_incidents(run_id="r-1", findings=[finding],
                           supervisor_text="", evidence_text="brute_force evidence for alice")
    assert n == 1
    data = json.loads(Path(monkey_path).read_text())
    assert data[0]["contributing_anomaly_ids"] == ["abc123"]
