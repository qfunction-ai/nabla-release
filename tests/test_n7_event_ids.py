"""N7 (round 4): anomalies carry the source events they derived from.

The round-3 chain gate (R11) dedups by event_ids but fell back to
anomaly_id — which is per-anomaly unique, so three detectors citing ONE
event still counted as three 'distinct' events and could flag a false
chain. N7: every anomaly carries event_ids (stable per-event hash,
capped at 50), the fallback collapses by (entity, timestamp), and the
pipeline report counts fallback uses so the fallback's death is
observable, not assumed.
"""

from nabla.detection import detect_anomalies


def _mixed_batch() -> list[dict]:
    """A batch that trips several detectors, some on the SAME event."""
    entries = []
    # population so batch stats exist
    for i in range(10):
        entries.append({"user": f"user_{i}", "action": "login_success",
                        "timestamp": "2024-01-01T10:00:00Z"})
    # brute-force burst: failed_login_ratio + z_score, same user
    for m in range(4):
        entries.append({"user": "attacker", "action": "login_failure",
                        "source_ip": "203.0.113.5",
                        "timestamp": f"2024-01-01T10:0{m}:00Z"})
    # off-hours burst
    for m in range(5):
        entries.append({"user": "nightowl", "action": "login_success",
                        "source_ip": "198.51.100.7",
                        "timestamp": f"2024-01-01T23:0{m}:00Z"})
    # multi-ip traveler
    for i in range(5):
        entries.append({"user": "traveler", "action": "login_success",
                        "source_ip": f"192.0.2.{i + 1}",
                        "timestamp": "2024-01-01T10:00:00Z"})
    return entries


def test_every_anomaly_carries_event_ids():
    anomalies, _ = detect_anomalies(_mixed_batch())
    assert anomalies, "fixture tripped nothing"
    missing = [a.get("detection_method") for a in anomalies
               if not a.get("event_ids")]
    assert not missing, f"anomalies without event_ids: {missing}"
    over = [a.get("detection_method") for a in anomalies
            if len(a.get("event_ids") or []) > 50]
    assert not over, f"event_ids over cap: {over}"


def test_multi_detector_single_event_shares_event_ids():
    """The reviewer's scenario: one event tripping several detectors must
    cite the same event id — the chain gate then counts ONE event."""
    entries = []
    for i in range(10):
        entries.append({"user": f"user_{i}", "action": "login_success",
                        "timestamp": "2024-01-01T10:00:00Z"})
    # one endpoint event that is BOTH a lolbin and a network anomaly
    entries.append({"type": "endpoint", "user": "attacker",
                    "process": "certutil.exe",
                    "command_line": "certutil.exe -urlcache -f http://x",
                    "action": "network_connect", "dest_ip": "203.0.113.9",
                    "dest_port": "80", "host": "WKSTN-1",
                    "timestamp": "2024-01-01T10:05:00Z"})
    anomalies, _ = detect_anomalies(entries)
    assert anomalies, "fixture tripped nothing"
    by_event: dict[str, set[str]] = {}
    for a in anomalies:
        for eid in a.get("event_ids") or []:
            by_event.setdefault(eid, set()).add(a["detection_method"])
    shared = {eid: methods for eid, methods in by_event.items() if len(methods) > 1}
    assert shared, "no event cited by more than one detector — dedup untestable"


def test_fallback_collapses_by_entity_timestamp():
    """Without event_ids, the fallback keys on (entity, timestamp) so three
    detectors on one event are one event — NOT three (anomaly_id fallback
    counted three). The stats dict counts fallback uses."""
    from nabla.temporal import TemporalChain, should_flag_chain

    chain = TemporalChain(
        events=[
            {"anomaly_id": "a1", "detection_method": "z_score",
             "user": "attacker", "timestamp": "2024-01-01T10:00:00Z"},
            {"anomaly_id": "a2", "detection_method": "failed_login_ratio",
             "user": "attacker", "timestamp": "2024-01-01T10:00:00Z"},
            {"anomaly_id": "a3", "detection_method": "multi_ip",
             "user": "attacker", "timestamp": "2024-01-01T10:00:00Z"},
        ],
        phases={"Execution"},
    )
    stats: dict = {}
    flagged = should_flag_chain(chain, stats=stats)
    assert stats.get("fallback_used") == 3, f"fallback not counted: {stats}"
    assert not flagged, "three detectors on ONE event flagged a chain"


def test_fallback_used_zero_on_real_output():
    """With event_ids stamped everywhere, the chain gate never falls back —
    the fallback's death is witnessed, not assumed."""
    from nabla.temporal import detect_temporal_chains_with_context

    anomalies, _ = detect_anomalies(_mixed_batch())
    assert anomalies
    stats: dict = {}
    _, chains = detect_temporal_chains_with_context(
        [], anomalies, {"temporal_chain_window_minutes": 600}, stats=stats)
    assert stats.get("fallback_used", 0) == 0, (
        f"chain gate still falling back on real output: {stats} — "
        f"a mapped detector is not stamping event_ids"
    )
