"""N10 (round 4): calibratable thresholds get real raw_scores;
non-score knobs report not_calibratable instead of the 'pinned — 0/30
labels' lie (labels can never arrive for a tier gate or a window knob).
"""


def test_calibratable_methods_emit_numeric_raw_score(tmp_path):
    """Every method mapping to a CALIBRATABLE threshold must emit a numeric
    raw_score when it fires, and the fixture must fire ALL of them —
    coverage is asserted, not sampled."""
    from nabla.rl.calibration import METHOD_TO_THRESHOLD, NOT_CALIBRATABLE
    from nabla.baselines import EntityProfileStore
    from nabla.detection import detect_anomalies

    calibratable_methods = {m for m, t in METHOD_TO_THRESHOLD.items()
                            if t not in NOT_CALIBRATABLE}

    # ── warm entity profiles (entity paths need warm-up) ──
    # NOTE: IPs must be ROUTABLE — is_routable_ip rejects RFC 5737
    # documentation ranges (the F3 dress-rehearsal lesson), so 192.0.2.x
    # and 203.0.113.x would be invisible to multi_ip/entity_new_ip.
    p = str(tmp_path / "prof.json")
    store = EntityProfileStore(p)
    for day in range(9, 16):  # 7 days of history
        hist = []
        for h in range(8):  # office hours, 2/hr
            hist.append({"user": "alice", "action": "login_success",
                         "source_ip": "8.8.4.4",
                         "timestamp": f"2024-01-{day:02d}T{9 + h:02d}:00:00Z"})
            hist.append({"user": "alice", "action": "login_success",
                         "source_ip": "8.8.4.4",
                         "timestamp": f"2024-01-{day:02d}T{9 + h:02d}:30:00Z"})
        # failures on alternating hours keep auth_failure_ratio variance
        # alive (entity_auth_failure skips profiles with zero variance)
        if day % 2 == 0:
            hist.append({"user": "alice", "action": "login_failure",
                         "source_ip": "8.8.4.4",
                         "timestamp": f"2024-01-{day:02d}T09:15:00Z"})
            hist.append({"user": "alice", "action": "login_success",
                         "source_ip": "8.8.4.4",
                         "timestamp": f"2024-01-{day:02d}T09:45:00Z"})
            hist.append({"user": "bob", "action": "login_success",
                         "source_ip": "9.9.9.9",
                         "timestamp": f"2024-01-{day:02d}T{9 + h:02d}:00:00Z"})
        store.update_user("alice", hist)
        store.update_user("bob", [e for e in hist if e["user"] == "bob"])
        store.update_host("WKSTN-1", [
            {"host": "WKSTN-1", "process": "chrome.exe", "user": "alice",
             "type": "endpoint", "timestamp": f"2024-01-{day:02d}T10:00:00Z"},
        ])

    # ── detection batch: trips every calibratable method ──
    entries = []
    for i in range(10):  # population for batch stats
        entries.append({"user": f"user_{i}", "action": "login_success",
                        "timestamp": "2024-01-16T10:00:00Z"})
    # z_score + failed_login_ratio (attacker)
    for m in range(4):
        entries.append({"user": "attacker", "action": "login_failure",
                        "source_ip": "45.33.10.5",
                        "timestamp": f"2024-01-16T10:0{m}:00Z"})
    # off_hours
    for m in range(5):
        entries.append({"user": "nightowl", "action": "login_success",
                        "source_ip": "45.33.10.7",
                        "timestamp": f"2024-01-16T23:0{m}:00Z"})
    # entity_off_hours: bob is warm on day hours; night events are unusual
    for m in range(5):
        entries.append({"user": "bob", "action": "login_success",
                        "source_ip": "9.9.9.9",
                        "timestamp": f"2024-01-16T23:1{m}:00Z"})
    # multi_ip
    for i in range(5):
        entries.append({"user": "traveler", "action": "login_success",
                        "source_ip": f"1.2.{i + 10}.1",
                        "timestamp": "2024-01-16T10:00:00Z"})
    # activity_spike
    for _ in range(20):
        entries.append({"user": "spiker", "action": "login_success",
                        "timestamp": "2024-01-16T10:00:00Z"})
    # batch z_score (no entity history — the batch-level path)
    for _ in range(60):
        entries.append({"user": "batchz", "action": "login_success",
                        "timestamp": "2024-01-16T10:00:00Z"})
    # entity_z_score + entity_auth_failure + entity_new_ip +
    # entity_behavior_composite (alice: burst of failures from a new IP)
    for m in range(30):
        entries.append({"user": "alice", "action": "login_failure",
                        "source_ip": "104.244.28.77",
                        "timestamp": f"2024-01-16T10:{m:02d}:00Z"})
    entries.append({"user": "alice", "action": "login_success",
                    "source_ip": "104.244.29.78",
                    "timestamp": "2024-01-16T10:59:00Z"})
    # entity_new_process (new proc on WKSTN-1)
    entries.append({"type": "endpoint", "user": "alice", "host": "WKSTN-1",
                    "process": "C:\\Users\\alice\\tmp\\tool.exe",
                    "action": "execute",
                    "timestamp": "2024-01-16T10:45:00Z"})
    # entity_host_composite: new process + new user on WKSTN-1
    entries.append({"type": "endpoint", "user": "newbie", "host": "WKSTN-1",
                    "process": "C:\\Users\\newbie\\run.exe",
                    "action": "execute",
                    "timestamp": "2024-01-16T10:46:00Z"})

    anomalies, _ = detect_anomalies(
        entries, entity_profiles=store,
        thresholds={"entity_new_ip_threshold": 1, "entity_new_process_threshold": 1},
    )

    seen: dict[str, list] = {}
    for a in anomalies:
        m = a.get("detection_method", "")
        if m in calibratable_methods:
            seen.setdefault(m, []).append(a.get("raw_score"))
    missing_methods = calibratable_methods - set(seen)
    assert not missing_methods, (
        f"fixture failed to fire: {sorted(missing_methods)} — extend the "
        f"fixture; coverage is asserted, not sampled"
    )
    non_numeric = {m: scores for m, scores in seen.items()
                   if not all(isinstance(s, (int, float)) for s in scores)}
    assert not non_numeric, f"non-numeric raw_score: {non_numeric}"


def test_not_calibratable_thresholds_reported_honestly(tmp_path, monkeypatch):
    """Tier gates, window knobs, and unmapped thresholds can never
    calibrate from labels. 'pinned — 0/30 labels' implied they could;
    the honest status is not_calibratable."""
    import os
    from nabla.rl import calibration as C

    monkeypatch.setattr(C, "feedback_store_path",
                        lambda: tmp_path / "labels.jsonl")
    monkeypatch.setattr(C, "calibration_store_path",
                        lambda: tmp_path / "calibration.json")
    report = C.run_calibration()
    lying = [t for t in C.NOT_CALIBRATABLE
             if report.get(t, {}).get("status") != "not_calibratable"]
    assert not lying, f"not_calibratable thresholds misreported: {lying}"
    # calibratable ones still report pinned (honest: labels CAN arrive)
    calibratable = set(C.THRESHOLDS) - C.NOT_CALIBRATABLE
    still_pinned = [t for t in calibratable
                    if report.get(t, {}).get("status") != "pinned"]
    assert not still_pinned, f"calibratable thresholds lost pinned status: {still_pinned}"


def test_not_calibratable_is_complete_and_sound():
    """Every threshold is either calibratable (some method maps to it) or
    explicitly not_calibratable — no third state, no orphans."""
    from nabla.rl.calibration import METHOD_TO_THRESHOLD, NOT_CALIBRATABLE, THRESHOLDS

    assert NOT_CALIBRATABLE <= set(THRESHOLDS), "not_calibratable names not in THRESHOLDS"
    mapped = set(METHOD_TO_THRESHOLD.values())
    # a threshold some method maps to MUST be calibratable (the method
    # emits a comparable score) — otherwise its labels are dead weight
    bad = mapped & NOT_CALIBRATABLE
    assert not bad, f"methods map to not_calibratable thresholds: {sorted(bad)}"
