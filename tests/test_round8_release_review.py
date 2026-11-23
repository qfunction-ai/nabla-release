"""Round-8 release review witnesses (nabla-release-review1.md, 2026-11-23).

Plan: docs/plans/2026-11-23-round8-release-review-remediation.md (v2).
Each test encodes a review finding verified live before remediation:
N-1 quarantine_summary NameError (entity detail 500s for quarantined entities)
N-2 fabricated entities resolve via the report's own entity list
N-3 truncated array discards every report; bracket prefix discards every report
N-5 one report can attach to several incidents
N-6 the contradiction safeguard edits the model's summary field
"""

import json

from nabla.pipeline.structured_report import (
    attach_structured_reports,
    parse_reports,
    resolve_report,
)


def _report(entity: str = "alice", claims=None, entities=None) -> dict:
    return {
        "entity": entity,
        "summary": f"report for {entity}",
        "severity": "high",
        "entities": entities if entities is not None else [entity],
        "attack_techniques": [],
        "recommended_actions": [],
        "claims": claims if claims is not None else [],
    }


def _text(*reports) -> str:
    return json.dumps(list(reports))


class TestN3Parser:
    def test_truncated_third_report_keeps_two_valid(self):
        reps = [_report("a"), _report("b"), _report("c")]
        text = _text(*reps)[:-40]  # cut partway through the third
        meta = parse_reports(text)
        assert len(meta["reports"]) == 2, (
            "complete elements before the cut must survive — one truncated "
            f"tail must not discard the run: {meta['parse_error']}"
        )
        assert [r["entity"] for r in meta["reports"]] == ["a", "b"]
        assert meta["invalid"] or meta["parse_error"], (
            "the incomplete tail must be FLAGGED, not silently absent"
        )

    def test_bracket_prefix_before_array(self):
        # The prompt tells the model every finding line carries
        # [anomaly_ids: ...] — echoing that bracket ahead of the JSON is
        # realistic. It must not poison the parse.
        reps = [_report("a"), _report("b"), _report("c")]
        text = "Findings carry [anomaly_ids: abc123] per line.\n" + _text(*reps)
        meta = parse_reports(text)
        assert len(meta["reports"]) == 3

    def test_unterminated_array_all_elements_valid(self):
        # Only the final ] is missing: every complete element stands,
        # with an unterminated note.
        reps = [_report("a"), _report("b")]
        text = _text(*reps)[:-1]  # strip the closing ]
        meta = parse_reports(text)
        assert len(meta["reports"]) == 2
        assert meta["invalid"] or meta["parse_error"]

    def test_example_array_in_prose_loses_to_real_array(self):
        # A schema-fragment example array in prose followed by the real
        # reports: the parser takes the first array with at least one
        # element that VALIDATES as a report — the fragment example is
        # skipped, the real array wins.
        prose = 'Example format: [{"summary": "...", "claims": []}]\n'
        reps = [_report("a"), _report("b")]
        meta = parse_reports(prose + _text(*reps))
        assert len(meta["reports"]) == 2
        assert [r["entity"] for r in meta["reports"]] == ["a", "b"]


class TestN2ResolutionSet:
    def _incident(self) -> dict:
        # contributing_anomaly_details AFTER the P-1 save-time capture:
        # user/host/source_ip recorded from the run anomaly itself.
        return {
            "entity": "alice",
            "contributing_anomaly_ids": ["aaaabbbbccccdddd"],
            "contributing_anomaly_details": [
                {
                    "anomaly_id": "aaaabbbbccccdddd",
                    "method": "lolbin",
                    "raw_score": 16,
                    "threshold_in_effect": 3.0,
                    "event_ids": [],
                    "user": "alice",
                    "host": "WKSTN-04",
                    "source_ip": "203.0.113.9",
                }
            ],
        }

    def test_fabricated_entity_in_report_list_still_unresolved(self):
        rep = _report(
            entity="alice",
            entities=["alice", "evilcorp-laptop"],  # model-invented entity
            claims=[{"text": "evilcorp-laptop is involved",
                     "evidence": ["evilcorp-laptop"]}],
        )
        resolved = resolve_report(rep, self._incident())
        ev = resolved["claims"][0]["evidence"][0]
        assert ev["resolved"] is False, (
            "an entity the MODEL listed must never resolve — resolution set is "
            "stored data only (incident entity + anomaly-detail fields)"
        )

    def test_stored_host_from_anomaly_details_resolves(self):
        # WKSTN-04 appears only in the incident's stored anomaly details —
        # legitimate citation, must resolve after the N-2 fix.
        rep = _report(
            entity="alice",
            entities=["alice"],
            claims=[{"text": "the host ran it", "evidence": ["WKSTN-04"]}],
        )
        resolved = resolve_report(rep, self._incident())
        ev = resolved["claims"][0]["evidence"][0]
        assert ev["resolved"] is True
        assert ev["kind"] == "entity_id"

    def test_stored_source_ip_resolves(self):
        rep = _report(
            entity="alice",
            entities=["alice"],
            claims=[{"text": "came from this address",
                     "evidence": ["203.0.113.9"]}],
        )
        resolved = resolve_report(rep, self._incident())
        ev = resolved["claims"][0]["evidence"][0]
        assert ev["resolved"] is True


class TestN5OneReportOneIncident:
    def test_shared_report_attaches_to_one_incident(self):
        rep = _report(
            entity="alice",
            claims=[{"text": "both",
                     "evidence": ["aaaabbbbccccdddd", "eeeeffff00001111"]}],
        )
        inc1 = {"incident_id": "i1", "entity": "alice",
                "contributing_anomaly_ids": ["aaaabbbbccccdddd"],
                "contributing_anomaly_details": []}
        inc2 = {"incident_id": "i2", "entity": "alice",
                "contributing_anomaly_ids": ["eeeeffff00001111"],
                "contributing_anomaly_details": []}
        attach_structured_reports([inc1, inc2], _text(rep), findings_count=2)
        attached = [
            inc["incident_id"] for inc in (inc1, inc2)
            if inc.get("review_status") == "ok" and inc.get("supervisor_report")
        ]
        assert len(attached) == 1, (
            f"one report attached to {len(attached)} incidents — R-1's disease: "
            "one narrative shown as each incident's own"
        )


class TestN6SafeguardDoesNotEditSummary:
    def test_contradiction_note_lives_in_its_own_field(self):
        rep = _report(entity="alice")
        rep["summary"] = "No threats detected in this batch."
        inc = {"incident_id": "i1", "entity": "alice",
               "contributing_anomaly_ids": ["aaaabbbbccccdddd"],
               "contributing_anomaly_details": []}
        attach_structured_reports([inc], _text(rep), findings_count=3)
        report = inc.get("supervisor_report")
        assert report is not None
        assert not report["summary"].startswith("DETERMINISTIC NOTE"), (
            "the safeguard must not edit the model's field (D-13) — "
            "it belongs in a separate safeguard_note"
        )
        assert "No threats detected" in report["summary"]
        assert report.get("safeguard_note"), "the note must exist somewhere"


class TestN1QuarantineUnification:
    def test_plural_carries_held_batches(self, env_data_dir):
        # The detail view renders held_batches (Entities.tsx:414); after
        # unification the plural (list path) must carry it too, or the
        # delegate would silently drop the field.
        import json as _json
        import pathlib
        from datetime import datetime, timedelta, timezone

        from nabla import baselines

        since = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        pathlib.Path(env_data_dir, "baseline_quarantine.json").write_text(_json.dumps({
            "alice": {"held": True, "since": since, "batches_held": 2, "tp_hold_days": 14},
        }))
        pathlib.Path(env_data_dir, "baseline_pending.json").write_text(_json.dumps({
            "alice": [{"batch_uid": "b1", "source_kind": "file",
                       "entries": [{"event_id": f"e{i}"} for i in range(20)]}],
        }))
        summaries = baselines.quarantine_summaries(["alice"])
        assert summaries["alice"] is not None
        assert summaries["alice"]["held_batches"] == 1

    def test_plural_returns_none_for_unknown_id(self, env_data_dir):
        from nabla import baselines

        out = baselines.quarantine_summaries(["never-quarantined"])
        assert "never-quarantined" in out
        assert out["never-quarantined"] is None

    def test_detail_endpoint_quarantined_entity(self, app_client, temp_data_dir):
        # N-1's camera case: after the attack, helpdeskone is quarantined
        # and its detail page must render — 200, not a NameError 500.
        import json as _json
        import os
        import pathlib
        from datetime import datetime, timedelta, timezone

        since = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        pathlib.Path(os.path.join(temp_data_dir, "baseline_quarantine.json")).write_text(_json.dumps({
            "alice": {"held": True, "since": since, "batches_held": 1},
        }))
        pathlib.Path(os.path.join(temp_data_dir, "baseline_pending.json")).write_text(_json.dumps({
            "alice": [{"batch_uid": "b1", "source_kind": "file",
                       "entries": [{"event_id": f"e{i}"} for i in range(7)]}],
        }))
        # alice must exist as an entity for the detail endpoint (real
        # profile-store shape: users/hosts/ips sections)
        pathlib.Path(os.path.join(temp_data_dir, "entity_profiles.json")).write_text(_json.dumps({
            "users": {"alice": {"observation_count": 5, "first_seen": "2025-01-01",
                                "last_seen": "2025-01-02", "typical_ips": [],
                                "ewma": {}, "account_created_at": None}},
            "hosts": {}, "ips": {},
        }))
        resp = app_client.get("/api/entities/alice")
        assert resp.status_code == 200, f"detail 500s for quarantined entity: {resp.status_code}"
        q = resp.json().get("quarantine")
        assert q is not None and q["held"] is True
        assert q["held_batches"] == 1
        assert q["held_events"] == 7


class TestLolbinIndexRobustness:
    def test_null_detection_entry_does_not_kill_index(self):
        # Round 8, found live during the Phase-1 exit gate: upstream
        # LOLBAS Ngen.exe carries "Detection": null — the old loop
        # raised TypeError, bootstrap left the block "not loaded",
        # and lolbin detection was silently dead on the stack.
        from nabla.lolbin_db import build_lolbin_index

        data = {
            "lolbas": [
                {"Name": "Ngen.exe", "Commands": [{"Category": "Download", "MitreID": "T1105"}], "Detection": None},
                {"Name": "Certutil.exe", "Commands": [{"Category": "Download", "MitreID": "T1105"}],
                 "Detection": [{"Sigma": "https://sigma/file.yml"}]},
            ],
            "gtfobins": {},
        }
        index = build_lolbin_index(data)
        assert "certutil" in index["windows"], "the good entry must survive the bad one"
        assert index["windows"]["certutil"]["detection"], "detection refs parsed"


class TestCompactorCarriesEntityFields:
    def test_compact_anomaly_keeps_user_host_ip(self):
        # Round 8 (N-2/P-1): the run-record compactor stripped the
        # user/host/source_ip the detectors emit (S2 dual attribution) —
        # the incident capture read the compacted shape and recorded
        # empties, so claims citing the victim host or attacker IP
        # showed UNRESOLVED on camera.
        from nabla.pipeline.orchestration import _compact_anomaly

        a = {
            "anomaly_id": "abcd", "entity": "helpdeskone", "severity": "high",
            "detection_method": "lolbin", "raw_score": 16,
            "user": "helpdeskone", "host": "HELPDESK-WKSTN4.qfunction.ai",
            "source_ip": "203.0.113.99",
        }
        compact = _compact_anomaly(a)
        assert compact["user"] == "helpdeskone"
        assert compact["host"] == "HELPDESK-WKSTN4.qfunction.ai"
        assert compact["source_ip"] == "203.0.113.99"

    def test_compact_anomaly_entity_fallback_for_user(self):
        from nabla.pipeline.orchestration import _compact_anomaly

        compact = _compact_anomaly({"anomaly_id": "x", "entity": "alice", "detection_method": "off_hours"})
        assert compact["user"] == "alice"
