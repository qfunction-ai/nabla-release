"""Phase 3 (frontend batch, R-1/FR-1/FR-3/D-10): structured supervisor
reports — per-incident JSON, per-element validation, evidence resolution.

Verified pre-change: the supervisor emitted FREE TEXT and the SAME
run-level report was attached to EVERY incident (incidents.py:244/293) —
clip 8's structured per-incident view was unbuildable, and the claims/
evidence contract had no IDs to cite (FR-3 fixed the block side).

These witnesses run through the REAL parse/resolve/attach/save paths —
the F9 lesson: never hand-build the record the production code writes.
"""
import json

import pytest

from nabla.pipeline.structured_report import (
    attach_structured_reports,
    parse_reports,
    resolve_report,
    summary_contradicts,
)

AID = "f29590d74df0cca3"
AID2 = "6084a74de8dcd68e"
EID = "siem:CD+123456"


def _report(entity="admin_user", summary="High-confidence attack.", sev="high", aid=AID):
    return {
        "entity": entity,
        "summary": summary,
        "severity": sev,
        "entities": [entity, "WKSTN-04"],
        "attack_techniques": ["T1059"],
        "recommended_actions": ["Isolate the host", "Rotate credentials"],
        "claims": [{"text": "LOLBIN executed off-hours", "evidence": [aid]}],
    }


def _valid_text(*reports):
    return json.dumps(list(reports))


class TestParsePerElement:
    """FR-1: one malformed report never invalidates its neighbors."""

    def test_per_element_isolation(self):
        good1, good2 = _report(), _report(entity="10.0.1.55", aid=AID2)
        bad = _report()
        del bad["severity"]  # malformed: missing required field
        meta = parse_reports(_valid_text(good1, bad, good2))
        assert len(meta["reports"]) == 2, "one bad element must not poison neighbors"
        assert len(meta["invalid"]) == 1
        assert meta["invalid"][0]["index"] == 1
        assert "severity" in meta["invalid"][0]["error"] or "Field required" in meta["invalid"][0]["error"]

    def test_bad_severity_rejected(self):
        meta = parse_reports(_valid_text(_report(sev="extreme")))
        assert meta["reports"] == []
        assert len(meta["invalid"]) == 1
        assert "extreme" in meta["invalid"][0]["error"]

    def test_truncated_array_detected_never_repaired(self):
        text = _valid_text(_report())[:-40]  # cut mid-element
        meta = parse_reports(text)
        # Either nothing parsed or fewer than fabricated-complete reports;
        # the parser must NEVER synthesize the missing tail.
        assert len(meta["reports"]) <= 1
        if meta["reports"]:
            # whatever parsed must be a complete, valid element
            assert meta["reports"][0]["entity"] == "admin_user"
        assert meta["parse_error"] is not None or meta["invalid"] or len(meta["reports"]) == 0

    def test_fence_wrapped_array_parses(self):
        text = "```json\n" + _valid_text(_report()) + "\n```"
        meta = parse_reports(text)
        assert len(meta["reports"]) == 1

    def test_prose_wrapped_array_parses(self):
        text = "Here is my analysis:\n" + _valid_text(_report()) + "\nDone."
        meta = parse_reports(text)
        assert len(meta["reports"]) == 1

    def test_empty_text_is_parse_error(self):
        meta = parse_reports("")
        assert meta["reports"] == []
        assert meta["parse_error"] is not None


class TestResolver:
    """D-10: evidence refs resolved server-side against stored data."""

    def _incident(self):
        return {
            "entity": "admin_user",
            "contributing_anomaly_ids": [AID, AID2],
            "contributing_anomaly_details": [
                {
                    "anomaly_id": AID,
                    "method": "lolbin",
                    "raw_score": 2.51,
                    "threshold_in_effect": 2.0,
                    "event_ids": [EID],
                },
                {
                    "anomaly_id": AID2,
                    "method": "off_hours",
                    "raw_score": 1.9,
                    "threshold_in_effect": 1.5,
                    "event_ids": [],
                },
            ],
        }

    def test_anomaly_ref_resolves_with_scores(self, monkeypatch):
        monkeypatch.setattr(
            "nabla.pipeline.structured_report._attack_technique_ids",
            lambda: {"T1059"},
        )
        resolved = resolve_report(_report(), self._incident())
        ev = resolved["claims"][0]["evidence"][0]
        assert ev["resolved"] is True
        assert ev["kind"] == "anomaly_id"
        assert ev["raw_score"] == 2.51
        assert ev["threshold_in_effect"] == 2.0
        assert ev["method"] == "lolbin"

    def test_event_and_entity_refs_resolve(self, monkeypatch):
        monkeypatch.setattr(
            "nabla.pipeline.structured_report._attack_technique_ids",
            lambda: {"T1059"},
        )
        rep = _report()
        rep["claims"][0]["evidence"] = [EID, "WKSTN-04"]
        resolved = resolve_report(rep, self._incident())
        kinds = [e["kind"] for e in resolved["claims"][0]["evidence"]]
        assert kinds == ["event_id", "entity_id"]

    def test_unknown_ref_flagged_not_dropped(self, monkeypatch):
        monkeypatch.setattr(
            "nabla.pipeline.structured_report._attack_technique_ids",
            lambda: {"T1059"},
        )
        rep = _report()
        rep["claims"][0]["evidence"] = ["deadbeefdeadbeef"]
        resolved = resolve_report(rep, self._incident())
        ev = resolved["claims"][0]["evidence"][0]
        assert ev["resolved"] is False
        assert ev["ref"] == "deadbeefdeadbeef", "unresolved refs are flagged, never dropped"

    def test_attack_ids_checked_one_source(self, monkeypatch):
        monkeypatch.setattr(
            "nabla.pipeline.structured_report._attack_technique_ids",
            lambda: {"T1059", "T1078"},
        )
        rep = _report()
        rep["attack_techniques"] = ["t1059", "T9999"]
        resolved = resolve_report(rep, self._incident())
        by_id = {t["id"]: t["known"] for t in resolved["attack_techniques"]}
        assert by_id == {"T1059": True, "T9999": False}


class TestAttach:
    def _incident(self, entity="admin_user"):
        return {
            "entity": entity,
            "contributing_anomaly_ids": [AID],
            "contributing_anomaly_details": [
                {"anomaly_id": AID, "method": "lolbin", "raw_score": 2.51,
                 "threshold_in_effect": 2.0, "event_ids": []}
            ],
        }

    def test_attach_ok_via_anomaly_overlap(self, monkeypatch):
        monkeypatch.setattr(
            "nabla.pipeline.structured_report._attack_technique_ids",
            lambda: {"T1059"},
        )
        inc = self._incident()
        attach_structured_reports([inc], _valid_text(_report()), findings_count=1)
        assert inc["review_status"] == "ok"
        assert inc["supervisor_report"]["claims"][0]["evidence"][0]["resolved"] is True

    def test_attach_entity_fallback(self, monkeypatch):
        monkeypatch.setattr(
            "nabla.pipeline.structured_report._attack_technique_ids",
            lambda: {"T1059"},
        )
        inc = self._incident()
        rep = _report()
        rep["claims"][0]["evidence"] = []  # no ID overlap — entity must carry it
        attach_structured_reports([inc], _valid_text(rep), findings_count=1)
        assert inc["review_status"] == "ok"

    def test_attach_invalid_when_no_match(self, monkeypatch):
        monkeypatch.setattr(
            "nabla.pipeline.structured_report._attack_technique_ids",
            lambda: {"T1059"},
        )
        inc = self._incident(entity="admin_user")
        # no anomaly overlap AND no entity match — anomaly overlap is the
        # stronger signal, so a report citing the incident's IDs matches
        # regardless of its entity label. This one shares neither.
        rep = _report(entity="someone_else")
        rep["claims"][0]["evidence"] = ["aaaaaaaaaaaaaaaa"]
        attach_structured_reports([inc], _valid_text(rep), findings_count=1)
        assert inc["review_status"] == "invalid"
        assert "supervisor_report" not in inc

    def test_attach_absent_when_no_text(self):
        inc = self._incident()
        attach_structured_reports([inc], "", findings_count=1)
        assert inc["review_status"] == "absent"

    def test_contradiction_prepends_deterministic_note(self, monkeypatch):
        monkeypatch.setattr(
            "nabla.pipeline.structured_report._attack_technique_ids",
            lambda: {"T1059"},
        )
        inc = self._incident()
        rep = _report(summary="No threats detected; all clear.")
        attach_structured_reports([inc], _valid_text(rep), findings_count=1)
        assert "DETERMINISTIC NOTE" in inc["supervisor_report"]["summary"]
        assert "1" in inc["supervisor_report"]["summary"]

    def test_summary_contradicts_patterns(self):
        assert summary_contradicts("Overall: no threats detected today")
        assert summary_contradicts("The network is clear of intrusions")
        assert not summary_contradicts("Three findings were confirmed as attacks")


class TestSaveIncidentsIntegration:
    """Through the REAL save path — the F9 lesson."""

    @pytest.fixture
    def mock_settings(self, tmp_path, monkeypatch):
        import importlib
        import nabla.config
        import nabla.incidents as inc_mod

        nabla.config._settings = None
        monkeypatch.setenv("NABLA_DATA_DIR", str(tmp_path))
        importlib.reload(nabla.config)
        importlib.reload(inc_mod)
        monkeypatch.setattr(
            "nabla.pipeline.structured_report._attack_technique_ids",
            lambda: {"T1059"},
        )
        return inc_mod

    def _findings(self):
        return [{
            "severity": "critical",
            "type": "lolbin_abuse",
            "entity": "admin_user",
            "entity_type": "user",
            "cross_type": "single-type",
            "log_types": ["auth"],
            "confidence": 0.9,
            "mitre_attack": [{"id": "T1218", "name": "x", "tactic": "y"}],
        }]

    def _anomalies(self):
        return [{
            "anomaly_id": AID,
            "entity": "admin_user",
            "user": "admin_user",
            "detection_method": "lolbin_abuse",
            "type": "lolbin",
            "raw_score": 2.51,
            "event_ids": [EID],
        }]

    def test_save_attaches_ok_report(self, mock_settings, monkeypatch):
        inc_mod = mock_settings
        monkeypatch.setattr(inc_mod, "_load_run_anomalies", lambda rid: self._anomalies())
        inc_mod.save_incidents(
            "run-001", self._findings(),
            supervisor_text=_valid_text(_report()),
        )
        incidents = inc_mod.list_incidents(limit=10)
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc["review_status"] == "ok"
        rep = inc["supervisor_report"]
        assert rep["claims"][0]["evidence"][0]["raw_score"] == 2.51
        # event_ids persisted on the details (resolver input)
        det = inc["contributing_anomaly_details"][0]
        assert det["event_ids"] == [EID]

    def test_save_malformed_output_marks_invalid(self, mock_settings, monkeypatch):
        inc_mod = mock_settings
        monkeypatch.setattr(inc_mod, "_load_run_anomalies", lambda rid: self._anomalies())
        raw = "I looked at the findings and everything seems fine, no JSON."
        inc_mod.save_incidents("run-002", self._findings(), supervisor_text=raw)
        incidents = inc_mod.list_incidents(limit=10)
        inc = incidents[0]
        assert inc["review_status"] == "invalid"
        assert "supervisor_report" not in inc
        # the raw text survives as the fallback display
        assert inc["supervisor_review"] == raw
