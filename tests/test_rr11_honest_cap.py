"""Round-11 F-1 witnesses: the findings cap must be honest.

RED-first per the plan (docs/plans/2026-11-23-round11-remediation.md,
Phase 1). Every witness exercises the REAL production path — real
correlate_anomalies → assess_findings → cap → format_findings, real
save_incidents — never hand-built shortcuts.

The contract:
- the run record carries the TRUE findings count; findings_shown says
  how many made the review prompt;
- the cap keeps the LOUDEST findings (severity, then confidence, then
  entity/type tie-break) — a pure function of the finding SET, not its
  input order;
- the header admits the cap on its face;
- incidents beyond the cap get review_status "capped" — never "invalid"
  (the report was never requested, it did not fail validation).
"""
import random
import re
from pathlib import Path

import pytest

from nabla.correlation import (
    correlate_anomalies,
    assess_findings,
    run_correlation as correlate_run,
)

MAX_BLOCK_FINDINGS = 27  # one above the cap under test (26 shown)


def _anomaly(user: str, log_type: str, severity: str = "medium") -> dict:
    return {
        "type": "off_hours_activity",
        "detection_method": "off_hours",
        "severity": severity,
        "user": user,
        "source_ip": "",
        "log_type": log_type,
        "timestamp": "2026-08-16T03:00:00Z",
        "details": f"off-hours activity for {user}",
        "anomaly_id": f"aid-{user}-{log_type}",
    }


def _user_findings(n: int, critical_user: str | None = None) -> list[dict]:
    """n distinct users × 2 log types → n user correlations → n findings."""
    anomalies = []
    for i in range(n):
        user = f"user{i:02d}"
        sev = "critical" if user == critical_user else "medium"
        anomalies.append(_anomaly(user, "auth", sev))
        anomalies.append(_anomaly(user, "endpoint", sev))
    return anomalies


GRAPH_CTX = "No provenance graph available."
ATTACK_MAP = "No ATT&CK mapping loaded."


class TestTrueCountSurvivesTheCap:
    """W1: a 27-finding run reports 27, shows 25, keeps all 27."""

    def test_run_record_carries_true_count_and_shown(self):
        result = correlate_run(
            entity_profiles=None,
            anomalies=_user_findings(27),
            graph_context_text=GRAPH_CTX,
            attack_mapping_text=ATTACK_MAP,
        )
        # 6-tuple: text, timeline, findings(FULL), correlations, lookup, shown
        assert len(result) == 6, f"expected 6-tuple, got {len(result)}"
        findings_text, _timeline, findings, _corrs, _lookup, shown = result
        assert len(findings) == 27, "the FULL list must survive for save_incidents"
        assert len(shown) == 25, "the cap shows 25"
        assert "Confirmed threats: 27" in findings_text, "header must carry the TRUE count"
        assert "(top 25 shown)" in findings_text, "header must admit the cap on its face"

    def test_header_regex_is_gone(self):
        """W5 (structural): the count is a VALUE, never regexed back."""
        src = Path("nabla/pipeline/correlation.py").read_text()
        assert "Confirmed threats:" not in src, (
            "pipeline/correlation.py must not regex the header — "
            "findings_count comes from the correlation result as a value"
        )
        orch = Path("nabla/pipeline/orchestration.py").read_text()
        assert "_extract_count" not in orch, (
            "orchestration must pass correlation.findings_count directly"
        )


class TestCapKeepsTheLoudest:
    """W2: the critical finding is shown even when it arrives last."""

    def test_critical_last_in_input_is_still_shown(self):
        anomalies = _user_findings(27, critical_user="user26")
        result = correlate_run(
            entity_profiles=None,
            anomalies=anomalies,
            graph_context_text=GRAPH_CTX,
            attack_mapping_text=ATTACK_MAP,
        )
        findings_text = result[0]
        assert "user26" in findings_text, (
            "the CRITICAL finding (last in input order) must survive the cap"
        )


class TestCapIsDeterministic:
    """W3: shuffled input order → identical shown set (the tie-break)."""

    def test_shuffled_orders_produce_identical_shown_set(self):
        anomalies = _user_findings(30)
        random.Random(1).shuffle(anomalies)
        r1 = correlate_run(
            entity_profiles=None, anomalies=list(anomalies),
            graph_context_text=GRAPH_CTX, attack_mapping_text=ATTACK_MAP,
        )
        random.Random(2).shuffle(anomalies)
        r2 = correlate_run(
            entity_profiles=None, anomalies=list(anomalies),
            graph_context_text=GRAPH_CTX, attack_mapping_text=ATTACK_MAP,
        )
        text1, text2 = r1[0], r2[0]
        set1 = set(re.findall(r'user\d\d', text1))
        set2 = set(re.findall(r'user\d\d', text2))
        assert set1 == set2, (
            f"shown set must be a pure function of the finding SET, "
            f"not input order (got {set1 ^ set2} differing)"
        )


class TestCappedIncidentsAreHonest:
    """W4: incidents beyond the cap get 'capped', never 'invalid'."""

    def test_beyond_cap_gets_capped_status(self, mock_settings, monkeypatch, tmp_path):
        # get_settings caches the module global — reload with a temp
        # data dir, the same honest pattern test_incidents.py uses.
        import importlib
        import nabla.config
        import nabla.incidents as inc_mod
        monkeypatch.setenv("NABLA_DATA_DIR", str(tmp_path))
        importlib.reload(nabla.config)
        importlib.reload(inc_mod)

        findings = []
        for i in range(27):
            findings.append({
                "entity": f"user{i:02d}",
                "entity_type": "user",
                "type": "off_hours_activity",
                "cross_type": "same-type",
                "log_types": ["auth", "endpoint"],
                "confidence": 0.7,
                "severity": "medium",
                "mitre_attack": [],
                "anomaly_ids": [f"aid-{i}"],
            })
        shown_keys = {(f["entity"], f["type"]) for f in findings[:25]}
        inc_mod.save_incidents(
            "run-rr11", findings,
            supervisor_text="Review text",
            shown_keys=shown_keys,
        )
        incidents = inc_mod.list_incidents(limit=100)
        assert len(incidents) == 27
        statuses = {i["review_status"] for i in incidents}
        assert "capped" in statuses, (
            f"incidents beyond the cap must be 'capped', got {statuses}"
        )
        capped = [i for i in incidents if i["review_status"] == "capped"]
        assert len(capped) == 2
        for inc in capped:
            assert inc["entity"] in {"user25", "user26"}
