"""Round-12 G-2 witnesses: the severity floor is a DELIBERATE scoring
change (round 11, unnamed in the plan — the review's process finding).

The floor: a correlation that already carries severity "critical" is
never re-derived downward — `if corr.get("severity") == "critical":
score = 4`. Without it, assess_findings re-derived severity from
anomaly types and log types alone and could flatten a critical
correlation to high, hiding the loudest finding from the F-1 cap's
sort (the cap keeps the loudest 25 — a flattened severity would
mis-sort).

Witness pairs:
  1. critical correlation → critical finding (the floor fires)
  2. high correlation → re-derived as before (the floor is inert)
  3. THE MOTIVATING CASE (review note): a critical finding beyond
     position 25 in correlation order still lands in the shown set
     after sorting — G-2 tied to F-1.
"""
from nabla.correlation import (
    CorrelationOutput,
    assess_findings,
    correlate_anomalies,
    run_correlation as correlate_run,
)

GRAPH_CTX = "No provenance graph available."
ATTACK_MAP = "No ATT&CK mapping loaded."


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


class TestSeverityFloor:
    def test_critical_correlation_stays_critical(self):
        """The floor: a critical correlation (critical anomaly in the
        group) produces a critical finding even when the re-derived
        score would be lower."""
        anomalies = _user_findings(1, critical_user="user00")
        correlations = correlate_anomalies(anomalies, {}, {})
        assert correlations, "fixture must produce a correlation"
        assert correlations[0].get("severity") == "critical"
        findings = assess_findings(correlations, {})
        assert findings, "fixture must produce a finding"
        assert findings[0]["severity"] == "critical", (
            "a critical correlation must never be flattened — the F-1 "
            "cap sorts by severity and a flattened score hides the loudest"
        )

    def test_medium_correlation_rederives_as_before(self):
        """The floor is inert below critical: a medium-only correlation
        is re-derived from anomaly/log types exactly as before."""
        anomalies = _user_findings(1)
        correlations = correlate_anomalies(anomalies, {}, {})
        assert correlations, "fixture must produce a correlation"
        assert correlations[0].get("severity") != "critical"
        findings = assess_findings(correlations, {})
        assert findings, "fixture must produce a finding"
        assert findings[0]["severity"] != "critical", (
            "no critical correlation in the input — the floor must not fire"
        )


class TestCriticalBeyondCapStillShown:
    """The motivating case (review note): the floor exists so the F-1
    sort keeps criticals in the shown set. A critical correlation
    whose finding sits beyond position 25 in correlation order must
    still be shown after sorting."""

    def test_critical_past_position_25_is_in_the_shown_set(self):
        # 26 medium users, then ONE critical user LAST in input order
        anomalies = _user_findings(26)
        anomalies += [
            _anomaly("user-critical", "auth", "critical"),
            _anomaly("user-critical", "endpoint", "critical"),
        ]

        result = correlate_run(
            entity_profiles=None,
            anomalies=anomalies,
            graph_context_text=GRAPH_CTX,
            attack_mapping_text=ATTACK_MAP,
        )
        assert isinstance(result, CorrelationOutput)
        assert len(result.findings) >= 26, (
            f"fixture must produce more findings than the 25 cap (got {len(result.findings)})"
        )
        shown_users = {f.get("entity") for f in result.shown_findings}
        assert "user-critical" in shown_users, (
            "the critical finding (last in correlation order) must be in "
            "the shown set after the F-1 sort — the floor's whole purpose"
        )
        assert len(result.shown_findings) == 25, "the cap still caps"
