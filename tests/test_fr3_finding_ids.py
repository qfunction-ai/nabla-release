"""FR-3 (frontend batch Phase 3 prerequisite): the threat_findings block
must carry the anomaly IDs the structured narrative is asked to cite.

Verified pre-change: correlation.py had ZERO anomaly_id references — the
findings block was built from findings_text alone, so the supervisor
could not cite evidence by ID and the claims/evidence contract
(D-10 resolver) was unbuildable. The model must SEE the IDs it's asked
to cite.
"""
from nabla.correlation import (
    assess_findings,
    correlate_anomalies,
    format_findings,
)


def _anom(aid, method, entity="smith", log_type="endpoint", ts="2026-08-16T04:00:05+00:00"):
    return {
        "anomaly_id": aid,
        "detection_method": method,
        "type": method,
        "user": entity,
        "entity": entity,
        "log_type": log_type,
        "timestamp": ts,
        "severity": "high",
        "details": "x",
    }


ANOMS = [
    _anom("f29590d74df0cca3", "lolbin"),
    _anom("6084a74de8dcd68e", "lolbin"),
    _anom("3fe319b480ff3609", "attack_script"),
]


class TestFindingIds:
    def test_correlations_carry_anomaly_ids(self):
        corrs = correlate_anomalies(ANOMS, [], [])
        all_ids = set()
        for c in corrs:
            all_ids.update(c.get("anomaly_ids") or [])
        assert {"f29590d74df0cca3", "6084a74de8dcd68e", "3fe319b480ff3609"} <= all_ids, (
            "correlations must carry their source anomaly IDs"
        )

    def test_findings_carry_anomaly_ids(self):
        corrs = correlate_anomalies(ANOMS, [], [])
        findings = assess_findings(corrs, {})
        ids = set()
        for f in findings:
            ids.update(f.get("anomaly_ids") or [])
        assert {"f29590d74df0cca3"} <= ids, "findings must carry anomaly IDs"

    def test_findings_text_shows_anomaly_ids(self):
        """The block the LLM reads must contain the IDs (FR-3 core)."""
        corrs = correlate_anomalies(ANOMS, [], [])
        findings = assess_findings(corrs, {})
        text = format_findings(findings)
        assert "f29590d74df0cca3" in text, (
            "the threat_findings block text must contain anomaly IDs — "
            "the model cannot cite IDs it cannot see"
        )
        assert "3fe319b480ff3609" in text

    def test_no_anomaly_ids_still_renders(self):
        """Legacy anomalies without IDs must not break the block."""
        anoms = [{k: v for k, v in a.items() if k != "anomaly_id"} for a in ANOMS]
        corrs = correlate_anomalies(anoms, [], [])
        findings = assess_findings(corrs, {})
        text = format_findings(findings)
        assert "Confirmed threats" in text
