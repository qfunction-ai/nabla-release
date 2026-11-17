"""UI2b: supervisor baseline context — block section, finding clauses, incident digest."""

from unittest.mock import MagicMock


def _profile(obs=10, hours=None, ips=None, events=None):
    p = MagicMock()
    p.observation_count = obs
    p.typical_hours = hours or []
    p.typical_ips = ips or []
    tec = MagicMock()
    tec.value = events or 0
    p.typical_event_count = tec
    return p


def _profiles_store(users=None):
    store = MagicMock()
    store.users = users or {}
    store.hosts = {}
    store.ips = {}
    return store


class TestEntityBaselineSection:
    def test_warm_entity_summary(self):
        from nabla.pipeline.env_context import _format_env_context_block

        profiles = _profiles_store({
            "alice": _profile(obs=10, hours=["9", "10", "11", "12", "13", "14", "15", "16", "17"], ips=["10.0.0.1", "10.0.0.2"], events=12.4),
        })
        block = _format_env_context_block(
            {"environment": [], "entities": {}},
            auto_ranges=[],
            anomalous_entities={"alice"},
            entity_profiles=profiles,
            run_stats={"alice": {"events": 47, "new_ips": 2, "off_hours": 3}},
        )
        assert "Entity Baselines" in block
        assert "typical hours 09:00-17:00" in block
        assert "2 typical addresses" in block
        assert "~12 events/run typical" in block
        assert "47 events this run" in block
        assert "3 off-hours events" in block  # the deviation, visible

    def test_cold_entity_one_liner(self):
        from nabla.pipeline.env_context import _format_env_context_block

        profiles = _profiles_store({"bob": _profile(obs=1)})
        block = _format_env_context_block(
            {"environment": [], "entities": {}},
            auto_ranges=[],
            anomalous_entities={"bob"},
            entity_profiles=profiles,
        )
        assert "no baseline yet — 1/3 observations" in block

    def test_hard_caps(self):
        from nabla.pipeline.env_context import _format_env_context_block

        many = {f"e{i}": _profile(obs=10, events=5) for i in range(20)}
        block = _format_env_context_block(
            {"environment": [], "entities": {}},
            auto_ranges=[],
            anomalous_entities=set(many.keys()),
            entity_profiles=_profiles_store(many),
        )
        # 12 entities cap (lexicographic order: e0,e1,e10..e19,e2,...)
        import re as _re
        listed = _re.findall(r"^  (e\d+):$", block, _re.MULTILINE)
        assert len(listed) == 12

    def test_no_profiles_no_section(self):
        from nabla.pipeline.env_context import _format_env_context_block

        block = _format_env_context_block(
            {"environment": [], "entities": {}},
            auto_ranges=[],
            anomalous_entities={"alice"},
            entity_profiles=None,
        )
        assert "Entity Baselines" not in block


class TestFindingBaselineClauses:
    def test_clause_appended_for_warm_entity(self):
        from nabla.correlation import format_findings

        profiles = _profiles_store({"alice": _profile(obs=10, ips=["1.2.3.4"], events=9)})
        findings = [{
            "severity": "high", "type": "brute_force", "entity_type": "user",
            "entity": "alice", "confidence": 0.8, "mitre_attack": [],
        }]
        text = format_findings(findings, entity_profiles=profiles)
        assert "baseline: ~9 events/run typical; 1 IPs typical" in text

    def test_no_clause_for_cold_or_absent(self):
        from nabla.correlation import format_findings

        profiles = _profiles_store({"alice": _profile(obs=1)})
        findings = [{
            "severity": "high", "type": "brute_force", "entity_type": "user",
            "entity": "alice", "confidence": 0.8, "mitre_attack": [],
        }]
        assert "baseline:" not in format_findings(findings, entity_profiles=profiles)
        assert "baseline:" not in format_findings(findings)  # no store


class TestIncidentDigest:
    def test_digest_bounded_and_filtered(self, tmp_path, monkeypatch):
        from nabla.pipeline import supervisor as S
        from datetime import datetime, timedelta, timezone

        import json as _json
        # Relative timestamps: the digest filters by a rolling 7-day window,
        # so hardcoded dates age out (same time-bomb class as the May
        # account-grace tests — fixed the same way).
        recent = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        incidents = []
        for i in range(30):
            incidents.append({
                "incident_id": f"inc-{i:04d}", "entity": f"e{i}", "finding_type": "lolbin",
                "severity": "high", "status": "new" if i < 25 else "resolved",
                "updated_at": recent,
            })
        # An old one outside the 7-day window
        incidents.append({"incident_id": "inc-old", "entity": "old", "finding_type": "x",
                          "severity": "low", "status": "new",
                          "updated_at": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()})
        (tmp_path / "incidents.json").write_text(_json.dumps(incidents))

        from nabla.config import Settings
        s = Settings(data_dir=str(tmp_path), letta_base_url="http://x", embedding_endpoint="http://x",
                     splunk_host="", sumologic_host="", splunk_validate_url=False, sumologic_validate_url=False)
        from unittest.mock import patch
        with patch("nabla.config.get_settings", return_value=s), patch("nabla.config._settings", s):
            digest = S._build_incident_digest()
        lines = digest.strip().split("\n")
        assert len(lines) == 20  # cap
        assert all("resolved" not in ln for ln in lines)
        assert "inc-old" not in digest
