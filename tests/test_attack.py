"""Tests for the MITRE ATT&CK integration module."""

import hashlib
import json
import os
import sys
import time
from unittest import mock

import pytest

from nabla.attack import (
    ANOMALY_TO_TECHNIQUES,
    ALL_TECHNIQUE_IDS,
    download_attack_bundle,
    build_attack_index,
    format_attack_block,
    enrich_lolbin_attack_mapping,
)


def test_anomaly_to_techniques_mapping():
    """All anomaly types should map to at least one technique."""
    for anomaly_type, techniques in ANOMALY_TO_TECHNIQUES.items():
        assert len(techniques) > 0, f"{anomaly_type} has no techniques"
        for tid in techniques:
            assert tid.startswith("T"), f"Invalid technique ID: {tid}"


def test_lolbin_mapping():
    """LOLBIN abuse should map to T1218 and/or T1202."""
    assert "lolbin_abuse" in ANOMALY_TO_TECHNIQUES
    techniques = ANOMALY_TO_TECHNIQUES["lolbin_abuse"]
    assert "T1218" in techniques or "T1202" in techniques


def test_all_technique_ids_unique():
    """ALL_TECHNIQUE_IDS should be sorted and unique."""
    assert len(ALL_TECHNIQUE_IDS) == len(set(ALL_TECHNIQUE_IDS))
    assert ALL_TECHNIQUE_IDS == sorted(ALL_TECHNIQUE_IDS)


def test_format_attack_block():
    """Formatting the attack block should produce parseable text."""
    index = {
        "brute_force_attempt": [
            {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
             "description": "Adversaries use brute force.", "groups": ["APT1"], "mitigations": ["M1"]},
        ],
        "lolbin_abuse": [
            {"id": "T1218", "name": "Signed Binary Proxy", "tactic": "Defense Evasion",
             "description": "Adversaries use signed binaries.", "groups": [], "mitigations": []},
        ],
    }
    text = format_attack_block(index)
    assert "T1110" in text
    assert "T1218" in text
    assert "brute_force_attempt" in text
    assert "lolbin_abuse" in text


def test_enrich_lolbin_attack_mapping():
    """enrich_lolbin_attack_mapping should add database-sourced technique IDs."""
    attack_index = {
        "lolbin_abuse": [
            {"id": "T1218", "name": "Signed Binary Proxy", "tactic": "Defense Evasion",
             "description": "Adversaries use signed binaries.", "groups": [], "mitigations": []},
        ],
    }
    lolbin_index = {
        "windows": {
            "certutil": {"name": "Certutil.exe", "categories": ["Download", "Encode"],
                         "mitre_ids": ["T1105", "T1140"], "detection": []},
        },
        "unix": {},
    }

    enriched = enrich_lolbin_attack_mapping(attack_index, lolbin_index)

    # Should still have T1218
    ids = [e["id"] for e in enriched["lolbin_abuse"]]
    assert "T1218" in ids

    # Should add T1105 and T1140 from the database
    assert "T1105" in ids
    assert "T1140" in ids


def test_enrich_lolbin_attack_mapping_no_duplicates():
    """enrich_lolbin_attack_mapping should not add duplicate technique IDs."""
    attack_index = {
        "lolbin_abuse": [
            {"id": "T1218", "name": "Signed Binary Proxy", "tactic": "Defense Evasion",
             "description": "Desc", "groups": [], "mitigations": []},
        ],
    }
    lolbin_index = {
        "windows": {
            "mshta": {"name": "Mshta.exe", "categories": ["Execute"],
                      "mitre_ids": ["T1218"], "detection": []},
        },
        "unix": {},
    }

    enriched = enrich_lolbin_attack_mapping(attack_index, lolbin_index)

    # T1218 should appear only once
    ids = [e["id"] for e in enriched["lolbin_abuse"]]
    assert ids.count("T1218") == 1


def test_enrich_lolbin_attack_mapping_empty_db():
    """enrich_lolbin_attack_mapping with empty database should return unchanged index."""
    attack_index = {
        "lolbin_abuse": [
            {"id": "T1218", "name": "Signed Binary Proxy", "tactic": "Defense Evasion",
             "description": "Desc", "groups": [], "mitigations": []},
        ],
    }
    lolbin_index = {"windows": {}, "unix": {}}

    enriched = enrich_lolbin_attack_mapping(attack_index, lolbin_index)

    assert len(enriched["lolbin_abuse"]) == 1
    assert enriched["lolbin_abuse"][0]["id"] == "T1218"


class TestBuildToolNameIndex:
    """Tests for build_tool_name_index — STIX-derived attack tool detection."""

    def _make_stix_bundle(self, tools, relationships=None):
        """Create a minimal STIX bundle for testing."""
        objects = [
            {
                "type": "identity",
                "id": "identity--test",
                "name": "Test",
                "identity_class": "individual",
            },
        ]
        # Add attack-patterns for technique lookup
        for tid in ["T1071", "T1003", "T1558", "T1059", "T1087", "T1021", "T1548"]:
            objects.append({
                "type": "attack-pattern",
                "id": f"attack-pattern--{tid.lower()}",
                "name": f"Technique {tid}",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": tid},
                ],
            })
        # Add tools/malware
        for tool in tools:
            obj = {
                "type": tool.get("type", "tool"),
                "id": tool["id"],
                "name": tool["name"],
            }
            if "description" in tool:
                obj["description"] = tool["description"]
            if "aliases" in tool:
                obj["x_mitre_aliases"] = tool["aliases"]
            objects.append(obj)
        # Add relationships
        if relationships:
            for rel in relationships:
                objects.append({
                    "type": "relationship",
                    "id": f"relationship--{rel['src']}-{rel['tgt']}",
                    "source_ref": rel["src"],
                    "target_ref": rel["tgt"],
                    "relationship_type": "uses",
                })
        return {"type": "bundle", "id": "bundle--test", "objects": objects}

    def test_extracts_tool_names(self, tmp_path):
        """Tool names are extracted from STIX bundle."""
        from nabla.attack import build_tool_name_index

        bundle = self._make_stix_bundle(
            tools=[
                {"id": "tool--cs", "name": "Cobalt Strike", "type": "malware"},
                {"id": "tool--mk", "name": "Mimikatz", "type": "tool"},
            ],
            relationships=[
                {"src": "tool--cs", "tgt": "attack-pattern--t1071"},
                {"src": "tool--mk", "tgt": "attack-pattern--t1003"},
            ],
        )
        stix_file = tmp_path / "test-attack.json"
        stix_file.write_text(json.dumps(bundle))

        result = build_tool_name_index(str(stix_file))
        assert "cobalt strike" in result
        assert "mimikatz" in result
        assert result["cobalt strike"][1] == "T1071"
        assert result["mimikatz"][1] == "T1003"

    def test_includes_aliases(self, tmp_path):
        """x_mitre_aliases are included in the index."""
        from nabla.attack import build_tool_name_index

        bundle = self._make_stix_bundle(
            tools=[
                {"id": "tool--bh", "name": "BloodHound", "type": "tool",
                 "aliases": ["SharpHound"]},
            ],
            relationships=[
                {"src": "tool--bh", "tgt": "attack-pattern--t1087"},
            ],
        )
        stix_file = tmp_path / "test-attack.json"
        stix_file.write_text(json.dumps(bundle))

        result = build_tool_name_index(str(stix_file))
        assert "bloodhound" in result
        assert "sharphound" in result

    def test_no_technique_uses_default(self, tmp_path):
        """Tools without 'uses' relationships get T1059 as default."""
        from nabla.attack import build_tool_name_index

        bundle = self._make_stix_bundle(
            tools=[{"id": "tool--unk", "name": "UnknownTool", "type": "tool"}],
        )
        stix_file = tmp_path / "test-attack.json"
        stix_file.write_text(json.dumps(bundle))

        result = build_tool_name_index(str(stix_file))
        assert "unknowntool" in result
        assert result["unknowntool"][1] == "T1059"

    def test_empty_bundle(self, tmp_path):
        """Empty bundle returns empty dict."""
        from nabla.attack import build_tool_name_index

        bundle = {"type": "bundle", "id": "bundle--test", "objects": []}
        stix_file = tmp_path / "test-attack.json"
        stix_file.write_text(json.dumps(bundle))

        result = build_tool_name_index(str(stix_file))
        assert result == {}

    def test_malware_and_tool_types(self, tmp_path):
        """Both 'tool' and 'malware' STIX types are extracted."""
        from nabla.attack import build_tool_name_index

        bundle = self._make_stix_bundle(
            tools=[
                {"id": "tool--t1", "name": "MyTool", "type": "tool"},
                {"id": "malware--m1", "name": "MyMalware", "type": "malware"},
            ],
            relationships=[
                {"src": "tool--t1", "tgt": "attack-pattern--t1059"},
                {"src": "malware--m1", "tgt": "attack-pattern--t1071"},
            ],
        )
        stix_file = tmp_path / "test-attack.json"
        stix_file.write_text(json.dumps(bundle))

        result = build_tool_name_index(str(stix_file))
        assert "mytool" in result
        assert "mymalware" in result

    def test_short_name_skipped(self, tmp_path):
        """Tool names shorter than 3 chars are skipped."""
        from nabla.attack import build_tool_name_index

        bundle = self._make_stix_bundle(
            tools=[
                {"id": "tool--at", "name": "at", "type": "tool"},
                {"id": "tool--ps", "name": "ps", "type": "tool"},
                {"id": "tool--real", "name": "RealTool", "type": "tool"},
            ],
            relationships=[
                {"src": "tool--real", "tgt": "attack-pattern--t1059"},
            ],
        )
        stix_file = tmp_path / "test-attack.json"
        stix_file.write_text(json.dumps(bundle))

        result = build_tool_name_index(str(stix_file))
        assert "at" not in result
        assert "ps" not in result
        assert "realtool" in result

    def test_skip_names_filtered(self, tmp_path):
        """Names in _SKIP_NAMES are filtered even if >= 3 chars."""
        from nabla.attack import build_tool_name_index

        bundle = self._make_stix_bundle(
            tools=[
                {"id": "tool--cmd", "name": "cmd", "type": "tool"},
                {"id": "tool--bat", "name": "bat", "type": "tool"},
                {"id": "tool--real", "name": "RealTool", "type": "tool"},
            ],
            relationships=[
                {"src": "tool--real", "tgt": "attack-pattern--t1059"},
            ],
        )
        stix_file = tmp_path / "test-attack.json"
        stix_file.write_text(json.dumps(bundle))

        result = build_tool_name_index(str(stix_file))
        assert "cmd" not in result
        assert "bat" not in result
        assert "realtool" in result

    def test_tool_no_aliases(self, tmp_path):
        """Tool without x_mitre_aliases only has the primary name."""
        from nabla.attack import build_tool_name_index

        bundle = self._make_stix_bundle(
            tools=[
                {"id": "tool--single", "name": "SingleTool", "type": "tool"},
            ],
            relationships=[
                {"src": "tool--single", "tgt": "attack-pattern--t1071"},
            ],
        )
        stix_file = tmp_path / "test-attack.json"
        stix_file.write_text(json.dumps(bundle))

        result = build_tool_name_index(str(stix_file))
        assert "singletool" in result
        assert len([k for k in result if result[k][1] == "T1071"]) == 1

    def test_multiple_tools_same_technique(self, tmp_path):
        """Multiple tools using the same technique are all indexed."""
        from nabla.attack import build_tool_name_index

        bundle = self._make_stix_bundle(
            tools=[
                {"id": "tool--a", "name": "ToolA", "type": "tool"},
                {"id": "tool--b", "name": "ToolB", "type": "malware"},
            ],
            relationships=[
                {"src": "tool--a", "tgt": "attack-pattern--t1071"},
                {"src": "tool--b", "tgt": "attack-pattern--t1071"},
            ],
        )
        stix_file = tmp_path / "test-attack.json"
        stix_file.write_text(json.dumps(bundle))

        result = build_tool_name_index(str(stix_file))
        assert "toola" in result
        assert "toolb" in result
        assert result["toola"][1] == "T1071"
        assert result["toolb"][1] == "T1071"


# ---------------------------------------------------------------------------
# download_attack_bundle tests
# ---------------------------------------------------------------------------


class TestDownloadAttackBundle:
    """Tests for STIX bundle download and freshness logic."""

    def test_fresh_file_returns_existing_path(self, tmp_path, monkeypatch):
        """Fresh file exists (age < refresh_days) → returns existing path, no download."""
        bundle_file = tmp_path / "enterprise-attack.json"
        bundle_file.write_text('{"type": "bundle"}')

        # Mock httpx.get to raise if called (proving no download happens)
        monkeypatch.setattr("httpx.get", mock.MagicMock(
            side_effect=AssertionError("Should not download")
        ))

        result = download_attack_bundle(str(tmp_path), refresh_days=30)
        assert result == str(tmp_path / "enterprise-attack.json")

    def test_stale_file_downloads_new_copy(self, tmp_path, monkeypatch):
        """Stale file exists (age >= refresh_days) → downloads new copy."""
        bundle_file = tmp_path / "enterprise-attack.json"
        bundle_file.write_text('{"type": "old_bundle"}')
        # Set mtime to 60 days ago
        old_time = time.time() - 60 * 86400
        os.utime(bundle_file, (old_time, old_time))

        mock_resp = mock.MagicMock()
        mock_resp.content = b'{"type": "new_bundle"}'
        mock_resp.raise_for_status = mock.MagicMock()
        monkeypatch.setattr("httpx.get", mock.MagicMock(return_value=mock_resp))

        result = download_attack_bundle(str(tmp_path), refresh_days=30)
        assert result == str(tmp_path / "enterprise-attack.json")
        with open(result) as f:
            assert json.load(f) == {"type": "new_bundle"}

    def test_missing_file_downloads_fresh_copy(self, tmp_path, monkeypatch):
        """Missing file → downloads fresh copy."""
        mock_resp = mock.MagicMock()
        mock_resp.content = b'{"type": "bundle"}'
        mock_resp.raise_for_status = mock.MagicMock()
        monkeypatch.setattr("httpx.get", mock.MagicMock(return_value=mock_resp))

        result = download_attack_bundle(str(tmp_path), refresh_days=30)
        assert result == str(tmp_path / "enterprise-attack.json")
        assert (tmp_path / "enterprise-attack.json").exists()

    def test_sha256_mismatch_raises_value_error(self, tmp_path, monkeypatch):
        """SHA-256 mismatch → raises ValueError."""
        content = b'{"type": "bundle"}'
        expected_hash = hashlib.sha256(b"different content").hexdigest()
        monkeypatch.setattr("nabla.attack.ATTACK_STIX_SHA256", expected_hash)

        mock_resp = mock.MagicMock()
        mock_resp.content = content
        mock_resp.raise_for_status = mock.MagicMock()
        monkeypatch.setattr("httpx.get", mock.MagicMock(return_value=mock_resp))

        with pytest.raises(ValueError, match="integrity check failed"):
            download_attack_bundle(str(tmp_path), refresh_days=0)

    def test_sha256_match_proceeds(self, tmp_path, monkeypatch):
        """SHA-256 match → proceeds normally."""
        content = b'{"type": "bundle"}'
        expected_hash = hashlib.sha256(content).hexdigest()
        monkeypatch.setattr("nabla.attack.ATTACK_STIX_SHA256", expected_hash)

        mock_resp = mock.MagicMock()
        mock_resp.content = content
        mock_resp.raise_for_status = mock.MagicMock()
        monkeypatch.setattr("httpx.get", mock.MagicMock(return_value=mock_resp))

        result = download_attack_bundle(str(tmp_path), refresh_days=0)
        assert result == str(tmp_path / "enterprise-attack.json")
        assert (tmp_path / "enterprise-attack.json").exists()

    def test_httpx_failure_propagates(self, tmp_path, monkeypatch):
        """httpx.get failure → propagates exception."""
        monkeypatch.setattr("httpx.get", mock.MagicMock(
            side_effect=ConnectionError("Network unreachable")
        ))

        with pytest.raises(ConnectionError, match="Network unreachable"):
            download_attack_bundle(str(tmp_path), refresh_days=0)


# ---------------------------------------------------------------------------
# build_attack_index tests
# ---------------------------------------------------------------------------


class TestBuildAttackIndex:
    """Tests for build_attack_index — STIX technique lookup."""

    def _mock_mitre_attack_data(self, monkeypatch, techniques=None, groups=None, mitigations=None, tactics=None):
        """Set up mock MitreAttackData in sys.modules."""
        mock_instance = mock.MagicMock()
        mock_instance.get_techniques.return_value = techniques or []
        mock_instance.get_all_groups_using_all_techniques.return_value = groups or {}
        mock_instance.get_all_mitigations_mitigating_all_techniques.return_value = mitigations or {}
        mock_instance.get_tactics_by_technique.return_value = tactics or []

        mock_class = mock.MagicMock(return_value=mock_instance)
        mock_stix20 = mock.MagicMock(MitreAttackData=mock_class)

        monkeypatch.setitem(sys.modules, "mitreattack", mock.MagicMock(stix20=mock_stix20))
        monkeypatch.setitem(sys.modules, "mitreattack.stix20", mock_stix20)

        return mock_instance

    def test_basic_technique_lookup(self, monkeypatch):
        """Techniques in ANOMALY_TO_TECHNIQUES are looked up and indexed."""
        techniques = [{
            "id": "attack-pattern--t1110",
            "name": "Brute Force",
            "description": "Adversaries guess passwords.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1110"},
            ],
        }]
        tactics = [{"name": "Credential Access"}]
        self._mock_mitre_attack_data(monkeypatch, techniques=techniques, tactics=tactics)

        # Reduce ANOMALY_TO_TECHNIQUES for a focused test
        monkeypatch.setattr("nabla.attack.ANOMALY_TO_TECHNIQUES", {
            "brute_force_attempt": ["T1110"],
        })

        result = build_attack_index("/dummy/path.json")
        assert "brute_force_attempt" in result
        assert len(result["brute_force_attempt"]) == 1
        assert result["brute_force_attempt"][0]["id"] == "T1110"
        assert result["brute_force_attempt"][0]["name"] == "Brute Force"

    def test_missing_technique_id_skipped(self, monkeypatch, caplog):
        """Technique ID not found in STIX → warning logged, skipped."""
        self._mock_mitre_attack_data(monkeypatch, techniques=[])

        monkeypatch.setattr("nabla.attack.ANOMALY_TO_TECHNIQUES", {
            "brute_force_attempt": ["T1110"],
        })

        with caplog.at_level("WARNING"):
            result = build_attack_index("/dummy/path.json")

        assert "brute_force_attempt" in result
        assert result["brute_force_attempt"] == []
        assert "T1110" in caplog.text or "not found" in caplog.text

    def test_empty_techniques_list(self, monkeypatch):
        """Empty techniques list → all anomaly types have empty entries."""
        self._mock_mitre_attack_data(monkeypatch, techniques=[])

        monkeypatch.setattr("nabla.attack.ANOMALY_TO_TECHNIQUES", {
            "brute_force_attempt": ["T1110"],
        })

        result = build_attack_index("/dummy/path.json")
        assert "brute_force_attempt" in result
        assert result["brute_force_attempt"] == []
