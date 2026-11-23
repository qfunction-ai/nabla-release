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
    """F-1 (final review): the pinned-bundle resolution order and the
    mandatory hash check. The pin kills age-based refresh — a pinned
    bundle never goes stale; a WRONG-hash bundle refetches."""

    def _pin_to(self, monkeypatch, content: bytes) -> None:
        """Pin ATTACK_STIX_SHA256 to the given content's hash."""
        monkeypatch.setattr("nabla.attack.ATTACK_STIX_SHA256",
                            hashlib.sha256(content).hexdigest())

    def test_pinned_file_returns_existing_path(self, tmp_path, monkeypatch):
        """Existing file whose hash matches the pin → returned, no fetch.
        Age is irrelevant under a pin: the file could be years old."""
        content = b'{"type": "bundle"}'
        bundle_file = tmp_path / "enterprise-attack.json"
        bundle_file.write_bytes(content)
        # Make it "stale" — 60 days old. The pin does not care.
        import time as _t
        old = _t.time() - 60 * 86400
        import os as _os
        _os.utime(bundle_file, (old, old))
        self._pin_to(monkeypatch, content)

        monkeypatch.setattr("httpx.get", mock.MagicMock(
            side_effect=AssertionError("Should not fetch")))

        result = download_attack_bundle(str(tmp_path))
        assert result == str(bundle_file)

    def test_wrong_hash_file_refetches(self, tmp_path, monkeypatch):
        """Existing file that does NOT match the pin → refetched."""
        stale = b'{"type": "old_unpinned_bundle"}'
        (tmp_path / "enterprise-attack.json").write_bytes(stale)
        fresh = b'{"type": "pinned_bundle"}'
        self._pin_to(monkeypatch, fresh)

        mock_resp = mock.MagicMock()
        mock_resp.content = fresh
        mock_resp.raise_for_status = mock.MagicMock()
        monkeypatch.setattr("httpx.get", mock.MagicMock(return_value=mock_resp))

        result = download_attack_bundle(str(tmp_path))
        with open(result, "rb") as f:
            assert f.read() == fresh

    def test_missing_file_downloads_pinned_copy(self, tmp_path, monkeypatch):
        """Missing file → network download from the pinned URL."""
        content = b'{"type": "bundle"}'
        self._pin_to(monkeypatch, content)

        mock_resp = mock.MagicMock()
        mock_resp.content = content
        mock_resp.raise_for_status = mock.MagicMock()
        monkeypatch.setattr("httpx.get", mock.MagicMock(return_value=mock_resp))

        result = download_attack_bundle(str(tmp_path))
        assert result == str(tmp_path / "enterprise-attack.json")
        assert (tmp_path / "enterprise-attack.json").exists()

    def test_sha256_mismatch_raises_value_error(self, tmp_path, monkeypatch):
        """SHA-256 mismatch → raises ValueError."""
        content = b'{"type": "bundle"}'
        self._pin_to(monkeypatch, b"different content")

        mock_resp = mock.MagicMock()
        mock_resp.content = content
        mock_resp.raise_for_status = mock.MagicMock()
        monkeypatch.setattr("httpx.get", mock.MagicMock(return_value=mock_resp))

        with pytest.raises(ValueError, match="integrity check failed"):
            download_attack_bundle(str(tmp_path))

    def test_empty_pin_is_a_configuration_error(self, tmp_path, monkeypatch):
        """F-1: an empty ATTACK_STIX_SHA256 must raise — the old code
        logged the hash and suggested pinning it later, which is the
        supply-chain pattern this fix exists to remove."""
        monkeypatch.setattr("nabla.attack.ATTACK_STIX_SHA256", "")

        mock_resp = mock.MagicMock()
        mock_resp.content = b'{"type": "bundle"}'
        mock_resp.raise_for_status = mock.MagicMock()
        monkeypatch.setattr("httpx.get", mock.MagicMock(return_value=mock_resp))

        with pytest.raises(ValueError, match="mandatory"):
            download_attack_bundle(str(tmp_path))

    def test_shipped_copy_preferred_over_network(self, tmp_path, monkeypatch):
        """settings.attack_bundle_local_path set + valid → copied, no
        network. Course snapshot builds never depend on GitHub."""
        content = b'{"type": "pinned_bundle"}'
        self._pin_to(monkeypatch, content)
        shipped = tmp_path / "shipped"
        shipped.mkdir()
        shipped_file = shipped / "enterprise-attack.json"
        shipped_file.write_bytes(content)

        class _S:
            attack_bundle_local_path = str(shipped_file)
        # get_settings is imported inside the function from nabla.config
        monkeypatch.setattr("nabla.config.get_settings", lambda: _S())

        monkeypatch.setattr("httpx.get", mock.MagicMock(
            side_effect=AssertionError("Should not fetch — shipped copy exists")))

        result = download_attack_bundle(str(tmp_path / "data"))
        assert (tmp_path / "data" / "enterprise-attack.json").exists()
        with open(result, "rb") as f:
            assert f.read() == content

    def test_shipped_copy_mismatch_raises(self, tmp_path, monkeypatch):
        """A shipped copy that fails the pin is rejected — shipping a
        file does not bypass verification."""
        self._pin_to(monkeypatch, b'{"type": "pinned_bundle"}')
        shipped = tmp_path / "shipped"
        shipped.mkdir()
        (shipped / "enterprise-attack.json").write_bytes(b'{"type": "wrong_version"}')

        class _S:
            attack_bundle_local_path = str(shipped / "enterprise-attack.json")
        monkeypatch.setattr("nabla.config.get_settings", lambda: _S())

        with pytest.raises(ValueError, match="integrity check failed"):
            download_attack_bundle(str(tmp_path / "data"))

    def test_httpx_failure_propagates(self, tmp_path, monkeypatch):
        """httpx.get failure → propagates exception."""
        content = b'{"type": "bundle"}'
        self._pin_to(monkeypatch, content)
        monkeypatch.setattr("httpx.get", mock.MagicMock(
            side_effect=ConnectionError("Network unreachable")
        ))

        with pytest.raises(ConnectionError, match="Network unreachable"):
            download_attack_bundle(str(tmp_path))


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
