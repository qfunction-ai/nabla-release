"""Round-11 F-3 residue: lock BOTH parse_lolbin_block shapes + the import binding.

The reviewer hit the round-8 same-name trap: parse_lolbin_block exists
in TWO modules with DIFFERENT return shapes —
  nabla.lolbin_db.parse_lolbin_block  → dict {"windows": {...}, "unix": {...}}
  nabla.detection.parse_lolbin_block  → (list[(name, patterns, mitre)], source_str)
The reviewer's ruling: a branch-level witness AND a structural import
check, because either one alone misses half the trap.

REACHABILITY AMENDMENT (found during F-2 witnessing): the legacy
synthetic branch — the only caller of the dict version in run_ingestion —
is UNREACHABLE (see test_rr11_f2_degrade.py). The branch-level drive
witness is therefore impossible; the residue here locks the import
binding, BOTH function shapes, and the cross-module no-flip property.
If the legacy branch is ever re-activated, add the live-drive witness.
"""
import ast
from pathlib import Path

import pytest


# The REAL block format (format_lolbin_block): name | categories |
# mitre | detection. The docstring example in lolbin_db.py was STALE
# (it showed "name: categories | ...") — copying it produced a fixture
# no parser could read. Verified against the live 246-entry block.
SAMPLE_BLOCK = """=== WINDOWS LOLBINS ===
certutil.exe | Download,Encode,Decode | T1105,T1140 | Sigma:proc_creation_win_certutil
mshta.exe | Execute | T1218

=== UNIX GTFOBINS ===
curl | download,file-read,upload | T1105
"""


class TestImportBinding:
    def test_ingestion_imports_the_dict_version(self):
        """The import in pipeline/ingestion.py must bind the DICT
        version from nabla.lolbin_db — flipping it to nabla.detection's
        tuple version is the F-3 crash."""
        src = Path("nabla/pipeline/ingestion.py").read_text()
        tree = ast.parse(src)
        bindings = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for a in node.names:
                    bindings[a.name] = node.module
        assert bindings.get("parse_lolbin_block") == "nabla.lolbin_db", (
            f"ingestion must import parse_lolbin_block from nabla.lolbin_db "
            f"(the dict version) — got {bindings.get('parse_lolbin_block')}"
        )

    def test_detection_imports_its_own_tuple_version(self):
        """pipeline/detection.py imports from nabla.detection (tuple
        version) — the two call sites must never swap."""
        src = Path("nabla/pipeline/detection.py").read_text()
        assert "from nabla.detection import parse_lolbin_block" in src


class TestShapeLocks:
    def test_dict_version_shape(self):
        from nabla.lolbin_db import parse_lolbin_block
        result = parse_lolbin_block(SAMPLE_BLOCK)
        assert isinstance(result, dict), "nabla.lolbin_db version returns a DICT"
        assert set(result.keys()) >= {"windows", "unix"}
        assert "certutil" in result["windows"]
        assert result["windows"]["certutil"]["mitre_ids"][0] == "T1105"
        assert "curl" in result["unix"]
        # the dict keys are the bare lowercased names — a key carrying
        # category text ("certutil: download,...") means the line format
        # drifted from what format_lolbin_block writes
        for key in result["windows"]:
            assert ":" not in key, f"key {key!r} — format drift"

    def test_tuple_version_shape(self):
        from nabla.detection import parse_lolbin_block
        result = parse_lolbin_block(SAMPLE_BLOCK)
        assert isinstance(result, tuple) and len(result) == 2, (
            "nabla.detection version returns (sigs, source)"
        )
        sigs, source = result
        assert isinstance(sigs, list)
        assert source == "db"
        names = [s[0] for s in sigs]
        assert "certutil" in names

    def test_tuple_version_fallback_on_empty(self):
        from nabla.detection import parse_lolbin_block
        sigs, source = parse_lolbin_block("")
        assert source == "fallback"
        assert sigs, "fallback signatures must be populated"
