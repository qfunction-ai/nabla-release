"""Round-11 F-2 witnesses: a duplicate lolbin_db block DEGRADES, never crashes.

The T-5 duplicate-label raise in find_block_by_label_exact is CORRECT
design — block identity is ambiguous and any silent choice would be
wrong some of the time. The bug is the pipeline read sites.

REACHABILITY FINDING (recorded while witnessing): the legacy synthetic
branch in run_ingestion (the else at ingestion.py:191 — the ONLY
lolbin_db read in ingestion) is UNREACHABLE. _resolve_source returns
only synthetic/splunk/sumologic/file; the first three resolve
connectors, file raises without file_path. No source value reaches the
else. The reviewer's F-2 second half describes dead code. The fix is
kept there as defense-in-depth; the finding goes to the round-11 ledger.
"""
import inspect
import os
from unittest.mock import MagicMock

import pytest

from nabla.connectors.base import Watchlist
from nabla.degradations import collect_degradations


def _dup_client():
    """A client whose lolbin_db label matches TWO blocks (the T-5 raise)."""
    client = MagicMock()

    class _B:
        def __init__(self, id):
            self.id = id

    def _list(label=None, limit=10, **kw):
        if label == "lolbin_db":
            return [_B("dup-1"), _B("dup-2")]
        return []

    client.blocks.list.side_effect = _list
    client.agents.blocks.list.return_value = []
    return client


def _settings(tmp_path, monkeypatch):
    """Point BOTH the passed settings and the cached global at tmp_path
    (internal helpers call get_settings(), which returns the cached
    module global — patch it, never reload mid-suite)."""
    from nabla.config import Settings
    s = Settings(data_dir=str(tmp_path), letta_base_url="http://localhost:9999",
                 setup_token="", dev_mode=True, embedding_endpoint="http://localhost:11434/v1",
                 splunk_host="", sumologic_host="", splunk_validate_url=False,
                 sumologic_validate_url=False)
    if monkeypatch is not None:
        monkeypatch.setattr("nabla.config._settings", s)
    return s


class TestDetectionDegradesNeverCrashes:
    def test_duplicate_lolbin_db_completes_on_fallback(self, tmp_path, monkeypatch):
        """A duplicate block must not kill run_detection: the run
        completes and the degradation reaches the run record."""
        from nabla.pipeline.detection import run_detection

        client = _dup_client()
        with collect_degradations(sink := []) as s:
            result = run_detection(
                client=client,
                agents={"supervisor": "sup-1"},
                settings=_settings(tmp_path, monkeypatch),
                all_entries=[],
                watchlist=Watchlist(),
            )
        assert s.count("lolbin_index_not_loaded") == 1, f"degradations: {s}"
        # the run completed — the crash is gone, detection ran through
        assert result is not None
        assert isinstance(result.anomalies, list)


class TestIngestionDegradesLoudly:
    """F-2's ingestion half — structural witness, because the branch is
    unreachable (see module docstring)."""

    def test_legacy_branch_except_degrades_loudly(self):
        """The legacy branch's except must carry the degradation, not a
        bare log line (the round-8 disease: catch-and-continue with zero
        degradations fired)."""
        from nabla.pipeline import ingestion

        src = inspect.getsource(ingestion)
        legacy = src.split("--- Legacy synthetic ingestion")[1]
        assert "report_degradation" in legacy
        assert "lolbin_index_not_loaded" in legacy

    def test_legacy_branch_is_unreachable_from_any_source(self, monkeypatch, tmp_path):
        """Every _resolve_source return value routes to a connector or
        the file branch — the legacy else is dead code today. If this
        test FAILS, someone added a source type: re-check whether the
        legacy branch needs its lolbin read, and whether this file needs
        a live-drive witness instead of a structural one."""
        from nabla.pipeline.helpers import _resolve_source

        for source in ("synthetic", "splunk", "sumologic", "file"):
            assert _resolve_source(source) == source
        # auto with no SIEM configured → synthetic → connector branch
        _settings(tmp_path, monkeypatch)
        from nabla.config import get_settings
        gs = get_settings()
        assert not gs.splunk_host and not gs.sumologic_host
        assert _resolve_source("auto") == "synthetic"
        with pytest.raises(ValueError):
            _resolve_source("banana")
