"""F2: timestamps must be validated, not passed through.

`_normalize_timestamp` returned any string containing "T" or "-" unchanged.
It never validated, so a Sysmon timestamp that had swallowed the following
XML passed straight through and blinded every time-based detector on 73% of
the dataset — 100% of the endpoint stream.

The export-side root cause is covered by
`test_export_query_cannot_overrun_the_timestamp`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from nabla.parsers import _normalize_timestamp
from nabla.utils import is_off_hours, parse_iso_timestamp

# The exact shape that blinded the dataset: a valid ISO timestamp followed by
# the XML the greedy capture swallowed.
CORRUPT = (
    '"2026-08-09T00:00:15.796640000Z"/><EventRecordID>1356237</EventRecordID>'
    '<Correlation/><Execution ProcessID="16983"'
)


class TestValidTimestampsPassThrough:
    @pytest.mark.parametrize("ts", [
        "2026-08-09T00:00:15Z",
        "2026-08-09T00:00:15.796640000Z",
        "2026-08-09T00:00:15+00:00",
        "2026-08-09T00:00:15+05:00",
        "2026-08-09T00:00:15.796640",
    ])
    def test_iso_forms(self, ts):
        assert _normalize_timestamp(ts) == ts

    def test_space_separated_is_parsed_not_echoed(self):
        """The old code echoed anything containing '-'; this one validates."""
        assert parse_iso_timestamp(_normalize_timestamp("2026-08-09 00:00:15"))

    def test_epoch_is_converted(self):
        out = _normalize_timestamp("1754694015")
        assert out.startswith("2025-")
        assert parse_iso_timestamp(out) is not None

    def test_empty_returns_now(self):
        assert parse_iso_timestamp(_normalize_timestamp("")) is not None


class TestCorruptionIsCaught:
    def test_leading_timestamp_is_recovered(self):
        """Recovery is right for messy real exports — but it is visible."""
        assert _normalize_timestamp(CORRUPT) == "2026-08-09T00:00:15.796640000Z"

    def test_recovery_is_logged(self, caplog):
        with caplog.at_level("WARNING"):
            _normalize_timestamp(CORRUPT)
        assert any("Recovered timestamp" in r.message for r in caplog.records)

    def test_recovered_value_is_usable_downstream(self):
        """The whole point: the recovered timestamp must drive the detectors
        the corruption had blinded."""
        recovered = _normalize_timestamp(CORRUPT)
        assert parse_iso_timestamp(recovered) is not None
        assert is_off_hours(recovered) is True  # 00:00 UTC

    def test_junk_is_discarded_not_echoed(self):
        """A non-timestamp must not flow downstream as a plausible string."""
        assert _normalize_timestamp("garbage") == ""

    def test_junk_is_logged(self, caplog):
        with caplog.at_level("WARNING"):
            _normalize_timestamp("garbage")
        assert any("unparseable timestamp" in r.message for r in caplog.records)

    def test_discarded_value_does_not_look_like_off_hours(self):
        """The old behaviour made `is_off_hours` return False for a blob,
        which is indistinguishable from a real daytime event."""
        assert is_off_hours(_normalize_timestamp("garbage")) is False


# The export script is dev-only (release plan D2: it embeds the org's
# collector names). Where the script is absent, these guards have no
# subject and skip rather than fail — they run in the dev repo.
@pytest.mark.skipif(
    not Path("scripts/export_course_dataset.py").exists(),
    reason="scripts/export_course_dataset.py not present in this tree (dev-only)",
)
class TestExportQueryCannotOverrun:
    """The root cause: a capture class that can run past the timestamp."""

    def _query(self) -> str:
        src = Path("scripts/export_course_dataset.py").read_text()
        match = re.search(r"LINUX_ENDPOINT_QUERY = \((.*?)\n\)", src, re.S)
        assert match, "LINUX_ENDPOINT_QUERY not found"
        return match.group(1)

    def test_capture_class_is_timestamp_characters_only(self):
        query = self._query()
        assert "[0-9T:.Z+-]+" in query

    def test_the_greedy_space_pattern_is_gone(self):
        assert "[^ ]+ [^ ]+" not in self._query()

    def test_pattern_matches_the_real_corrupted_data(self):
        """The regression that matters. The capture began immediately after
        `SystemTime=`, so the source text is exactly the captured value
        followed by the rest of the XML — and the first character of that
        value is the attribute's opening quote.

        A pattern that does not consume that quote matches NOTHING, so the
        next export would silently produce empty timestamps: the same class
        of failure as the bug being fixed. This is why the pattern is
        asserted against real data rather than against its own source text.
        """
        source = "SystemTime=" + CORRUPT
        pattern = re.compile(r"SystemTime=[^0-9]*(?P<ts>[0-9T:.Z+-]+)")
        match = pattern.search(source)
        assert match, "pattern does not match real corrupted data"
        assert match.group("ts") == "2026-08-09T00:00:15.796640000Z"

    def test_pattern_also_handles_an_unquoted_value(self):
        """Robust to both forms, so a format change does not silently break
        the export again."""
        pattern = re.compile(r"SystemTime=[^0-9]*(?P<ts>[0-9T:.Z+-]+)")
        match = pattern.search("SystemTime=2026-08-09T00:00:15Z")
        assert match and match.group("ts") == "2026-08-09T00:00:15Z"
