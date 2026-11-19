"""N13 (round 4): the detector reference's threshold table is GENERATED
from calibration.THRESHOLDS, and a drift guard keeps it that way.

The doc previously claimed "all thresholds are RL-tunable" — wrong since
N10 (calibration only moves thresholds for raw_score emitters). The table
below is the honest contract: every THRESHOLDS key, its default/range,
and whether label-driven calibration can move it.
"""

import re
from pathlib import Path

DOC = Path(__file__).resolve().parents[1] / "docs" / "detection-methods.md"


def _render_table() -> str:
    from nabla.rl.calibration import THRESHOLDS, NOT_CALIBRATABLE
    rows = ["| key | default | range | calibratable |",
            "|---|---|---|---|"]
    for name, (lo, hi, step, default) in sorted(THRESHOLDS.items()):
        cal = "yes" if name not in NOT_CALIBRATABLE else "no"
        rows.append(f"| `{name}` | {default} | {lo}–{hi} (step {step}) | {cal} |")
    return "\n".join(rows)


def test_threshold_table_in_doc_matches_calibration():
    src = DOC.read_text()
    m = re.search(
        r"<!-- threshold-table-start -->\n(.*?)<!-- threshold-table-end -->",
        src, re.S)
    assert m, "generated threshold table marker missing from the doc"
    assert m.group(1).strip() == _render_table(), (
        "docs/detection-methods.md threshold table drifted from "
        "calibration.THRESHOLDS — regenerate it (see this test's "
        "_render_table)"
    )
