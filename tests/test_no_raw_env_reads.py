"""N14 (round 4): no raw NABLA_* env reads outside Settings.

The D1/R14/N9 class: code reading os.environ directly is unreachable in
Docker (compose only forwards declared keys) and invisible to the
settings-plumbing guard. Settings (pydantic BaseSettings) is the ONE
sanctioned env reader. This guard sweeps every module for the pattern.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Sites that may keep raw reads, with justification. Empty as of N14 —
# the round-4 fixes moved all six finds into Settings. Add an entry ONLY
# with a comment a reviewer can check, and expect to defend it.
ALLOWED_RAW_ENV_READS: dict[str, str] = {}


def test_no_raw_nabla_env_reads():
    # actual READS only — os.environ.get/[ and os.getenv( — not docstring
    # mentions of the pattern (the guard's own docs name the disease)
    pattern = re.compile(r"os\.environ\.get|os\.environ\[|os\.getenv\(")
    offenders = []
    for py in (ROOT / "nabla").rglob("*.py"):
        if "__pycache__" in str(py):
            continue
        for lineno, line in enumerate(py.read_text().splitlines(), 1):
            if pattern.search(line):
                key = f"{py.relative_to(ROOT)}:{lineno}"
                if key not in ALLOWED_RAW_ENV_READS:
                    offenders.append(f"{key}: {line.strip()}")
    assert not offenders, (
        "raw env reads outside Settings (unreachable in Docker, invisible "
        "to the plumbing guard):\n" + "\n".join(offenders)
    )
