"""Silent-swallow enforcement (lint-class rule, 2026-09 sweep).

Every except-handler whose body is a bare pass/continue/... must either
follow a log call or carry the `# silent by design:` provenance marker.
This test fails CI on regressions — the sweep's enforcement mechanism.

Self-test: verified once during implementation by injecting a bare pass
and confirming failure (see git history).
"""

import re
from pathlib import Path

SWALLOW = re.compile(r'^(\s*)(pass|continue|\.\.\.)\s*(#.*)?$')
EXCEPT_HEADER = re.compile(r'^(\s*)except.*:\s*(#.*)?$')
MARKER = "# silent by design"


def _find_violations(root: Path) -> list[str]:
    """Flag except-handlers whose ENTIRE body is a bare swallow statement.

    The rule (matching the sweep plan's census): a handler whose body is
    exactly pass/continue/... with no log call and no marker. A continue
    that follows a log line, or sits inside a larger try block doing other
    work, is filter semantics — not a silent handler.
    """
    violations = []
    for path in sorted(root.rglob("*.py")):
        if ".ipynb_checkpoints" in str(path) or "__pycache__" in str(path):
            continue
        lines = path.read_text().split("\n")
        for i, line in enumerate(lines):
            m = EXCEPT_HEADER.match(line)
            if not m:
                continue
            indent = len(m.group(1))
            body_indent = indent + 4
            # first non-blank body line
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j >= len(lines):
                continue
            body = lines[j]
            bm = SWALLOW.match(body)
            if not bm:
                continue  # body has real statements — not a bare swallow
            if (len(body) - len(body.lstrip())) != body_indent:
                continue  # not the handler's direct body
            if MARKER in body:
                continue  # marked, by design
            violations.append(f"{path}:{j + 1} bare '{bm.group(2)}' handler swallow without log or marker")
    return violations


def test_no_unmarked_silent_swallows():
    root = Path(__file__).parent.parent / "nabla"
    violations = _find_violations(root)
    assert not violations, (
        "Silent-swallow violations found (add a logger.warning with "
        "exc_info, or a '# silent by design: <reason> (date sweep)' "
        "marker):\n  " + "\n  ".join(violations)
    )


def test_enforcer_catches_injected_violation(tmp_path):
    """The enforcer enforces: a bare pass in a scratch tree is caught."""
    bad = tmp_path / "bad.py"
    bad.write_text("try:\n    x = 1\nexcept Exception:\n    pass\n")
    good = tmp_path / "good.py"
    good.write_text("try:\n    x = 1\nexcept Exception:\n    pass  # silent by design: test (sweep)\n")
    vs = _find_violations(tmp_path)
    assert any("bad.py" in v for v in vs)
    assert not any("good.py" in v for v in vs)
