"""R7 (round 3): both-direction method-map coverage — the gate that was
declared in phase 3 and never built (the adversarial review's sharpest
finding). Runs in CI so drift fails the build.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _emitted_methods() -> set[str]:
    """Every detection_method string the detectors actually emit."""
    methods = set()
    for py in (ROOT / "nabla").rglob("*.py"):
        if "__pycache__" in str(py):
            continue
        src = py.read_text()
        methods.update(re.findall(r'"detection_method":\s*"([a-z_]+)"', src))
    return methods


def _threshold_reads() -> set[str]:
    """Every threshold name detection.py reads (get or bracket form)."""
    src = (ROOT / "nabla" / "detection.py").read_text()
    reads = set(re.findall(r'thresholds\.get\("([a-z_]+)"', src))
    reads.update(re.findall(r'thresholds\["([a-z_]+)"\]', src))
    return reads


def test_every_mapped_threshold_is_read():
    from nabla.rl.calibration import METHOD_TO_THRESHOLD
    reads = _threshold_reads()
    dead = {t for t in METHOD_TO_THRESHOLD.values() if t not in reads}
    assert not dead, f"mapped thresholds no detector reads: {sorted(dead)}"


def test_every_emitted_method_classified():
    from nabla.rl.calibration import METHOD_TO_THRESHOLD, STATIC_DETECTORS
    emitted = _emitted_methods()
    classified = set(METHOD_TO_THRESHOLD) | STATIC_DETECTORS
    uncovered = emitted - classified
    assert not uncovered, f"emitted but unclassified methods: {sorted(uncovered)}"


def test_no_dead_map_keys():
    from nabla.rl.calibration import METHOD_TO_THRESHOLD
    emitted = _emitted_methods()
    dead = set(METHOD_TO_THRESHOLD) - emitted
    assert not dead, f"map keys never emitted (dead): {sorted(dead)}"


def test_env_example_keys_are_settings():
    """R22: every NABLA_* key in .env.example is a Settings field."""
    import re as _re
    from pathlib import Path as _P
    from nabla.config import Settings
    env = (ROOT / ".env.example").read_text()
    keys = set(_re.findall(r'^(NABLA_[A-Z_]+)', env, _re.M))
    fields = set(Settings.model_fields.keys())
    bad = {k for k in keys if k.removeprefix("NABLA_").lower() not in fields}
    assert not bad, f"env keys without Settings fields: {sorted(bad)}"
