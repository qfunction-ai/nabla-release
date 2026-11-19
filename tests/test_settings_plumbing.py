"""N8 (round 4): settings plumbing, driven by Settings.model_fields.

The old guard checked .env.example keys against compose — a file with 4
documented keys checked 4 keys. The new guard checks ALL Settings fields
reach compose (reachability is mechanical) and that .env.example equals
the curated operator set exactly (omissions are decisions on the
documentation-exclusion list, not accidents).
"""

import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_settings_plumbing.py"
_spec = importlib.util.spec_from_file_location("check_settings_plumbing", _SCRIPT)
_plumbing = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_plumbing)


def test_every_settings_field_forwarded_in_compose():
    INTERNAL_COMPOSE_EXCLUSIONS = _plumbing.INTERNAL_COMPOSE_EXCLUSIONS
    compose_env_keys = _plumbing.compose_env_keys
    settings_fields = _plumbing.settings_fields
    missing = sorted(settings_fields() - INTERNAL_COMPOSE_EXCLUSIONS
                      - compose_env_keys())
    assert not missing, (
        f"Settings fields not forwarded to the nabla service: {missing} "
        f"(unreachable in Docker — the N9 class)"
    )


def test_env_example_equals_operator_set():
    OPERATOR_SET = _plumbing.OPERATOR_SET
    env_example_keys = _plumbing.env_example_keys
    extra = sorted(env_example_keys() - OPERATOR_SET)
    missing = sorted(OPERATOR_SET - env_example_keys())
    assert not extra and not missing, (
        f".env.example must equal the curated operator set exactly. "
        f"extra: {extra} | missing: {missing}"
    )


def test_operator_set_is_settings_fields():
    OPERATOR_SET = _plumbing.OPERATOR_SET
    settings_fields = _plumbing.settings_fields
    bad = sorted(OPERATOR_SET - settings_fields())
    assert not bad, f"operator-set keys that are not Settings fields: {bad}"
