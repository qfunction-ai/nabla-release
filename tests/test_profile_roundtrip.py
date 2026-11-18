"""F4: every persisted dataclass must survive the store's serialization.

This is the test that catches F1. `_ProfileMixin` serializes by field
introspection, driven by hand-maintained `_EWMA_FIELDS` / `_SET_FIELDS` /
`_RECENCY_FIELDS` sets. A field missing from the right set serializes as the
object itself, and `atomic_write_json` used to turn that into its repr string
via `default=str` — silently. `UserProfile.network_event_rate` was declared as
an EWMAProfile but never listed in `_EWMA_FIELDS`, so it persisted as
`"EWMAProfile(value=0.0, ...)"`, reloaded as that string, and killed the
`exfil_volume` detector for an entire round without a single error.

The audit is exhaustive over the declared fields, so it does not need updating
when a field is added — only when a field is added to the WRONG set, which is
exactly when it should fail.
"""

from __future__ import annotations

import dataclasses
import importlib
import inspect
import json
import pkgutil

import pytest

import nabla


def _persisted_dataclasses():
    """Every dataclass in the package that declares to_dict + a from_dict."""
    found = {}
    for mod_info in pkgutil.walk_packages(nabla.__path__, "nabla."):
        if "test" in mod_info.name:
            continue
        try:
            module = importlib.import_module(mod_info.name)
        except Exception:  # optional dependency missing — not this test's job
            continue
        for _, obj in vars(module).items():
            if not inspect.isclass(obj) or not dataclasses.is_dataclass(obj):
                continue
            has_loader = hasattr(obj, "from_dict") or hasattr(obj, "_from_dict")
            if hasattr(obj, "to_dict") and has_loader:
                found[f"{obj.__module__}.{obj.__name__}"] = obj
    return found


_PERSISTED = _persisted_dataclasses()


def test_audit_finds_the_profile_classes():
    """Guard against the audit silently discovering nothing."""
    assert _PERSISTED, "no persisted dataclasses discovered — the audit is broken"
    for expected in ("UserProfile", "HostProfile", "IPProfile"):
        assert any(name.endswith(f".{expected}") for name in _PERSISTED), expected


@pytest.mark.parametrize("qualname", sorted(_PERSISTED))
def test_roundtrip_preserves_field_types(qualname, tmp_path):
    """Serialize, reload through the real JSON path, compare field types.

    A field that comes back as a different type is a field that was declared
    in the wrong set — the bug class F1 belongs to.

    This goes through `atomic_write_json` itself rather than reimplementing
    it, so the audit tests whatever the store actually does on disk. With the
    old `default=str` handler it fails on the type comparison; with the
    hardened handler it fails on the write. Either way it is RED.
    """
    cls = _PERSISTED[qualname]
    try:
        instance = cls()
    except Exception as exc:  # needs constructor args — skip, not a failure
        pytest.skip(f"{qualname} needs constructor args: {exc}")

    try:
        serialized = instance.to_dict()
    except Exception as exc:
        pytest.fail(f"{qualname}.to_dict() raised {type(exc).__name__}: {exc}")

    from nabla.persistence import atomic_write_json

    path = str(tmp_path / "roundtrip.json")
    try:
        atomic_write_json(path, serialized)
    except TypeError as exc:
        pytest.fail(
            f"{qualname}.to_dict() emitted a value the store cannot serialize: {exc}"
        )
    with open(path) as fh:
        reloaded_raw = json.load(fh)

    loader = getattr(cls, "from_dict", None) or getattr(cls, "_from_dict")
    try:
        reloaded = loader(reloaded_raw)
    except Exception as exc:
        pytest.fail(f"{qualname} failed to reload: {type(exc).__name__}: {exc}")

    mismatches = []
    for field in dataclasses.fields(cls):
        before = getattr(instance, field.name)
        after = getattr(reloaded, field.name)
        if type(before) is not type(after):
            mismatches.append(
                f"{field.name}: {type(before).__name__} -> {type(after).__name__} "
                f"({after!r:.60})"
            )
    assert not mismatches, (
        f"{qualname} lost field types across a save/load cycle — a field is "
        f"missing from its _EWMA_FIELDS/_SET_FIELDS/_RECENCY_FIELDS set:\n  "
        + "\n  ".join(mismatches)
    )


@pytest.mark.parametrize("qualname", sorted(_PERSISTED))
def test_declared_field_sets_only_name_real_fields(qualname):
    """The reverse direction: a set naming a field that no longer exists is
    dead configuration that hides the next mistake."""
    cls = _PERSISTED[qualname]
    real = {f.name for f in dataclasses.fields(cls)}
    for attr in ("_EWMA_FIELDS", "_SET_FIELDS", "_RECENCY_FIELDS"):
        declared = set(getattr(cls, attr, set()) or set())
        stale = declared - real
        assert not stale, f"{qualname}.{attr} names non-existent fields: {sorted(stale)}"
