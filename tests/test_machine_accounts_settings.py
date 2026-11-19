"""N9 (round 4): machine-account overrides reachable through Settings.

utils.py read NABLA_MACHINE_ACCOUNTS/NABLA_HUMAN_ACCOUNTS straight from
os.environ — absent from Settings, compose, and .env.example, so the
override was unreachable in Docker (third occurrence of the D1/R14
class). The witnesses pin the SETTINGS path, not the env path: patch
get_settings, leave os.environ alone — if the classification honors
the env var instead of Settings, the test fails.
"""


def test_machine_account_override_via_settings(monkeypatch):
    from nabla.config import Settings
    import nabla.config
    import nabla.utils as U  # noqa: F401 (import target under test)

    monkeypatch.delenv("NABLA_MACHINE_ACCOUNTS", raising=False)
    monkeypatch.setattr(nabla.config, "get_settings",
                        lambda: Settings(machine_accounts="svc-newthing, root"))
    assert U.is_machine_account("svc-newthing")
    assert not U.is_baselineable_user("svc-newthing")
    assert U.is_machine_account("root")


def test_human_account_override_via_settings(monkeypatch):
    from nabla.config import Settings
    import nabla.config
    import nabla.utils as U  # noqa: F401 (import target under test)

    monkeypatch.delenv("NABLA_HUMAN_ACCOUNTS", raising=False)
    monkeypatch.setattr(nabla.config, "get_settings",
                        lambda: Settings(human_accounts="ftp"))
    # human override wins over the machine predicate in the BASELINING
    # decision (is_machine_account still reports the raw predicate)
    assert U.is_baselineable_user("ftp")


def test_operator_via_settings(monkeypatch):
    """history.py's audit operator: NABLA_OPERATOR was a raw env read on a
    key that wasn't even a Settings field."""
    from nabla.config import Settings
    import nabla.history as H

    monkeypatch.delenv("NABLA_OPERATOR", raising=False)
    monkeypatch.setattr(H, "get_settings",
                        lambda: Settings(operator="pat.smith"))
    assert H._audit_operator(None) == "pat.smith"
    assert H._audit_operator("cli-override") == "cli-override"
