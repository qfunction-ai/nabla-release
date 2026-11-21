"""F5: machine accounts must not be behaviorally baselined.

Behavioral baselines describe a person. A service account has no habits to
deviate from: `root` and `SYSTEM` doing privileged work at 03:00 is the job,
not an anomaly. Scoring them produces incidents that are always wrong, and
those incidents bury the ones that matter.

This is not a corner case. The real dataset-v1 has 13 machine principals to
one human (`helpdeskone`), so the off-hours detector was firing on almost
entirely the wrong population.
"""

from __future__ import annotations

import pytest

from nabla.utils import is_baselineable_user, is_machine_account


class TestStructuralRules:
    """Unambiguous markers — no guessing involved."""

    @pytest.mark.parametrize("name", [
        "WIN-SRV01$", "WIN-SRV02$", "WORKSTATION01$", "DC01$",
    ])
    def test_windows_machine_accounts(self, name):
        assert is_machine_account(name)

    @pytest.mark.parametrize("name", [
        "root", "daemon", "bin", "sys", "adm", "mail", "ftp", "games",
        "nobody", "tss", "sshd", "www-data",
    ])
    def test_unix_system_principals(self, name):
        assert is_machine_account(name)

    @pytest.mark.parametrize("name", [
        "SYSTEM", "Local System", "NETWORK SERVICE", "Local Service",
        "NT AUTHORITY\\SYSTEM", "DEFAULTACCOUNT",
    ])
    def test_windows_system_principals(self, name):
        assert is_machine_account(name)

    @pytest.mark.parametrize("name", [
        "svc-jenkins", "svc_backup", "service-account", "sa_deploy",
        "build-svc", "reporting_service",
    ])
    def test_service_naming_conventions(self, name):
        assert is_machine_account(name)

    @pytest.mark.parametrize("name", ["", "-", "n/a", "unknown", "NONE"])
    def test_placeholders_are_not_people(self, name):
        assert is_machine_account(name)

    @pytest.mark.parametrize("name", ["jenkins", "gitlab-runner", "nagios",
                                      "prometheus", "wsus", "ec2-user"])
    def test_known_automation(self, name):
        assert is_machine_account(name)


class TestHumansAreNotCaught:
    """The false-positive direction matters as much as the true-positive one.
    Excluding a real analyst from baselining silently blinds the product."""

    @pytest.mark.parametrize("name", [
        "helpdeskone", "rsmith", "johnson", "smith", "brown", "williams",
        "a.patel", "maria.garcia", "jdoe", "admin", "administrator",
        "service.desk", "rootcause", "sven", "bintou",
    ])
    def test_human_names_are_baselineable(self, name):
        assert not is_machine_account(name), f"{name} wrongly excluded"
        assert is_baselineable_user(name)

    def test_case_insensitive(self):
        assert is_machine_account("SYSTEM")
        assert is_machine_account("system")
        assert is_machine_account("SyStEm")

    def test_whitespace_tolerated(self):
        assert is_machine_account("  root  ")

    def test_none_is_not_a_person(self):
        assert is_machine_account(None)


class TestOverrides:
    """N9 (round 4): overrides reach the classifier through Settings.
    The old raw-env mechanism died with the raw-read guard; these pin
    the Settings path explicitly (env vars still work in production —
    Settings reads them at load — but tests must not depend on cache
    invalidation)."""

    @staticmethod
    def _settings(monkeypatch, **kw):
        from nabla.config import Settings
        import nabla.config
        monkeypatch.setattr(nabla.config, "get_settings",
                            lambda: Settings(**kw))

    def test_machine_override_adds_an_account(self, monkeypatch):
        self._settings(monkeypatch, machine_accounts="custom-bot,other-svc")
        assert is_baselineable_user("custom-bot") is False
        assert is_baselineable_user("other-svc") is False
        assert is_baselineable_user("helpdeskone") is True

    def test_human_override_rescues_a_false_positive(self, monkeypatch):
        """An operator who knows `ftp` is a person at their site should not
        have to patch the code."""
        assert is_baselineable_user("ftp") is False
        self._settings(monkeypatch, human_accounts="ftp")
        assert is_baselineable_user("ftp") is True

    def test_human_override_beats_machine_override(self, monkeypatch):
        self._settings(monkeypatch, machine_accounts="alice",
                       human_accounts="alice")
        assert is_baselineable_user("alice") is True


class TestRealDatasetPopulation:
    """The predicate against the actual dataset-v1 principal list.

    This is the regression that matters: exactly one of these is a person.
    """

    DATASET_PRINCIPALS = {
        "root": False, "WIN-SRV01$": False, "-": False, "adm": False,
        "WIN-SRV02$": False, "helpdeskone": True, "SYSTEM": False,
        "bin": False, "mail": False, "ftp": False, "ec2-user": False,
        "games": False, "daemon": False, "tss": False,
    }

    def test_every_dataset_principal_classified_correctly(self):
        wrong = {
            name: is_baselineable_user(name)
            for name, expected in self.DATASET_PRINCIPALS.items()
            if is_baselineable_user(name) != expected
        }
        assert not wrong, f"misclassified dataset principals: {wrong}"

    def test_exactly_one_human_in_the_dataset(self):
        humans = [n for n in self.DATASET_PRINCIPALS if is_baselineable_user(n)]
        assert humans == ["helpdeskone"]
