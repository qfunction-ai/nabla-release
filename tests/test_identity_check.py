# Round 7 Phase 6 witnesses: the leak-free identity check (R-13/R-18).
# These test the MECHANISM with a synthetic salt and synthetic tokens —
# the real salt is a CI secret, the real tokens live outside the repo.

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "check_identities.py"


def _load_check():
    import importlib.util
    spec = importlib.util.spec_from_file_location("ci_mod", SCRIPT)
    ci = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ci)
    return ci


def _run(tree: Path, salt):
    import os
    env = dict(os.environ)
    if salt is None:
        env.pop("NABLA_IDENTITY_CHECK_SALT", None)
    else:
        env["NABLA_IDENTITY_CHECK_SALT"] = salt
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--tree", str(tree)],
        capture_output=True, text=True, env=env)


def _mini_repo(tmp_path: Path, files: dict) -> Path:
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "-c", "user.email=t@t",
                    "-c", "user.name=t", "commit", "-qm", "x"], check=True)
    return tmp_path


def _digests(salt: str, tokens):
    import hashlib
    return {hashlib.sha256((salt + t).encode()).hexdigest() for t in tokens}


class TestIdentityCheckMechanism:
    def test_finds_forbidden_hostname_with_dollar_suffix(self):
        # R-18's named witness: a forbidden hostname with a `$` suffix
        # (machine-account form) is caught via its split components.
        ci = _load_check()
        salt = "test-salt"
        digests = _digests(salt, ["forbiddenhost", "oddcode"])
        ci._FORBIDDEN_DIGESTS = list(digests)
        candidates = ci._candidates('MACHINE = "FORBIDDENHOST$"\n')
        assert any(ci._digest(salt, c) in digests for c in candidates), (
            f"the $-suffixed hostname escaped the tokenizer: {candidates}")

    def test_domain_and_host_domain_joins_caught(self):
        ci = _load_check()
        salt = "test-salt"
        digests = _digests(salt, ["secretdomain", "hostsecretdomain"])
        # "host.secretdomain" — split tokens give host/secretdomain;
        # the line join gives hostsecretdomain
        candidates = ci._candidates('computer = "host.secretdomain"\n')
        assert any(ci._digest(salt, c) in digests for c in candidates)

    def test_public_org_name_and_generics_do_not_flag(self):
        # R-18 scope: the public GitHub org word and generic replacement
        # names must never flag. Only the JOINED domain form is
        # forbidden — the bare org word is the public GitHub name.
        ci = _load_check()
        salt = "test-salt"
        digests = _digests(salt, ["qfunctionai"])
        candidates = ci._candidates(
            'url = "https://github.com/qfunction-ai/nabla"\n'
            'host = "DC01"\n'
            'acct = "WORKSTATION01$"\n')
        assert not any(ci._digest(salt, c) in digests for c in candidates), (
            "the public org name or a generic replacement flagged")

    def test_fail_closed_without_salt(self, tmp_path):
        tree = _mini_repo(tmp_path, {"README.md": "clean file\n"})
        r = _run(tree, salt=None)
        assert r.returncode == 1, "missing salt must fail closed, not pass"
        assert "salt" in r.stderr.lower()

    def test_clean_tree_passes(self, tmp_path):
        tree = _mini_repo(tmp_path, {"README.md": "generic DC01 fixtures\n"})
        r = _run(tree, salt="test-salt")
        assert r.returncode == 0, r.stderr

    def test_dirty_tree_fails_and_names_the_file(self, tmp_path):
        # module-level API (what the subprocess runs) with a synthetic
        # forbidden token — verifies file attribution end to end.
        ci = _load_check()
        salt = "test-salt"
        digests = _digests(salt, ["forbiddenhost"])
        ci._FORBIDDEN_DIGESTS = list(digests)
        tree = _mini_repo(tmp_path, {"fixture.py": 'H = "FORBIDDENHOST"\n'})
        findings = []
        for rel in ci._tracked_files(str(tree)):
            for tok in ci._candidates((tmp_path / rel).read_text()):
                if ci._digest(salt, tok) in digests:
                    findings.append(rel)
        assert findings == ["fixture.py"], findings

    def test_committed_digest_list_well_formed(self):
        # No placeholders, all hex, correct length, no dupes — a
        # malformed digest list silently disables the check.
        ci = _load_check()
        assert ci._FORBIDDEN_DIGESTS, "empty digest list — check disabled"
        for d in ci._FORBIDDEN_DIGESTS:
            assert len(d) == 64 and all(c in "0123456789abcdef" for c in d), (
                f"malformed digest: {d!r}")
        assert len(set(ci._FORBIDDEN_DIGESTS)) == len(ci._FORBIDDEN_DIGESTS), (
            "duplicate digests — token list drifted")

    def test_exclusions_are_paths_not_identities(self):
        # R-13: the exclusion list must not smuggle identity strings —
        # every entry is a path shape.
        ci = _load_check()
        for p in (*ci._EXCLUDED_PREFIXES, *ci._EXCLUDED_PATHS):
            assert "/" in p or p.endswith((".py", ".txt")), (
                f"exclusion {p!r} does not look like a path")
