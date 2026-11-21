#!/usr/bin/env python3
"""Leak-free identity check (round 7, R-13/R-18).

The forbidden tokens are NOT in this file — only salted SHA-256
digests. The salt comes from NABLA_IDENTITY_CHECK_SALT at run time;
an absent salt fails closed (a check that silently passes without its
key is no check). Every TRACKED file is tokenized, each candidate is
hashed with the salt, compared against the digests.

Tokenizer (R-18): candidates are (a) alphanumeric tokens split on
non-alphanumerics, case-folded, and (b) the alphanumeric JOIN of each
line, case-folded — so "HOST.DOMAIN" matches the host+domain digest
and "NAME$" matches the hostname digest via its split components.
Scope: the org's internal domain and hostnames ONLY — the public
GitHub org name and generic replacement names (DC01, WORKSTATION01)
must never flag.

Exclusions (by PATH, never by identity — each justified here):
  course-assets/                real course data; dev-only, on the
                                release exclude list since round 3
  docs/plans/                   internal working documents (they quote
                                the scrubs they ordered)
  scripts/export_course_dataset.py  real collector names; dev-only,
                                on the release exclude list
Untracked files are not scanned — local-only artifacts (real captures)
never enter either tree.

To add a forbidden token (salt must be set):
    python scripts/check_identities.py --hash THE_TOKEN
append the printed digest to _FORBIDDEN_DIGESTS.

Usage:
    python scripts/check_identities.py [--tree PATH] [--hash TOKEN]
Exit 0 = clean; 1 = findings (or missing salt).
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys

_SPLIT_RE = re.compile(r"[^0-9a-zA-Z]+")
_JOIN_RE = re.compile(r"[^0-9a-zA-Z]")

# sha256(salt + token) for the forbidden tokens, case-folded. Digests
# only — the tokens live outside the repo (R-13: a committed grep leaks
# the patterns AND matches itself). Regenerate with --hash when the
# salt or the token list changes.
_FORBIDDEN_DIGESTS: list[str] = [
    # internal domain (joined form; the bare org word is the public
    # GitHub name and must NOT flag)
    "52e6154dce012fb3be5f2a50d7c74bde9fdd00c9e8b056c36d491e0eb82c2994",
    # internal hostnames (joined form)
    "ea5faf4a23595d332053bb7842f40c75f3a7291ca60017e1bdd3e1eee3742f3b",
    "289b608dc2f3ce287f075027f71307ffadcef9f2b37b12cfb9e8714e57ea4904",
    "7ad6ef9564be63405718d188a768ac7dc87d8979c282d83916ee5d08601d8b31",
    "24c8b9bcdaf9464a6dd4be5361e1b812fc77ae3c2684ebbf794d1e6c356a0c8b",
    "b3d0eaf19b13360320115595c8f80669731e609c7ca061102ccbba74e10aa7e1",
    # hostname suffixes — the org-identifying parts; these catch the
    # "$"-suffixed machine-account forms via split tokens
    "b0fe4d850249b875d6c8f8560e23a66d821c988ad364f7309abc44d334995243",
    "086eca0653d2db604839e60989e0b47d9407af6dce0f3e34bdeff3240671f9e1",
    "e65af08dc8fec50db581ef67978d295b306ec87055ec49b941ad03cff1321ef3",
    "6dc424c9aeed2a7fdd3cb0003e4e7b42089504d57ffd6d93c3f96894ebb48c81",
    # host+domain joins
    "4e6ae58dddf67a4e34f098326492669adbc318003a47c120acdb924844f0eabb",
    "bc45845b82dc0d6fb4bb163fb32e20ec954a266803a69a0d3734677b291baaed",
]

_EXCLUDED_PREFIXES = (
    "course-assets/",
    "docs/plans/",
)
_EXCLUDED_PATHS = {
    "scripts/export_course_dataset.py",
}


def _salt() -> str:
    s = os.environ.get("NABLA_IDENTITY_CHECK_SALT", "")
    if not s:
        print("FAIL closed: NABLA_IDENTITY_CHECK_SALT is not set — "
              "the identity check cannot run without its salt "
              "(set it in the environment / CI secrets).", file=sys.stderr)
        raise SystemExit(1)
    return s


def _digest(salt: str, token: str) -> str:
    return hashlib.sha256((salt + token).encode()).hexdigest()


def _candidates(text: str):
    """R-18 tokenizer: split tokens + per-line alphanumeric joins,
    all case-folded."""
    seen: set[str] = set()
    for line in text.splitlines():
        for tok in _SPLIT_RE.split(line):
            if len(tok) >= 4:
                seen.add(tok.lower())
        joined = _JOIN_RE.sub("", line).lower()
        if len(joined) >= 4:
            seen.add(joined)
    return seen


def _tracked_files(tree: str) -> list[str]:
    out = subprocess.run(["git", "-C", tree, "ls-files", "-z"],
                         capture_output=True, check=True)
    return [f.decode() for f in out.stdout.split(b"\0") if f]


def check_tree(tree: str) -> int:
    salt = _salt()
    forbidden = set(_FORBIDDEN_DIGESTS)
    findings: list[str] = []
    for rel in _tracked_files(tree):
        if rel.startswith(_EXCLUDED_PREFIXES) or rel in _EXCLUDED_PATHS:
            continue
        path = os.path.join(tree, rel)
        if not os.path.isfile(path):
            continue
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for tok in _candidates(text):
            if _digest(salt, tok) in forbidden:
                findings.append(f"{rel}: token digest match")
    if findings:
        print(f"FAIL: {len(findings)} identity finding(s):", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("identity check: clean")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if "--hash" in args:
        i = args.index("--hash")
        token = args[i + 1] if len(args) > i + 1 else ""
        if not token:
            print("usage: --hash TOKEN", file=sys.stderr)
            return 2
        print(_digest(_salt(), token.lower()))
        return 0
    tree = os.path.abspath(args[args.index("--tree") + 1]) if "--tree" in args \
        else os.getcwd()
    return check_tree(tree)


if __name__ == "__main__":
    raise SystemExit(main())
