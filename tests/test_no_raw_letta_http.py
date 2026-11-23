"""MR-2 (migration review): no raw HTTP to Letta outside client.py.

The pattern that caused the v0.16.38 break: nabla/agents/env.py made
raw httpx.patch calls to the Letta API with no auth header — invisible
to every settings/plumbing guard because it never touched Settings.
ONE authenticated path exists: the shared client from nabla.client,
which carries base URL, timeout and the api_key. Raw HTTP is still
legitimate for Ollama and SIEM connectors — the guard flags a file only
when it makes raw HTTP calls AND references a Letta URL, the combination
that means "talking to Letta around the client".
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# The one sanctioned raw-HTTP-to-Letta site: the client itself.
ALLOWED: dict[str, str] = {
    "nabla/client.py": "the shared authenticated client — the choke point itself",
}

# Actual CALLS only (with open paren) — docstrings name the disease
# ("raw httpx.patch calls") and must not flag.
CALL_PATTERN = re.compile(
    r"httpx\.(get|post|put|patch|delete|head|options|request|stream|Client|AsyncClient)\("
    r"|requests\.(get|post|put|patch|delete|head|request|Session)\("
)
LETTA_URL_PATTERN = re.compile(
    r"letta_base_url|LETTA_BASE_URL|:8283|/v1/agents|/v1/health"
)


def test_no_raw_letta_http_outside_client():
    offenders = []
    for py in (ROOT / "nabla").rglob("*.py"):
        if "__pycache__" in str(py):
            continue
        rel = py.relative_to(ROOT).as_posix()
        if rel in ALLOWED:
            continue
        text = py.read_text()
        if CALL_PATTERN.search(text) and LETTA_URL_PATTERN.search(text):
            offenders.append(rel)
    assert not offenders, (
        "Raw HTTP calls + Letta URL references outside client.py — "
        "route Letta calls through nabla.client.get_client() so "
        f"authentication applies: {offenders}"
    )
