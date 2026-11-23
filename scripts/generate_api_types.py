#!/usr/bin/env python3
"""R-4: generate frontend API types from the FastAPI OpenAPI schema.

One source of truth: the Pydantic response models. frontend/openapi.json
and frontend/src/types/api.ts are both generated artifacts — never edit
them by hand. --check regenerates and fails on drift, so hand-copied
interfaces cannot come back (the L14 disease: raw-dict endpoints and
hand-copied frontend interfaces, including one drifted lie —
duration_ms never existed on run records).

Usage:
  python scripts/generate_api_types.py           # regenerate
  python scripts/generate_api_types.py --check   # CI: fail on staleness
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "frontend" / "openapi.json"
TYPES = ROOT / "frontend" / "src" / "types" / "api.ts"


def main() -> int:
    check = "--check" in sys.argv

    from nabla.server import app

    schema = app.openapi()
    SPEC.write_text(json.dumps(schema, indent=2) + "\n")

    result = subprocess.run(
        ["npx", "openapi-typescript", str(SPEC), "-o", str(TYPES)],
        cwd=ROOT / "frontend",
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stdout + result.stderr, file=sys.stderr)
        return 1

    if check:
        diff = subprocess.run(
            ["git", "diff", "--exit-code", "--", str(SPEC), str(TYPES)],
            cwd=ROOT,
        )
        if diff.returncode != 0:
            print(
                "API TYPES STALE — backend models changed without "
                "regenerating. Run: python scripts/generate_api_types.py",
                file=sys.stderr,
            )
            return 1
        print("api types fresh: openapi.json and api.ts match the models")
    else:
        print(f"generated {TYPES}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
