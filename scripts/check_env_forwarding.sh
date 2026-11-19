#!/bin/bash
# R22 (round 3) / N8 (round 4): compose-level forwarding check. The
# Settings-driven guard (scripts/check_settings_plumbing.py, wired into
# CI) is the primary; this one validates the RENDERED compose config —
# that interpolation actually resolves with a real .env in place.
# Exits LOUDLY on compose config failure (N8.4): a silent skip here is
# how a broken compose file passed CI.
set -uo pipefail
cd "$(dirname "$0")/.."
if [ ! -f .env ]; then
  cp .env.example .env.check && mv .env.check .env
  trap 'rm -f .env' EXIT
fi
if ! cfg="$(docker compose config 2>&1)"; then
  echo "COMPOSE CONFIG FAILED — forwarding check did not run:" >&2
  echo "$cfg" >&2
  echo "" >&2
  echo "Hint: docker compose config requires POSTGRES_PASSWORD to be set." >&2
  echo "Generate one: python3 -c \"import secrets; print(secrets.token_urlsafe(24))\"" >&2
  exit 2
fi
missing=0
for k in $(grep -oE '^NABLA_[A-Z0-9_]+' .env.example); do
  echo "$cfg" | grep -q "$k" || { echo "not forwarded to nabla: $k"; missing=1; }
done
exit $missing
