#!/bin/bash
# R22 (round 3): every NABLA_* key in .env.example reaches the nabla service.
set -euo pipefail
cd "$(dirname "$0")/.."
cp .env.example .env.check && mv .env.check .env 2>/dev/null || true
trap 'rm -f .env' EXIT
cfg="$(docker compose config 2>/dev/null)"
missing=0
for k in $(grep -oE '^NABLA_[A-Z_]+' .env.example); do
  echo "$cfg" | grep -q "$k" || { echo "not forwarded to nabla: $k"; missing=1; }
done
exit $missing
