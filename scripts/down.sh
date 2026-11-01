#!/usr/bin/env bash
# Stop the stack. Runtime state under run/ and secrets/ is preserved.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_FILE=".env"
[ -f "$ENV_FILE" ] || ENV_FILE=".env.example"
docker compose --env-file "$ENV_FILE" \
    --profile bootstrap --profile client --profile gpu \
    --profile test-fast --profile test \
    down --remove-orphans "$@"
