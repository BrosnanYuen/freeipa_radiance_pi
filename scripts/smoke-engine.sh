#!/usr/bin/env bash
# Verify that the engine behind the gateway is loaded and answering, not merely
# that its container is up. Used by `make smoke` (mock) and `make up-gpu`.
#
#   ./scripts/smoke-engine.sh [--gpu|--mock] [--timeout SECONDS]
#
# The API key is read inside the gateway container and piped to curl's config on
# stdin; it never appears in an argv list. On failure the last 50 engine log
# lines are printed.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"

mode="mock"
timeout=""
while [ $# -gt 0 ]; do
    case "$1" in
    --gpu) mode="gpu" ;;
    --mock) mode="mock" ;;
    --timeout)
        shift
        timeout="${1:-}"
        ;;
    -h | --help)
        sed -n '2,10p' "$0"
        exit 0
        ;;
    *)
        die "unknown argument: $1"
        ;;
    esac
    shift
done

if [ "$mode" = "gpu" ]; then
    service="radiance"
    [ -n "$timeout" ] || timeout=1800
else
    service="mock-radiance"
    [ -n "$timeout" ] || timeout=120
fi

require_docker
set -a
# shellcheck disable=SC1090
. "./$ENV_FILE"
set +a
model="${RADIANCE_SERVED_NAME:-qwen3.8-27b}"

service_running "$service" || die "$service is not running"
service_running radiance-gateway || die "radiance-gateway is not running"

log "waiting for $service /health (up to ${timeout}s)"
if ! wait_for_engine "$timeout"; then
    "${COMPOSE[@]}" logs --tail=50 "$service" >&2 || true
    die "$service did not become healthy within ${timeout}s"
fi

# 1. /v1/models with the private key (key on stdin, not argv).
models_json="$("${COMPOSE[@]}" exec -T radiance-gateway bash -c '
    printf "header = \"Authorization: Bearer %s\"\n" \
        "$(cat /secrets-src/radiance_api_key)" |
        curl -fsS --max-time 30 -K - http://127.0.0.1:8000/v1/models
')" || die "$service /v1/models failed"

printf '%s' "$models_json" | python3 -c '
import json, sys
payload = json.load(sys.stdin)
ids = [item.get("id") for item in payload.get("data", [])]
if sys.argv[1] not in ids:
    raise SystemExit(f"model {sys.argv[1]!r} not in {ids!r}")
' "$model" || die "$service did not list $model"

# 2. A one-token completion, which proves the serving path, not just metadata.
completion="$("${COMPOSE[@]}" exec -T radiance-gateway bash -c '
    printf "header = \"Authorization: Bearer %s\"\n" \
        "$(cat /secrets-src/radiance_api_key)" |
        curl -fsS --max-time 300 -K - \
            -H "Content-Type: application/json" \
            -d "{\"model\":\"'"$model"'\",\"messages\":[{\"role\":\"user\",\"content\":\"smoke\"}],\"max_tokens\":1}" \
            http://127.0.0.1:8000/v1/chat/completions
')" || {
    "${COMPOSE[@]}" logs --tail=50 "$service" >&2 || true
    die "$service chat completion failed"
}

printf '%s' "$completion" | python3 -c '
import json, sys
payload = json.load(sys.stdin)
if not payload.get("choices"):
    raise SystemExit("empty choices")
' || die "$service returned no completion choice"

log "$service is serving ${model}"
