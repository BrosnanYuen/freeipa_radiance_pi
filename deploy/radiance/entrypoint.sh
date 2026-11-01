#!/bin/sh
# radiance entrypoint: export the API key from the 0400 host file, then exec the
# engine. The flags live only in compose.yaml command: (single source of truth).
set -eu

RADIANCE_API_KEY="$(cat /secrets-src/radiance_api_key)"
export RADIANCE_API_KEY
exec radiance "$@"
