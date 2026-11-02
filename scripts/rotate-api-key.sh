#!/usr/bin/env bash
# Rotate the radiance engine API key.
#
# The gateway injects this key on the loopback hop and the engine reads it from the
# same file at start. Both are recreated. The key is 0400 and owned by the
# engine UID; the write temporarily adds the owner-write bit and restores it.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"

require_docker
secret_file="secrets/radiance_api_key"
require_owned_secret "$secret_file"
old="$(secret_value "$secret_file")"
new="$(openssl rand -hex 32)"
[ -n "$new" ] || die "could not generate a new key"

log "rotating the engine API key"
write_secret_inplace "$secret_file" "$new" 400
log "recreating the gateway and engine"
if ! recreate_gateway_stack 120 || ! verify_gateway_auth; then
    log "gateway verification failed; restoring the previous key"
    write_secret_inplace "$secret_file" "$old" 400
    recreate_gateway_stack 120 || die "CRITICAL: gateway did not recover after restoring the key"
    die "API key rotation failed and was rolled back"
fi
log "API key rotated; the gateway authenticated a pi request"
log "the engine (if running) now uses the new key; no request was sent to the model"
