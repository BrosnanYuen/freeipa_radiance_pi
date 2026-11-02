#!/usr/bin/env bash
# Delete the realm state (run/ipa-data). This destroys the KDC, CA and LDAP
# database; there is no automatic backup. Refuses while any service is running.
#
#   ./scripts/reset.sh          interactive confirmation
#   ./scripts/reset.sh --yes    non-interactive (still requires the stack down)
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"

require_docker
target="$ROOT/run/ipa-data"
[ -d "$target" ] || die "nothing to reset: $target does not exist"
case "$target" in
"$ROOT"/run/ipa-data) ;;
*) die "refusing to delete unexpected path: $target" ;;
esac

if "${COMPOSE[@]}" ps -q 2>/dev/null | grep -q .; then
    die "the stack is still running; run ./scripts/down.sh first"
fi

if [ "${1:-}" != "--yes" ]; then
    printf '%s\n' "This deletes $target (KDC, CA, LDAP and keytabs)." >&2
    printf '%s' "Type RESET to continue: " >&2
    read -r answer
    [ "$answer" = "RESET" ] || die "aborted"
fi

rm -rf -- "$target"
log "removed $target; the next up.sh installs a new realm"
