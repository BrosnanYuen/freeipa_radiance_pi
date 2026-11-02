#!/usr/bin/env bash
# Rotate the FreeIPA admin password.
#
# The IPA JSON API delegates the admin TGT server-side, so an admin reset made
# with an existing ticket is immediately usable. `ipa user-mod --password` marks
# the new password expired (verified); the following `user-mod` clears that flag
# before the password is written to secrets/.
#
# FreeIPA enforces the group policy's minimum password lifetime (1 hour by
# default), which blocks a second rotation until the window passes. `--force`
# temporarily sets minlife=0 for the duration of the reset and restores the
# previous value; use it for incident response, not as the normal path.
#
# Runs inside the IPA container: no secret is passed on a command line.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"

force=0
case "${1:-}" in
--force) force=1 ;;
"") ;;
*)
    die "usage: $0 [--force]"
    ;;
esac

require_docker
secret_file="secrets/ipa_admin_password"
require_owned_secret "$secret_file"
old="$(secret_value "$secret_file")"
new="$(openssl rand -hex 24)"
[ -n "$new" ] || die "could not generate a new password"

log "rotating the admin password"
if ! printf '%s\n%s\n' "$old" "$new" | "${COMPOSE[@]}" exec -T \
    -e FORCE_ADMIN_ROTATE="$force" ipa \
    env KRB5CCNAME=/tmp/krb5cc_admin_rotate bash -c '
        set -euo pipefail
        read -r old
        read -r new
        printf "%s\n" "$old" | kinit -f admin >/dev/null

        if [ "${FORCE_ADMIN_ROTATE:-0}" = "1" ]; then
            min_seconds="$(ipa pwpolicy-show --raw |
                sed -n "s/^[[:space:]]*krbminpwdlife:[[:space:]]*//p")"
            case "$min_seconds" in
                ""|*[!0-9]*) min_seconds=3600 ;;
            esac
            min_hours=$((min_seconds / 3600))
            [ "$min_hours" -ge 1 ] || min_hours=1
            restore_policy() {
                ipa pwpolicy-mod --minlife="$min_hours" >/dev/null 2>&1 || true
            }
            trap restore_policy EXIT
            ipa pwpolicy-mod --minlife=0 >/dev/null
        fi

        # Admin reset: this marks the password expired.
        printf "%s\n%s\n" "$new" "$new" | ipa user-mod admin --password >/dev/null
        # Clear the reset expiry with the still-valid ticket.
        ipa user-mod admin --setattr=krbPasswordExpiration=20380101000000Z >/dev/null
        # Restore the policy while the admin ticket still exists. Doing this
        # after kdestroy silently leaves minlife=0.
        if [ "${FORCE_ADMIN_ROTATE:-0}" = "1" ]; then
            if ! ipa pwpolicy-mod --minlife="$min_hours" >/dev/null 2>&1; then
                echo "CRITICAL: could not restore pwpolicy minlife" >&2
                exit 6
            fi
            trap - EXIT
        fi
        kdestroy
        printf "%s" "$new" | kinit -f admin >/dev/null
        kdestroy
        if printf "%s" "$old" | kinit -f admin >/dev/null 2>&1; then
            kdestroy
            echo "old admin password is still valid" >&2
            exit 3
        fi
    '; then
    # The reset may have succeeded even though a later verification step
    # failed (for example the policy restore). Probe the new password before
    # leaving the old secret in place and locking the account out.
    if printf '%s' "$new" | "${COMPOSE[@]}" exec -T ipa \
        env KRB5CCNAME=/tmp/krb5cc_admin_probe bash -c '
            read -r pw
            printf "%s" "$pw" | kinit -f admin >/dev/null 2>&1
        '; then
        write_secret_inplace "$secret_file" "$new" 600
        die "rotation reported a failure after the password changed; the new password is saved in $secret_file"
    fi
    die "admin password rotation failed; secrets/ipa_admin_password was not changed"
fi

write_secret_inplace "$secret_file" "$new" 600
log "admin password rotated; the new value is in $secret_file"
log "the running test-runner keeps its old Compose secret until it is recreated"
