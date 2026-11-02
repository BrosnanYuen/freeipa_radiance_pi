#!/usr/bin/env bash
# Back up the FreeIPA realm to run/backups/ (gitignored, mode 0600).
#
#   ./scripts/backup-ipa.sh            online data backup (services stay up)
#   ./scripts/backup-ipa.sh --offline  full offline backup (IPA stops briefly)
#
# Restore is deliberately manual and destructive; see docs/RUNBOOK.md §9.
set -euo pipefail
# shellcheck source=scripts/lib.sh
. "$(dirname "$0")/lib.sh"

mode="online"
case "${1:-}" in
--offline) mode="offline" ;;
"") ;;
*)
    die "usage: $0 [--offline]"
    ;;
esac

require_docker
service_running ipa || die "the ipa service is not running"
mkdir -p run/backups
chmod 700 run/backups

container="$("${COMPOSE[@]}" ps -q ipa | head -n1)"
[ -n "$container" ] || die "could not find the ipa container"

newest() {
    "${COMPOSE[@]}" exec -T ipa bash -c \
        'ls -1t /var/lib/ipa/backup 2>/dev/null | head -n1' | tr -d '\r'
}

before="$(newest)"

if [ "$mode" = "online" ]; then
    log "running an online data backup (LDAP only)"
    "${COMPOSE[@]}" exec -T ipa ipa-backup --data --online
else
    log "running a full offline backup; IPA stops and restarts"
    "${COMPOSE[@]}" exec -T ipa ipa-backup
fi

after="$(newest)"
[ -n "$after" ] || die "ipa-backup produced no file in /var/lib/ipa/backup"
[ "$after" != "$before" ] || die "ipa-backup did not create a new archive (newest is still $before)"

dest="run/backups/$after"
docker cp "$container:/var/lib/ipa/backup/$after" "$dest" >/dev/null
if [ -d "$dest" ]; then
    chmod -R go-rwx "$dest"
    chmod 700 "$dest"
else
    chmod 600 "$dest"
fi
size="$(du -sb "$dest" | cut -f1)"
[ "$size" -gt 0 ] || die "backup $dest is empty"
log "wrote $dest (${size} bytes, owner-only)"

if [ "$mode" = "offline" ]; then
    log "waiting for IPA to become healthy again"
    timeout=600
    for ((i = 0; i < timeout; i += 3)); do
        status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || true)"
        [ "$status" = "healthy" ] && break
        sleep 3
    done
    [ "$status" = "healthy" ] || die "IPA did not become healthy after the offline backup"
fi

log "keep run/backups private: the archive contains the realm database and secrets"
