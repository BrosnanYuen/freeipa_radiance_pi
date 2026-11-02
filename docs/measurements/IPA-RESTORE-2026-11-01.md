# FreeIPA backup restore rehearsal — 2026-11-01

**Result: data restore PASSED in an isolated container; a true clean-host
rehearsal and a version upgrade were not possible here.**

## Scope

This was a **containerized** rehearsal on the same host, not a clean physical
host. It used a fresh FreeIPA 4.13.4 container, a fresh Docker volume and a
separate bridge network, so the live realm was untouched. The backup was the
online data backup from the live realm:

`run/backups/ipa-data-2026-11-01-07-12-41/` (`ipa-backup --data --online`).

## Procedure

```sh
docker network create radiance-restore-net
docker volume create ipa-restore-data
# fresh install options with a new admin/DM password
docker run -d --name radiance-ipa-restore --hostname ipa.ipa.test \
  --network radiance-restore-net --cgroupns host --stop-signal SIGRTMIN+3 \
  --tmpfs /run --tmpfs /tmp \
  -v ipa-restore-data:/data \
  -v "$PWD/run/ipa-restore-options:/data/ipa-server-install-options:ro" \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  "$FREEIPA_IMAGE"

# wait for the fresh install (about 12 minutes), then:
docker cp run/backups/ipa-data-2026-11-01-07-12-41 radiance-ipa-restore:/data/ipa-backup
docker exec -i radiance-ipa-restore ipa-restore --data --online --unattended \
  -p "$DM_PASSWORD" /data/ipa-backup
```

The restore reported:

```
Performing DATA restore from DATA backup
Restoring from userRoot in IPA-TEST
Waiting for LDIF to finish
Restoring from ipaca in IPA-TEST
Waiting for LDIF to finish
The ipa-restore command was successful
```

## Verification

With the restored realm's Directory Manager credentials:

| Check | Result |
|---|---|
| `uid=pi,cn=users,cn=accounts,dc=ipa,dc=test` | present |
| `cn=ai-users` membership | `member: uid=pi,...` |
| `HTTP/radiance.ipa.test@IPA.TEST` service principal | present |
| `ipactl status` | Directory Service, KDC, kadmin, httpd, custodia, pki-tomcatd and otpd RUNNING |

## Upgrade rehearsal

`ipa-server-upgrade` was run on the restored copy. It completed the LDAP/config
phase but failed while starting `pki-tomcatd@pki-tomcat.service` (systemd start
timeout):

```
IPA server upgrade failed: ...
CalledProcessError: ... /bin/systemctl start pki-tomcatd@pki-tomcat.service ...
```

No newer FreeIPA image was tested; the image is 4.13.4, the same version as the
source. This is **not** a successful upgrade rehearsal. A real one needs a newer
image and a clean host, not the same container version.

## What remains

- **Clean-host restore:** requires a separate host (or a disposable VM) and a
  physical/host-level install; this environment has one host, no sudo, and the
  container rehearsal shares the host kernel.
- **Replica:** `ipa-replica-install` needs a second host, DNS/SRV records (or
  explicit host mappings), and CA/DNS coordination. Not attempted here.
- **Upgrade:** blocked on a newer image and the pki-tomcat startup failure above.

The rehearsal container, volume and network were removed after verification. The
live realm and stack were not modified by it.
