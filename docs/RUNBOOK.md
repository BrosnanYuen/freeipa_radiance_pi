# Runbook

Everything here assumes the repository root as the working directory and a
`.env` copied from `.env.example`.

## 1. Prerequisites

- Docker Engine with Compose v2.
- Free ports on `BIND_ADDR` (default `127.0.0.1`): 88/tcp+udp, 464/tcp+udp,
  8443/tcp. Nothing publishes radiance.
- `openssl`, `python3`, `shred` (coreutils), `realpath`.
- For `--gpu`: an AMD GPU whose driver supports radiance's ROCm userspace,
  `/dev/kfd`, `/dev/dri`, the host `render`/`video` GIDs, and a `.rad` model.
- FreeIPA's image runs systemd. The base Compose file already sets
  `cgroup: host` and mounts `/sys/fs/cgroup` read-write: on a cgroup-v2 host the
  private namespace otherwise dies during boot (observed, and documented
  upstream). Upstream does not support `privileged: true`. On SELinux hosts the
  `/data` bind already carries `:Z`.
- After the first IPA start, the container makes `run/ipa-data` root-owned.
  Host-side scripts therefore stage client files in `run/ipa-client/` and
  remove `/data` files with `docker exec`; `up.sh` handles this.

## 2. Bring-up

```sh
cp .env.example .env
# edit PI_UID/PI_GID, RADIANCE_UID/RADIANCE_GID, RENDER_GID, VIDEO_GID,
# RADIANCE_MODELS, and keep the image digests.

./scripts/up.sh          # mock engine, works without a GPU
./scripts/up.sh --gpu    # real radiance; model load can take several minutes
```

`--gpu` first enforces two gates: every `.rad` container needs an allowed
licence decision ([MODEL-LICENSES.md](MODEL-LICENSES.md)), and
`CAPACITY_MEASURED=1` must be set after E0. `make up-gpu` then runs the engine
smoke test (`scripts/smoke-engine.sh --gpu`), which waits for the model and
prints the last 50 log lines on failure.

`up.sh` is idempotent and performs:

1. creates `secrets/`, `run/`, `work/` with 0700 and generates any missing
   random secrets;
2. renders `run/krb5.conf` and `run/ipa-data/ipa-server-install-options`
   (0600) and generates the TLS key/CSR;
3. starts `ipa` and waits for `ipactl status` (up to 30 min);
4. shreds the installer options file, then runs the one-off `bootstrap`
   container (users, groups, service, keytab, certificate, CA copy, ticket
   policy);
5. starts `radiance-gateway` and waits for its health endpoint;
6. starts `mock-radiance` or `radiance`, then `radiance-shim`.

If a step fails, logs are printed with the failure. Re-running `up.sh` is safe;
the bootstrap does not rotate an existing keytab or reissue an existing cert.

Check readiness:

```sh
docker compose ps
curl -fsS http://127.0.0.1:8443/v1/models   # 401, not a connection error
docker compose logs --tail=50 radiance-gateway
```

## 3. User session

```sh
docker compose --profile client up -d radiance-shim
docker compose --profile client run --rm pi-login pi-krb login
docker compose --profile client run --rm pi-login pi-krb status
docker compose --profile client run --rm pi-client pi-krb run --model radiance-krb/qwen3.8-27b
```

`pi-krb login` runs `kinit -F -l 8h -r 7d pi` in `pi-login` and writes the
ccache to `run/ccache/krb5cc` (0600). `pi-krb status` prints `klist -e` and
rejects non-AES tickets. `pi-krb run` waits for the shim's token and health,
writes `models.json` under `run/pi-agent` (0600), and execs `pi`.

The ccache is mounted only into `pi-login` and `radiance-shim`. The
`pi-client` container has no ccache, no keytab, no certificate and no IPA
secret; it can reach only `radiance-shim:8088` on the internal `shim-net`.

Container-to-container names (`radiance-shim`, `radiance.ipa.test`,
`ipa.ipa.test`) work on the Compose networks without `/etc/hosts`.

### Host-mode Pi

Host-mode is tested (2026-11-01) with the pinned Pi 1.4.0 running from the host
via `npx` and a loopback-published shim container:

```sh
# Requires a valid run/ccache/krb5cc (pi-krb login), Docker and npx.
./scripts/host-pi-smoke.sh --turns 10    # or: make host-pi
```

The script starts a temporary shim on `127.0.0.1:18088`, writes a throwaway
Pi agent directory with `baseUrl http://127.0.0.1:18088/v1`, runs the turns
(`--continue` after the first), and removes the shim and temp state on exit.
It does not touch `~/.pi` or `/etc/hosts`. `tests/host/test_host_pi.py` runs
three turns under `RUN_E2E=1`.

A fully host-installed shim is still possible: it needs `python3-gssapi` and
`krb5-user` on the host, `--token-file run/pi-agent/shim-token`, and
`--listen 127.0.0.1:8088`; the gateway hostname must resolve (the default
`/etc/hosts` entry is `127.0.0.1 ipa.ipa.test radiance.ipa.test`). That variant
is not part of the automated suite.

## 4. Capacity gate (E0)

**Completed 2026-11-01:** 197,952-token admission, `M = 1.0`, cold TTFT
145.356 s, 1,361.8 tok/s prefill, 23.8 tok/s decode, 20.58 GiB peak. The record
is in [CAPACITY.md](CAPACITY.md) and
[measurements/E0-2026-11-01.md](measurements/E0-2026-11-01.md). The procedure is
kept for re-measurement on a new card or container:

```sh
# 1. Boot with --debug-placement once and capture the kv: line.
docker compose --profile gpu run --rm radiance \
  --debug-placement ... # same flags as compose.yaml, plus this one

# 2. Build a near-200k prompt with the engine's own tokenizer. The gateway
#    allowlist deliberately does not expose /tokenize, so run curl inside the
#    gateway's network namespace:
docker compose exec radiance-gateway curl -s http://127.0.0.1:8000/tokenize ...

# 3. Record admission, TTFT, prefill tok/s, decode tok/s, peak VRAM and the
#    number of full-length sessions in docs/CAPACITY.md.
```

If `M < 1`, apply the ladder in [CAPACITY.md](CAPACITY.md) before changing
Pi's `contextWindow`.

The shipped code default is 32,768 tokens and `CAPACITY_MEASURED=0`; `up.sh
--gpu` refuses to start until the measurement is recorded. E0 itself is run
with `docker compose run` as shown above, which bypasses the gate deliberately.

## 5. Credential and certificate rotation

The full inventory, ownership and last-rotation dates are in
[SECRETS.md](SECRETS.md). Every script verifies the new credential, writes the
secret in place (bind mounts keep their inode), recreates the gateway and its
sidecar, and rolls back where possible:

```sh
./scripts/rotate-admin-password.sh [--force]  # --force relaxes minlife briefly
./scripts/rotate-dm-password.sh               # ldapi EXTERNAL, no old password
./scripts/rotate-ldap-bind-password.sh        # gateway rolls back on failure
./scripts/rotate-api-key.sh                   # gateway/engine recreate
./scripts/rotate-cert.sh                      # new key+CSR, revokes old serial
./scripts/rotate-keytab.sh                    # new kvno
```

### Keytab rotation

```sh
./scripts/rotate-keytab.sh
```

The script runs inside the one-off `bootstrap` container, fetches a new
keytab (new kvno) with `ipa-getkeytab`, moves it into place, then recreates the
gateway (a plain restart would strand the mock/engine sharing its namespace). Old
cached service tickets stop working; clients must re-run `pi-krb login` (or wait
for the old service ticket to expire) to obtain a ticket under the new key.
`deploy/systemd/radiance-krb-rotate-keytab.{service,timer}` provides a weekly
user timer; installation is in [SECRETS.md](SECRETS.md). Verify:

```sh
docker compose exec radiance-gateway stat -c '%a %U:%G %n' /run/gateway/radiance.keytab
# 400 gateway /run/gateway/radiance.keytab
```

## 6. Diagnose

| Symptom | Check | Cause |
|---|---|---|
| `Cannot contact any KDC` | `nc -vz ipa.ipa.test 88`; `KRB5_CONFIG`; `/etc/hosts` for host mode | network/realm |
| 401 despite a ticket | `klist`; `kvno HTTP/radiance.ipa.test`; gateway log | wrong SPN, expired ticket, keytab owner/mode |
| 403 as `pi` | `ipa group-show ai-users --all`; `LDAPCacheTTL` | not in `ai-users`; stale LDAP cache (≤60 s) |
| `Server not found in Kerberos DB` | `ipa service-show HTTP/...` | missing/case-mismatched SPN |
| TLS error in the shim | `openssl s_client -connect radiance.ipa.test:8443 -CAfile run/ipa-data/certs/ca.crt` | CA/SAN/hostname |
| 403 on a valid API path | allowlist regex; `make gateway-check` | path not allowed (by design) |
| `pi-client` cannot reach IPA/gateway | expected | it is on `shim-net` only |
| Shim 401 "credentials expired" | `pi-krb status` in `pi-login`; re-login | missing/expired ccache |
| 413/504 | body limit, prefill time, `ProxyTimeout` | oversized prompt or long stream |
| OOM in radiance | boot `kv:` line; `--debug-placement` | context/KV beyond the card |
| Gateway unhealthy after bootstrap | `docker compose logs radiance-gateway`; keytab/cert modes | marker/cert/keytab missing or unreadable |
| `model licence gate failed` | `make license-check`; `model-licenses.json` | undocumented or blocked `.rad` container |
| `CAPACITY_MEASURED is not 1` | `docs/CAPACITY.md` E0 record | capacity has not been measured |
| `Too soon to change password` | `ipa pwpolicy-show` | admin minlife (1 h); use `rotate-admin-password.sh --force` |
| Host-mode Pi cannot connect | `curl -f http://127.0.0.1:18088/healthz`; ccache | shim not published/ccache expired |

## 7. Tests

```sh
make unit                       # host, fast
make config                     # compose lint
make gateway-check                 # build and module-check the gateway image
make up && make test-fast       # integration + security (mock engine)
make test-host                  # container/mount/secret inspections
make test-slow                    # T4b revocation, T10 expiry (~4 min)
make test-rotation                # all five rotation scripts against the live realm
RUN_SLOW=1 pytest tests/host/test_advanced.py      # same as make test-slow
RUN_DESTRUCTIVE=1 pytest tests/host/test_destructive.py  # T5 wrong keytab, T16 rotation
RUN_E2E=1 pytest tests/host/test_e2e.py            # Pi login + tool loop + JSON mode
RUN_E2E=1 pytest tests/host/test_host_pi.py        # host-mode Pi, 3 turns
make smoke                        # engine lists and serves the model
make host-pi                      # 10-turn host-mode session
```

Inside the test-runner (`/tests` as the working directory), `pytest -q integration security` runs with
`EDGE_URL=https://radiance.ipa.test:8443`, the IPA CA at `/certs/ca.crt`, and
the Compose secrets under `/run/secrets`.

T5 (wrong keytab) and T16 (rotation) change stack state; they are documented
manual checks or opt-in host tests. `testssl.sh` is not shipped; the security
suite performs the equivalent TLS-version, cipher, chain and header checks with
Python's `ssl` module and `openssl`.

## 8. Teardown

```sh
./scripts/down.sh       # stops containers; run/ and secrets/ are preserved
./scripts/reset.sh      # deletes run/ipa-data after typing RESET; stack must be down
make clean              # removes run/, secrets/, work/ and caches — destructive
```

`run/ipa-data` holds the realm state and must be backed up if the realm matters.
Deleting it loses the KDC, CA and LDAP database.

## 9. Backup and restore

```sh
./scripts/backup-ipa.sh             # online data backup (services stay up)
./scripts/backup-ipa.sh --offline   # full backup; IPA stops and restarts
```

Archives land under `run/backups/` with owner-only permissions. They contain the
realm database (and, for a full backup, private keys): treat them as secrets and
store them encrypted off-host. The online backup is `ipa-backup --data
--online`; the directory contains `ipa-data.tar`.

Restore is manual and destructive. For an online data backup, with the clients
stopped:

```sh
docker compose --env-file .env stop radiance-gateway mock-radiance radiance \
    radiance-shim pi-login pi-client
docker compose --env-file .env exec -T ipa ipactl stop
docker cp run/backups/<dir>/ipa-data.tar \
    "$(docker compose --env-file .env ps -q ipa):/var/lib/ipa/backup/restore.tar"
# Interactive: enter the Directory Manager password at the prompt.
docker compose --env-file .env exec ipa ipa-restore --data --online \
    --unattended /var/lib/ipa/backup/restore.tar
docker compose --env-file .env exec -T ipa ipactl start
./scripts/up.sh
```

For unattended automation `ipa-restore -p` puts the Directory Manager password
in the container's argv for the duration of the restore; prefer the interactive
form and do not log the command. A full/offline backup restores the CA as well;
follow the upstream `ipa-restore` procedure and rehearse on a disposable realm
first. Replication, replica promotion, and a clean-host restore rehearsal remain
production work (TODO §5).

## 10. Verified versions (2026-11-01)

| Component | Version |
|---|---|
| radiance-gateway | Python 3.11 + `python3-gssapi` 1.8.2 + `python3-ldap` 3.4.3, TLS 1.3 |
| OpenSSL in the gateway | 3.0.22 |
| FreeIPA | 4.13.4 (digest-pinned image) |
| Pi | 1.4.0 (npm; verified as the current release, integrity pinned) |
| radiance | 1.15.1 (image pinned; `qwen3.8-27b-mxfp4.rad` served; E0/T11/T11b measured) |
| Python test image | 3.13, pytest 9.2.0, gssapi 1.12.0 |

The gateway image digest and Python/GSSAPI package versions change when the pinned base
digest is updated; re-record this table at that point.
