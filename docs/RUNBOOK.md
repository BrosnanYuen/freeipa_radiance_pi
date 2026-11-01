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

`up.sh` is idempotent and performs:

1. creates `secrets/`, `run/`, `work/` with 0700 and generates any missing
   random secrets;
2. renders `run/krb5.conf` and `run/ipa-data/ipa-server-install-options`
   (0600) and generates the TLS key/CSR;
3. starts `ipa` and waits for `ipactl status` (up to 30 min);
4. shreds the installer options file, then runs the one-off `bootstrap`
   container (users, groups, service, keytab, certificate, CA copy, ticket
   policy);
5. starts `radiance-edge` and waits for its health endpoint;
6. starts `mock-radiance` or `radiance`, then `radiance-shim`.

If a step fails, logs are printed with the failure. Re-running `up.sh` is safe;
the bootstrap does not rotate an existing keytab or reissue an existing cert.

Check readiness:

```sh
docker compose ps
curl -fsS http://127.0.0.1:8443/v1/models   # 401, not a connection error
docker compose logs --tail=50 radiance-edge
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

The container path is the tested one. For a Pi installed on the host:

```sh
sudo sh -c 'printf "127.0.0.1 ipa.ipa.test radiance.ipa.test\n" >> /etc/hosts'
docker compose --profile client up -d radiance-shim
docker compose run --rm -T pi-login pi-krb login --password-stdin < /dev/tty

KRB5_CONFIG="$PWD/run/krb5.conf" \
KRB5CCNAME="FILE:$PWD/run/ccache/krb5cc" \
docker compose run --rm -T pi-login pi-krb status

# Run the shim from the Pi image with the host token path, bind loopback, and:
#   --token-file run/pi-agent/shim-token
# then:
pi-krb run --shim-url http://127.0.0.1:8088 \
           --token-file run/pi-agent/shim-token \
           --agent-dir ~/.pi/agent --model radiance-krb/qwen3.8-27b
```

## 4. Capacity gate (E0)

Do this before advertising 200k:

```sh
# 1. Boot with --debug-placement once and capture the kv: line.
docker compose --profile gpu run --rm radiance \
  --debug-placement ... # same flags as compose.yaml, plus this one

# 2. Build a near-200k prompt with the engine's own tokenizer. The edge
#    allowlist deliberately does not expose /tokenize, so run curl inside the
#    edge's network namespace:
docker compose exec radiance-edge curl -s http://127.0.0.1:8000/tokenize ...

# 3. Record admission, TTFT, prefill tok/s, decode tok/s, peak VRAM and the
#    number of full-length sessions in docs/CAPACITY.md.
```

If `M < 1`, apply the ladder in [CAPACITY.md](CAPACITY.md) before changing
Pi's `contextWindow`.

## 5. Keytab rotation

```sh
./scripts/rotate-keytab.sh
```

The script runs inside the one-off `bootstrap` container, fetches a new
keytab (new kvno) with `ipa-getkeytab`, moves it into place, then restarts the
edge. Old cached service tickets stop working after the restart; clients must
re-run `pi-krb login` (or wait for the old service ticket to expire) to obtain
a ticket under the new key. Verify:

```sh
docker compose exec radiance-edge stat -c '%a %U:%G %n' /run/radiance/radiance.keytab
# 400 www-data /run/radiance/radiance.keytab
```

## 6. Diagnose

| Symptom | Check | Cause |
|---|---|---|
| `Cannot contact any KDC` | `nc -vz ipa.ipa.test 88`; `KRB5_CONFIG`; `/etc/hosts` for host mode | network/realm |
| 401 despite a ticket | `klist`; `kvno HTTP/radiance.ipa.test`; edge log | wrong SPN, expired ticket, keytab owner/mode |
| 403 as `pi` | `ipa group-show ai-users --all`; `LDAPCacheTTL` | not in `ai-users`; stale LDAP cache (≤60 s) |
| `Server not found in Kerberos DB` | `ipa service-show HTTP/...` | missing/case-mismatched SPN |
| TLS error in the shim | `openssl s_client -connect radiance.ipa.test:8443 -CAfile run/ipa-data/certs/ca.crt` | CA/SAN/hostname |
| 403 on a valid API path | allowlist regex; `make edge-check` | path not allowed (by design) |
| `pi-client` cannot reach IPA/edge | expected | it is on `shim-net` only |
| Shim 401 "credentials expired" | `pi-krb status` in `pi-login`; re-login | missing/expired ccache |
| 413/504 | body limit, prefill time, `ProxyTimeout` | oversized prompt or long stream |
| OOM in radiance | boot `kv:` line; `--debug-placement` | context/KV beyond the card |
| Edge unhealthy after bootstrap | `docker compose logs radiance-edge`; keytab/cert modes | marker/cert/keytab missing or unreadable |

## 7. Tests

```sh
make unit                       # host, fast
make config                     # compose lint
make edge-check                 # apachectl -t on the rendered vhost
make up && make test-fast       # integration + security (mock engine)
make test-host                  # container/mount/secret inspections
RUN_SLOW=1 pytest tests/host/test_advanced.py      # T4b revocation, T10 expiry (~3.5 min)
RUN_DESTRUCTIVE=1 pytest tests/host/test_destructive.py  # T5 wrong keytab, T16 rotation
RUN_E2E=1 pytest tests/host/test_e2e.py            # Pi login + tool loop + JSON mode
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
make clean              # removes run/, secrets/, work/ and caches — destructive
```

`run/ipa-data` holds the realm state and must be backed up if the realm matters.
Deleting it loses the KDC, CA and LDAP database.
