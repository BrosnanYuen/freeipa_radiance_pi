# FreeIPA + radiance + Pi

A Docker Compose development/test stack in which **FreeIPA is the Kerberos
identity provider**, **radiance serves the model**, and the **Pi harness** drives
it across many turns. radiance is reachable only by Kerberos-authenticated
members of the `ai-users` group; the agent container never holds a ticket,
keytab, certificate, or IPA secret.

This repository implements P0–P5 of [PLAN.md](PLAN.md), including the measured
200k single-card result (197,952-token admission, `M = 1.0`) and the real-model
GPU/T11b runs. **radiance is unmodified**; a new `radiance-gateway` terminates
TLS, validates Kerberos with FreeIPA, checks the `ai-users` group, and is the
only path to the engine. The research behind the design is in
[RESEARCH.md](RESEARCH.md).

```
Pi (pi-client) ──bearer──▶ radiance-shim ──TLS 1.3 + Negotiate──▶ radiance-gateway ──key──▶ radiance
   no ccache                 ccache + GSSAPI                    Python GSSAPI proxy      127.0.0.1:8000
                                                                      │ LDAPS
                                                                      ▼
                                                                    FreeIPA
```

## What works

| Piece | Implementation |
|---|---|
| Identity | FreeIPA 4.13.4: realm `IPA.TEST`, users `pi`/`mallory`, groups `ai-users`/`ai-ops`, system account `svc-radiance`, service `HTTP/radiance.ipa.test` |
| AuthN | `radiance-gateway`, Python GSSAPI acceptor, per-request SPNEGO, TLS 1.3 only, IPA-issued certificate; see [docs/GATEWAY.md](docs/GATEWAY.md) |
| AuthZ | Live LDAPS check of `cn=ai-users` (authentication **and** group) |
| Engine | radiance 1.15.1 on loopback in the gateway's network namespace; private API key; required seccomp profile; MXFP4 model served on the R9700 |
| Pi | Pinned Pi 1.4.0, `pi-krb login/status/run`, `models.json` rendered per session |
| Credential agent | `radiance-krb-shim` exchanges Pi's bearer token for a fresh Negotiate token per request |
| Tests | 127 unit tests, 38 integration/security tests, host inspection tests, plus opt-in slow (`T4b`, `T10`), destructive (`T5`, `T16`, credential/certificate rotation), host-mode Pi and Pi E2E suites |
| Lifecycle | Verified rotation scripts for admin, Directory Manager, LDAP bind, engine API key, keytab and TLS key/certificate, with rollback and a weekly keytab timer |
| Gates | Model-licence manifest checked before GPU start; measured-context gate (`CAPACITY_MEASURED`) blocks the unmeasured 200k default |

## Quick start

Requirements: Docker with Compose v2, `openssl`, Python 3.10+. For the `gpu`
profile: an AMD GPU supported by radiance and a `.rad` model container.

```sh
cp .env.example .env        # review UIDs/GIDs, RADIANCE_MODELS, BIND_ADDR
./scripts/up.sh             # IPA + gateway + mock-radiance + shim (no GPU needed)

docker compose --profile client run --rm pi-login pi-krb login
docker compose --profile client run --rm pi-login pi-krb status
docker compose --profile client run --rm pi-client pi-krb run --model radiance-krb/qwen3.8-27b
make smoke                  # engine lists and serves the model
```

For a real model (licence manifest and E0 measurement required):

```sh
./scripts/up.sh --gpu
```

The first FreeIPA install takes 10–15 minutes. The default bind address is
`127.0.0.1`; set `BIND_ADDR=0.0.0.0` only behind a firewall. The tested
host-mode path (`make host-pi`: pinned Pi via `npx` + a loopback-published shim)
needs no `/etc/hosts` changes; a fully host-installed shim does. See
[docs/RUNBOOK.md](docs/RUNBOOK.md).

## Testing

```sh
make unit        # no Docker, no GPU
make config      # docker compose config against .env.example
make gateway-check  # build the gateway image and run its module check
make up          # stack with the mock engine
make smoke       # engine lists and serves the model
make test-fast   # integration + security tests inside the test-runner
make test-host   # container/mount/secret inspections on the host
make test-rotation  # destructive rotation checks (RUN_DESTRUCTIVE=1)
make host-pi     # 10-turn host-mode Pi session through a loopback shim
make license-check  # fail if a .rad container has no licence decision
make backup-ipa  # online data backup into run/backups
```

Integration tests need a running stack; the suite skips cleanly otherwise.
`tests/host` and a few destructive scenarios are opt-in (see
[docs/RUNBOOK.md](docs/RUNBOOK.md)).

## Security posture

- Gateway: TLS 1.3 only, HSTS, exact-path allowlist (`/v1/models`,
  `/v1/chat/completions`, `/v1/completions`), everything else denied.
- Keytab `0400 gateway:gateway` under `/run/gateway`; the gateway copies it from a read-only mount at start.
- `pi-client` mounts only `work/` and its own agent directory, has no ccache,
  no certs, no IPA data, `cap_drop: ALL`, read-only rootfs, and only the
  internal `shim-net`.
- Shim token is 0600, re-read per request, and never logged.
- Long-lived secrets are bind-mounted files with explicit modes, not Compose
  secrets; Compose secrets are used only by the ephemeral bootstrap and the
  test runner. The inventory, owners and last-rotation dates are in
  [docs/SECRETS.md](docs/SECRETS.md).
- Every long-lived credential has a rotation script that verifies the new value
  before writing it and recreates the gateway; the LDAP bind and API-key paths
  roll back. A weekly systemd timer rotates the keytab.
- Residual risks, including the loopback trust boundary, LDAP cache staleness
  and the Pi image's transitive-dependency CVEs, are recorded in
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Repository layout

```
compose.yaml               # the stack
deploy/ipa                 # install options + idempotent bootstrap
deploy/gateway             # Python GSSAPI/TLS reverse proxy
deploy/pi                  # Pi image, pi-krb, GSSAPI shim, token helper
deploy/radiance            # entrypoint + upstream seccomp profile
deploy/systemd             # weekly keytab-rotation timer
scripts/                   # up/down, cert, krb5, rotation, backup, smoke
tests/{unit,integration,security,host,mock}
docs/                      # runbook, secrets, licences, threat model, capacity, deviations
```

## Capacity (200k context)

PLAN §8 made 200k on one 32 GB R9700 a **measured gate**; it is now measured.
E0 admitted **197,952 tokens** with `M = 1.0`, cold TTFT 145.4 s (1,361.8 tok/s
prefill), 23.8 tok/s decode and 20.58 GiB peak VRAM. The record is in
[docs/CAPACITY.md](docs/CAPACITY.md) and
[docs/measurements/E0-2026-11-01.md](docs/measurements/E0-2026-11-01.md).
`RADIANCE_CONTEXT_WINDOW=200000` and `CAPACITY_MEASURED=1` are set; the example
file still ships the conservative 32,768 / 0 defaults.

## Licensing

The root license is the GPLv3 text committed in this repository. Upstream
components keep their own licenses: FreeIPA is GPL-3.0-or-later, radiance is
Apache-2.0 (its seccomp profile is included with attribution in
`deploy/radiance/README.md`), and Pi is MIT. Model weights are licensed by
their upstream projects; see RESEARCH §8 before serving them to others.

## Known limitations

See [docs/DEVIATIONS.md](docs/DEVIATIONS.md) for every deliberate difference
from PLAN.md, including the gateway authorization design, the Pi
version pin, and the capacity/rotation gates. Model-weight licensing is in [docs/MODEL-LICENSES.md](docs/MODEL-LICENSES.md).
