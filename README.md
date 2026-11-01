# FreeIPA + radiance + Pi

A Docker Compose development/test stack in which **FreeIPA is the Kerberos
identity provider**, **radiance serves the model**, and the **Pi harness** drives
it across many turns. radiance is reachable only by Kerberos-authenticated
members of the `ai-users` group; the agent container never holds a ticket,
keytab, certificate, or IPA secret.

This repository implements P0–P5 of [PLAN.md](PLAN.md); the optional native
GSSAPI work in radiance (P6) is deliberately deferred. The research behind the
design is in [RESEARCH.md](RESEARCH.md).

```
Pi (pi-client) ──bearer──▶ radiance-shim ──TLS 1.3 + Negotiate──▶ edge ──key──▶ radiance
   no ccache                 ccache + GSSAPI                    mod_auth_gssapi    127.0.0.1:8000
                                                                      │ LDAPS
                                                                      ▼
                                                                    FreeIPA
```

## What works

| Piece | Implementation |
|---|---|
| Identity | FreeIPA 4.13.4: realm `IPA.TEST`, users `pi`/`mallory`, groups `ai-users`/`ai-ops`, system account `svc-radiance`, service `HTTP/radiance.ipa.test` |
| AuthN | Apache 2.4 + `mod_auth_gssapi`, per-request SPNEGO, TLS 1.3 only, IPA-issued certificate |
| AuthZ | Live LDAPS check of `cn=ai-users` via `RequireAll` (authentication **and** group) |
| Engine | radiance 1.15.1 on loopback in the edge's network namespace; private API key; required seccomp profile |
| Pi | Pinned Pi 1.4.0, `pi-krb login/status/run`, `models.json` rendered per session |
| Credential agent | `radiance-krb-shim` exchanges Pi's bearer token for a fresh Negotiate token per request |
| Tests | 107 unit tests, 35 integration/security tests, host inspection tests, plus opt-in slow (`T4b`, `T10`) and destructive (`T5`, `T16`) and Pi E2E suites |

## Quick start

Requirements: Docker with Compose v2, `openssl`, Python 3.10+. For the `gpu`
profile: an AMD GPU supported by radiance and a `.rad` model container.

```sh
cp .env.example .env        # review UIDs/GIDs, RADIANCE_MODELS, BIND_ADDR
./scripts/up.sh             # IPA + edge + mock-radiance + shim (no GPU needed)

docker compose --profile client run --rm pi-login pi-krb login
docker compose --profile client run --rm pi-login pi-krb status
docker compose --profile client run --rm pi-client pi-krb run --model radiance-krb/qwen3.8-27b
```

For a real model:

```sh
./scripts/up.sh --gpu
```

The first FreeIPA install takes 10–15 minutes. The default bind address is
`127.0.0.1`; set `BIND_ADDR=0.0.0.0` only behind a firewall. Host-mode Pi needs
`127.0.0.1 ipa.ipa.test radiance.ipa.test` in `/etc/hosts`; see
[docs/RUNBOOK.md](docs/RUNBOOK.md).

## Testing

```sh
make unit        # no Docker, no GPU
make config      # docker compose config against .env.example
make edge-check  # build the edge image, render the vhost, apachectl -t
make up          # stack with the mock engine
make test-fast   # integration + security tests inside the test-runner
make test-host   # container/mount/secret inspections on the host
```

Integration tests need a running stack; the suite skips cleanly otherwise.
`tests/host` and a few destructive scenarios are opt-in (see
[docs/RUNBOOK.md](docs/RUNBOOK.md)).

## Security posture

- Edge: TLS 1.3 only, HSTS, exact-path allowlist (`/v1/models`,
  `/v1/chat/completions`, `/v1/completions`), everything else denied.
- Keytab `0400 www-data`; the edge copies it from a read-only mount at start.
- `pi-client` mounts only `work/` and its own agent directory, has no ccache,
  no certs, no IPA data, `cap_drop: ALL`, read-only rootfs, and only the
  internal `shim-net`.
- Shim token is 0600, re-read per request, and never logged.
- Long-lived secrets are bind-mounted files with explicit modes, not Compose
  secrets; Compose secrets are used only by the ephemeral bootstrap and the
  test runner.
- Residual risks, including the loopback trust boundary and LDAP cache
  staleness, are recorded in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Repository layout

```
compose.yaml               # the stack
deploy/ipa                 # install options + idempotent bootstrap
deploy/edge                # Apache image, vhost template, renderer
deploy/pi                  # Pi image, pi-krb, GSSAPI shim, token helper
deploy/radiance            # entrypoint + upstream seccomp profile
scripts/                   # up/down, cert, krb5, install options, rotation
tests/{unit,integration,security,host,mock}
docs/                      # runbook, threat model, capacity, deviations
```

## Capacity (200k context)

PLAN §8 makes 200k on one 32 GB R9700 a **measured gate**, not an assumption.
The documented 2-card measurement gives a 518,800-token `fp8` pool; the
single-card value must be measured with the E0 procedure in
[docs/CAPACITY.md](docs/CAPACITY.md). Do not advertise a context window you
have not measured: `pi-krb run --context-window N` and
`RADIANCE_CONTEXT_WINDOW` control the value written to `models.json`.

## Licensing

The root license is the GPLv3 text committed in this repository. Upstream
components keep their own licenses: FreeIPA is GPL-3.0-or-later, radiance is
Apache-2.0 (its seccomp profile is included with attribution in
`deploy/radiance/README.md`), and Pi is MIT. Model weights are licensed by
their upstream projects; see RESEARCH §8 before serving them to others.

## Known limitations

See [docs/DEVIATIONS.md](docs/DEVIATIONS.md) for every deliberate difference
from PLAN.md, including the explicit `RequireAll` authorization fix, the Pi
version pin, and the deferred P6 native-GSSAPI work.
