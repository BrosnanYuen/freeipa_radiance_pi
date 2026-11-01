# PLAN: Kerberos-authenticated radiance for the Pi harness

**Version:** 3 — security and correctness fixes (see [§17](#17-revision-notes-v3-security-and-correctness-fixes))
**Status:** Implemented (P0–P5); P6 (native GSSAPI) deferred — see [docs/DEVIATIONS.md](docs/DEVIATIONS.md)
**Date:** 2026-10-31
**Scope:** Docker Compose development/test stack; production topology notes included
**Target model:** `qwen3.8-27b-mxfp4.rad`, 200k context, one local AMD Radeon AI PRO R9700 (32 GB)
**Companion:** [RESEARCH.md](RESEARCH.md)

---

## Contents

1. [Goal and requirement traceability](#1-goal-and-requirement-traceability)
2. [Architecture decisions](#2-architecture-decisions)
3. [Architecture](#3-architecture)
4. [Identity and Kerberos design](#4-identity-and-kerberos-design)
5. [Docker Compose deployment](#5-docker-compose-deployment)
6. [Configuration](#6-configuration)
7. [Security design](#7-security-design)
8. [Capacity: 200k context on one R9700](#8-capacity-200k-context-on-one-r9700)
9. [Test strategy](#9-test-strategy)
10. [Implementation phases](#10-implementation-phases)
11. [Operations runbook](#11-operations-runbook)
12. [Acceptance checklist](#12-acceptance-checklist)
13. [Open questions](#13-open-questions)
14. [Risks](#14-risks)
15. [References](#15-references)
16. [Revision notes: what upstream verification changed](#16-revision-notes-what-upstream-verification-changed)
17. [Revision notes: v3 security and correctness fixes](#17-revision-notes-v3-security-and-correctness-fixes)

---

## 1. Goal and requirement traceability

Build a Docker Compose stack in which **FreeIPA is the Kerberos identity provider**, **radiance is reachable only by Kerberos-authenticated users**, and **the Pi harness drives radiance across many turns**. The five user steps are the contract:

| # | Requirement | Implementation | Acceptance |
|---|---|---|---|
| 1 | User gives Kerberos credentials to the Pi harness | `pi-krb login` in the one-off `pi-login` container runs `kinit`; ccache is 0600 and is mounted only into `pi-login` and `radiance-shim` | T1, T10, T25 |
| 2 | Pi authenticates with FreeIPA using Kerberos | The `radiance-shim` container uses the user's TGT to obtain or reuse a service ticket and sends a fresh authenticator per request; the agent container never sees the ccache | T2, T5, T10, T25 |
| 3 | Pi gives Kerberos credentials to radiance | HTTP `Authorization: Negotiate` (SPNEGO) per request; only a service ticket, never the TGT | T2, T8, T19 |
| 4 | radiance authenticates with FreeIPA using Kerberos | Kerberos edge validates the ticket with the IPA-issued keytab; authorizes against IPA LDAP | T2, T3, T4, T6 |
| 5 | radiance responds to Pi across many turns | Streaming SSE, stateless per-request auth, ticket refresh | T7, T8, T9, T10, T11 |

### Non-goals

- OAuth/OIDC, social login, browser SSO for end users. Kerberos is the protocol.
- Multi-tenant quotas, billing, per-user model isolation (candidates for a later gateway).
- Model conversion, quantisation, or licence compliance for the weights.
- A production FreeIPA deployment; Compose is for development and CI. Production guidance is noted but not automated.

### Definition of done

`./scripts/up.sh` brings up the stack (including `radiance-shim`); `pi-krb login` (run in `pi-login`) then `pi-krb run` (run in `pi-client`) opens a 10-turn, tool-using conversation against `qwen3.8-27b-mxfp4.rad`; every model request is TLS 1.3 + Kerberos authenticated, authorized against `ai-users`, and logged with the full principal; the agent container holds neither the ccache nor any IPA secret; unit, integration, security, and nightly GPU tests pass; 200k context is measured and honestly advertised.

---

## 2. Architecture decisions

ALL CODE AND CONFIG MUST BE ONLY IN THIS DIRECTORY. DO NOT MODIFY OTHER DIRECTORIES.
MUST HAVE INTEGRATION AND UNIT TESTING.
### 2.1 The hard constraint

radiance 1.15.1 has **no GSSAPI/Kerberos support**. Its documented auth model is: an optional single `--api-key` (or `--api-key-env`), or keyless loopback-only routes with Origin/Host checks. There is no auth plugin point. Something must validate Kerberos in front of, or inside, the engine.

### 2.2 Options

| Option | Description | Security | Effort | Verdict |
|---|---|---|---|---|
| **A. Kerberos edge** | Apache httpd + `mod_auth_gssapi` terminates TLS 1.3, validates SPNEGO with the radiance keytab, authorizes via IPA LDAP, proxies over loopback | Strong, mature GSSAPI; auditable; no fork | 3–4 days | **MVP** |
| **B. Native radiance GSSAPI** | Add `core/server/auth_gssapi.cpp`, flags, principal mapping, tests; upstream | Strong in-process; removes the loopback trust boundary | 2–3 weeks + review | Phase 6, optional |
| **C. Custom gateway** | Go/Rust reverse proxy with `gokrb5`, per-user quotas, metrics | Strong if fuzzed/tested; full control | 1–2 weeks | Fallback if Apache authz/limits fall short |

### 2.3 Decision record

- **D1 (MVP): Kerberos enforcement lives in the radiance edge**, deployed as part of the radiance service unit. The edge holds the FreeIPA-issued keytab for `HTTP/radiance.ipa.test@IPA.TEST`, so the *service* holds credentials from the realm and decrypts tickets minted by its KDC. The engine binds `127.0.0.1` inside the edge's network namespace and requires a private API key from the edge.
  - **Consequence to approve:** radiance's process does not parse Negotiate; the radiance *service* does. If "the radiance binary must validate tickets" is literal, approve Phase 6 early.
- **D2: Authorization is a live IPA LDAP group check** (`cn=ai-users,cn=groups,cn=accounts,dc=ipa,dc=test`) over LDAPS, using a dedicated system account. A generated allowlist is fallback only.
- **D3: Per-request Negotiate, no session cookies.** `GssapiUseSessions Off`; every request re-authenticates. Ticket lifetime and replay cache bound exposure.
- **D4: Pi integration uses a separate SPNEGO shim container** (`radiance-shim`, same `deploy/pi` image) on an internal-only `shim-net` as the primary path. Only `pi-login` and the shim mount the ccache; the `pi-client` agent container mounts neither the ccache nor the IPA CA. Reason: Pi's OpenAI client receives `apiKey` and the OpenAI SDK emits `Authorization: Bearer <apiKey>`; a custom `models.json` `Authorization` header risks being overwritten. The shim also keeps Kerberos native code and the TGT out of the agent container. A direct-header mode is a spike (S1), not the baseline.
- **D5: Compose runs FreeIPA without integrated DNS**, with explicit `krb5.conf` KDC entries and Compose network aliases. Production uses DNS + SRV.
- **D6: TLS certificates come from the FreeIPA Dogtag CA** for `radiance.ipa.test`; the IPA CA is distributed to clients as the only trust anchor.
- **D7: 200k on one R9700 is a measured gate**, not an assumption. The hybrid model makes it plausible; the fallback ladder is fixed in [§8](#8-capacity-200k-context-on-one-r9700).
- **D8: The edge exposes an endpoint allowlist, not the whole API**: only `/v1/models` and `/v1/chat/completions` (plus `/v1/completions` if needed). Admin/LoRA/model-loading and media endpoints are denied even to authenticated users.

### 2.4 What "radiance authenticates" means

```
User ──TGT──▶ shim/helper ──service ticket──▶ edge ──validates with keytab──▶ radiance
                                             └── LDAPS group check ──▶ FreeIPA
```

Validation is local: the edge decrypts the service ticket with the keytab, verifies the authenticator and replay cache, maps the principal, and queries IPA LDAP for authorization. No KDC call per request. The KDC's authority is delegated cryptographically through the keytab. This is exactly how `mod_auth_gssapi` services work.

---

## 3. Architecture

### 3.1 Components

| Component | Image / build | Responsibility | Exposed |
|---|---|---|---|
| `ipa` | `quay.io/freeipa/freeipa-server:<os>-<ver>` (digest-pinned) | KDC, LDAP, CA, policy, groups | 88/464 to clients; 636 internal |
| `radiance-edge` | `deploy/edge` (httpd + `mod_auth_gssapi`) | TLS 1.3, SPNEGO, LDAP authz, allowlist, audit, proxy | 8443 (TLS) |
| `radiance` | `stilldeadcode/radiance` (digest-pinned) | Inference; loopback only | None |
| `radiance-shim` | `deploy/pi` (Python + `gssapi`) | Credential agent: holds the ccache, does Negotiate to the edge, exposes an OpenAI-compatible surface to Pi | 8088 on `shim-net` only |
| `pi-login` | `deploy/pi` | One-off `kinit`/`klist` container; one of only two ccache holders | None |
| `pi-client` | `deploy/pi` (Node ≥22.19 + pinned Pi) | Agent session; mounts `work/` and its agent dir only | None (interactive) |
| `mock-radiance` | `tests/mock` (FastAPI) | OpenAI-compatible stub for fast tests | None (shares edge netns) |
| `test-runner` | `tests` image | Unit/integration/security tests | None |

`radiance` uses `network_mode: "service:radiance-edge"`: shared network namespace, shared loopback, no routable address, no published port. The edge proxies to `http://127.0.0.1:8000`.

`pi-client` is attached only to `shim-net` (an `internal: true` bridge); it cannot reach IPA, the edge, or the KDC directly. Only `radiance-shim` is on both `shim-net` and `krb-net`.

### 3.2 Trust boundaries

```
┌────────────────────────────── host ───────────────────────────────┐
│  user ── kinit ──▶ ccache (0600)                                  │
│                      │ mounted only in pi-login + radiance-shim   │
│  ┌───────────────────▼────────────────────┐                       │
│  │ pi-login (one-off): kinit/klist        │                       │
│  └────────────────────────────────────────┘                       │
│  ┌──────────────────────────┐   ┌──────────────────────────────┐  │
│  │ pi-client: Pi            │   │ radiance-shim                │  │
│  │ tools: bash/edit/write   │──▶│ ccache · Negotiate           │  │
│  │ no ccache, no certs,     │   │ shim token 0600              │  │
│  │ no IPA secrets           │   └──────────────┬───────────────┘  │
│  └──────────────────────────┘                  │ TLS 1.3 + Negotiate
│        shim-net (internal)                     │                  │
│  ══════════════════════════════════════════════╪═ krb-net ══════  │
│                                                ▼                  │
│  ┌──────────┐  LDAPS  ┌──────────────────────────────┐            │
│  │   ipa    │◀────────│ radiance-edge (Apache)       │            │
│  │ KDC/LDAP │  TGS    │ SPNEGO · authz · allowlist   │            │
│  │ CA       │◀────────│ keytab 0400 www-data         │            │
│  └──────────┘         └──────────────┬───────────────┘            │
│                                      │ shared netns, loopback,    │
│                                      │ internal API key           │
│                       ┌──────────────▼───────────────┐            │
│                       │ radiance 127.0.0.1:8000      │            │
│                       │ R9700 · qwen3.8-27b-mxfp4    │            │
│                       └──────────────────────────────┘            │
└────────────────────────────────────────────────────────────────────┘
```

Boundaries: user → pi-login/shim (same UID, ccache); Pi → shim (internal `shim-net` + bearer token); shim → edge (TLS + Kerberos); edge → IPA (LDAPS + KDC); edge → engine (kernel loopback + private key); engine → GPU (host devices). The agent container has no mount of `run/ccache`, `run/ipa-data`, `secrets/`, `certs/`, or the ccache; only `run/pi-agent` (state + bearer token) and `work/`.

### 3.3 Sequence

```
pi-login: kinit ── AS-REQ/AS-REP ──▶ IPA; TGT written to the shared ccache

Pi                  radiance-shim             Edge                      IPA
 │  HTTP + token ───▶│                        │                         │
 │                   │  TGS-REQ (HTTP/…) ─────┼────────────────────────▶│  (first request)
 │                   │  service ticket        │                         │
 │                   │  AP-REQ in Negotiate   │                         │
 │                   ├───────────────────────▶│  decrypt w/ keytab      │
 │                   │                        │  replay/clock checks    │
 │                   │                        │  LDAP group check ─────▶│
 │                   │                        │  allowlist → proxy      │
 │                   │◀──── SSE stream ───────┤◀──── radiance           │
 │  SSE ◀────────────│◀───────────────────────┤                         │
 │  next turn ──────▶│  new authenticator,    │                         │
 │                   │  cached service ticket │                         │
```

After the first TGS, requests do local GSSAPI work in the shim and local validation on the edge; **no KDC round trip**. The service ticket is cached until expiry; the TGT governs renewal.

---

## 4. Identity and Kerberos design

### 4.1 Objects

| Object | Value | Notes |
|---|---|---|
| Realm / domain | `IPA.TEST` / `ipa.test` | Dev; parameterised for production |
| IPA server | `ipa.ipa.test` | KDC, LDAP, CA |
| radiance FQDN | `radiance.ipa.test` | TLS SAN; SPN host |
| User | `pi@IPA.TEST` | Member of `ai-users` |
| Negative user | `mallory@IPA.TEST` | Valid ticket, not in `ai-users`; password in `secrets/mallory_password` |
| Group | `ai-users` | Authorized to call radiance |
| Service principal | `HTTP/radiance.ipa.test@IPA.TEST` | Only principal in the edge keytab |
| Keytab | `run/ipa-data/keytabs/radiance.keytab` | 0600 on host; 0400 `www-data` on tmpfs inside edge |
| TLS cert | `CN=radiance.ipa.test`, SAN DNS, EKU serverAuth | Profile `caIPAserviceCert` |
| LDAP bind | `uid=svc-radiance,cn=sysaccounts,cn=etc,dc=ipa,dc=test` | System account, no Kerberos principal, read-only |
| Admin | `admin@IPA.TEST` | Bootstrap only (ephemeral `bootstrap` container); rotated after |
| Directory Manager | `cn=Directory Manager` | Separate password from admin; installer only; rotated after bootstrap |

### 4.2 Ticket policy

- TGT 8h, renewable 7d (`ipa krbtpolicy-mod --maxlife=28800 --maxrenew=604800`; verified option names).
- `kinit -F` (non-forwardable), `-l 8h`, `-r 7d`; `forwardable = false`, `proxiable = false` in `krb5.conf`.
- **No delegation, no S4U2Self/S4U2Proxy, no unconstrained delegation.** The user's TGT never leaves the Pi machine; only `HTTP/radiance.ipa.test` service tickets are presented.
- AES only: `aes256-cts-hmac-sha1-96`, `aes128-cts-hmac-sha1-96`; add RFC 8009 (`aes256-cts-hmac-sha384-192`, `aes128-cts-hmac-sha256-128`) only if the pinned KDC and all clients support it. No RC4/DES/3DES.
- Clock skew 300s; host runs chrony; containers use host time.

### 4.3 Credential custody

| Secret | Location | Reader | Rotation |
|---|---|---|---|
| User password | User memory, `kinit` prompt | User | On demand |
| TGT + service tickets | `run/ccache/krb5cc`, 0600 | `pi-login` and `radiance-shim` only | `kdestroy`, logout |
| Service keytab | Host 0600 → edge tmpfs 0400 `www-data` | Apache worker | `ipa-getkeytab` new kvno, restart edge |
| Admin password | `secrets/ipa_admin_password`, 0600; ephemeral `bootstrap` container only | bootstrap (piped stdin) | After bootstrap |
| Directory Manager password | `secrets/ipa_dm_password`, 0600; installer options file | one-off installer | After bootstrap |
| LDAP bind password | `secrets/ldap_bind_password`, 0600 → rendered 0400 root | Apache master | Quarterly / incident |
| radiance API key | `secrets/radiance_api_key`, 0400 `${RADIANCE_UID}` → env → `--api-key-env` | edge, engine | Quarterly |
| TLS private key | `run/ipa-data/certs/radiance.key`, 0600 | Apache master | Rotation script |
| Shim token | `run/pi-agent/shim-token`, 0600, generated by the shim | shim and `pi-client` (bearer only) | On shim restart |

No keytab or ccache in the agent container (`pi-client`); the ccache is mounted only into `pi-login` and `radiance-shim`, and the keytab exists only in the edge. The one-off `bootstrap` container is the only place a bootstrap password is present; the installer's options file is shredded and both the admin and Directory Manager passwords are rotated after bootstrap. No secrets in images or logs.

---

## 5. Docker Compose deployment

### 5.1 Layout

```
.
├── PLAN.md · RESEARCH.md
├── compose.yaml
├── .env.example
├── .gitignore                    # run/, secrets/, work/
├── work/                         # Pi workspace (gitignored; no secrets)
├── deploy/
│   ├── ipa/                      # install options template, bootstrap.sh
│   ├── edge/                     # Dockerfile, entrypoint, vhost template, health
│   ├── pi/                       # Dockerfile, pi-krb, shim, token helper, models.json
│   └── radiance/                 # entrypoint, seccomp-radiance.json
├── scripts/
│   ├── up.sh · down.sh
│   ├── gen-cert.sh               # key + CSR on host
│   ├── bootstrap-ipa.sh          # docker compose run --rm bootstrap
│   └── rotate-keytab.sh
├── run/                          # gitignored runtime state
│   ├── ipa-data/                 # /data volume: config, keytabs, certs (incl. ca.crt)
│   │   └── certs/                # radiance.key/.csr/.crt (key 0600)
│   ├── krb5.conf                 # generated client config
│   ├── ccache/                   # krb5cc; mounted only into pi-login + radiance-shim
│   └── pi-agent/                 # models.json, session state, shim-token (0600)
├── secrets/                      # gitignored (0600)
└── tests/{unit,integration,security,mock}/
```

### 5.2 Networks and exposure

| Network | Members | Purpose |
|---|---|---|
| `krb-net` (bridge) | ipa, edge, pi-login, radiance-shim, test-runner | Kerberos, LDAPS, HTTPS |
| `shim-net` (bridge, `internal: true`) | radiance-shim, pi-client | Pi → shim only; no egress |
| edge netns | edge + radiance/mock (shared) | Loopback proxy |

| Published port | Service | Notes |
|---|---|---|
| 88/tcp, 88/udp | ipa | Bound to `${BIND_ADDR:-127.0.0.1}` |
| 464/tcp, 464/udp | ipa | Optional kpasswd; same bind |
| 8443/tcp | edge | The only radiance entry point; same bind |
| (443/tcp) | ipa | Optional Web UI; internal by default |

radiance publishes nothing. 636/389 stay internal to `krb-net`. The agent container (`pi-client`) is on `shim-net` only. For LAN access set `BIND_ADDR=0.0.0.0` and add firewall rules; the default is loopback.

### 5.3 Compose skeleton

```yaml
name: radiance-krb

networks:
  krb-net:
    driver: bridge
  shim-net:
    driver: bridge
    internal: true

secrets:
  ipa_admin_password: { file: ./secrets/ipa_admin_password }
  pi_password:        { file: ./secrets/pi_password }
  mallory_password:   { file: ./secrets/mallory_password }
  ldap_bind_password: { file: ./secrets/ldap_bind_password }

services:
  ipa:
    image: ${FREEIPA_IMAGE:?pin a digest}      # quay.io/freeipa/freeipa-server:<os>-<ver>
    hostname: ipa.ipa.test
    read_only: true
    restart: unless-stopped
    # Do NOT set init: true — systemd must be PID 1. The image sets STOPSIGNAL RTMIN+3.
    volumes:
      - ./run/ipa-data:/data:Z
      - ./deploy/ipa:/bootstrap:ro
    ports:
      - "${BIND_ADDR:-127.0.0.1}:88:88/tcp"
      - "${BIND_ADDR:-127.0.0.1}:88:88/udp"
      - "${BIND_ADDR:-127.0.0.1}:464:464/tcp"
      - "${BIND_ADDR:-127.0.0.1}:464:464/udp"
    networks:
      krb-net:
        aliases: [ipa.ipa.test]
    healthcheck:
      test: ["CMD-SHELL", "ipactl status >/dev/null 2>&1"]
      interval: 15s
      timeout: 10s
      retries: 80
      start_period: 15m

  # One-off bootstrap: mounts the secrets, runs in the IPA network namespace,
  # writes /data, then exits. The long-lived IPA service never receives the
  # bootstrap secrets.
  bootstrap:
    image: ${FREEIPA_IMAGE:?pin a digest}
    profiles: ["bootstrap"]
    network_mode: "service:ipa"
    depends_on:
      ipa: { condition: service_healthy }
    read_only: true
    volumes:
      - ./run/ipa-data:/data
      - ./deploy/ipa:/bootstrap:ro
      - ./run/krb5.conf:/etc/krb5.conf:ro
    secrets: [ipa_admin_password, pi_password, mallory_password, ldap_bind_password]
    entrypoint: ["/bin/bash", "/bootstrap/bootstrap.sh"]
    environment:
      HOME: /tmp
    cap_drop: [ALL]
    cap_add: [DAC_OVERRIDE, CHOWN, FOWNER]
    security_opt: ["no-new-privileges:true"]
    tmpfs: [/tmp, /run]

  radiance-edge:
    build: deploy/edge
    hostname: radiance.ipa.test
    depends_on:
      ipa: { condition: service_healthy }
    ports:
      - "${BIND_ADDR:-127.0.0.1}:8443:8443"
    volumes:
      - ./run/ipa-data/keytabs:/keytabs:ro
      - ./run/ipa-data/certs:/certs:ro
      - ./run/krb5.conf:/etc/krb5.conf:ro
      - ./secrets/ldap_bind_password:/secrets-src/ldap_bind_password:ro
      - ./secrets/radiance_api_key:/secrets-src/radiance_api_key:ro
    networks:
      krb-net:
        aliases: [radiance.ipa.test]
    cap_drop: [ALL]
    cap_add: [CHOWN, SETGID, SETUID, DAC_OVERRIDE]   # copy/chown keytab to www-data; TLS key read at startup
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: [/run, /tmp]
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:8081/healthz"]
      interval: 10s
      timeout: 3s
      retries: 120
      start_period: 10m

  radiance:
    image: ${RADIANCE_IMAGE:?pin a digest}
    profiles: ["gpu"]
    network_mode: "service:radiance-edge"
    depends_on:
      radiance-edge: { condition: service_healthy }
    init: true
    user: "${RADIANCE_UID:?}:${RADIANCE_GID:?}"
    devices: ["/dev/kfd:/dev/kfd", "/dev/dri:/dev/dri"]
    group_add: ["${RENDER_GID:?}", "${VIDEO_GID:?}"]
    volumes:
      - ${RADIANCE_MODELS:?}:/models:ro
      - ./deploy/radiance/entrypoint.sh:/entrypoint.sh:ro
      - ./secrets/radiance_api_key:/secrets-src/radiance_api_key:ro
    entrypoint: ["/bin/sh", "/entrypoint.sh"]
    security_opt:
      - no-new-privileges:true
      - seccomp=${RADIANCE_SECCOMP:?set RADIANCE_SECCOMP to the verified profile}
    cap_drop: [ALL]
    ulimits: { memlock: -1 }
    read_only: true
    tmpfs: [/tmp]
    command:
      - --model
      - /models/qwen3.8-27b-mxfp4.rad
      - --host
      - 127.0.0.1
      - --port
      - "8000"
      - --api-key-env
      - RADIANCE_API_KEY
      - --served-model-name
      - qwen3.8-27b
      - --tp
      - "1"
      - --max-model-len
      - "200000"
      - --kv-cache-dtype
      - fp8
      - --max-num-seqs
      - "1"
      - --max-num-batched-tokens
      - "2048"
      - --num-speculative-tokens
      - "0"
      - --mm-max-patches
      - "0"
      - --no-cors

  mock-radiance:
    build: tests/mock
    profiles: ["test-fast"]
    network_mode: "service:radiance-edge"
    depends_on:
      radiance-edge: { condition: service_healthy }
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]

  # One-off kinit/klist container. It is the only service besides the shim
  # that mounts the ccache; the agent container does not.
  pi-login:
    build: deploy/pi
    profiles: ["client"]
    user: "${PI_UID:-1000}:${PI_GID:-1000}"
    depends_on:
      ipa: { condition: service_healthy }
    volumes:
      - ./run/ccache:/creds
      - ./run/krb5.conf:/etc/krb5.conf:ro
    environment:
      KRB5CCNAME: FILE:/creds/krb5cc
      KRB5_CONFIG: /etc/krb5.conf
    networks: [krb-net]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: [/tmp]
    stdin_open: true
    tty: true
    command: ["sleep", "infinity"]

  # Credential agent. Holds the ccache; the agent container holds only the
  # bearer token that this service issues.
  radiance-shim:
    build: deploy/pi
    profiles: ["client"]
    user: "${PI_UID:-1000}:${PI_GID:-1000}"
    depends_on:
      radiance-edge: { condition: service_healthy }
    volumes:
      - ./run/ccache:/creds
      - ./run/pi-agent:/agent
      - ./run/krb5.conf:/etc/krb5.conf:ro
      - ./run/ipa-data/certs/ca.crt:/certs/ca.crt:ro
    environment:
      KRB5CCNAME: FILE:/creds/krb5cc
      KRB5_CONFIG: /etc/krb5.conf
    networks: [krb-net, shim-net]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: [/tmp]
    command:
      - radiance-krb-shim
      - --listen
      - 0.0.0.0:8088
      - --edge
      - https://radiance.ipa.test:8443
      - --service
      - HTTP/radiance.ipa.test
      - --ca
      - /certs/ca.crt
      - --token-file
      - /agent/shim-token
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:8088/healthz"]
      interval: 10s
      timeout: 3s
      retries: 30
      start_period: 1m

  # The agent. No ccache, no certs, no secrets, no IPA data; only work/ and
  # its own agent directory. It can reach only the shim.
  pi-client:
    build: deploy/pi
    profiles: ["client"]
    user: "${PI_UID:-1000}:${PI_GID:-1000}"
    depends_on:
      radiance-shim: { condition: service_healthy }
    volumes:
      - ./work:/work
      - ./run/pi-agent:/agent
    environment:
      PI_CODING_AGENT_DIR: /agent
      HOME: /tmp
    working_dir: /work
    networks: [shim-net]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: [/tmp]
    stdin_open: true
    tty: true
    command: ["sleep", "infinity"]

  test-runner:
    build: tests
    profiles: ["test"]
    depends_on:
      ipa: { condition: service_healthy }
      radiance-edge: { condition: service_healthy }
    working_dir: /tests
    environment:
      EDGE_URL: https://radiance.ipa.test:8443
      KRB5_CONFIG: /etc/krb5.conf
      KRB5CCNAME: FILE:/creds/krb5cc
      REQUESTS_CA_BUNDLE: /certs/ca.crt
      SSL_CERT_FILE: /certs/ca.crt
    volumes:
      - ./tests:/tests:ro
      - ./compose.yaml:/compose.yaml:ro
      - ./.env.example:/.env.example:ro
      - ./scripts:/scripts:ro
      - ./run/ccache:/creds
      - ./run/krb5.conf:/etc/krb5.conf:ro
      - ./run/ipa-data/certs/ca.crt:/certs/ca.crt:ro
    secrets: [pi_password, mallory_password, ipa_admin_password]
    networks: [krb-net]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
```

Notes and constraints:

- **IPA bootstrap is a one-off container, not a long-lived service.** The image runs `ipa-server-install` itself on first start from `/data/ipa-server-install-options`; `scripts/bootstrap-ipa.sh` runs the `bootstrap` service with `docker compose --profile bootstrap run --rm bootstrap`. It shares the IPA network namespace, mounts `/data` and the bootstrap secrets, writes the service keytab, TLS cert, and CA copy, then exits. The long-lived `ipa` service never mounts those secrets.
- The IPA container needs systemd; `privileged` is explicitly unsupported upstream. If the Docker daemon is rootless or cgroup delegation fails, use an override with `cgroupns: host`, `cgroup: host`, and `/sys/fs/cgroup:/sys/fs/cgroup:rw` as the upstream README requires.
- `read_only: true` works with the image's declared `VOLUME /tmp /run /data`; `/data` is the bind mount.
- Keytabs/certs are host files, not Compose secrets: Compose secrets are 0444 by default, which is wrong for a keytab. The edge and engine therefore read their long-lived secrets from bind-mounted files (`/secrets-src/...`), and `up.sh` sets modes/ownership. Compose secrets are used only by the ephemeral bootstrap and the test runner.
- The radiance entrypoint reads `/secrets-src/radiance_api_key`, exports `RADIANCE_API_KEY`, and execs `radiance "$@"`; `--api-key-env` then reads it without argv exposure. The flags live only in the compose `command:` — do not duplicate them in the entrypoint.
- `read_only: true` on the engine is stricter than the upstream compose files. If the pinned image needs a writable cache/home, add a tmpfs for that path and record the deviation rather than dropping read-only.
- The edge keeps `DAC_OVERRIDE` only so the root entrypoint can read a host-owned 0600 TLS key and keytab before copying/chowning them to `www-data`; the **keytab must end at 0400 owned by `www-data`**, because mod_auth_gssapi opens it per request in the worker. The TLS key can remain `root:root` 0600 (mod_ssl reads it at startup).
- The edge entrypoint waits for `/certs/.bootstrap-complete`, `/certs/radiance.crt`, and `/keytabs/radiance.keytab` before rendering the vhost. The marker is written into `/data/certs/` by the bootstrap so the edge can see it through its existing `/certs` mount.
- The edge's health endpoint must not depend on the engine (otherwise `depends_on` is circular). It reports config/keytab/cert readiness; tests poll `/v1/models` for engine readiness.
- The engine's `seccomp` profile is **required** (`RADIANCE_SECCOMP` has no weak default); Docker's default profile blocks `io_uring` and NUMA calls, so ship the verified profile in `deploy/radiance/seccomp-radiance.json` and set `RADIANCE_SECCOMP` in `.env`. `cap_drop: [ALL]` is set on the engine, the mock, the shim, the login container, the agent, and the test runner.
- `--mm-max-patches 0` serves text only and keeps the vision tower off the card. Re-enable only after measuring VRAM.
- `--num-speculative-tokens 0` removes drafter work; verify whether the merged drafter's weights are still resident and, if so, treat the flag as latency-only, not a VRAM saving.
- `pi-client` has **no** mounts of `run/ccache`, `run/ipa-data`, `secrets/`, or `certs/`, and no ccache; it mounts only `work/` and `run/pi-agent` (agent state + bearer token). It is on `shim-net` only.
- `pi-login` and `radiance-shim` run as `${PI_UID}:${PI_GID}`; `up.sh` chowns `run/ccache`, `run/pi-agent`, and `work/` to that UID/GID. The shim creates `run/pi-agent/shim-token` (0600) at startup and re-reads it per request.
- The `gpu` and `test-fast` profiles are **mutually exclusive**: both bind `127.0.0.1:8000` in the edge's network namespace. Never enable both.
- `BIND_ADDR` defaults to `127.0.0.1`; set `BIND_ADDR=0.0.0.0` only behind a firewall.

### 5.4 Bring-up sequence

1. `scripts/up.sh` creates `run/`, `secrets/`, and `work/` (0700), generates random secrets if missing (`ipa_admin_password`, `ipa_dm_password`, `pi_password`, `mallory_password`, `ldap_bind_password`, `radiance_api_key`), writes `run/krb5.conf` (from the template, with the dev realm/KDC), creates `run/ipa-data/{certs,keytabs}`, chowns `run/ccache`, `run/pi-agent`, and `work/` to `${PI_UID}:${PI_GID}`, sets `secrets/radiance_api_key` to 0400 `${RADIANCE_UID}`, and writes `run/ipa-data/ipa-server-install-options` (0600) containing:
   ```
   -U
   --realm=IPA.TEST
   --domain=ipa.test
   --no-ntp
   --skip-mem-check
   --admin-password=<admin secret>
   --ds-password=<DM secret>
   ```
   This file is read by the image on first start and its contents are passed as `ipa-server-install` arguments. The passwords never enter the image build or a Compose `environment:` block, but they are visible in host `ps` for the duration of the install (container processes are visible on the host); the file is shredded immediately afterward and both passwords are rotated after bootstrap. If the container's reverse lookup fails, add `--no-host-dns` to the options file (the installer supports it; verify on the pinned image).
2. `openssl` generates `run/ipa-data/certs/radiance.key` (0600) and `radiance.csr` with `subjectAltName=DNS:radiance.ipa.test`, then copies the CSR into the IPA data volume where the bootstrap can read it.
3. `docker compose up -d ipa`; wait for `ipactl status`. Once the realm is installed, `shred -u run/ipa-data/ipa-server-install-options` — the image ignores it after first start, and it holds both admin and Directory Manager passwords.
4. `docker compose --profile bootstrap run --rm bootstrap`; the one-off container shares the IPA network namespace, mounts `/data`, `/bootstrap`, `run/krb5.conf`, and the bootstrap secrets (no stdin juggling):
   - `kinit admin < /run/secrets/ipa_admin_password`; create `pi`, `mallory`, `ai-users`, `ai-ops`; add `pi` to `ai-users`.
   - Set `pi`'s password from `/run/secrets/pi_password` and `mallory`'s from `/run/secrets/mallory_password`; clear the forced change: `ipa user-mod pi --setattr=krbPasswordExpiration=20380101000000Z` (verify on the pinned version; fallback below).
   - Create `svc-radiance` as a **system account** with `/run/secrets/ldap_bind_password` (`ipa sysaccount-add … --password`).
   - Create the service host and principal: `ipa host-add radiance.ipa.test --force --no-reverse`, then `ipa service-add HTTP/radiance.ipa.test`. If no host object is wanted, replace both with `ipa service-add --skip-host-check HTTP/radiance.ipa.test`.
   - `ipa-getkeytab -s ipa.ipa.test -p HTTP/radiance.ipa.test -k /data/keytabs/radiance.keytab -e aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96`; `chmod 600`.
   - `ipa cert-request --principal=HTTP/radiance.ipa.test --chain /data/certs/radiance.csr`, extract the PEM block to `/data/certs/radiance.crt` (or parse the serial and use `ipa cert-show SERIAL --out … --chain`).
   - Copy `/etc/ipa/ca.crt` to `/data/certs/ca.crt`; `ipa krbtpolicy-mod --maxlife=28800 --maxrenew=604800`.
   - Write `/data/certs/.bootstrap-complete` (0600); `kdestroy`.
   After the bootstrap succeeds, rotate the admin and Directory Manager passwords (record the exact commands in `docs/RUNBOOK.md`); the one-off installer's argv exposure is RR7.
5. Start the edge (it waits for `/certs/.bootstrap-complete`, cert, and keytab), then radiance or the mock.
6. Start the shim (`docker compose --profile client up -d radiance-shim`), then `docker compose --profile client run --rm pi-login pi-krb login` (kinit as `pi`), then `docker compose --profile client run --rm pi-client pi-krb run --model radiance-krb/qwen3.8-27b`.

**Password-change fallback:** if the pinned IPA still forces a change after `--setattr`, bootstrap uses `expect`/`pexpect` once to answer the "Password expired" prompts and stores the new password; the test suite asserts `kinit` succeeds non-interactively either way. Do not ship a workaround that leaves the test user's password expired.

---

## 6. Configuration

### 6.1 `krb5.conf`

```ini
[libdefaults]
    default_realm = IPA.TEST
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    dns_canonicalize_hostname = false
    udp_preference_limit = 1
    forwardable = false
    proxiable = false
    ticket_lifetime = 8h
    renew_lifetime = 7d
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96
    default_tgs_enctypes = aes256-cts-hmac-sha1-96

[realms]
    IPA.TEST = {
        kdc = ipa.ipa.test:88
        admin_server = ipa.ipa.test:749
        kpasswd_server = ipa.ipa.test:464
    }

[domain_realm]
    .ipa.test = IPA.TEST
    ipa.test = IPA.TEST
```

### 6.2 Edge virtual host

```apache
Listen 8443 https
ServerTokens Prod
ServerSignature Off
TraceEnable Off
KeepAliveTimeout 5
Timeout 600
ProxyTimeout 3600
LimitRequestFields 50
MaxRequestWorkers 128

# mod_ldap's cache/trust directives are SERVER-SCOPE ONLY. They must not be
# placed inside <VirtualHost> or <LocationMatch>; httpd refuses to start.
LDAPTrustedGlobalCert CA_BASE64 /certs/ca.crt
LDAPVerifyServerCert On
LDAPCacheTTL 60
LDAPCacheEntries 1024

<VirtualHost *:8443>
    ServerName radiance.ipa.test
    SSLEngine on
    SSLProtocol -all +TLSv1.3
    # TLS 1.3 suites are configured with the protocol prefix; an unprefixed
    # SSLCipherSuite list is applied to TLS <=1.2 and is rejected here.
    SSLCipherSuite TLSv1.3 TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256
    SSLCompression off
    SSLSessionTickets off
    SSLCertificateFile    /certs/radiance.crt
    SSLCertificateKeyFile /certs/radiance.key
    SSLCACertificateFile  /certs/ca.crt

    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
    Header always unset Server
    Header always unset X-Powered-By
    RequestHeader unset X-Radiance-Principal

    # Only these operations exist for model users.
    <LocationMatch "^/v1/(models|chat/completions|completions)$">
        Require method GET POST

        AuthType GSSAPI
        AuthName "radiance"
        GssapiCredStore keytab:/run/radiance/radiance.keytab
        GssapiAcceptorName HTTP@radiance.ipa.test
        GssapiSSLonly On
        GssapiUseSessions Off
        GssapiBasicAuth Off
        # GssapiLocalName On maps REMOTE_USER to the uid and sets GSS_NAME to
        # the full principal; PublishMech exposes GSS_MECH (Negotiate/krb5).
        GssapiLocalName On
        GssapiPublishMech On
        GssapiNegotiateOnce On

        # Live IPA LDAP group check over LDAPS. The LDAP cache/trust
        # directives above are server-scope; only AuthLDAP* lives here.
        AuthLDAPURL "ldaps://ipa.ipa.test:636/dc=ipa,dc=test?uid?sub?(objectClass=posixAccount)"
        AuthLDAPBindDN "uid=svc-radiance,cn=sysaccounts,cn=etc,dc=ipa,dc=test"
        # Rendered at start from a secret; the rendered file is mode 0400.
        AuthLDAPBindPassword "{{LDAP_BIND_PASSWORD}}"
        AuthLDAPGroupAttribute member
        AuthLDAPGroupAttributeIsDN On

        Require valid-user
        Require ldap-group CN=ai-users,CN=groups,CN=accounts,DC=ipa,DC=test

        # LimitRequestBody is valid in a Location. LimitRequestFields is not
        # (it is server/vhost scope); it is set above.
        LimitRequestBody 16777216
    </LocationMatch>

    # Everything not expressly allowed is denied before any handler runs.
    <LocationMatch "^/(?!v1/(models|chat/completions|completions)$)">
        Require all denied
    </LocationMatch>

    ProxyRequests Off
    ProxyPreserveHost Off
    SSLProxyEngine Off
    # Exact-path proxy: no prefix match, so no unauthenticated path can reach the
    # engine. The same regex is used by the authenticated LocationMatch.
    ProxyPassMatch "^/v1/(models|chat/completions|completions)$" "http://127.0.0.1:8000/v1/$1"

    RequestHeader set Authorization "Bearer {{RADIANCE_API_KEY}}"
    RequestHeader set X-Radiance-Principal "%{GSS_NAME}e"
    RequestHeader set Host "127.0.0.1:8000"

    LogFormat "{\"ts\":\"%{%FT%TZ}t\",\"principal\":\"%{GSS_NAME}e\",\"uid\":\"%{REMOTE_USER}e\",\"mech\":\"%{GSS_MECH}e\",\"status\":%>s,\"bytes\":%B,\"dur_us\":%D,\"tls\":\"%{SSL_PROTOCOL}x\",\"cipher\":\"%{SSL_CIPHER}x\"}" json_audit
    CustomLog /proc/self/fd/1 json_audit
    ErrorLog  /proc/self/fd/2
</VirtualHost>

# Loopback-only health, not published.
Listen 127.0.0.1:8081
<VirtualHost 127.0.0.1:8081>
    DocumentRoot /var/www/health
    <Location "/healthz">
        Require all granted
    </Location>
</VirtualHost>
```

Verification points (P2):

- `apachectl -t`; required modules loaded (`auth_gssapi`, `ssl`, `proxy_http`, `headers`, `ldap`, `authnz_ldap`, `authz_core`, `rewrite`). Pin a current 2.4.x httpd; `Require method` is a 2.4 core provider (the older "2.4.40" note was a conservative guess, not a requirement — verify on the pinned image).
- The entrypoint renders the vhost into `/run/apache2/` (tmpfs) and the image's `apache2.conf` includes it; `APACHE_RUN_DIR`/`APACHE_LOCK_DIR`/`APACHE_LOG_DIR` all point into `/run/apache2` so the read-only rootfs never needs a write.
- **Directive contexts:** `LimitRequestFields`, `MaxRequestWorkers`, `LDAPTrustedGlobalCert`, `LDAPVerifyServerCert`, `LDAPCacheTTL`, and `LDAPCacheEntries` are server-scope; `LimitRequestBody` and the `AuthLDAP*`/`Gssapi*` directives are valid in `<LocationMatch>`. U18 asserts this.
- **TLS 1.3 suites:** `SSLCipherSuite` must carry the `TLSv1.3` protocol prefix. An unprefixed list of `TLS_AES_*` names makes OpenSSL's `SSL_CTX_set_cipher_list()` fail, and mod_ssl exits the server. U18 asserts the prefix.
- `Require valid-user` + `Require ldap-group` are ANDed (verified pattern: `GssapiLocalName On` + `AuthLDAPURL ?uid` + `AuthLDAPGroupAttribute member`).
- `GSS_NAME` is the full `pi@IPA.TEST`; `REMOTE_USER` is `pi`.
- `GssapiNegotiateOnce On` avoids repeated 401 challenges after a failed attempt; test with a bad cache. Note that after a failed token the 401 may carry no `WWW-Authenticate` challenge; the shim must retry with a fresh initial token.
- **SPNEGO vs raw krb5:** `GssapiAllowedMech` is intentionally omitted here. If you add `GssapiAllowedMech krb5`, verify `curl --negotiate` and the Python helper still work; avoid NTLM by not installing `gss-ntlmssp`, not by relying on the directive alone.
- **Keytab ownership:** the entrypoint copies the keytab from `/keytabs` to `/run/radiance/radiance.keytab` as `0400 www-data:www-data`. `0400 root:root` would make every request fail, because mod_auth_gssapi opens the keytab per request in the worker.
- **Timeout vs ProxyTimeout:** `ProxyTimeout 3600` is deliberate. A 16k-token answer on one R9700 can exceed the default 600 s proxy timeout and be truncated mid-stream.
- **Allowlist is a security boundary:** `ProxyPassMatch` uses the same exact regex as the authenticated `<LocationMatch>`; there is no broad `ProxyPass /v1/` and no prefix match. A unit test asserts both regexes are identical and that no prefix proxy exists.
- **LDAP caching:** `LDAPCacheTTL 60` means a removed user can remain authorized for up to 60 s. T4b asserts revocation after the TTL; document the window.

### 6.3 radiance flags and key handling

```sh
#!/bin/sh
set -eu
RADIANCE_API_KEY="$(cat /secrets-src/radiance_api_key)"
export RADIANCE_API_KEY
exec radiance "$@"
```

The flags are declared **only** in the compose `command:` ([§5.3](#53-compose-skeleton)); the entrypoint must not repeat them. For reference, the effective invocation is:

```sh
radiance \
  --model /models/qwen3.8-27b-mxfp4.rad \
  --host 127.0.0.1 --port 8000 \
  --api-key-env RADIANCE_API_KEY \
  --served-model-name qwen3.8-27b \
  --tp 1 \
  --max-model-len 200000 \
  --kv-cache-dtype fp8 \
  --max-num-seqs 1 \
  --max-num-batched-tokens 2048 \
  --num-speculative-tokens 0 \
  --mm-max-patches 0 \
  --no-cors
```

- `--api-key-env` is the documented non-argv mechanism; the key is exported from `/secrets-src/radiance_api_key` (0400 `${RADIANCE_UID}`, set by `up.sh`), so it is not in `ps` or `/proc/<pid>/cmdline`.
- One source of truth: if the flag list changes, change the compose `command:` only; the entrypoint just exports the key and `exec`s `"$@"`.
- `--no-cors` removes browser reachability even inside the network.
- `--served-model-name` makes `/v1/models` and responses agree with Pi's model id.
- `--mm-max-patches 0` disables vision (text-only tests); re-enable with a measured VRAM budget.
- Never enable `--debug-graph`, `--profile-ops`, or `--live` in normal operation.

### 6.4 Pi and the shim

`pi-krb` isolates Pi state under `run/pi-agent` and writes `models.json`:

```json
{
  "$schema": "https://pi.dev/schemas/models.schema.json",
  "providers": {
    "radiance-krb": {
      "name": "radiance (Kerberos)",
      "baseUrl": "http://radiance-shim:8088/v1",
      "api": "openai-completions",
      "apiKey": "!cat /agent/shim-token",
      "authHeader": true,
      "models": [
        {
          "id": "qwen3.8-27b",
          "name": "Qwen3.8 27B MXFP4 (radiance)",
          "reasoning": false,
          "input": ["text"],
          "contextWindow": 200000,
          "maxTokens": 16384,
          "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 }
        }
      ]
    }
  }
}
```

Pi source confirms the important property: `models.json` command values are resolved **uncached** at auth resolution on each request (`resolveConfigValueOrThrow` → `resolveConfigValueUncached`), unlike `auth.json` commands, which are cached for the process lifetime. That is why the shim token can rotate safely. The shim creates `/agent/shim-token` (0600) and re-reads it per request; `pi-krb` renders `models.json` with the actual token path: `/agent/shim-token` in the compose stack, `run/pi-agent/shim-token` when Pi runs on the host. Host mode also changes the provider `baseUrl` to `http://127.0.0.1:8088/v1`. After E0, replace `200000` with the measured `ctx_max` if it is lower; never advertise an unmeasured context.

**Why the shim, not a direct header:** Pi's OpenAI-completions client receives `options.apiKey` and constructs the SDK with `apiKey`, which emits `Authorization: Bearer …`. A `headers.Authorization = "!krb-token"` entry can be overwritten by the Bearer header. The shim sidesteps this entirely and is testable without native Node modules. It also runs in its own container, so the agent container never mounts the ccache.

**Shim contract**

```
radiance-krb-shim [--listen 0.0.0.0:8088] [--edge https://radiance.ipa.test:8443]
                  [--service HTTP/radiance.ipa.test] [--ca /certs/ca.crt]
                  [--token-file /agent/shim-token]
  - binds 8088 on shim-net only (host mode: 127.0.0.1)
  - creates --token-file (0600) if absent; requires
    Authorization: Bearer <token from that file> on every request
  - for each request: gss_init_sec_context (no delegation, no mutual flag),
    base64 token, Authorization: Negotiate <token> to the edge
  - streams SSE and request/response bodies without buffering
  - maps 401 to a single retry with a fresh authenticator; if the TGT is expired,
    returns 401 with body "kerberos credentials expired; run pi-krb login"
  - never logs tokens, prompts, or Authorization headers
  - /healthz is unauthenticated and reports ccache/token/cert readiness
```

`radiance-krb-token` (same Python module, CLI form):

```
radiance-krb-token --service HTTP/radiance.ipa.test [--format header|token] [--check]
  stdout: "Negotiate <base64>"   exit 0
  exit 2 no ccache · 3 expired · 4 GSSAPI failure
```

**User flow**

```sh
docker compose --profile client up -d radiance-shim   # credential agent
docker compose --profile client run --rm pi-login pi-krb login [--principal pi]
docker compose --profile client run --rm pi-login pi-krb status
docker compose --profile client run --rm pi-client pi-krb run --model radiance-krb/qwen3.8-27b
```

`pi-krb login` runs in `pi-login` and writes the ccache (`kinit -F -l 8h -r 7d`; password prompt, no echo). `pi-krb status` runs in `pi-login` (`klist -e`; asserts AES and remaining life). `pi-krb run` runs in `pi-client`, waits for `/agent/shim-token` and the shim's `/healthz`, writes `models.json`, points `PI_CODING_AGENT_DIR` at `/agent`, then `exec`s `pi`. This is the entire "give credentials to the harness" step; the agent container never mounts the ccache, and no TGT is copied or forwarded.

**Optional direct mode (S1):** if a spike proves that a `models.json` `headers.Authorization` value from `!radiance-krb-token` survives Pi's Bearer handling, a shim-free mode can be offered. It is not the baseline.

### 6.5 Client trust, time, and host-mode resolution

- Shim trusts only the IPA CA (`--ca /certs/ca.crt` in the container; `run/ipa-data/certs/ca.crt` on the host); never disable verification.
- In the compose stack the agent speaks HTTP only to `radiance-shim:8088` on the internal `shim-net`; in host mode the shim binds `127.0.0.1:8088` and Pi talks only to loopback. `NODE_EXTRA_CA_CERTS` is unnecessary for Pi and is not set to a permissive value.
- Host-mode Pi needs `127.0.0.1 ipa.ipa.test radiance.ipa.test` in `/etc/hosts` (the KDC and edge ports are published on loopback by default). `run/krb5.conf` uses `ipa.ipa.test`; without the entry, `kinit`/`pi-krb` fail with "Cannot contact any KDC".
- Host chrony; containers inherit the host clock.

---

## 7. Security design

### 7.1 Objectives

1. Only `ai-users@IPA.TEST` members can invoke the model; authorization is checked server-side per request.
2. Only a service ticket scoped to `HTTP/radiance.ipa.test` is presented; the **agent container** holds no TGT, no keytab, and no password. The ccache exists only in `pi-login` and `radiance-shim`.
3. TLS 1.3 on the client edge, LDAPS to IPA, AES Kerberos end to end; the edge→engine hop is loopback-only and keyed (documented residual).
4. The engine is unreachable except through the authenticated edge, and only an endpoint allowlist is proxied.
5. Secrets are files with least privilege, rotatable, absent from images and logs. The sole argv exception is the one-off `ipa-server-install` first start, which is shredded/rotated immediately (RR7).
6. Every request is attributable to a full principal and timestamp.

### 7.2 Threat model

| Threat | Control | Test |
|---|---|---|
| Eavesdrop prompts | TLS 1.3 only; HSTS; no TLS 1.2 | T6, T13 |
| Steal user credentials | No TGT in the agent container; ccache only in `pi-login`/`radiance-shim`, 0600; no keytab in the agent; short TGT | T1, T5, T19, T23 |
| Replay captured Negotiate token | GSSAPI replay cache; 300 s skew; TLS | T12 (hard) |
| Forged service | Keytab-only decryption; `GssapiAcceptorName`; IPA-issued TLS cert | T3, T5, T6 |
| Valid ticket, unauthorized user | LDAP `ai-users` check; 403 | T4 |
| Authorized user calls admin/LoRA routes | Edge allowlist; `Require all denied` elsewhere | T18b |
| Direct engine access | No port, no alias; shared netns loopback; internal key | T14 |
| Stolen keytab | 0400 `www-data` tmpfs; rotation; minimal keytab | T15, T16 |
| Secret leakage via logs/argv | File mounts 0600/0400; ephemeral bootstrap; redaction; no Authorization logs; RR7 | T15 |
| DoS (large bodies, slow clients) | Body/field limits, timeouts, ProxyTimeout, worker limits | T17 |
| Local user steals shim | `shim-net` internal; random token 0600; per-user state dir | T20 |
| Agent container compromise / prompt injection | No ccache, certs, `run/ccache`, `run/ipa-data`, or `secrets/` in `pi-client`; only `work/` and `run/pi-agent` (state + bearer token); `cap_drop: ALL`; no-new-privileges; read-only rootfs; no docker socket | T23, T24, manual |
| Agent modifies host stack | `work/` is a dedicated directory; the repo, `compose.yaml`, `scripts/`, and `.git` are not mounted | U22 |

Out of scope: KDC host compromise, hardware attacks, GPU driver side channels, model-operator prompt privacy, a compromised Docker daemon.

### 7.3 Controls by layer

**Transport**

- TLS 1.3 only; AEAD suites via `SSLCipherSuite TLSv1.3 …`; session tickets off; HSTS two years.
- Cert `radiance.ipa.test` from IPA CA; key 0600; never baked into images.
- LDAPS with `LDAPVerifyServerCert On`; IPA CA pinned. The `LDAP*` cache/trust directives are server-scope (see §6.2).
- Kerberos forced to TCP (`udp_preference_limit = 1`) to reduce spoofing/amplification.
- Loopback hop to the engine carries the private API key; documented residual: a process in the same network namespace could read it.

**Authentication**

- SPNEGO on every `/v1/*` request; `GssapiUseSessions Off`; no Basic fallback; `GssapiSSLonly On`.
- `GssapiAcceptorName` pins the SPN; only that principal is in the keytab.
- `GssapiLocalName On` gives both `REMOTE_USER` (uid) and `GSS_NAME` (full principal) for authz and audit.
- `GssapiPublishMech On`; logs and tests assert `Negotiate/krb5`.

**Authorization**

- Per-request LDAP group check over LDAPS as `svc-radiance` (system account, no Kerberos principal).
- `LDAPCacheTTL 60` bounds revocation staleness; test T4b.
- Endpoint allowlist: `/v1/models`, `/v1/chat/completions`, `/v1/completions`; methods GET/POST; everything else denied (including `/v1/load_lora_adapter`, `/v1/unload_lora_adapter`, `/v1/systemone`, `/v1/audio`, `/v1/images`, `/v1/videos`, `/dashboard`, `/diagnostics`).

**Secrets**

- Long-lived secrets are host files with explicit modes (`0600` root for the edge, `0400 ${RADIANCE_UID}` for the engine), bind-mounted under `/secrets-src`; not Compose secrets.
- Compose secrets are used only by the ephemeral `bootstrap` container and the test runner (0444 is acceptable there).
- `pi-login` and `radiance-shim` mount the ccache; `radiance-shim` additionally mounts only the CA file; `pi-client` mounts neither.
- `pi-client` mounts no ccache, cert, or IPA secret; the only credential it can read is the bearer token in `run/pi-agent` (plus its own state there and `work/`).
- Bootstrap passwords are separate (admin vs Directory Manager), used once, and rotated; the options file is shredded.
- Rotation: keytab (new kvno), TLS cert (new CSR/serial), LDAP bind password (new sysaccount password), API key (restart both sides), user password.

**Runtime**

- Edge: `cap_drop: ALL`, only CHOWN/SETGID/SETUID/DAC_OVERRIDE added, `no-new-privileges`, read-only rootfs, tmpfs.
- Engine: fixed UID/GID from `.env`, read-only rootfs, **required** seccomp profile, `cap_drop: [ALL]`, `memlock: -1`.
- IPA: heavy systemd image; isolated on `krb-net`; only 88/464 published, loopback by default; no privileged mode.
- Bootstrap: one-off, `cap_drop: ALL` + the minimum needed to write `/data`, exits after use.
- Agent: `pi-client` runs as `${PI_UID}:${PI_GID}`, `cap_drop: ALL`, `no-new-privileges`, read-only rootfs, tmpfs, `shim-net` only.
- Shim: `cap_drop: ALL`, `no-new-privileges`, read-only rootfs; the only container with both `shim-net` and `krb-net`.
- No Docker socket mounted anywhere; model volume read-only.

**Logging**

- JSON audit: timestamp, full principal, uid, mechanism, status, bytes, duration, TLS version/cipher.
- No tokens, no Authorization, no prompt/response bodies, no query strings with secrets.
- Redaction test with canary token and canary prompt; retention/access policy documented.

**Supply chain**

- Digest-pin IPA, radiance, httpd; hash the model file; SBOM + trivy; `hadolint`, `shellcheck`, `yamllint`; gitleaks; Node ≥22.19 for Pi.

### 7.4 Residual risks (accepted)

| # | Risk | Why accepted | Mitigation |
|---|---|---|---|
| RR1 | Engine has no auth | Edge is the boundary | Phase 6 native GSSAPI if required |
| RR2 | Shared engine API key | No user model in engine | Edge-only reachability; rotation; Phase 6 |
| RR3 | Loopback trust edge↔engine | Engine has no TLS | Same netns; read-only; key 0400 |
| RR4 | LDAP cache staleness (≤60 s) | Performance | Short TTL; test T4b; document |
| RR5 | Replay detection across worker processes | GSSAPI replay caches are per-process unless a shared cache is configured | T12 requires a 401 on replay; if a cross-worker replay is accepted, the design must change (single worker or shared replay cache) — it is not waived |
| RR6 | Pi tools run as the user | Harness design | Dedicated `work/`; no ccache/certs/IPA data in the agent (only the shim bearer token); `cap_drop: ALL`; read-only rootfs; the shim can still act as the user (by design) |
| RR7 | Installer argv exposure during first start | The image's options mechanism passes them to `ipa-server-install` | One-off window; host `ps` risk documented; options file shredded; both passwords rotated |
| RR8 | Shim is a credential oracle for the same UID | It is the intended delegation point | Internal `shim-net`; 0600 token; no ccache in the agent; per-request auth |

---

## 8. Capacity: 200k context on one R9700

### 8.1 Evidence from radiance's own measurements

Qwen3.8-27B is a hybrid model (paged attention groups plus recurrent state), so its per-token KV cost is far lower than a dense 27B. The published numbers for the **MXFP4 container on two R9700s**, with `--tp 2`, 12 GiB per card reserved for another engine, and `--max-num-batched-tokens 2048`:

| `--kv-cache-dtype` | KV pool | Change |
|---|---|---|
| `fp8` | 518,800 tokens | baseline |
| `fp8_v4` | 664,400 tokens | +28% |
| `k6_v4` | 755,184 tokens | +46% |

The documented serve recipe for this container is `--tp 2 --max-num-seqs 32 --max-model-len 200000 --kv-cache-dtype fp8`. A single card must be **measured**; the hybrid geometry makes 200k plausible, and `fp8_v4`/`k6_v4` provide headroom if the default pool is short.

**Do not use `--kv-resident` (streaming KV) for this model.** The docs are explicit: Qwen3.5/3.6/3.8 dense (`qwen35_*`) is **not** supported and the flag is ignored with a warning; it applies only to Flash-Next and GLM-5.3-Flash.

### 8.2 Gate E0 (before P4)

1. Boot with `--debug-placement` once; capture the `kv:` receipt line (`the pool backs N% of the worst case … M full-length sessions`).
2. Boot with the §6.3 flags and request a near-200k prompt built via `/v1/tokenize` (the server's own tokenizer), directly against the engine inside the edge network namespace — the edge allowlist deliberately does not expose `/tokenize`.
3. Record: admission, TTFT, prefill tok/s, decode tok/s, peak VRAM, `M` full-length sessions.
4. Write `docs/CAPACITY.md` with the measured maximum (`ctx_max`) and the exact flags.

If `M < 1`, apply the ladder in order:

1. `--kv-cache-dtype fp8_v4` (+28% pool), then `k6_v4` (+46%); these are supported on Qwen3.8-27B attention (head_dim 256, gqa 6) and are real quantisations — run the quality checks in T11b.
2. `--state-cache-dtype f16` (halves recurrent state; lossy; only if the model's plugin serves it).
3. `--max-num-seqs 1` and `--max-num-batched-tokens 2048` (already).
4. `--mm-max-patches 0` (already) and `--num-speculative-tokens 0` (already).
5. Lower `--max-model-len` to `ctx_max`; set Pi's `contextWindow` to the same value.
6. Add a second R9700 and switch to `--tp 2` with the documented recipe.

`--attn-prefill-fp8 qk`, `pv`, or `both` improves prefill speed at 200k (measured +15–20% with `both` on a 221K prompt) but is lossy and does **not** add KV capacity; consider it only after admission passes.

### 8.3 Performance budgets

| Metric | Target |
|---|---|
| Auth + proxy overhead, service ticket cached | p50 < 10 ms, p95 < 25 ms |
| First request after `kinit` (TGS) | < 100 ms |
| Streaming first-token penalty | < 50 ms |
| 100 concurrent authenticated requests (mock) | No 5xx |
| Edge CPU at 10 req/s | < 20% of one core |

---

## 9. Test strategy

### 9.1 Layers

| Layer | Tooling | Runs | Proves |
|---|---|---|---|
| Unit | pytest, shellcheck, hadolint, yamllint, `apachectl -t` | PR (<30 s) | Parsers, renderers, flags, helper, shim, redaction |
| Fast integration | Compose `test-fast`: IPA + edge + mock + test-runner | PR (~10–15 min) | Kerberos, SPNEGO, authz, allowlist, TLS, streaming |
| GPU integration | Compose `gpu`: real radiance + model | Nightly/labelled | Model path, 200k, Pi multi-turn |
| Security | testssl.sh, trivy, gitleaks, config lint | PR/nightly | TLS, CVEs, secrets |
| Performance | k6/locust + radiance timings | Nightly | Latency/concurrency budgets |

`mock-radiance` implements `/health`, `/v1/models`, `/v1/chat/completions` (SSE + non-streaming), tool-call chunks, and configurable errors/delays. Auth tests never need a GPU.

### 9.2 Unit tests

| ID | Test | Assertion |
|---|---|---|
| U1 | Token helper SPN | `HTTP@radiance.ipa.test`, hostbased name |
| U2 | Helper output | Exactly `Negotiate <base64>`; no trailing data |
| U3 | No ccache | Exit 2; actionable, secret-free stderr |
| U4 | Expired ticket | Exit 3; message points to `pi-krb login` |
| U5 | GSSAPI failure | Exit 4; no token in output |
| U6 | Token never logged | Canary scan of stdout/stderr/logs |
| U7 | `krb5.conf` renderer | Realm/KDC, AES-only, `forwardable=false` |
| U8 | Apache vhost renderer | TLS1.3 only; HSTS; allowlist; loopback upstream; `UseSessions Off`; `SSLCipherSuite TLSv1.3 …`; server-scope `LDAP*`/`LimitRequestFields` |
| U9 | Secret rendering | File-sourced; config 0400; no stdout leak |
| U10 | Bootstrap idempotency | Mocked `ipa`: second run adds nothing; no keytab rotation |
| U11 | Bootstrap failure modes | Missing secret / failed `ipa` / failed cert → nonzero, no marker |
| U12 | Radiance flag builder | Single source of truth; no duplicate flags with the entrypoint; `--max-model-len 200000`, loopback, `--api-key-env`, `--no-cors` |
| U13 | Pi `models.json` | Schema-valid; context matches capacity; `baseUrl http://radiance-shim:8088/v1`; token path |
| U14 | Principal mapping | `pi@IPA.TEST`→`pi`; realm/case rules |
| U15 | Audit redaction | Canary prompt/token absent |
| U16 | Shim auth | Wrong/missing bearer → 401; correct → proxied |
| U17 | Shim streaming | SSE chunks pass through unbuffered; retry once on 401 |
| U18 | Apache config lint | `apachectl -t`; modules; only TLS1.3; cipher prefix; allowlist regex; directive contexts |
| U19 | Compose lint | `docker compose config` all profiles; no radiance ports; `BIND_ADDR` defaults loopback; `RADIANCE_SECCOMP` required |
| U20 | Sysaccount DN | Renderer uses `cn=sysaccounts,cn=etc` |
| U21 | GSSAPI flags | Shim requests no delegation and no mutual-auth flag; token is a fresh AP-REQ |
| U22 | Agent mount invariants | `pi-client` has no `run/ccache`, `run/ipa-data`, `secrets/`, or certs mount; no `./` mount; only `work/` + `run/pi-agent`; `shim-net` only |
| U23 | Shim token | Created 0600 by the shim if absent; re-read per request; never in argv/logs |
| U24 | Bootstrap secret scope | Long-lived `ipa` service has no `secrets:`; only the one-off `bootstrap` and `test-runner` do |
| U25 | Keytab ownership | Renderer/entrypoint sets `0400 www-data` on `/run/radiance/radiance.keytab` |

### 9.3 Integration tests (real FreeIPA + mock)

| ID | Scenario | Expected |
|---|---|---|
| T1 | `pi-krb login` in `pi-login` (`kinit pi`, password from `/run/secrets/pi_password`); `klist -e` | Exit 0; AES-256; ccache 0600 |
| T2 | Negotiate GET `/v1/models` as `pi` | 200; TLS1.3; audit has `pi@IPA.TEST`, `GSS_MECH=Negotiate/krb5` |
| T3 | No `Authorization` | 401 + `WWW-Authenticate: Negotiate`; no body leak |
| T4 | `kinit mallory` (password from `/run/secrets/mallory_password`; not in `ai-users`) | 403 (not 401) |
| T4b | Remove `pi` from `ai-users`; wait > `LDAPCacheTTL` | 403 after ≤60 s; document the window |
| T5 | Edge with wrong keytab/SPN | 401 on every request; the edge logs the GSSAPI failure (a startup refusal is not required, but an accepted ticket would be a bug) |
| T6 | TLS 1.2 client; untrusted CA; missing SAN | Handshake fails; no downgrade |
| T7 | Negotiate streaming chat | SSE incremental; first chunk < 2 s with mock |
| T8 | 10-turn conversation | 10 authenticated requests; same principal; all 200 |
| T9 | Multi-turn tool use via Pi | Tool call streamed; `read` executed; final answer; JSONL events |
| T10 | `kinit -l 2m`; expire mid-session | 401 with actionable shim error; re-`kinit`; `pi --continue` succeeds |
| T11 | Near-200k prompt (GPU) | 200 + answer; `>ctx_max` clean 400; TTFT/throughput recorded |
| T11b | `fp8` vs `fp8_v4` quality (GPU) | Output quality note; mean KL check if a harness exists |
| T12 | Replay a captured Negotiate header (same and cross-worker) | 401 required; a cross-worker acceptance is a design failure (RR5), not a waiver |
| T13 | 10-minute client clock skew (`libfaketime`) | 401; edge logs skew |
| T14 | From test-runner, reach `radiance:8000` | Fails; no port/alias |
| T14b | From `pi-client`, reach `ipa`, `radiance-edge`, or the KDC; scan `shim-net` | Only `radiance-shim:8088` responds; no route to IPA/edge/KDC |
| T15 | Keytab/secret perms; `ps`/`/proc` cmdline; logs | Keytab 0400 `www-data`; long-lived secrets 0600/0400; only the one-off installer has a password in argv (RR7); no secret in logs |
| T16 | Keytab rotation; restart edge | Old keytab 401; new 200 |
| T17 | Oversized body, slow header, 100 parallel | 413/408; consistent 200; no crash |
| T18 | TLS scan and headers | TLS1.3 only; HSTS; no banner; grade A |
| T18b | Authenticated call to `/v1/load_lora_adapter`, `/dashboard`, `/v1/audio` | 403/404; not proxied |
| T19 | Pi `--mode json` run | Negotiate only; no TGT on the wire; no Bearer reaches edge |
| T20 | Host-mode shim: another local user reads the shim token / calls the shim | Blocked by 0600 + token check; in the compose stack the shim is on `shim-net`, not host loopback |
| T21 | Client sends forged `Authorization: Bearer` + no Negotiate | 401; cannot bypass |
| T22 | `GSS_MECH` / logs after NTLM-style client | krb5 only; no 200 |
| T23 | Inspect `pi-client` mounts/env | No ccache, certs, `run/ccache`, `run/ipa-data`, or `secrets/`; only `work/` + `/agent` |
| T24 | Inspect `ipa` service | No bootstrap secrets mounted; they exist only in the one-off `bootstrap` |
| T25 | Pi request path | Pi → `radiance-shim` → edge; the agent never talks to the edge and never sees a TGT |

Every test has a negative counterpart where meaningful. Fresh ccache per test (`KRB5CCNAME=FILE:/tmp/cc-<uuid>`), `kdestroy` after.

Example:

```python
import pytest, requests
from requests_gssapi import HTTPSPNEGOAuth

pytestmark = pytest.mark.integration

def test_negotiate_models(edge_url):
    r = requests.get(f"{edge_url}/v1/models",
                     auth=HTTPSPNEGOAuth(opportunistic_auth=False), timeout=10)
    assert r.status_code == 200
    assert r.headers.get("strict-transport-security")

def test_missing_auth(edge_url):
    r = requests.get(f"{edge_url}/v1/models", timeout=10)
    assert r.status_code == 401
    assert "Negotiate" in r.headers.get("www-authenticate", "")

def test_forged_bearer(edge_url):
    r = requests.get(f"{edge_url}/v1/models",
                     headers={"Authorization": "Bearer forged"}, timeout=10)
    assert r.status_code == 401
```

### 9.4 Pi end-to-end

| ID | Test | Assertion |
|---|---|---|
| P1 | `pi-krb login` in `pi-login`, then `pi-krb run --print "read README.md"` in `pi-client` | Succeeds; edge audit shows authenticated request(s) |
| P2 | `pi --mode json "..."` | Tool call/result + assistant text events |
| P3 | 10 prompts via `--continue` | All succeed; no credential prompt after first `kinit` |
| P4 | Kill edge mid-stream | Clean error; session resumable |
| P5 | Run without `kinit` | Actionable failure before/at first request |
| P6 | Near-200k context (GPU) | Admitted; usage reported; overflow handling sane |

### 9.5 Security tests

- `testssl.sh --severity HIGH` on 8443: TLS 1.3 only, no weak ciphers, chain to IPA CA, HSTS.
- `trivy image` edge/pi/tests; no HIGH/CRITICAL without documented exceptions.
- `gitleaks`; `.gitignore` covers `secrets/`, `run/`, and `work/` (a P0 deliverable, not an assumption).
- Container inspection: no privileged; the edge and one-off bootstrap add only their documented capabilities; radiance, mock, shim, login, agent, and test runner have `cap_drop: [ALL]`; the IPA image runs systemd as root by design; read-only roots for edge/engine/shim/login/agent; no Docker socket.
- Log scan: no Authorization, bearer, internal key, prompt canary.
- `nmap -sT` from `krb-net`: IPA's 88/636 plus its own 80/389/443/749, and the edge's 8443; the engine is absent. From `shim-net` only `radiance-shim:8088` responds; `pi-client` has no route to `krb-net`.

### 9.6 CI

| Stage | Trigger | Contents |
|---|---|---|
| `lint` | PR | shellcheck, hadolint, yamllint, `apachectl -t`, compose config |
| `unit` | PR | U1–U25 |
| `integration-fast` | PR | T1–T9, T14–T18b, T20–T25 with mock |
| `security` | PR + nightly | testssl, trivy, gitleaks |
| `integration-gpu` | nightly | T11, T11b, P6, 200k measurement |
| `perf` | nightly | auth latency, concurrency, streaming |

FreeIPA startup is the slow fixture; cache the image, pin the digest, allow 10–15 minutes (the fast suite is ~10–15 min, not 8–10). If PR latency suffers, keep T1–T4, T6, T14–T18b on PRs and run the rest nightly with a required nightly green.

---

## 10. Implementation phases

### P0 — Decisions and spikes (1–2 days)

- [ ] Approve D1 (edge) or commit to Phase 6.
- [ ] Confirm R9700, model file hash, GPU GIDs, Docker cgroup mode.
- [ ] Pin digests: IPA, radiance, httpd; Pi version (Node ≥22.19); model checksum.
- [ ] Commit `.gitignore` (`secrets/`, `run/`, `work/`), `work/`, and the `RADIANCE_SECCOMP` profile path; fix `PI_UID`/`PI_GID`/`RADIANCE_UID`/`RADIANCE_GID`/`BIND_ADDR` in `.env.example`.
- [ ] Write the Apache vhost draft and run `apachectl -t` with the pinned image (the P2 gate; catches directive-context errors early).
- [ ] **S1 (optional):** test whether Pi's `models.json` header command survives Bearer handling; record result. Shim remains default either way.
- [ ] **S0:** confirm the IPA container starts read-only/systemd on this host; record required cgroup overrides.
- **Exit:** `.env.example` pins; `.gitignore`/`work/` present; decision note appended.

### P1 — FreeIPA realm (2–3 days)

- [ ] `deploy/ipa` install options + bootstrap script; host `up.sh`; two independent passwords (`admin`, Directory Manager); `mallory` password.
- [ ] One-off `bootstrap` container (shares the IPA netns; secrets ephemeral); users/groups/service/sysaccount/keytab/cert/krbtpolicy; CA export; `/data/certs/.bootstrap-complete`.
- [ ] `krb5.conf` for containers/host; `pi-login` with `pi-krb login/status`.
- [ ] Tests: T1, T4b (setup), T5, T6, U7, U10, U11, U20, U24.
- **Exit:** non-interactive `kinit pi`; AES tickets; keytab 0400 `www-data`; IPA-issued cert; bootstrap idempotent; the `ipa` service mounts no bootstrap secrets.

### P2 — Kerberos edge (3–4 days)

- [ ] Edge image, entrypoint, vhost template, TLS1.3 with the `TLSv1.3` cipher prefix, allowlist, server-scope `LDAP*`, LDAP authz, audit JSON.
- [ ] Keytab copy `0400 www-data`; `ProxyTimeout 3600`; wait for `/certs/.bootstrap-complete`.
- [ ] Mock radiance in edge netns; health listener.
- [ ] Tests: T2–T4b, T7, T14, T17, T18, T18b, T21, T22; U8, U9, U18, U19, U25.
- **Exit:** 200 as `pi`, 403 as `mallory`, 401 unauthenticated, 403 for admin/LoRA routes; engine unreachable; `apachectl -t` clean.

### P3 — Pi harness and shim (2–3 days)

- [ ] `deploy/pi`: Node ≥22.19, pinned Pi, krb5, Python gssapi, shim, `pi-krb`, models template, `curl` (healthchecks).
- [ ] Split `pi-login` / `radiance-shim` / `pi-client`; internal `shim-net`; shim-generated 0600 token; no ccache/certs/IPA data in `pi-client` (shim token only); `cap_drop`/read-only hardening.
- [ ] Helper + shim implementation and tests U1–U6, U13–U17, U22, U23.
- [ ] P1–P5, T8–T10, T14b, T19, T20, T23, T25.
- **Exit:** 10-turn tool-using session; expiry diagnosed and recovered; the agent container never sees a TGT, keytab, cert, or IPA secret.

### P4 — Real model and 200k (2–4 days)

- [ ] GPU profile, engine wrapper, model mount, required seccomp profile, `cap_drop: [ALL]`, UID/GID.
- [ ] E0 gate; record `ctx_max`; update Pi context and README.
- [ ] T11, T11b, P6; tune `max-num-seqs`, `max-num-batched-tokens`, cache dtype.
- **Exit:** measured capacity documented; 200k passes or ladder applied and plan updated.

### P5 — Hardening and docs (1–2 days)

- [ ] Container hardening, secret rotation (admin/DM/keytab/cert/API key), SBOM/trivy, testssl, nightly CI.
- [ ] `docs/RUNBOOK.md`, `docs/THREAT-MODEL.md`, `docs/CAPACITY.md`; record RR5/RR7/RR8.
- **Exit:** all acceptance tests green; clean-host runbook rehearsal.

### P6 — Optional native GSSAPI in radiance (2–3 weeks)

- [ ] `core/server/auth_gssapi.{h,cpp}`: `Authorization: Negotiate`, `gss_accept_sec_context`, replay cache, principal mapping, 401 challenge.
- [ ] Flags: `--krb5-keytab`, `--krb5-service`, `--krb5-require`, `--krb5-ldap-uri`/group.
- [ ] Tests: GoogleTest with a mocked GSSAPI, integration with FreeIPA, header parser fuzzing.
- [ ] Upstream PR (Apache-2.0 compatible; follow Codeberg policy).
- **Exit:** edge removable without losing authentication; no decode regression.

---

## 11. Operations runbook

### Bring-up

```sh
umask 077
cp .env.example .env          # image pins, UIDs/GIDs, BIND_ADDR, model path, RADIANCE_SECCOMP
mkdir -p secrets run work && chmod 700 secrets run work
openssl rand -hex 24 > secrets/ipa_admin_password
openssl rand -hex 24 > secrets/ipa_dm_password
openssl rand -hex 16 > secrets/pi_password
openssl rand -hex 16 > secrets/mallory_password
openssl rand -hex 24 > secrets/ldap_bind_password
openssl rand -hex 32 > secrets/radiance_api_key
chmod 600 secrets/*
./scripts/up.sh               # options file, cert CSR, IPA up, bootstrap, edge, shim
```

### User session

```sh
docker compose --profile client up -d radiance-shim
docker compose --profile client run --rm pi-login pi-krb login
docker compose --profile client run --rm pi-client pi-krb run --model radiance-krb/qwen3.8-27b
```

(For a host-run Pi, add `127.0.0.1 ipa.ipa.test radiance.ipa.test` to `/etc/hosts`, run the shim from `deploy/pi` with `--token-file run/pi-agent/shim-token`, and use `deploy/pi/pi-krb` with `KRB5_CONFIG=run/krb5.conf` and `KRB5CCNAME=FILE:run/ccache/krb5cc`; the container path is the supported and tested one.)

### Keytab rotation

```sh
docker compose --profile bootstrap run --rm --entrypoint /bin/bash bootstrap -lc '
  kinit admin < /run/secrets/ipa_admin_password
  ipa-getkeytab -p HTTP/radiance.ipa.test -k /data/keytabs/radiance.new \
    -e aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96
  chmod 600 /data/keytabs/radiance.new
  mv /data/keytabs/radiance.new /data/keytabs/radiance.keytab'
docker compose restart radiance-edge
# test old keytab: 401; new: 200
```

### Diagnose

| Symptom | Check | Cause |
|---|---|---|
| `Cannot contact any KDC` | `nc -vz ipa.ipa.test 88`; `KRB5_CONFIG`; `/etc/hosts` for host mode | DNS/port/realm |
| 401 despite ticket | `klist`, `kvno HTTP/radiance.ipa.test`, edge log; keytab owner/mode | Wrong SPN/keytab, expired ticket, or keytab not `0400 www-data` |
| 403 as `pi` | LDAP group, bind DN `cn=sysaccounts`, `LDAPCacheTTL` | Not in `ai-users`; stale/wrong bind |
| `Server not found in Kerberos DB` | `ipa service-show HTTP/...` | Missing/case-mismatched SPN |
| Clock skew | `chronyc tracking` | Host drift |
| TLS error in shim | `openssl s_client -connect radiance.ipa.test:8443` | CA/SAN/hostname |
| 403 on a valid API path | allowlist regex; `apachectl -t` | Endpoint not allowed |
| `pi-client` cannot reach `ipa`/edge | expected: it is on `shim-net` only; use the shim health | Network isolation, not a fault |
| Shim returns 401 "credentials expired" | `pi-krb status` in `pi-login`; re-login | Missing/expired ccache |
| 413/504 | body limit/timeouts; prefill; `ProxyTimeout` | Oversized prompt or long stream |
| OOM in radiance | boot `kv:` line; `--debug-placement` | Context/KV beyond card |

---

## 12. Acceptance checklist

- [ ] IPA realm `IPA.TEST` installs reproducibly; bootstrap idempotent; the long-lived `ipa` service mounts no bootstrap secrets.
- [ ] Non-interactive `kinit pi` in `pi-login`; AES ticket; ccache 0600; the agent container has no ccache mount.
- [ ] Every request to the edge carries `Authorization: Negotiate`; the agent container holds no TGT, keytab, cert, or IPA secret.
- [ ] Edge validates with the IPA keytab (`0400 www-data`); wrong keytab 401; `GSS_NAME`/`GSS_MECH` logged.
- [ ] `ai-users` 200; other authenticated users 403; unauthenticated 401; forged Bearer 401; `mallory` password provisioned.
- [ ] Admin/LoRA/dashboard paths 403 even when authenticated.
- [ ] TLS 1.3 only with the `TLSv1.3` cipher prefix; IPA-issued cert; HSTS; LDAPS verified; AES Kerberos.
- [ ] Engine has no published port; unreachable from other containers; required seccomp profile and `cap_drop: [ALL]`.
- [ ] KDC/edge ports bound to `127.0.0.1` by default (`BIND_ADDR`).
- [ ] 10-turn tool-using Pi session; expiry mid-session diagnosable and recoverable.
- [ ] 200k measured; Pi `contextWindow` matched; `fp8_v4`/`k6_v4` ladder documented.
- [ ] Keytab rotation, secret perms, no secrets in argv/logs except the one-off installer (RR7).
- [ ] Unit/integration/security/perf suites pass; nightly GPU green; runbook works fresh.

---

## 13. Open questions

1. **D1 approval:** edge-based enforcement, or native GSSAPI (Phase 6, +2–3 weeks)?
2. **Hardware:** if E0 shows 200k does not fit on one R9700, is a second card available? If not, choose reduced context vs. a smaller model.
3. **Shim acceptance:** is the separate `radiance-shim` sidecar (internal `shim-net`, 0600 token) acceptable as "the Pi harness", or is a Pi provider extension required? (The shim is testable, avoids native Node modules, and keeps the ccache out of the agent.)
4. **Names:** parameterise `IPA.TEST`/`ipa.test` now, or keep dev values and template later?
5. **IPA hosting:** Compose service for the team, or a shared externally operated IPA? This changes secret/network ownership.
6. **Quotas:** per-principal concurrency/rate limits in v1? If yes, plan for option C or `mod_lua` work.
7. **Logging scope:** authentication events only, or token counts/model/timing for chargeback?
8. **Installer argv:** accept the one-off `ipa-server-install` password-in-argv window (RR7), or wrap the installer with a helper that feeds the options file over stdin?

---

## 14. Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | 200k does not fit on one R9700 | Medium | High | E0 gate; `fp8_v4`/`k6_v4`; second card |
| R2 | IPA container/systemd/cgroup friction | Medium | Medium | S0 validation; documented overrides; VM fallback |
| R3 | `Require ldap-group` behavior on the pinned Apache | Low | Medium | Early T4; verify the implicit AND of multiple `Require`s; allowlist fallback |
| R4 | SPNEGO vs raw krb5 helper mismatch | Medium | Medium | T2/S0; omit `GssapiAllowedMech` or test both |
| R5 | Password-change automation surprises | Medium | Low | T1; pexpect fallback; verify `--password-expiration` |
| R6 | Keytab/secret leakage | Low | High | 0400 `www-data` keytab; file mounts; env key; rotation; redaction tests |
| R7 | LDAP cache delays revocation | Medium | Medium | `LDAPCacheTTL 60`; T4b; document |
| R8 | radiance/Pi upgrades change flags/behavior | Medium | Medium | Pin digests; integration suite on upgrade |
| R9 | Prompt injection drives Pi tools | Medium | High | Agent container with no ccache/certs/IPA data (only the shim token); dedicated `work/`; `cap_drop: ALL`; read-only rootfs; HBAC; no docker socket |
| R10 | Model licence constraints | Low | Medium | Verify container licence before external use |
| R11 | Agent modifies the host stack | Medium | High | Only `work/` is mounted; `compose.yaml`/`scripts/`/`.git`/`secrets/`/`run/` are not visible to `pi-client` |
| R12 | Replay accepted across Apache workers | Low | Medium | T12 is a hard 401 gate; otherwise single worker or shared replay cache (RR5) |

---

## 15. References

**FreeIPA**

- Repository: <https://codeberg.org/freeipa/freeipa>
- Container images and run notes: <https://github.com/freeipa/freeipa-container>, <https://www.freeipa.org/page/Docker>
- Release 4.13.4 (security): <https://www.freeipa.org/release-notes/4-13-4.html>
- Web app authentication: <https://www.freeipa.org/page/Web_App_Authentication>
- Apache group authorization (draft): <https://www.freeipa.org/page/Apache_Group_Based_Authorization>
- Verified in source: `ipa cert-request`/`cert-show` options (`ipaserver/plugins/cert.py`), `krbtpolicy-mod` (`ipaserver/plugins/krbtpolicy.py`), `sysaccount-add` (`ipaserver/plugins/sysaccounts.py`), `ipa-getkeytab` options (`client/ipa-getkeytab.c`), installer options (`ipaserver/install/server/install.py`)

**radiance**

- Repository: <https://codeberg.org/StillDeadcode/radiance>
- README, `spec.md`, `docs/GUIDE.md` (§4.4 long context, §4.4.1 streaming KV, §6.6 security), `docs/TOOLS.md`
- Compose conventions: `deploy/compose/common.yaml`, `deploy/compose/qwen3.8-27b-mxfp4.yaml`, `deploy/compose/.env.example`; seccomp profile `seccomp-radiance.json`

**Pi**

- Docs: <https://pi.dev/docs/latest/models-configuration>, <https://pi.dev/docs/latest/models>, <https://pi.dev/docs/latest/quickstart>, <https://pi.dev/docs/latest/cli>
- Source verified: `packages/coding-agent/src/core/resolve-config-value.ts` (uncached vs cached command resolution), `provider-composer.ts` (headers resolved per auth), `packages/ai/src/api/openai-completions.ts` (apiKey → Bearer)

**Kerberos / Apache**

- RFC 4559 (SPNEGO over HTTP), RFC 4120 (Kerberos V5), RFC 8009 (AES-SHA2), RFC 4121 (GSSAPI)
- `mod_auth_gssapi`: <https://github.com/gssapi/mod_auth_gssapi> (README and `src/mod_auth_gssapi.c`: `gss_acquire_cred_from()` runs per request in the worker)
- Apache `mod_authnz_ldap`: <https://httpd.apache.org/docs/2.4/mod/mod_authnz_ldap.html>
- Apache `core` directive contexts: <https://httpd.apache.org/docs/2.4/mod/core.html> (`LimitRequestFields` is server/vhost only; `LimitRequestBody` allows directory context)
- Apache `mod_ldap` directive contexts: <https://httpd.apache.org/docs/2.4/mod/mod_ldap.html> (the `LDAP*` cache/trust directives are server-scope)
- Apache `mod_ssl` `SSLCipherSuite`: <https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslciphersuite> (TLS 1.3 suites need the `TLSv1.3` prefix)
- MIT `kinit` manual: <https://web.mit.edu/kerberos/krb5-1.21/doc/user/user_commands/kinit.html>

> **Note on the companion document:** [RESEARCH.md](RESEARCH.md) §6.4 still says Pi caches `!command` output for the process lifetime. Its own §14.4 — and [§6.4](#64-pi-and-the-shim) above — supersede that: model-config commands are resolved per request, while `auth.json` commands are cached.

---

## 16. Revision notes: what upstream verification changed

| # | v1 assumption | Verified reality (v2) | Source |
|---|---|---|---|
| 1 | Key only via `--api-key` argv | `--api-key-env NAME` exists, refuses empty/unset; shipped compose uses it | `GUIDE.md` §6.6, flags table |
| 2 | Bootstrap as a sibling container | IPA image runs systemd and self-installs from `/data/ipa-server-install-options`; bootstrap must `docker compose exec` into it; privileged is unsupported | `freeipa-container` README, Dockerfile |
| 3 | `--host`, seccomp, UID/GID guessed | Upstream compose uses host networking, `user: UID:GID`, `memlock: -1`, and a dedicated seccomp profile; default Docker seccomp blocks radiance startup | `deploy/compose/common.yaml` |
| 4 | Streaming KV could rescue 200k | `--kv-resident` **does not support** Qwen3.5/3.6/3.8 dense; ignored with a warning | `GUIDE.md` §4.4.1 |
| 5 | 200k likely impossible on one card | Hybrid model; measured 2-card fp8 pool 518,800 tokens; `fp8_v4`/`k6_v4` add 28%/46%; 200k plausible but must be measured | `GUIDE.md` §4.4 |
| 6 | `--mm-max-patches` irrelevant | `0` serves text only and keeps the tower off the card; `--served-model-name` fixes the model id | flags table, §6.6 |
| 7 | LDAP bind as a normal user | Use `cn=sysaccounts,cn=etc` (`ipa sysaccount-add`), not `cn=users` | FreeIPA Apache authz page, `sysaccounts.py` |
| 8 | `ipa-getkeytab` rotation unclear | Default generates a new key (new kvno); `-r` retrieves existing; `-e` pins enctypes | `client/ipa-getkeytab.c` |
| 9 | Cert issuance hand-waved | `ipa cert-request --principal … --chain`; `ipa cert-show SERIAL --out FILE --chain` | `cert.py` |
| 10 | Pi header command could carry Negotiate | Headers are resolved uncached per request, **but** Pi passes `apiKey` to the OpenAI SDK, which emits Bearer; custom Authorization can be clobbered | `resolve-config-value.ts`, `provider-composer.ts`, `openai-completions.ts` |
| 11 | Apache authz config untested | `GssapiLocalName On` + `AuthLDAPURL ?uid` + `Require ldap-group` is a known working pattern; `GSS_NAME`/`GSS_MECH` expose full principal/mech | mod_auth_gssapi README, issue #240 |
| 12 | Whole `/v1` proxied | radiance has LoRA/admin/media routes behind the same key; edge must allowlist chat/models only | `GUIDE.md` §6.6, route list |
| 13 | `kinit --password-file` | MIT `kinit` has no such flag; pipe the password on stdin | MIT kinit manual |
| 14 | FreeIPA DNS in Compose | Default installer path (unattended, no `--setup-dns`) leaves DNS out; explicit KDC config + aliases is simpler | installer source, container README |

**v3 update:** the bootstrap now runs in the one-off `bootstrap` container sharing the IPA network namespace (not `docker compose exec` into the long-lived `ipa` service), so the bootstrap secrets never persist in the IPA container.

---

## 17. Revision notes: v3 security and correctness fixes

This revision fixes the issues found in the security/correctness review of v2.

| # | v2 issue | v3 fix |
|---|---|---|
| 1 | `SSLCipherSuite` listed only TLS 1.3 names without the `TLSv1.3` prefix; OpenSSL rejects the list and httpd exits at startup | `SSLCipherSuite TLSv1.3 …` (§6.2, U18) |
| 2 | `LimitRequestFields` was inside `<LocationMatch>` (server/vhost only) | moved to server scope (§6.2) |
| 3 | `LDAPTrustedGlobalCert`/`LDAPVerifyServerCert`/`LDAPCacheTTL`/`LDAPCacheEntries` were inside `<LocationMatch>` (server-scope only) | moved to server scope; only `AuthLDAP*` remains in the location (§6.2) |
| 4 | Keytab stated as `0400` without owner; mod_auth_gssapi reads it per request | keytab `0400 www-data`; U25, T15 |
| 5 | Edge waited for `/data/.bootstrap-complete`, which was not mounted | marker moved to `/data/certs/.bootstrap-complete` (visible via `/certs`) (§5.4) |
| 6 | Radiance flags duplicated in compose `command:` and the §6.3 entrypoint | entrypoint reduced to secret export + `exec "$@"`; compose is the single source |
| 7 | `pi-client` mounted the repo (`./:/work`), the certs dir, and the ccache | dedicated `work/`; CA file only in the shim; no ccache/certs/IPA data in `pi-client` (shim token only) |
| 8 | Agent ran as root with no hardening | `${PI_UID}:${PI_GID}`, `cap_drop: ALL`, `no-new-privileges`, read-only rootfs, `shim-net` only |
| 9 | Shim, agent, and kinit were one container | split into `pi-login`, `radiance-shim`, `pi-client`; `shim-net` internal |
| 10 | Test runner mounted the repo root and the whole certs dir, and had the admin password with no IPA dependency | `tests/`/compose/scripts only, CA file only; `depends_on: ipa`; mallory secret |
| 11 | Admin and Directory Manager shared one password; secrets stayed in the IPA container | separate `ipa_admin_password`/`ipa_dm_password`; one-off `bootstrap` container; `ipa` service has no secrets |
| 12 | Installer argv exposure described as container-only | documented as host-wide `ps` exposure, one-off, rotated (RR7) |
| 13 | KDC/edge published on `0.0.0.0` | `${BIND_ADDR:-127.0.0.1}` for 88/464/8443 |
| 14 | Engine seccomp defaulted to `unconfined`; no `cap_drop` | `RADIANCE_SECCOMP` required; `cap_drop: [ALL]` |
| 15 | Compose secrets 0444 used for long-lived passwords | file mounts `0600`/`0400` for edge/engine; Compose secrets only for bootstrap/test |
| 16 | `Timeout 600` would truncate long streams | `ProxyTimeout 3600` |
| 17 | `mallory` had no password; T4 could not run | `secrets/mallory_password` provisioned in bootstrap/up.sh |
| 18 | Host-mode Pi had no resolution step; ccache path was relative | `/etc/hosts` documented; ccache path fixed to `run/ccache/krb5cc` |
| 19 | No `.gitignore` deliverable despite claiming `secrets/`/`run/` are ignored | `.gitignore` added as a P0 exit criterion |
| 20 | T12 allowed "else documented risk"; T14/nmap and "no added caps" expectations were wrong | T12 is a hard 401 gate; T14 split into T14/T14b; nmap and cap expectations corrected |
| 21 | Shim started "if absent" and rewrote the token → race | shim is a compose service; it creates the 0600 token; `pi-krb run` waits for it |
| 22 | `pi-client` had no `user:`; host-mode files became root-owned | UID/GID on all Pi containers; `up.sh` chowns `run/ccache`, `run/pi-agent`, `work/` |
| 23 | `Require method` version claim was speculative | corrected to "2.4 core provider; verify on the pinned image" |
| 24 | RESEARCH §6.4's "cached for process lifetime" contradicted §14.4 | noted as superseded in §15; companion file left untouched for this revision |

**Verification still required:** the vhost must pass `apachectl -t` on the pinned httpd; the keytab-permission and TLS 1.3 cipher points are based on mod_auth_gssapi/mod_ssl source and OpenSSL behaviour, not on a run of this stack. The container/UID/ownership changes need the full integration suite (T1, T14b, T23–T25) on a clean host.
