# TODO

**Status snapshot (2026-11-01):** P0–P5 are implemented. The real MXFP4 model
is downloaded and hash-verified, E0 admits 197,952 tokens on one R9700, T11 and
T11b pass, and a 10-turn Pi session runs on the real engine. P6 (native GSSAPI
in radiance) is not pursued; `radiance-gateway` is the front door. Production
IPA topology/restore is the remaining external item.
On 2026-11-01 every long-lived credential was rotated against the live realm,
T13/T17 were added, host-mode Pi completed ten turns, the CI linters/scanners
and SBOM path were added, and the capacity and model-licence gates were made
fail-closed.

**Verified on this host:** 127 repository unit tests, 38 integration/security
tests, 11 non-destructive host tests, 5 destructive rotation tests, and a
10-turn host-mode Pi session. The new `radiance-gateway` passes 7 gateway unit
cases, 38 integration/security tests with the mock engine, 36 with the real
engine, plus the T11 197,952-token prompt through the gateway (145.8 s), TLS,
replay, slow-header and 100-concurrent checks. `make gateway-check`, `make config`,
yamllint, hadolint, gitleaks and trivy-config pass with the committed configs.

**Still pending:** the production IPA replica/upgrade/clean-host work. The
E0/T11/T11b/GPU items, gateway behavior/latency and a containerized
data-restore rehearsal are measured and recorded in `docs/measurements/`.

Items are ordered by what blocks a production or external-use claim. `[x]`
means done and verified on 2026-11-01 unless noted.

---

## P0 — Blocking commercial/external use

### 1. Capacity gate E0 (one R9700, 200k context)

- [x] Make the code fail closed: shipped defaults are `RADIANCE_CONTEXT_WINDOW=32768`
      and `CAPACITY_MEASURED=0`; `up.sh --gpu` refuses to start until measured.
- [x] Keep the E0 procedure and measurement table in [docs/CAPACITY.md](docs/CAPACITY.md).
- [x] Downloaded `qwen3.8-27b-mxfp4.rad` to `run/models/rad` (18.04 GiB), verified
      SHA-256 `a4908940…df4f8`, and recorded the licence/provenance beside it.
- [x] Booted with `--debug-placement`; captured the `kv:` receipt: **M = 1.0**,
      100% of the 200k worst case, 6.25 GiB KV pool.
- [x] Tokenized and admitted a **197,952-token** prompt (HTTP 200, 197,984 total).
- [x] Measured cold TTFT **145.356 s** (1,361.8 tok/s prefill), decode **23.8 tok/s**,
      peak VRAM **20.58 GiB**; warm TTFT 1.746 s with 196,608 prefix-cached tokens.
- [x] Filled [docs/CAPACITY.md](docs/CAPACITY.md) and
      [docs/measurements/E0-2026-11-01.md](docs/measurements/E0-2026-11-01.md);
      set `RADIANCE_CONTEXT_WINDOW=200000` and `CAPACITY_MEASURED=1`.
- **Exit (met):** real numbers recorded; the GPU gate passes for the measured
  value. No unmeasured 200k code default remains.

### 2. Real-model GPU integration

- [x] The `gpu` profile, seccomp profile, entrypoint and flags are wired; the
      seccomp checksum is pinned and unit-tested.
- [x] `./scripts/up.sh --gpu` succeeds on the R9700; the engine reports gfx1201
      and serves with the required seccomp profile.
- [x] `/v1/models` lists `qwen3.8-27b`; streaming, tool calls and reasoning work
      through the authenticated gateway (Pi P1/P2 and T7/T8).
- [x] T11 near-200k passes through the gateway; T11b passes for `fp8_v4`
      (3/3 retrieval, exact match vs fp8, mean top-5 KL 0.00017 nats).
- [x] Confirmed the seccomp profile is sufficient (the engine loaded 15.64 GiB and
      served without a permission failure).
- [x] `--num-speculative-tokens 0` starts without the drafter path; the placement
      receipt shows no expert plane and the card fits.
- [x] Ten-turn Pi session on the real model (P3 `--continue`, 10 turns) and the
      tool-using P1 pass.
- **Exit (met):** a 10-turn, tool-capable Pi session on the real model; the
  gateway replaces the native-auth phase (§12).

### 3. Model-licence inventory (E7)

- [x] Fail-closed `model-licenses.json` gate + `scripts/check_model_licenses.py`,
      enforced by `up.sh --gpu` and `make license-check`; unit-tested.
- [x] Policy and manifest format documented in
      [docs/MODEL-LICENSES.md](docs/MODEL-LICENSES.md).
- [x] Recorded the Apache-2.0 decision for `qwen3.8-27b-mxfp4.rad`, with the
      upstream `LICENSE`, model card, recipe and `PROVENANCE.md` beside the file.
- **Exit (met for the supplied model):** every available model has a recorded decision.

---

## P1 — Production hardening

### 4. Rotate bootstrap credentials after realm creation

- [x] Admin password rotated (with an expiry clear; `--force` handles FreeIPA's
      1-hour `minlife` and restores the policy while authenticated).
- [x] Directory Manager password rotated via `ldapi://` + SASL EXTERNAL.
- [x] LDAP bind password rotated; the gateway recreated and an authenticated request
      verified; rollback tested.
- [x] Engine API key rotated with the 0400 mode preserved; gateway/engine recreated.
- [x] Keytab and TLS key/certificate rotated; the old certificate serial was revoked
      and the old key shredded.
- [x] Scripts, last-rotation dates and ownership recorded in
      [docs/SECRETS.md](docs/SECRETS.md).
- **Exit (met):** no long-lived password remains the one generated by the first
  `up.sh`; each rotation has a tested procedure.

### 5. FreeIPA production topology

- [x] Decision recorded: Compose remains the development/CI realm; production is an
      externally operated realm with DNS/SRV, a replica, backups and NTP/chrony.
- [x] Online data backup script (`scripts/backup-ipa.sh`) tested; restore procedure
      documented in RUNBOOK §9.
- [x] **Containerized data-restore rehearsal passed**: a fresh isolated FreeIPA
      container restored the 07:12 backup; `pi`, `ai-users` membership and the
      radiance SPN verified. See
      [measurements/IPA-RESTORE-2026-11-01.md](docs/measurements/IPA-RESTORE-2026-11-01.md).
- [ ] **BLOCKED (infrastructure):** a true clean-host restore needs a separate
      host; this rehearsal shares the host kernel and Docker.
- [ ] **BLOCKED (infrastructure):** `ipa-server-upgrade` on the restored copy
      failed at `pki-tomcatd` startup; no newer image was available. Replicas need
      a second host, DNS/SRV and root.
- **Exit (partially met):** data restore is rehearsed; production topology,
  replica promotion and a version upgrade remain.

### 6. Secret/certificate lifecycle

- [x] Keytab rotation scheduled by `deploy/systemd/` (weekly user timer, documented).
- [x] TLS certificate renewal script tested (new key/CSR/cert, old serial revoked).
- [x] LDAP bind password and API key rotation scripts tested with rollback.
- [x] Secrets-owner/rotation table with dates and owner in
      [docs/SECRETS.md](docs/SECRETS.md).
- **Exit (met):** each rotation has a tested procedure and a recorded date.

### 7. Per-user identity, quotas and audit retention

- [x] Decision recorded: the v1 MVP keeps one shared engine key and does **not**
      require per-user quotas or chargeback. The documented path if that changes is
      a federated gateway (Keycloak + `oauth2-proxy`) or another authenticated
      front door.
- [x] Audit scope remains authentication events (full principal, path, status,
      duration, TLS metadata); no prompts/tokens/bodies.
- [ ] **DEFERRED:** durable audit shipping and alerting for repeated 401/403 or
      keytab/LDAP failures. Not required while quotas are out of scope.
- **Exit (met for v1):** a documented decision; no quota implementation is needed.

---

## P2 — Test gaps

### 8. Clock-skew test (T13)

- [x] Uses `faketime` in the test image; asserts a normal request is 200 and a
      +10 minute client is 401.
- **Exit (met):** `tests/integration/test_robustness.py` passes.

### 9. Remaining performance/negative tests

- [x] T17 slow-header: the gateway enforces a 10 s header read timeout and the
      test observes a bounded close in about 10 s.
- [x] 100 concurrent authenticated requests: all 200 (mock).
- [x] `testssl.sh`: the Python/OpenSSL substitute is the accepted replacement
      (DEVIATIONS #11); the TLS suite passes.
- [x] T11b: `fp8_v4` retrieval 3/3, exact outputs vs fp8, 22/22 token agreement,
      mean top-5 KL 0.00017 nats ([measurement](docs/measurements/T11b-2026-11-01.md)).
- **Exit (met):** results recorded; the GPU and gateway paths are covered.

### 10. Host-mode Pi

- [x] Host Pi 1.4.0 via `npx` and a loopback-published shim completed 10 turns
      with `--continue` (`scripts/host-pi-smoke.sh`, `make host-pi`).
- [x] Token resolution (`!cat`), token path, shim URL and ccache reuse verified;
      three turns are in `tests/host/test_host_pi.py` under `RUN_E2E=1`.
- [x] The user's `~/.pi` and `/etc/hosts` are not modified by the test path.
- **Exit (met):** a documented 10-turn host-mode session.

### 11. CI

- [x] Added yamllint, hadolint, gitleaks, trivy config, trivy image (fixable
      CRITICAL gate + HIGH report), and SPDX SBOM artifacts for four images.
- [x] All workflows pass `actionlint`; all scanners pass locally with the committed
      configs.
- [x] **N/A (owner request):** GitHub integration is ignored; the workflow and
      local scanner/CI commands are validated locally.
- [x] **OUT OF SCOPE:** nightly GPU job; the GPU is explicitly lab-only until a
      self-hosted runner exists. The GPU suite was run manually on the real model.
- **Exit (met for the owner scope):** workflows/scanners are validated locally;
  GitHub is explicitly out of scope.

---

## P3 — Optional / deferred

### 12. P6: native GSSAPI in radiance — not pursued

- [x] **UNDONE:** the radiance source/patched image and the P6 patch, overlay,
      keytab helper and direct-auth tests were removed. The pinned radiance
      image is unmodified.
- [x] Replaced by `radiance-gateway`: a separate Kerberos proxy in front of the
      unmodified engine. The engine keeps its private API key and is reachable
      only from the gateway's network namespace.
- **Exit (met by the gateway):** Kerberos authentication and IPA group
  authorization happen in front of radiance without changing radiance.

### 13. Operational niceties

- [x] `make reset` deletes `run/ipa-data` only after typing `RESET` and only while
      the stack is down.
- [x] `make up-gpu` runs `scripts/smoke-engine.sh --gpu`, waits for the model and
      prints the last 50 engine log lines on failure; the mock variant is
      `make smoke` and was exercised against the live stack.
- [x] First `up.sh`/`make env` detects this host's UID/GIDs (including render/video)
      via `scripts/render_env.py`; unit-tested.
- [x] Root-owned `run/ipa-data` workarounds remain documented in RUNBOOK §1/§2.
- [x] Pi pin revisited: npm's current release is still 1.4.0 and matches the pinned
      integrity; host and container E2E pass. RESEARCH §14.6 records this.
- **Exit (met):** the operational gaps above are closed or explicitly lab-only.

### 14. Documentation follow-ups

- [x] DEVIATIONS updated with rotation, timeout, concurrency, licence, capacity,
      scanner, host-mode, backup and gateway changes.
- [x] `radiance-gateway` (Python 3.11, python3-gssapi 1.8.2, python3-ldap
      3.4.3), FreeIPA 4.13.4 and Pi 1.4.0 recorded in RUNBOOK §10.
- [x] Keytab-rotation client note added (re-login clears cached service tickets).
- [x] Auth/proxy latency through the Python gateway under keep-alive load:
      **p50 6.51 ms, p95 7.14 ms** over 50 requests, inside the p50 <10 ms /
      p95 <25 ms budget. The old Apache-edge 1.77/2.22 ms figure is retired.
- **Exit (met):** docs match the implementation.

---

## Open decisions — resolved for v1

1. **P6 vs gateway:** native GSSAPI in radiance is not pursued. A separate
   gateway owns Kerberos authentication, so radiance stays unmodified.
2. **Hardware:** 200k is measured (197,952-token admission, `M = 1.0`); no ladder
   was needed. The code refuses an unmeasured value by default.
3. **Identity:** Compose-managed realm for dev/test; externally operated FreeIPA
   with replicas/DNS for production.
4. **Quotas:** not required in v1; revisit with a Keycloak/`oauth2-proxy` gateway.
5. **Audit:** authentication/authorization events only in v1; no chargeback data.
6. **Host mode:** supported and tested with the pinned Pi via `npx` + loopback shim.

## Remaining work

1. **Gateway:** keep `radiance-gateway` as the single Kerberos front door;
   delete or archive the unused `deploy/edge` legacy tree once its vhost unit
   test is retired.
2. **Production IPA:** replicas, integrated DNS and an upgrade rehearsal need a
   second host, DNS control and root/sudo. A containerized data-restore rehearsal
   is recorded in `docs/measurements/IPA-RESTORE-2026-11-01.md`; a true
   clean-host rehearsal still needs a host.
3. A per-model licence decision for any further container added to the directory.
