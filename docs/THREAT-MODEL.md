# Threat model

Scope: the Compose development/test stack in this repository. Production
deployments need the same controls plus host hardening, backups, and a real
replication topology for FreeIPA.

## Assets

1. The user's TGT and ccache (`run/ccache/krb5cc`).
2. The gateway keytab for `HTTP/radiance.ipa.test`.
3. The IPA admin and Directory Manager passwords (bootstrap only).
4. The LDAP bind password and the radiance engine API key.
5. Model prompts and responses in transit.
6. The IPA LDAP/Kerberos/CA services.

## Trust boundaries

- **User → `pi-login`/`radiance-shim`**: same UID, shared ccache. The ccache is
  0600 and mounted only into those two containers.
- **Pi → shim**: internal `shim-net` (no egress) plus a 0600 bearer token that
  is re-read per request.
- **Shim → gateway**: TLS 1.3 verified against the IPA CA; a fresh GSSAPI context
  per request; one retry on 401.
- **Edge → IPA**: LDAPS with certificate verification and a dedicated system
  account `uid=svc-radiance,cn=sysaccounts,cn=etc`.
- **Edge → engine**: loopback inside a shared network namespace, with the
  engine's private API key; no published port.
- **Engine → GPU**: host devices, fixed UID/GID, read-only root, required
  seccomp profile.

## Threats and controls

| Threat | Control | Test |
|---|---|---|
| Eavesdrop prompts | TLS 1.3 only; HSTS; no TLS 1.2 | T6, T18 |
| Steal user credentials | No TGT/keytab/cert in `pi-client`; ccache only in `pi-login` and the shim, 0600; `kinit -F`, 8 h lifetime | T1, T23 |
| Replay a Negotiate header | GSSAPI replay cache, 300 s clock skew, TLS | T12 (hard gate) |
| Forged service | Keytab-only decryption; `GssapiAcceptorName`; IPA-issued TLS cert | T5 |
| Valid ticket, wrong user | `RequireAll` of `valid-user` and `ldap-group ai-users` | T4 |
| Authorized user calls admin/LoRA/media | Exact-path allowlist; `Require all denied` elsewhere; shim also allows only three paths | T18b |
| Direct engine access | No port, no alias; shared netns loopback; private API key | T14 |
| Stolen keytab | 0400 `gateway` in tmpfs; minimal keytab; rotation script | T15, T16 |
| Secret leakage in argv/logs | Files not argv; `--api-key-env`; JSON audit without tokens/bodies; password stdin to kinit; installer argv window documented | T15 |
| DoS by large/slow requests | `LimitRequestBody`, field/worker/timeout limits, `ProxyTimeout 3600` | T17 |
| Local user steals the shim | Internal `shim-net`; random 0600 token; per-user state dir | T20 |
| Agent compromise or prompt injection | `pi-client` has only `work/` and `run/pi-agent`; `cap_drop: ALL`; read-only root; no Docker socket; no route to IPA/gateway | T23, T24 |
| Agent edits the host stack | `work/` is a dedicated directory; the repo, compose file, scripts and `.git` are not mounted | U22 |
| Stale credential after exposure | Rotation scripts for admin, DM, LDAP bind, API key, keytab and TLS key/cert; each verifies the replacement and writes in place | Host rotation suite (`RUN_DESTRUCTIVE=1`) |
| Undocumented model licence | `model-licenses.json` gate; `up.sh --gpu` fails closed | Unit tests + `make license-check` |
| Unmeasured context advertised | 32,768-token development default and `CAPACITY_MEASURED=1` gate | `make unit` compose contract |

## Residual risks

| # | Risk | Why accepted | Mitigation |
|---|---|---|---|
| RR1 | The engine has no native user authentication | The gateway is the boundary | Gateway enforces Kerberos; engine is loopback-only in its namespace |
| RR2 | One shared engine API key | The gateway is the only client; engine has no user model | Gateway-only reachability; rotation; 0400 file |
| RR3 | Loopback trust between gateway and engine | Engine has no TLS | Same network namespace; read-only; private key |
| RR4 | LDAP cache staleness (≤60 s) | Performance | `LDAPCacheTTL 60` and `LDAPOpCacheTTL 60`; T4b verifies revocation after the window |
| RR5 | GSSAPI replay detection across workers | Replay cache is a file cache; processes must share `KRB5RCACHEDIR` | Gateway sets `KRB5RCACHEDIR=/tmp`; one process serves all worker threads |
| RR6 | Pi tools run as the invoking user | Harness design | Dedicated `work/`; no ccache/keytab in the agent; `cap_drop`; HBAC |
| RR7 | Installer passwords briefly in host `ps` | The image passes the options file to `ipa-server-install` | One-off window; file shredded; both passwords rotated |
| RR8 | The shim is a credential oracle for the same UID | It is the intended delegation point | Internal network; 0600 token; per-request auth |
| RR9 | The admin password is readable by the one-off bootstrap and test runner | Needed for realm automation | Compose secrets only in those short-lived/trusted containers; rotate after bootstrap |
| RR10 | The Pi image contains HIGH-severity transitive npm CVEs (brace-expansion, undici, pacote, picomatch, sigstore) and an outdated ImageMagick | Pi 1.4.0 is the current npm release; no fixed package is available and the image is version-pinned for reproducibility | Not published; container runs as `PI_UID`, `cap_drop: ALL`, read-only root, no IPA secrets/ccache; CI reports HIGH and gates fixable CRITICAL; re-evaluate on each Pi release |
| RR11 | Host-mode Pi fetches the pinned release through `npx`, which trusts the npm registry's integrity metadata rather than the repository's `PI_INTEGRITY` hash | Host mode is a convenience path; the container image is the reproducible one | Use the container path when build-time integrity matters; `npx` still pins the version, and the model traffic remains bound to the Kerberos shim |

Out of scope: KDC host compromise, hardware attacks, GPU driver side channels,
model-operator prompt privacy, and a compromised Docker daemon.

## Security invariants enforced by tests

- No private key material is committed; `.env.example` never carries a secret.
- `pi-client` mounts only `work/` and its agent directory and is attached only
  to `shim-net`.
- The long-lived `ipa` service mounts no bootstrap secrets.
- The gateway keytab is `0400 gateway`; the TLS key is `0400 gateway` after the entrypoint copy.
- The gateway proxies only the three allowlisted paths.
- The audit log records the full principal and mechanism, never tokens,
  Authorization headers, prompts or responses.

## Rotation invariants

- No secret is passed in argv by the rotation scripts; passwords travel on
  stdin, and the Directory Manager path uses `ldapi://` with SASL EXTERNAL.
- A new credential is verified before `secrets/` is updated. The LDAP bind and
  API-key scripts roll back to the old value if the gateway stops authenticating;
  the certificate script restores the previous key/cert pair.
- Secret files are rewritten in place: an atomic rename would leave a
  bind-mounted gateway reading the old inode.
- The admin rotation's `--force` relaxes `minlife` only for the duration of the
  reset and restores it while the admin ticket still exists.
