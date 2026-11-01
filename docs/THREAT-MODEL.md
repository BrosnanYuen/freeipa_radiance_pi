# Threat model

Scope: the Compose development/test stack in this repository. Production
deployments need the same controls plus host hardening, backups, and a real
replication topology for FreeIPA.

## Assets

1. The user's TGT and ccache (`run/ccache/krb5cc`).
2. The edge keytab for `HTTP/radiance.ipa.test`.
3. The IPA admin and Directory Manager passwords (bootstrap only).
4. The LDAP bind password and the radiance engine API key.
5. Model prompts and responses in transit.
6. The IPA LDAP/Kerberos/CA services.

## Trust boundaries

- **User → `pi-login`/`radiance-shim`**: same UID, shared ccache. The ccache is
  0600 and mounted only into those two containers.
- **Pi → shim**: internal `shim-net` (no egress) plus a 0600 bearer token that
  is re-read per request.
- **Shim → edge**: TLS 1.3 verified against the IPA CA; a fresh GSSAPI context
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
| Stolen keytab | 0400 `www-data` in tmpfs; minimal keytab; rotation script | T15, T16 |
| Secret leakage in argv/logs | Files not argv; `--api-key-env`; JSON audit without tokens/bodies; password stdin to kinit; installer argv window documented | T15 |
| DoS by large/slow requests | `LimitRequestBody`, field/worker/timeout limits, `ProxyTimeout 3600` | T17 |
| Local user steals the shim | Internal `shim-net`; random 0600 token; per-user state dir | T20 |
| Agent compromise or prompt injection | `pi-client` has only `work/` and `run/pi-agent`; `cap_drop: ALL`; read-only root; no Docker socket; no route to IPA/edge | T23, T24 |
| Agent edits the host stack | `work/` is a dedicated directory; the repo, compose file, scripts and `.git` are not mounted | U22 |

## Residual risks

| # | Risk | Why accepted | Mitigation |
|---|---|---|---|
| RR1 | The engine has no authentication | Edge is the boundary | Phase 6 native GSSAPI if required |
| RR2 | One shared engine API key | Engine has no user model | Edge-only reachability; rotation; 0400 file |
| RR3 | Loopback trust between edge and engine | Engine has no TLS | Same network namespace; read-only; private key |
| RR4 | LDAP cache staleness (≤60 s) | Performance | `LDAPCacheTTL 60` and `LDAPOpCacheTTL 60`; T4b verifies revocation after the window |
| RR5 | GSSAPI replay detection across workers | Replay cache is per-process unless shared | T12 requires 401; a cross-worker acceptance is a design failure, not a waiver |
| RR6 | Pi tools run as the invoking user | Harness design | Dedicated `work/`; no ccache/keytab in the agent; `cap_drop`; HBAC |
| RR7 | Installer passwords briefly in host `ps` | The image passes the options file to `ipa-server-install` | One-off window; file shredded; both passwords rotated |
| RR8 | The shim is a credential oracle for the same UID | It is the intended delegation point | Internal network; 0600 token; per-request auth |
| RR9 | The admin password is readable by the one-off bootstrap and test runner | Needed for realm automation | Compose secrets only in those short-lived/trusted containers; rotate after bootstrap |

Out of scope: KDC host compromise, hardware attacks, GPU driver side channels,
model-operator prompt privacy, and a compromised Docker daemon.

## Security invariants enforced by tests

- No private key material is committed; `.env.example` never carries a secret.
- `pi-client` mounts only `work/` and its agent directory and is attached only
  to `shim-net`.
- The long-lived `ipa` service mounts no bootstrap secrets.
- The edge keytab is `0400 www-data`; the rendered vhost is `0600`.
- The edge proxies only the three allowlisted paths.
- The audit log records the full principal and mechanism, never tokens,
  Authorization headers, prompts or responses.
