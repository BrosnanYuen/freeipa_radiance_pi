# Deliberate deviations from PLAN.md

Every difference is listed so the plan and the code do not silently diverge.

| # | PLAN says | Implemented | Why |
|---|---|---|---|
| 1 | Pi 1.0 pinned | Pi **1.4.0** (current npm release at implementation), integrity `sha512-…` verified at image build | 1.0 is no longer the published package; the `models.json` contract used here is unchanged |
| 2 | Bare `Require valid-user` + `Require ldap-group` | Wrapped in `<RequireAll>` | Apache can merge sibling `Require` directives with OR semantics, which would let any valid principal through; T4 asserts 403 for `mallory` |
| 3 | `bootstrap` has `tmpfs: [/tmp, /run]` | Only `/tmp` | Compose mounts secrets under `/run/secrets`; a `/run` tmpfs would hide them |
| 4 | Installer options template without `--no-host-dns` | No `--no-host-dns`: it is a replica/KRA option, not a server-install option on the pinned image | The image's `verify_fqdn` logs a reverse-lookup warning but proceeds; passing an unknown option would abort `ipa-server-install` |
| 5 | `GssapiNegotiateOnce` unverified | Kept, verified valid in `<Location>` context on the pinned module (`apachectl -t` passes) | It avoids repeated 401 challenges; not valid at server scope |
| 6 | Shim "ASGI/FastAPI-style" implied by the plan's tests section | Stdlib `http.server` implementation | No third-party runtime dependency, easier to unit-test, and full control of SSE chunking |
| 7 | Mock uses FastAPI | Stdlib mock | Same reason; the test image installs no web framework |
| 8 | `pi-krb run` writes `models.json` from a template | Generated in `pi_krb.build_models_config` | One code path, schema-validated by U13; no placeholder substitution bugs |
| 9 | Shim `/healthz` readiness gate | `/healthz` returns 200 with `ready`/`ccache`/`token` booleans; `pi-krb run` requires `ready` and `token` | A Compose liveness probe must not restart the shim before the user runs `kinit`; the client still refuses to start without credentials |
| 10 | Test runner mounts tests and compose only | Also mounts `deploy/` (read-only) and `run/pi-agent` (read-only) | Static contract tests and shim-token tests run inside the same image |
| 11 | `testssl.sh` in the security suite | Python `ssl` + `openssl s_client` checks | No extra dependency; equivalent TLS-version, cipher, chain and header assertions |
| 12 | T5 (wrong keytab) and T16 (rotation) in the PR suite | Implemented as host tests gated by `RUN_DESTRUCTIVE=1`; T4b/T10 gated by `RUN_SLOW=1` | They restart or mutate the live edge; running them in the default suite would make it flaky and destructive. All four have been exercised against the live stack |
| 13 | P6 native GSSAPI in radiance (2–3 weeks) | **Deferred** | The plan marks it optional and it requires modifying radiance itself (outside this repository); the edge is the MVP boundary |
| 14 | E0 measured in this build | Procedure and record template only | No `.rad` model was available in the implementation environment; never advertise an unmeasured context |
| 15 | `.env.example` GIDs as blanks | Host-specific defaults (`989`/`985`) | They match the implementation host; the file says to run `getent group` and change them |
| 16 | Install-options argv exposure RR7 | Kept, documented | The installer receives the passwords through the upstream image's supported options file; the file is shredded and passwords are rotated |
| 17 | `models.json` `maxTokens` 16384 | `min(16384, max(1024, context/4))` | Avoid advertising more output tokens than the context can hold |
| 18 | Test IDs all in one suite | Unit (U1–U25), integration (T1–T25), security, and host suites | Host-only checks need Docker access, which the test-runner deliberately does not have |
| 19 | `pi-krb` shim token path always `/agent/shim-token` | Container default `/agent/shim-token`; host default `run/pi-agent/shim-token` via `--token-file` | Host mode has no `/agent` mount |
| 20 | `pi-krb` login password automation unspecified | `--password-stdin` for tests/automation; interactive `kinit` otherwise | MIT `kinit` has no `--password-file`; stdin is the verified mechanism |
| 21 | Bootstrap reads `/etc/ipa/ca.crt` from inside the one-off container | `scripts/copy-ipa-client-config.sh` stages `/etc/ipa/ca.crt` and `/etc/ipa/default.conf` from the running IPA server into `run/ipa-client/` and mounts them into the bootstrap | A separate container does not inherit the server's rootfs; without these the `ipa` CLI cannot verify TLS or find the realm. Neither file is a secret |
| 22 | cgroup override only if needed | `cgroup: host` and a writable `/sys/fs/cgroup` are in the base Compose file | On this cgroup-v2 host the IPA container otherwise exits during systemd boot (observed); upstream documents the same override. It is not privileged |
| 23 | Options file lives in `/data` and the host shreds it | Created before the first start; removed with `docker exec … shred` after installation | `populate-volume-from-template` makes `/data` root-owned, so host-side writes/removals after the first start are not reliable |
| 25 | `ipa service-add` without a DNS check | `ipa service-add --force` | This stack deliberately has no integrated DNS, so the host object has no A/AAAA record. On 4.13.4 `--force` skips the DNS check; `--skip-host-check` only covers the host-object check |
| 37 | `LDAPCacheTTL 60` bounds revocation | Also `LDAPOpCacheTTL 60` (operation cache) | Group membership is cached by mod_ldap's **operation** cache, whose default is 600 s; with only `LDAPCacheTTL` set, a removed member stayed authorized for minutes (verified). Both caches now expire at 60 s |
| 36 | `pi-krb` forwards unknown Pi flags verbatim | `allow_abbrev=False` on every parser and subparser | Argparse abbreviated Pi's `--mode` to `pi-krb`'s `--model`, swallowing the flag (Pi then ran text mode). Disabling abbreviations preserves all Pi flags |
| 35 | `LimitRequestBody` enforces the size | `LimitRequestBody` remains, but `mod_rewrite` returns 413 when `Content-Length > 16 MiB` and 411 for chunked bodies | mod_proxy streams bodies past `LimitRequestBody` (verified: a 17 MB body reached the mock with 200/400). The rewrite phase sees the header before proxying |
| 34 | Test-runner runs as root | Runs as `${PI_UID}:${PI_GID}` | Compose ignores secret `mode` outside Swarm and mounts the host 0600 files owned by that UID; the test-runner drops all capabilities, so root cannot read them. Non-root also matches the least-privilege design |
| 33 | Authorization failure status | `AuthzSendForbiddenOnFailure On` | Otherwise Apache returns 401 for an authenticated principal outside `ai-users`; T4 expects 403 so callers can distinguish "bad credentials" from "not authorized" |
| 32 | Shim service name `HTTP/radiance.ipa.test` passed to GSSAPI as-is | `TokenProvider.hostbased_name()` converts to `HTTP@radiance.ipa.test` | GSSAPI host-based names use `service@host`; passing the principal spelling made python-gssapi build a malformed target (`HTTP/radiance.ipa.test/radiance.ipa.test@IPA.TEST`) |
| 31 | mod_ldap uses `/certs/ca.crt` directly | The edge copies the CA to `/run/radiance/ca.crt` 0644; `LDAPTrustedGlobalCert` and `LDAPTLS_CACERT` use that | `/certs` is a 0700 root bind mount; Apache workers run as www-data and could not read the CA, so every LDAPS/StartTLS bind failed with "TLS: could not use CA certificate file" (found with LDAPLibraryDebug) |
| 30 | LDAP search base `dc=ipa,dc=test` | `cn=users,cn=accounts,dc=ipa,dc=test` | FreeIPA exposes the same user in the **compat tree** (`cn=users,cn=compat`) and the accounts tree; a domain-root search matched both, and mod_authnz_ldap refused the non-unique result. The accounts subtree has exactly one match |
| 29 | Replay cache location default | `KRB5RCACHEDIR=/tmp` for the edge | `/var/tmp` is read-only in the read-only-rootfs edge, so GSSAPI accept failed with "Read-only file system" until the cache was moved to tmpfs. A shared `/tmp` also makes replay detection cross-worker rather than per-process |
| 28 | Container file modes unspecified | Dockerfiles chmod copied source read-only for non-root users (`mock` runs as 65534; the Pi image runs as `PI_UID`) | Files created with a restrictive umask would otherwise be unreadable by the container user |
| 27 | Edge starts via `apache2ctl` | Edge starts `/usr/sbin/apache2` directly with `APACHE_*` environment set | Debian's `apache2ctl` sources `/etc/apache2/envvars`, which unconditionally forces `/var/log`, `/var/run`, `/var/lock`; those are read-only in this container. Direct `apache2` uses the writable tmpfs paths. `apache2 -t` remains the config gate |
| 26 | Edge capabilities: CHOWN, SETGID, SETUID, DAC_OVERRIDE | Also `FOWNER`, and the entrypoint removes the old keytab before installing | Without FOWNER the edge cannot replace a keytab that a previous run already chowned to `www-data`; this is needed for restarts and rotation |
| 24 | No delegation anywhere | The one-off bootstrap uses `kinit -f admin` and destroys the ccache at the end; user tickets stay non-forwardable (`kinit -F`) and the edge never delegates | FreeIPA's JSON API session delegates the admin TGT server-side; without a forwardable ticket every `ipa` CLI session returns 401 (verified live). The admin ticket exists only in the ephemeral bootstrap container |

## Not implemented (explicitly out of scope)

- P6: native `Authorization: Negotiate` validation inside radiance.
- Production FreeIPA (replicas, integrated DNS, backups, certificate profiles
  beyond `caIPAserviceCert`).
- Per-user quotas/chargeback; the plan lists these as a later gateway.
- Model conversion, quantisation, or licence review of individual weights.
- A GUI/dashboard. radiance's dashboard is deliberately not proxied.
