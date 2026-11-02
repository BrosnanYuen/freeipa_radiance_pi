# radiance-gateway

`radiance-gateway` is the Kerberos-authenticated TLS front door for the
**unmodified** radiance image. It is a small Python service in
[deploy/gateway](../deploy/gateway); it has no dependency on radiance internals.

```
Pi / SDK ──TLS 1.3 + Negotiate──▶ radiance-gateway ──Bearer key, loopback──▶ radiance
                                      │
                                      └── LDAPS uid → user DN → member of ai-users
```

## Request path

1. TLS 1.3 only, IPA-issued certificate for `radiance.ipa.test`; HSTS and
   `nosniff` on every response; no `Server` banner.
2. Exactly one `Authorization: Negotiate` header, strict base64, one SPNEGO
   token accepted with the FreeIPA keytab. A missing/bad token is 401 with
   `WWW-Authenticate: Negotiate`.
3. The authenticated principal is checked against `cn=ai-users` over LDAPS,
   using `svc-radiance` and the IPA CA. A non-member is 403; an LDAP outage is a
   fail-closed 503. Results are cached for 60 s.
4. Only `GET /v1/models`, `POST /v1/chat/completions` and
   `POST /v1/completions` are proxied. Everything else is 403. Request bodies
   are capped at 16 MiB; chunked request bodies are refused 411.
5. The client's `Authorization` is removed. The gateway injects the private
   engine key and `X-Radiance-Principal`, and forwards SSE without buffering.
6. Audit is one JSON line per request: timestamp, full principal, peer, path,
   status, bytes, duration, TLS version/cipher. Tokens, prompts and bodies are
   never logged.

The engine is on `127.0.0.1:8000` inside the gateway's network namespace and is
not reachable from `krb-net`. The gateway itself publishes only
`${BIND_ADDR:-127.0.0.1}:8443`.

## Files and secrets

| Path | Owner/mode | Purpose |
|---|---|---|
| `/keytabs/radiance.keytab` (host) | root `0400` | FreeIPA service keytab; copied to `/run/gateway` as `gateway` `0400` |
| `/certs/radiance.crt`, `.key` | root `0644`/`0600` | IPA TLS certificate/key; copied to `/run/gateway` |
| `/secrets-src/radiance_api_key` | `RADIANCE_UID` `0400` | private bearer key injected on loopback |
| `/secrets-src/ldap_bind_password` | `0600` | `svc-radiance` LDAP bind |

The entrypoint reads the files as root, installs them for the unprivileged
`gateway` user (UID 10001), then drops to that user. It waits for
`/certs/.bootstrap-complete`, like the old edge did.

## Configuration

The image entrypoint supplies the deployment's settings:

- `--service HTTP@radiance.ipa.test` (host-based; the gateway resolves it using
  the mounted `krb5.conf`)
- `--upstream-host 127.0.0.1 --upstream-port 8000`
- `--ldap-uri ldaps://ipa.ipa.test:636 --ldap-base cn=users,...`
- `--ldap-bind-dn uid=svc-radiance,... --ldap-group cn=ai-users,...`
- `--health-port 8081 --read-timeout 10`

The gateway refuses to start on a keytab/key/password that is group/other
readable, a missing CA, a non-`ldaps://` URI, or an incomplete LDAP group
configuration.

`RADIANCE_CONTEXT_WINDOW` capacity flags stay in the radiance service
command; the gateway does not alter the model request.

## Tests

- `tests/unit/test_gateway.py` (7 cases): strict Negotiate/base64 parser, exact
  allowlist, LDAP filter escaping, principal validation, OpenAI error object,
  config file modes.
- `tests/integration/test_auth.py` T2/T3/T4/T12/T21/T22 against the gateway.
- `tests/integration/test_robustness.py` T17 slow header and 100 concurrent
  authenticated requests (gateway backlog 256, 10 s header timeout).
- `tests/integration/test_streaming.py` T7/T8/T9 SSE and tool turns.
- `tests/security/test_tls.py` TLS 1.3, chain, HSTS, no weak ciphers.
- `tests/security/test_static.py` plus `tests/unit/test_gateway.py` for the
  allowlist and header hygiene.
- `tests/host/test_topology.py` proves the engine publishes no port and the
  gateway is the only TLS surface.
- `make gateway-check` imports `gssapi`/`ldap` and compiles the module in the
  image.

Measured keep-alive auth/proxy overhead through the gateway: **p50 6.51 ms,
p95 7.14 ms** over 50 `/v1/models` requests (budget p50 <10 ms, p95 <25 ms).
The full mock suite has passed against the gateway: **38 passed, 6 skipped**
(T20 shim token included after refreshing the ccache). The real-model path has
also been exercised: `/v1/models` 200 for `pi`, 403 for `mallory`, and a chat
completion returned `gateway ok`.

## Operations

`./scripts/up.sh` starts IPA, the gateway, the mock engine and the shim.
`./scripts/up.sh --gpu` starts the real engine behind the gateway. The rotation
scripts (`rotate-keytab`, `rotate-cert`, `rotate-api-key`,
`rotate-ldap-bind-password`) recreate the gateway and whichever engine shares
its namespace. `verify_gateway_auth` performs a real `pi` Negotiate request.

The gateway health endpoint is `http://127.0.0.1:8081/healthz` inside the
container; the Compose healthcheck uses it.

## Deliberate differences

- The engine is unmodified. Native GSSAPI in radiance was removed; no patch,
  fork or patched image is used.
- Authentication is stateless per request. There are no cookies or sessions.
- The gateway is a single Python process with a thread per connection; GSSAPI
  accepts and LDAP lookups are serialized. It is sized for the Pi workload
  (one model, one or a few users), not a multi-tenant gateway.
- The old Apache edge under `deploy/edge` is retained only as a legacy
  reference and is no longer in `compose.yaml`.
