# radiance-gateway

A Kerberos-authenticated TLS reverse proxy in front of the unmodified radiance
image.

- `gateway.py` terminates TLS 1.3, accepts `Authorization: Negotiate` with the
  FreeIPA keytab, checks the `ai-users` LDAP group, and forwards only
  `/v1/models`, `/v1/chat/completions` and `/v1/completions`.
- The engine is bound to `127.0.0.1` inside the gateway's network namespace and
  is reached with a private bearer key. The gateway strips the client's
  `Authorization` and injects `X-Radiance-Principal`.
- `entrypoint.sh` installs the root-owned keytab/cert/secrets as 0400/0644 for
  the unprivileged `gateway` user, then drops privileges.

`--check` imports the GSSAPI/LDAP modules and validates the Python code without
a realm; `make edge-check` uses it.
