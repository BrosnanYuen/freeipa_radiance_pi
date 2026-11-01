# radiance edge

Apache httpd with `mod_auth_gssapi`, TLS 1.3, and a live FreeIPA LDAP group
check. It is the only published entry point to radiance.

- `vhost.conf.tmpl` – the virtual host. `{{LDAP_BIND_PASSWORD}}` and
  `{{RADIANCE_API_KEY}}` are the only placeholders; `render.py` refuses secrets
  with characters unsafe inside an Apache quoted string.
- `entrypoint.sh` – waits for the bootstrap marker, installs the keytab as
  `0400 www-data` (mod_auth_gssapi opens it per request in the worker), renders
  the vhost at `0600`, runs `apachectl -t`, then execs Apache.
- `--check` mode renders a throwaway config with a self-signed certificate and
  runs `apachectl -t`; `make edge-check` uses it.

Deliberate choices:
- Only `/v1/models`, `/v1/chat/completions` and `/v1/completions` are proxied,
  by exact-path `ProxyPassMatch`. Everything else is denied, including LoRA
  admin, `/diagnostics`, media endpoints and the dashboard.
- `RequireAll` combines `Require valid-user` with `Require ldap-group` so a
  valid ticket for a user outside `ai-users` gets 403, not 200.
- Plain HTTP to the engine is loopback-only inside the shared network
  namespace; the edge rewrites `Authorization` to the engine's private key.
