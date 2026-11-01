# FreeIPA service

The `ipa` service runs the upstream `freeipa-container` image, which runs
systemd as PID 1 and self-installs on first start from
`/data/ipa-server-install-options`.

- State lives in `run/ipa-data` (gitignored). `scripts/up.sh` renders the
  install-options file from `install-options.tmpl` and shreds it after the
  realm is installed.
- The bootstrap runs in a **separate one-off container** (`bootstrap` profile)
  that shares the IPA network namespace. It is the only place the bootstrap
  secrets are mounted; the long-lived `ipa` service never sees them.
- Unlike upstream's usual `podman` invocation, this stack does not enable
  integrated DNS. `run/krb5.conf` points clients directly at `ipa.ipa.test:88`,
  and the Compose network alias provides name resolution.
- If the host daemon is rootless or cgroup delegation fails, add an override
  with `cgroupns: host`, `cgroup: host` and a writable `/sys/fs/cgroup`; see
  `docs/RUNBOOK.md`.

Bootstrap logic: `bootstrap.py` (unit-tested, idempotent, passwords on stdin
only). Wrapper: `bootstrap.sh`.
