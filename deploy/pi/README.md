# Pi image

One image serves three roles in Compose:

| Service | Role |
|---|---|
| `pi-login` | `pi-krb login` / `status`; one of two ccache holders |
| `radiance-shim` | Negotiate credential agent; the other ccache holder |
| `pi-client` | Pi itself; no ccache, no certificate, no IPA secret |

Contents: Node 22 (Pi requires >= 22.19), Pi pinned to `PI_VERSION` with the
npm `PI_INTEGRITY` verified, `krb5-user` (kinit/klist), Python 3 +
`python3-gssapi`, `git` and `ripgrep` for Pi's tools.

The `radiance_krb` package is copied to `/opt/radiance-krb`; console scripts
`pi-krb`, `radiance-krb-shim` and `radiance-krb-token` set `PYTHONPATH` and
exec it with the system Python.

Unit tests import this package directly from the repository; they do not need
python-gssapi (it is imported lazily and replaced with a fake in tests).
