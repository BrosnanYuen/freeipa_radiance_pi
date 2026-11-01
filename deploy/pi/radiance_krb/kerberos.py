"""GSSAPI helpers.

Only this module imports python-gssapi, and it does so lazily so that the unit
tests (and ``--help``) work on machines without a Kerberos stack.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any, Mapping


class KerberosError(Exception):
    """Base class; ``exit_code`` is the token-helper process exit code."""

    exit_code = 4


class NoCCache(KerberosError):
    exit_code = 2


class CredentialsExpired(KerberosError):
    exit_code = 3


class GSSFailure(KerberosError):
    exit_code = 4


def ccache_path(env: Mapping[str, str] | None = None) -> Path | None:
    """Return the FILE ccache path, or None for a non-file / implicit cache."""
    env = os.environ if env is None else env
    value = env.get("KRB5CCNAME", "")
    if not value:
        return Path(f"/tmp/krb5cc_{os.getuid()}")
    if value.startswith("FILE:"):
        return Path(value[len("FILE:") :])
    return None


def ccache_available(env: Mapping[str, str] | None = None) -> bool:
    """Best-effort readiness check that never reads the cache contents."""
    path = ccache_path(env)
    if path is None:
        # KCM/KEYRING caches cannot be checked with the filesystem. Let GSSAPI
        # decide; report ready so the shim does not block needlessly.
        return True
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def _check_ccache(env: Mapping[str, str] | None) -> None:
    path = ccache_path(env)
    if path is None:
        return
    if not ccache_available(env):
        raise NoCCache(
            f"no Kerberos credentials at {path}; run `pi-krb login`"
        )


def _import_gssapi() -> Any:
    try:
        import gssapi  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on host packages
        raise GSSFailure(
            f"python-gssapi is not available: {exc}"
        ) from exc
    return gssapi


def _classify(exc: BaseException) -> KerberosError:
    name = type(exc).__name__.lower()
    text = str(exc).lower()
    if "expired" in name or "expired" in text:
        return CredentialsExpired(
            "Kerberos credentials have expired; run `pi-krb login`"
        )
    if "missing" in name or "no credentials" in text or "ccache" in text:
        return NoCCache(
            "no usable Kerberos credentials; run `pi-krb login`"
        )
    return GSSFailure(f"GSSAPI failure: {exc}")


class TokenProvider:
    """Acquire a fresh SPNEGO/Negotiate token for ``service``.

    No delegation and no mutual-authentication flags are requested. Every
    call starts a new security context, so the shim can retry a 401 with a new
    authenticator without reusing state.
    """

    def __init__(
        self,
        service: str = "HTTP/radiance.ipa.test",
        env: Mapping[str, str] | None = None,
        gssapi_module: Any | None = None,
    ) -> None:
        self.service = service
        self.env = os.environ if env is None else env
        self._gssapi = gssapi_module

    @staticmethod
    def hostbased_name(service: str) -> str:
        """GSSAPI host-based names are ``service@host``, not ``service/host``.

        The CLI/config uses the Kerberos principal spelling
        ``HTTP/radiance.ipa.test``; passing that to NameType.hostbased_service
        makes GSSAPI append the hostname again (verified: it produced
        ``HTTP/radiance.ipa.test/radiance.ipa.test@IPA.TEST``).
        """
        if "@" in service:
            return service
        if "/" in service:
            service_name, host = service.split("/", 1)
            return f"{service_name}@{host}"
        return service

    def token(self) -> bytes:
        _check_ccache(self.env)
        gssapi = self._gssapi or _import_gssapi()
        try:
            name = gssapi.Name(
                self.hostbased_name(self.service),
                gssapi.NameType.hostbased_service,
            )
            context = gssapi.SecurityContext(name=name, usage="initiate")
            token = context.step(None)
        except KerberosError:
            raise
        except Exception as exc:
            raise _classify(exc) from exc
        if not token:
            raise GSSFailure("GSSAPI returned an empty token")
        return bytes(token)

    def header(self) -> str:
        return "Negotiate " + base64.b64encode(self.token()).decode("ascii")
