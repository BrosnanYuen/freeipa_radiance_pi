#!/usr/bin/env python3
"""Pi-side Kerberos workflow.

    pi-krb login    # kinit in pi-login; captures the ccache
    pi-krb status   # klist -e checks, AES enforced
    pi-krb run      # write models.json and exec pi against radiance-shim

``run`` never reads the ccache: it only needs the shim's bearer token and the
shim health endpoint. The agent container never sees a TGT.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Mapping, Sequence

AES_PREFIXES = ("aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96",
                "aes256-cts-hmac-sha384-192", "aes128-cts-hmac-sha256-128")
ENCTYPE_RE = re.compile(r"Etype \(skey, tkt\):\s*(.+)$", re.MULTILINE)
PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9._@/-]+$")
DEFAULT_MODEL = "radiance-krb/qwen3.8-27b"
DEFAULT_CONTEXT = 200_000


class PiKrbError(RuntimeError):
    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def parse_enctypes(klist_output: str) -> set[str]:
    found: set[str] = set()
    for match in ENCTYPE_RE.finditer(klist_output):
        for item in match.group(1).split(","):
            item = item.strip()
            if item:
                found.add(item)
    return found


def has_aes(enctypes: set[str]) -> bool:
    return any(item.startswith(AES_PREFIXES) for item in enctypes)


def _run_klist(*args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["klist", *args], text=True, capture_output=True, timeout=30
        )
    except FileNotFoundError as exc:
        raise PiKrbError("klist not found; install krb5-user") from exc


def verify_credentials() -> str:
    result = _run_klist("-e")
    if result.returncode != 0:
        raise PiKrbError(
            "no valid Kerberos credentials; run `pi-krb login`", exit_code=2
        )
    enctypes = parse_enctypes(result.stdout)
    if not enctypes:
        raise PiKrbError(
            "could not determine ticket enctypes from klist -e", exit_code=3
        )
    if not has_aes(enctypes):
        raise PiKrbError(
            "tickets are not AES: " + ", ".join(sorted(enctypes)), exit_code=3
        )
    return result.stdout


def status() -> int:
    try:
        output = verify_credentials()
    except PiKrbError as exc:
        print(f"pi-krb: {exc}", file=sys.stderr)
        return exc.exit_code
    print(output, end="" if output.endswith("\n") else "\n")
    return 0


def login(principal: str, lifetime: str, renewal: str, password_stdin: bool) -> int:
    if not PRINCIPAL_RE.match(principal) or principal.startswith("-"):
        print("pi-krb: invalid principal", file=sys.stderr)
        return 1
    argv = ["kinit", "-F", "-l", lifetime, "-r", renewal, principal]
    try:
        if password_stdin:
            password = sys.stdin.readline().rstrip("\n")
            if not password:
                raise PiKrbError("empty password on stdin")
            proc = subprocess.run(
                argv, input=password + "\n", text=True,
                capture_output=True, timeout=120,
            )
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout or "").strip()
                raise PiKrbError(detail or "kinit failed")
        else:
            proc = subprocess.run(argv, check=False)
            if proc.returncode != 0:
                raise PiKrbError("kinit failed")
        output = verify_credentials()
    except PiKrbError as exc:
        print(f"pi-krb: {exc}", file=sys.stderr)
        return exc.exit_code
    except FileNotFoundError:
        print("pi-krb: kinit not found; install krb5-user", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print("pi-krb: kinit timed out", file=sys.stderr)
        return 1
    print(output, end="" if output.endswith("\n") else "\n")
    return 0


def normalize_base_url(url: str) -> str:
    base = url.rstrip("/")
    if base.endswith("/v1"):
        return base
    return base + "/v1"


def _health_url(shim_url: str) -> str:
    base = shim_url.rstrip("/")
    if base.endswith("/v1"):
        base = base[: -len("/v1")]
    return base + "/healthz"


def build_models_config(
    shim_url: str,
    token_path: str,
    model: str,
    context_window: int = DEFAULT_CONTEXT,
) -> dict[str, object]:
    if any(ch.isspace() for ch in token_path) or not token_path:
        raise PiKrbError("token path must not contain whitespace")
    provider, _, model_id = model.partition("/")
    if not model_id:
        provider, model_id = "radiance-krb", model
    if context_window < 1024:
        raise PiKrbError("context window is implausibly small")
    return {
        "$schema": "https://pi.dev/schemas/models.schema.json",
        "providers": {
            provider: {
                "name": "radiance (Kerberos)",
                "baseUrl": normalize_base_url(shim_url),
                "api": "openai-completions",
                "apiKey": f"!cat {token_path}",
                "authHeader": True,
                "models": [
                    {
                        "id": model_id,
                        "name": f"{model_id} (radiance)",
                        "reasoning": False,
                        "input": ["text"],
                        "contextWindow": context_window,
                        "maxTokens": min(16384, max(1024, context_window // 4)),
                        "cost": {
                            "input": 0,
                            "output": 0,
                            "cacheRead": 0,
                            "cacheWrite": 0,
                        },
                    }
                ],
            }
        },
    }


def write_models_config(agent_dir: Path, config: Mapping[str, object]) -> Path:
    agent_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(agent_dir, 0o700)
    target = agent_dir / "models.json"
    fd, tmp_name = tempfile.mkstemp(prefix=".models-", dir=str(agent_dir))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
        os.chmod(target, 0o600)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise
    return target


def wait_for_shim(
    shim_url: str, token_file: Path, timeout: float = 60.0
) -> None:
    deadline = time.monotonic() + timeout
    last_error = "not reachable"
    while time.monotonic() < deadline:
        if token_file.is_file():
            try:
                with urllib.request.urlopen(
                    _health_url(shim_url), timeout=2
                ) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            except (OSError, ValueError, urllib.error.URLError) as exc:
                last_error = str(exc)
            else:
                if payload.get("ready") and payload.get("token"):
                    return
                last_error = (
                    "shim is up but Kerberos credentials are not ready "
                    "(run `pi-krb login`)"
                )
        else:
            last_error = f"waiting for token file {token_file}"
        time.sleep(1)
    raise PiKrbError(
        f"radiance-shim is not ready at {shim_url}: {last_error}"
    )


def _default_agent_dir() -> Path:
    env = os.environ.get("PI_CODING_AGENT_DIR")
    if env:
        return Path(env)
    if Path("/agent").is_dir():
        return Path("/agent")
    return Path.home() / ".pi" / "agent"


def _default_token_file(agent_dir: Path) -> Path:
    env = os.environ.get("RADIANCE_SHIM_TOKEN")
    if env:
        return Path(env)
    if Path("/agent").is_dir():
        return Path("/agent/shim-token")
    return agent_dir / "shim-token"


def _default_shim_url() -> str:
    env = os.environ.get("RADIANCE_SHIM_URL")
    if env:
        return env
    if Path("/agent").is_dir():
        return "http://radiance-shim:8088"
    return "http://127.0.0.1:8088"


def run_pi(
    model: str,
    agent_dir: Path,
    token_file: Path,
    shim_url: str,
    context_window: int,
    extra_args: Sequence[str],
) -> int:
    wait_for_shim(shim_url, token_file)
    config = build_models_config(
        shim_url, str(token_file), model, context_window
    )
    write_models_config(agent_dir, config)
    pi = shutil.which("pi")
    if not pi:
        raise PiKrbError("pi executable not found in PATH")
    argv = [pi]
    if "--model" not in extra_args and "-m" not in extra_args:
        argv.extend(["--model", model])
    argv.extend(extra_args)
    env = os.environ.copy()
    env["PI_CODING_AGENT_DIR"] = str(agent_dir)
    os.execvpe(pi, argv, env)
    return 0  # unreachable


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)

    login_p = sub.add_parser(
        "login", help="kinit into the shared ccache", allow_abbrev=False
    )
    login_p.add_argument("--principal", default="pi")
    login_p.add_argument("--lifetime", default="8h")
    login_p.add_argument("--renewal", default="7d")
    login_p.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the password from stdin (automation; not for humans)",
    )

    sub.add_parser(
        "status", help="show and validate the current tickets", allow_abbrev=False
    )

    run_p = sub.add_parser(
        "run", help="configure Pi and exec it", allow_abbrev=False
    )
    run_p.add_argument("--model", default=DEFAULT_MODEL)
    run_p.add_argument("--agent-dir", type=Path)
    run_p.add_argument("--token-file", type=Path)
    run_p.add_argument("--shim-url")
    run_p.add_argument(
        "--context-window",
        type=int,
        default=int(os.environ.get("RADIANCE_CONTEXT_WINDOW", DEFAULT_CONTEXT)),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args, extra = build_parser().parse_known_args(argv)
    try:
        if args.command == "login":
            return login(
                args.principal, args.lifetime, args.renewal, args.password_stdin
            )
        if args.command == "status":
            return status()
        agent_dir = args.agent_dir or _default_agent_dir()
        token_file = args.token_file or _default_token_file(agent_dir)
        shim_url = args.shim_url or _default_shim_url()
        return run_pi(
            args.model, agent_dir, token_file, shim_url,
            args.context_window, extra,
        )
    except PiKrbError as exc:
        print(f"pi-krb: {exc}", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    sys.exit(main())
