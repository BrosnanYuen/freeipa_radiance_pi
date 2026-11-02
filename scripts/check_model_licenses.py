#!/usr/bin/env python3
"""Enforce a recorded licence decision for every served ``.rad`` container.

The manifest lives beside the models, e.g. ``/srv/models/rad/model-licenses.json``:

    {
      "qwen3.8-27b-mxfp4.rad": {
        "license": "Apache-2.0",
        "allowed": true,
        "notes": "Internal use only; review before external distribution."
      },
      "restricted-example.rad": {
        "license": "Research-only",
        "allowed": false,
        "notes": "Must stay out of models.json."
      }
    }

Exit codes:
  0  every present container is allowed
  1  at least one container is blocked, undocumented, or the manifest is invalid
  2  the model directory does not exist
  3  the directory contains no .rad containers (nothing to serve)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

MANIFEST_NAME = "model-licenses.json"


@dataclass(frozen=True)
class Decision:
    model: str
    license: str
    allowed: bool
    notes: str


class ManifestError(ValueError):
    pass


def load_manifest(path: Path) -> dict[str, dict]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ManifestError(f"missing licence manifest: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManifestError(f"{path} must contain a JSON object")
    manifest: dict[str, dict] = {}
    for model, record in raw.items():
        if not isinstance(record, dict):
            raise ManifestError(f"{model}: decision must be an object")
        license_name = record.get("license")
        allowed = record.get("allowed")
        if not isinstance(license_name, str) or not license_name.strip():
            raise ManifestError(f"{model}: 'license' must be a non-empty string")
        if not isinstance(allowed, bool):
            raise ManifestError(f"{model}: 'allowed' must be true or false")
        notes = record.get("notes", "")
        if not isinstance(notes, str):
            raise ManifestError(f"{model}: 'notes' must be a string")
        manifest[model] = {
            "license": license_name.strip(),
            "allowed": allowed,
            "notes": notes.strip(),
        }
    return manifest


def evaluate(
    models_dir: Path, manifest: Mapping[str, Mapping[str, object]]
) -> tuple[list[Decision], list[str]]:
    containers = sorted(
        path.name for path in models_dir.glob("*.rad") if path.is_file()
    )
    decisions: list[Decision] = []
    errors: list[str] = []
    for name in containers:
        record = manifest.get(name)
        if record is None:
            errors.append(f"{name}: no licence decision in {MANIFEST_NAME}")
            decisions.append(Decision(name, "", False, "undocumented"))
            continue
        license_name = str(record["license"])
        allowed = bool(record["allowed"])
        notes = str(record.get("notes", ""))
        decisions.append(Decision(name, license_name, allowed, notes))
        if not allowed:
            errors.append(f"{name}: blocked by licence decision ({license_name})")
    for name, record in manifest.items():
        if name not in containers:
            decisions.append(
                Decision(name, str(record["license"]), False, "not present (stale entry)")
            )
    return decisions, errors


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check that every .rad container has an allowed licence record"
    )
    parser.add_argument(
        "--models-dir",
        type=Path,
        default=Path(os.environ.get("RADIANCE_MODELS", "/srv/models/rad")),
        help="directory holding .rad containers and model-licenses.json",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    models_dir: Path = args.models_dir
    if not models_dir.is_dir():
        print(
            f"model-licences: model directory not found: {models_dir}",
            file=sys.stderr,
        )
        return 2

    containers = [p for p in models_dir.glob("*.rad") if p.is_file()]
    if not containers:
        print(
            f"model-licences: no .rad containers in {models_dir}; nothing to serve",
            file=sys.stderr,
        )
        return 3

    try:
        manifest = load_manifest(models_dir / MANIFEST_NAME)
    except ManifestError as exc:
        print(f"model-licences: {exc}", file=sys.stderr)
        return 1

    decisions, errors = evaluate(models_dir, manifest)
    if args.json:
        print(
            json.dumps(
                {
                    "models_dir": str(models_dir),
                    "decisions": [decision.__dict__ for decision in decisions],
                    "errors": errors,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        for decision in decisions:
            state = "allowed" if decision.allowed else "BLOCKED"
            print(f"{decision.model}\t{state}\t{decision.license}\t{decision.notes}")
        for error in errors:
            print(f"model-licences: {error}", file=sys.stderr)
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
