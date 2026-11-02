from __future__ import annotations

import json
from pathlib import Path

import check_model_licenses as gate


def _model(directory: Path, name: str = "model.rad") -> Path:
    path = directory / name
    path.write_bytes(b"\0")
    return path


def _manifest(directory: Path, payload: object) -> None:
    (directory / "model-licenses.json").write_text(json.dumps(payload), encoding="utf-8")


def test_missing_directory(tmp_path: Path, capsys) -> None:
    assert gate.main(["--models-dir", str(tmp_path / "nope")]) == 2
    assert "not found" in capsys.readouterr().err


def test_empty_directory(tmp_path: Path, capsys) -> None:
    assert gate.main(["--models-dir", str(tmp_path)]) == 3
    assert "nothing to serve" in capsys.readouterr().err


def test_allowed_model(tmp_path: Path, capsys) -> None:
    _model(tmp_path)
    _manifest(
        tmp_path,
        {
            "model.rad": {
                "license": "Apache-2.0",
                "allowed": True,
                "notes": "reviewed",
            }
        },
    )
    assert gate.main(["--models-dir", str(tmp_path)]) == 0
    assert "allowed" in capsys.readouterr().out


def test_undocumented_model_is_blocked(tmp_path: Path) -> None:
    _model(tmp_path)
    _manifest(tmp_path, {})
    assert gate.main(["--models-dir", str(tmp_path)]) == 1


def test_restricted_model_is_blocked(tmp_path: Path) -> None:
    _model(tmp_path)
    _manifest(
        tmp_path,
        {"model.rad": {"license": "Research", "allowed": False, "notes": "no"}},
    )
    assert gate.main(["--models-dir", str(tmp_path)]) == 1


def test_string_allowed_is_a_manifest_error(tmp_path: Path) -> None:
    _model(tmp_path)
    _manifest(tmp_path, {"model.rad": {"license": "MIT", "allowed": "yes"}})
    assert gate.main(["--models-dir", str(tmp_path)]) == 1


def test_stale_entry_does_not_fail(tmp_path: Path) -> None:
    _model(tmp_path)
    _manifest(
        tmp_path,
        {
            "model.rad": {"license": "MIT", "allowed": True},
            "gone.rad": {"license": "MIT", "allowed": True},
        },
    )
    decisions, errors = gate.evaluate(
        tmp_path,
        gate.load_manifest(tmp_path / "model-licenses.json"),
    )
    assert errors == []
    assert any(item.model == "gone.rad" and "not present" in item.notes for item in decisions)


def test_json_output_is_machine_readable(tmp_path: Path, capsys) -> None:
    _model(tmp_path)
    _manifest(
        tmp_path, {"model.rad": {"license": "MIT", "allowed": True, "notes": ""}}
    )
    assert gate.main(["--models-dir", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["decisions"][0]["model"] == "model.rad"
