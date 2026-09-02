# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false, reportArgumentType=false
"""Positive and recovery coverage for the C7 identity boundary."""

from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any

import pytest

import avo_correlate.application.main_graduation_offline_identity as module
from avo_correlate.application.main_graduation_offline_identity import (
    C7WorkspaceIdentity,
    C7WorkspaceIdentityVerifier,
    child_environment_identity,
    sanitized_child_environment,
)
from tests.unit.test_main_graduation_offline_identity import _authority, _observed


def test_environment_identity_accepts_bounded_safe_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", "safe-path")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-read")
    values = sanitized_child_environment()
    assert values["PATH"] == "safe-path"
    assert "OPENAI_API_KEY" not in values
    assert child_environment_identity(values).startswith("sha256:")


def test_identity_verifier_accepts_exact_observation_and_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = C7WorkspaceIdentityVerifier(Path.cwd())
    observed = _observed()
    monkeypatch.setattr(verifier, "observe", lambda: observed)
    authority = _authority(
        environment_identity_digest=observed.environment_identity_digest,
        uv_digest=observed.uv_digest,
    )
    verifier.verify(authority)
    verifier(authority)


def _positive_runtime_fixture(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    runtime = tmp_path / "runtime"
    site = runtime / "Lib" / "site-packages"
    scripts = runtime / "Scripts"
    pytest_pkg = site / "pytest"
    pytest_info = site / "pytest-9.0.dist-info"
    plugin_pkg = site / "avo_plugin"
    plugin_info = site / "avo_plugin-1.0.dist-info"
    for directory in (pytest_pkg, pytest_info, plugin_pkg, plugin_info, scripts):
        directory.mkdir(parents=True)
    python = runtime / "python.exe"
    launcher = scripts / "pytest.exe"
    python.write_bytes(b"python")
    launcher.write_bytes(b"pytest-launcher")
    (pytest_pkg / "__init__.py").write_bytes(b"pytest")
    (pytest_pkg / "runner.py").write_bytes(b"runner")
    (plugin_pkg / "__init__.py").write_bytes(b"plugin")

    def record(info: Path, rows: list[str]) -> str:
        path = info / "RECORD"
        path.write_text("".join(f"{row},,\n" for row in rows), encoding="utf-8")
        return path.relative_to(site).as_posix()

    pytest_record = record(
        pytest_info,
        [
            "pytest/__init__.py",
            "pytest/runner.py",
            "pytest-9.0.dist-info/RECORD",
            "../../Scripts/pytest.exe",
        ],
    )
    plugin_record = record(
        plugin_info,
        ["avo_plugin/__init__.py", "avo_plugin-1.0.dist-info/RECORD"],
    )
    payload: dict[str, object] = {
        "implementation": "CPython",
        "plugins": [["avo-plugin", "avo_plugin", "avo_plugin", "1.0"]],
        "plugin_distributions": [
            {
                "name": "avo_plugin",
                "version": "1.0",
                "root": str(site),
                "record": plugin_record,
            }
        ],
        "pytest": str(pytest_pkg / "__init__.py"),
        "pytest_distribution": {
            "name": "pytest",
            "version": "9.0",
            "root": str(site),
            "record": pytest_record,
        },
        "pytest_launcher": str(launcher),
        "pytest_version": "9.0",
        "python": str(python),
        "runtime_root": str(runtime),
        "version": "3.12.0",
    }
    return runtime / "uv.exe", payload


def test_runtime_identity_accepts_complete_distribution_and_plugin_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher, payload = _positive_runtime_fixture(tmp_path)

    def runner(argv: list[str], **_kwargs: Any) -> CompletedProcess[str]:
        return CompletedProcess(argv, 0, stdout=json.dumps(payload, sort_keys=True), stderr="")

    monkeypatch.setattr(module.subprocess, "run", runner)
    interpreter, pytest_digest, plugin_digest = module._uv_runtime_identity(
        tmp_path, launcher, {"PATH": "safe"}
    )
    assert all(value.startswith("sha256:") for value in (interpreter, pytest_digest, plugin_digest))
    runtime = Path(str(payload["runtime_root"]))
    assert module._runtime_regular_root(str(runtime)) == runtime
    assert module._runtime_relative_path("pkg/module.py") == "pkg/module.py"
    assert module._runtime_record_path("../../Scripts/pytest.exe") == "../../Scripts/pytest.exe"


def test_runtime_distribution_identity_accepts_empty_hash_columns(tmp_path: Path) -> None:
    root = tmp_path / "site-packages"
    info = root / "demo-1.dist-info"
    package = root / "demo"
    info.mkdir(parents=True)
    package.mkdir()
    (package / "__init__.py").write_bytes(b"demo")
    (info / "RECORD").write_text(
        "demo/__init__.py,,\ndemo-1.dist-info/RECORD,,\n", encoding="utf-8"
    )
    identity = module._runtime_distribution_identity(
        {"name": "demo", "version": "1", "root": str(root), "record": "demo-1.dist-info/RECORD"},
        tmp_path,
    )
    assert identity["file_count"] == 2
    assert identity["total_bytes"] == len(b"demo") + (info / "RECORD").stat().st_size


def test_identity_dataclass_retains_all_measured_pins() -> None:
    observed: C7WorkspaceIdentity = _observed()
    assert observed.environment_identity_digest != observed.uv_digest
