# pyright: reportPrivateUsage=false
"""Adversarial checks for the independent C7 workspace identity boundary."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from typing import Any

import pytest

import avo_correlate.application.main_graduation_offline_identity as identity_module
from avo_correlate.application.main_graduation_offline_drill_service import (
    PinnedC7AuthorityVerifier,
)
from avo_correlate.application.main_graduation_offline_identity import (
    FROZEN_OFFLINE_EXECUTION_ARGV,
    C7WorkspaceIdentity,
    C7WorkspaceIdentityError,
    C7WorkspaceIdentityVerifier,
    resolve_uv_path,
    sanitized_child_environment,
)
from avo_correlate.application.main_graduation_offline_pytest_executor import (
    OfflinePytestExecutionError,
    _node_identity,
    _pytest_node_id,
)
from avo_correlate.contracts.main_graduation_offline_drill import (
    FROZEN_OFFLINE_EXECUTION_NODE_IDS,
    FROZEN_OFFLINE_EXECUTION_PARAMETER_IDS,
)


def _authority(**updates: Any) -> Any:
    nodes = tuple(
        SimpleNamespace(node_id=node_id, parameter_id=parameter_id)
        for node_id, parameter_id in zip(
            FROZEN_OFFLINE_EXECUTION_NODE_IDS,
            FROZEN_OFFLINE_EXECUTION_PARAMETER_IDS,
            strict=True,
        )
    )
    values: dict[str, Any] = {
        "argv": FROZEN_OFFLINE_EXECUTION_ARGV,
        "nodes": nodes,
        "source_commit": "a" * 40,
        "source_tree": "b" * 40,
        "source_tree_digest": "sha256:" + "c" * 64,
        "lockfile_digest": "sha256:" + "d" * 64,
        "interpreter_digest": "sha256:" + "e" * 64,
        "pytest_digest": "sha256:" + "f" * 64,
        "plugin_set_digest": "sha256:" + "0" * 64,
        "toolchain_digest": "sha256:" + "1" * 64,
    }
    values.update(updates)
    return SimpleNamespace(**values)


def _observed() -> C7WorkspaceIdentity:
    return C7WorkspaceIdentity(
        source_commit="a" * 40,
        source_tree="b" * 40,
        source_tree_digest="sha256:" + "c" * 64,
        lockfile_digest="sha256:" + "d" * 64,
        interpreter_digest="sha256:" + "e" * 64,
        pytest_digest="sha256:" + "f" * 64,
        plugin_set_digest="sha256:" + "0" * 64,
        toolchain_digest="sha256:" + "1" * 64,
        environment_identity_digest="sha256:" + "2" * 64,
        uv_digest="sha256:" + "3" * 64,
    )


def test_identity_verifier_rejects_argv_drift_before_observing_workspace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = C7WorkspaceIdentityVerifier(Path.cwd())
    monkeypatch.setattr(verifier, "observe", lambda: pytest.fail("workspace was observed"))
    authority = _authority(argv=("uv", "run", "pytest", "-q"))
    with pytest.raises(C7WorkspaceIdentityError, match="argv"):
        verifier.verify(authority)


def test_identity_verifier_rejects_frozen_node_drift() -> None:
    verifier = C7WorkspaceIdentityVerifier(Path.cwd())
    authority = _authority(
        nodes=(SimpleNamespace(node_id=FROZEN_OFFLINE_EXECUTION_NODE_IDS[0], parameter_id="wrong"),)
    )
    with pytest.raises(C7WorkspaceIdentityError, match="nodes"):
        verifier.verify(authority)


def test_identity_verifier_rejects_dirty_worktree_before_toolchain_probe(
    tmp_path: Path,
) -> None:
    def runner(argv: list[str], **_kwargs: Any) -> Any:
        if argv[1] == "rev-parse":
            return _completed(str(tmp_path))
        if argv[1] == "status":
            return _completed("1 .M file.py")
        return _completed("")

    verifier = C7WorkspaceIdentityVerifier(tmp_path, command_runner=runner)
    with pytest.raises(C7WorkspaceIdentityError, match="dirty"):
        verifier.observe()


def test_identity_verifier_rejects_any_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = C7WorkspaceIdentityVerifier(Path.cwd())
    monkeypatch.setattr(verifier, "observe", lambda: _observed())
    authority = _authority(lockfile_digest="sha256:" + "9" * 64)
    with pytest.raises(C7WorkspaceIdentityError, match="lockfile_digest"):
        verifier.verify(authority)


def test_identity_verifier_rejects_zero_environment_or_uv_pins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = C7WorkspaceIdentityVerifier(Path.cwd())
    monkeypatch.setattr(verifier, "observe", lambda: _observed())
    with pytest.raises(C7WorkspaceIdentityError, match="environment_identity_digest"):
        verifier.verify(
            _authority(
                environment_identity_digest="sha256:" + "0" * 64,
                uv_digest="sha256:" + "3" * 64,
            )
        )


def test_real_pytest_junit_shape_requires_exact_repository_module() -> None:
    frozen = FROZEN_OFFLINE_EXECUTION_NODE_IDS[0]
    testcase = ET.Element(
        "testcase",
        {
            "classname": f"tests.unit.{frozen.split('::', 1)[0][:-3]}",
            "name": frozen.split("::", 1)[1],
        },
    )
    assert _node_identity(testcase, frozen) == frozen
    assert _pytest_node_id(frozen).startswith("tests/unit/")
    testcase.set("classname", "tests.other." + frozen.split("::", 1)[0][:-3])
    with pytest.raises(OfflinePytestExecutionError, match="identity"):
        _node_identity(testcase, frozen)


def test_controller_and_artifact_pins_are_required_externally() -> None:
    with pytest.raises(ValueError, match="artifact digest"):
        PinnedC7AuthorityVerifier("sha256:" + "a" * 64)
    with pytest.raises(ValueError, match="controller authority pin"):
        PinnedC7AuthorityVerifier("sha256:" + "a" * 64, "sha256:" + "b" * 64)


def test_scrubbed_environment_requires_path_and_excludes_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PATH", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-propagate")
    with pytest.raises(C7WorkspaceIdentityError, match="PATH"):
        sanitized_child_environment()


def test_uv_runtime_probe_uses_one_resolved_absolute_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher = Path(sys.executable).resolve()
    pytest_distribution = importlib.metadata.distribution("pytest")
    record = next(item for item in pytest_distribution.files or () if item.name == "RECORD")
    pytest_origin = importlib.util.find_spec("pytest")
    pytest_launcher = shutil.which("pytest")
    assert pytest_origin is not None and pytest_origin.origin
    assert pytest_launcher
    calls: list[list[str]] = []

    def runner(argv: list[str], **_kwargs: Any) -> CompletedProcess[str]:
        calls.append(argv)
        payload = json.dumps(
            {
                "implementation": "CPython",
                "plugins": [],
                "plugin_distributions": [],
                "pytest": pytest_origin.origin,
                "pytest_distribution": {
                    "name": pytest_distribution.name,
                    "version": pytest_distribution.version,
                    "root": str(pytest_distribution.locate_file("")),
                    "record": record.as_posix(),
                },
                "pytest_launcher": pytest_launcher,
                "pytest_version": pytest_distribution.version,
                "python": str(launcher),
                "runtime_root": sys.prefix,
                "version": "3",
            },
            sort_keys=True,
        )
        return CompletedProcess(argv, 0, stdout=payload, stderr="")

    monkeypatch.setattr(identity_module.subprocess, "run", runner)
    identity_module._uv_runtime_identity(tmp_path, launcher, {"PATH": "unused"})
    assert calls and calls[0][0] == str(launcher)


def test_uv_runtime_identity_hashes_non_init_pytest_and_plugin_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime_root = tmp_path / "venv"
    site_packages = runtime_root / "Lib" / "site-packages"
    scripts = runtime_root / "Scripts"
    pytest_package = site_packages / "pytest"
    pytest_info = site_packages / "pytest-1.0.dist-info"
    plugin_package = site_packages / "c7plugin"
    plugin_info = site_packages / "c7plugin-1.0.dist-info"
    for directory in (
        pytest_package,
        pytest_info,
        plugin_package,
        plugin_info,
        scripts,
    ):
        directory.mkdir(parents=True)
    (runtime_root / "python.exe").write_bytes(b"python")
    (scripts / "pytest.exe").write_bytes(b"launcher")
    (pytest_package / "__init__.py").write_bytes(b"init")
    (pytest_package / "core.py").write_bytes(b"pytest core")
    (pytest_info / "METADATA").write_bytes(b"Name: pytest\nVersion: 1.0\n")
    (plugin_package / "__init__.py").write_bytes(b"plugin init")
    (plugin_package / "hooks.py").write_bytes(b"plugin hooks")
    (plugin_info / "METADATA").write_bytes(b"Name: c7plugin\nVersion: 1.0\n")

    def write_record(info: Path, rows: list[str]) -> str:
        record = info / "RECORD"
        record.write_text("".join(f"{row},,\n" for row in rows), encoding="utf-8")
        return str(record.relative_to(site_packages).as_posix())

    pytest_record = write_record(
        pytest_info,
        [
            "pytest/__init__.py",
            "pytest/core.py",
            "pytest-1.0.dist-info/METADATA",
            "pytest-1.0.dist-info/RECORD",
            "../../Scripts/pytest.exe",
        ],
    )
    plugin_record = write_record(
        plugin_info,
        [
            "c7plugin/__init__.py",
            "c7plugin/hooks.py",
            "c7plugin-1.0.dist-info/METADATA",
            "c7plugin-1.0.dist-info/RECORD",
        ],
    )
    payload = {
        "implementation": "CPython",
        "plugins": [["c7plugin", "c7plugin.hooks", "c7plugin", "1.0"]],
        "plugin_distributions": [
            {
                "name": "c7plugin",
                "version": "1.0",
                "root": str(site_packages),
                "record": plugin_record,
            }
        ],
        "pytest": str(pytest_package / "__init__.py"),
        "pytest_distribution": {
            "name": "pytest",
            "version": "1.0",
            "root": str(site_packages),
            "record": pytest_record,
        },
        "pytest_launcher": str(scripts / "pytest.exe"),
        "pytest_version": "1.0",
        "python": str(runtime_root / "python.exe"),
        "runtime_root": str(runtime_root),
        "version": "3.12.0",
    }

    def runner(argv: list[str], **_kwargs: Any) -> CompletedProcess[str]:
        return CompletedProcess(argv, 0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(identity_module.subprocess, "run", runner)
    first = identity_module._uv_runtime_identity(tmp_path, runtime_root / "uv.exe", {})
    (pytest_package / "core.py").write_bytes(b"tampered pytest core")
    changed_pytest = identity_module._uv_runtime_identity(tmp_path, runtime_root / "uv.exe", {})
    assert first[1] != changed_pytest[1]
    (plugin_package / "hooks.py").write_bytes(b"tampered plugin hooks")
    changed_plugin = identity_module._uv_runtime_identity(tmp_path, runtime_root / "uv.exe", {})
    assert first[2] != changed_plugin[2]


def test_resolve_uv_path_rejects_missing_environment_path() -> None:
    with pytest.raises(C7WorkspaceIdentityError, match="PATH"):
        resolve_uv_path({})


def _completed(stdout: str) -> Any:
    from subprocess import CompletedProcess

    return CompletedProcess([], 0, stdout=stdout, stderr="")
