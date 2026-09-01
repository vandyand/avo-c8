# pyright: reportPrivateUsage=false
"""Focused tests for finite C7 execution and authority timing bounds."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import avo_correlate.application.main_graduation_offline_identity as identity_module
import avo_correlate.application.main_graduation_offline_pytest_executor as executor_module
from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.application.c7_controller_root import (
    MAX_CONTROLLER_ROOT_WINDOW_SECONDS,
    C7ControllerRoot,
)
from avo_correlate.application.main_graduation_offline_identity import (
    FROZEN_OFFLINE_EXECUTION_ARGV,
    C7WorkspaceIdentity,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation_offline_drill import (
    FROZEN_OFFLINE_EXECUTION_NODE_IDS,
    MainGraduationOfflineExecutionAuthority,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_main_graduation_offline_drill_contracts import _authority

D = "sha256:" + "a" * 64
NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def test_controller_root_rejects_window_over_bound() -> None:
    values: dict[str, Any] = {
        "operation_id": D,
        "repository_digest": D,
        "target_ref": "refs/heads/main",
        "issuer_identity": "offline-controller",
        "source_commit": "b" * 40,
        "source_tree": "c" * 40,
        "source_tree_digest": D,
        "protocol_digest": D,
        "configuration_digest": D,
        "policy_digest": D,
        "activation_digest": D,
        "authorized_at": NOW,
        "expires_at": NOW + timedelta(seconds=MAX_CONTROLLER_ROOT_WINDOW_SECONDS + 1),
        "nonce": D,
    }
    stub = C7ControllerRoot.model_construct(
        **values, controller_authority_digest="sha256:" + "0" * 64
    )
    values["controller_authority_digest"] = canonical_digest(
        {
            "domain": "avo-004.7-c7/controller-root/v1",
            "value": stub.model_dump(
                exclude={"controller_authority_digest"}, mode="json"
            ),
        }
    )
    with pytest.raises(ValueError, match="window exceeds maximum"):
        C7ControllerRoot.model_validate(values)


def test_executor_rejects_authority_window_over_bound(tmp_path: Path) -> None:
    executor = executor_module.HermeticPytestExecutor(
        tmp_path,
        FilesystemArtifactStore(tmp_path / "artifacts"),
        clock=lambda: NOW,
        identity_checker=lambda _authority: None,
    )
    authority: Any = SimpleNamespace(
        authorized_at=NOW,
        expires_at=NOW + timedelta(seconds=MAX_CONTROLLER_ROOT_WINDOW_SECONDS + 1),
        argv=FROZEN_OFFLINE_EXECUTION_ARGV,
    )
    with pytest.raises(
        executor_module.OfflinePytestExecutionError,
        match="authority window exceeds maximum",
    ):
        executor.validate_authority(authority)


def test_identity_probe_uses_short_finite_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher = Path(sys.executable).resolve()
    pytest_distribution = importlib.metadata.distribution("pytest")
    record = next(item for item in pytest_distribution.files or () if item.name == "RECORD")
    pytest_origin = importlib.util.find_spec("pytest")
    pytest_launcher = shutil.which("pytest")
    assert pytest_origin is not None and pytest_origin.origin
    assert pytest_launcher
    calls: list[dict[str, Any]] = []

    def runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(kwargs)
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
        return subprocess.CompletedProcess(argv, 0, stdout=payload, stderr="")

    monkeypatch.setattr(identity_module.subprocess, "run", runner)
    identity_module._uv_runtime_identity(tmp_path, launcher, {"PATH": "unused"})
    assert calls[0]["timeout"] == identity_module._IDENTITY_COMMAND_TIMEOUT_SECONDS


def test_pytest_runner_uses_longer_finite_timeout_and_propagates_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []

    def runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(kwargs)
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(executor_module.subprocess, "run", runner)
    monkeypatch.setattr(executor_module, "sanitized_child_environment", lambda: {"PATH": "unused"})
    with pytest.raises(subprocess.TimeoutExpired):
        executor_module._default_runner(["uv", "run", "pytest"], tmp_path, tmp_path / "junit.xml")
    assert calls[0]["timeout"] == executor_module._PYTEST_COMMAND_TIMEOUT_SECONDS
    assert (
        executor_module._PYTEST_COMMAND_TIMEOUT_SECONDS
        > identity_module._IDENTITY_COMMAND_TIMEOUT_SECONDS
    )


def test_executor_constructs_report_digest_from_json_safe_datetime_values(
    tmp_path: Path,
) -> None:
    authority_source = _authority()
    authority_values = authority_source.model_dump()
    authority_values["nodes"] = authority_source.nodes
    authority_values["argv"] = FROZEN_OFFLINE_EXECUTION_ARGV
    authority_values["authority_digest"] = D
    authority_values["authorized_at"] = NOW
    authority_values["expires_at"] = NOW + timedelta(hours=1)
    authority_probe = MainGraduationOfflineExecutionAuthority.model_construct(
        **authority_values
    )
    authority_values["authority_digest"] = canonical_digest(
        {
            "domain": "avo-004.7-c7/offline-execution-authority/v1",
            "value": authority_probe.model_dump(exclude={"authority_digest"}, mode="json"),
        }
    )
    authority = MainGraduationOfflineExecutionAuthority.model_validate(authority_values)

    identity = C7WorkspaceIdentity(
        **{
            field: getattr(authority, field)
            for field in (
                "source_commit",
                "source_tree",
                "source_tree_digest",
                "lockfile_digest",
                "interpreter_digest",
                "pytest_digest",
                "plugin_set_digest",
                "toolchain_digest",
                "environment_identity_digest",
                "uv_digest",
            )
        }
    )

    class FakeIdentityChecker:
        def __init__(self) -> None:
            self._last_uv_path = tmp_path / "uv"
            self._last_uv_path.write_text("uv", encoding="utf-8")

        def __call__(self, _authority: MainGraduationOfflineExecutionAuthority) -> None:
            return None

        def observe(self) -> C7WorkspaceIdentity:
            return identity

    def runner(argv: list[str], cwd: Path, report_path: Path) -> int:
        del argv, cwd
        root = ET.Element("testsuite")
        for node_id in FROZEN_OFFLINE_EXECUTION_NODE_IDS:
            path, _, name = node_id.partition("::")
            ET.SubElement(
                root,
                "testcase",
                classname=f"tests.unit.{path[:-3].replace('/', '.')}",
                name=name,
                status="passed",
            )
        report_path.write_bytes(ET.tostring(root, encoding="utf-8"))
        return 0

    authority_ref = ArtifactRef(
        digest=D,
        size_bytes=1,
        media_type="application/vnd.avo.c7.execution-authority+json",
        role="c7-execution-authority",
        created_at=authority.authorized_at,
    )
    executor = executor_module.HermeticPytestExecutor(
        tmp_path,
        FilesystemArtifactStore(tmp_path / "artifacts"),
        clock=lambda: authority.authorized_at + timedelta(minutes=1),
        runner=runner,
        identity_checker=FakeIdentityChecker(),
    )

    report = executor.execute(authority, authority_ref)

    assert report.executed_at == authority.authorized_at + timedelta(minutes=1)
    assert report.authority_expires_at == authority.expires_at
    assert report.report_digest == canonical_digest(
        {
            "domain": "avo-004.7-c7/offline-execution-report/v1",
            "value": report.model_dump(exclude={"report_digest"}, mode="json"),
        }
    )
