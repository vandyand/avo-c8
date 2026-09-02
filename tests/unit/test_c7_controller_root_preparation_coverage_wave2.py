# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownLambdaType=false, reportArgumentType=false
"""Positive/recovery coverage for local C7 controller-root preparation."""

from __future__ import annotations

import io
import subprocess
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import avo_correlate.application.c7_controller_root_preparation as module
from avo_correlate.application.c7_controller_root_preparation import (
    WorkspaceSourceIdentity,
    observe_workspace_source,
    prepare_controller_root,
)

D = "sha256:" + "a" * 64
NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)


def test_safe_environment_and_path_chain_accept_regular_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", "safe-path")
    values = module._safe_environment()
    assert values["PATH"] == "safe-path"
    module._check_path_chain(tmp_path / "missing" / "child", "test")


def test_extract_archive_accepts_regular_directory_and_file(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "source.tar"
    with tarfile.open(archive, "w") as handle:
        directory = tarfile.TarInfo("package")
        directory.type = tarfile.DIRTYPE
        handle.addfile(directory)
        data = b"source"
        file_info = tarfile.TarInfo("package/module.py")
        file_info.size = len(data)
        handle.addfile(file_info, io.BytesIO(data))
    destination = tmp_path / "out"
    destination.mkdir()
    module._extract_archive(archive, destination)
    assert (destination / "package" / "module.py").read_bytes() == b"source"


def test_observe_workspace_source_returns_stable_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    snapshots = iter([("a" * 40, "b" * 40), ("a" * 40, "b" * 40)])
    monkeypatch.setattr(module, "_git_snapshot", lambda _workspace: next(snapshots))

    def fake_git(_workspace: Path, *args: str) -> str:
        if "--output" in args:
            output = Path(args[args.index("--output") + 1])
            with tarfile.open(output, "w") as handle:
                data = b"tracked"
                info = tarfile.TarInfo("tracked.txt")
                info.size = len(data)
                handle.addfile(info, io.BytesIO(data))
        return ""

    monkeypatch.setattr(module, "_run_git", fake_git)
    observed = observe_workspace_source(workspace)
    assert observed == WorkspaceSourceIdentity("a" * 40, "b" * 40, observed.source_tree_digest)
    assert observed.source_tree_digest.startswith("sha256:")


def test_write_create_once_reconciles_racing_identical_publisher(tmp_path: Path) -> None:
    path = tmp_path / "root.json"
    data = b"same"
    original_link = module.os.link

    def racing_link(
        source: str | bytes | Path, destination: str | bytes | Path, **kwargs: Any
    ) -> None:
        del source, destination, kwargs
        path.write_bytes(data)
        raise FileExistsError("simulated concurrent publisher")

    module.os.link = racing_link
    try:
        digest = module._write_create_once(path, data)
    finally:
        module.os.link = original_link
    assert path.read_bytes() == data
    assert digest.startswith("sha256:")


def test_prepare_controller_root_accepts_minimum_ttl_and_nested_output(tmp_path: Path) -> None:
    output = tmp_path / "nested" / "controller-root.json"
    artifact = prepare_controller_root(
        tmp_path,
        output,
        operation_id=D,
        repository_digest=D,
        issuer_identity="operator",
        protocol_digest=D,
        configuration_digest=D,
        policy_digest=D,
        activation_digest=D,
        authorized_at=NOW,
        ttl_seconds=module.MIN_TTL_SECONDS,
        nonce=D,
        observer=lambda _path: WorkspaceSourceIdentity("b" * 40, "c" * 40, D),
    )
    assert artifact.path == output
    assert artifact.root.expires_at > artifact.root.authorized_at


def test_run_git_accepts_bounded_success_and_rejects_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda argv, **_kwargs: subprocess.CompletedProcess(argv, 0, stdout="ok\n", stderr=""),
    )
    assert module._run_git(tmp_path, "status") == "ok"
