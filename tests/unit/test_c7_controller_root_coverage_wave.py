# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportUnknownMemberType=false, reportArgumentType=false
"""Additional rejection/atomicity coverage for C7 root preparation."""

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
    C7ControllerRootPreparationError,
    WorkspaceSourceIdentity,
    observe_workspace_source,
    prepare_controller_root,
)

D = "sha256:" + "a" * 64
NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)


def _base(tmp_path: Path, **updates: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "workspace": tmp_path,
        "output_file": tmp_path / "root.json",
        "operation_id": D,
        "repository_digest": D,
        "issuer_identity": "operator",
        "protocol_digest": D,
        "configuration_digest": D,
        "policy_digest": D,
        "activation_digest": D,
        "authorized_at": NOW,
        "ttl_seconds": 60,
        "nonce": D,
        "observer": lambda _workspace: WorkspaceSourceIdentity("b" * 40, "c" * 40, D),
    }
    values.update(updates)
    return values


def test_safe_environment_rejects_missing_and_oversized_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PATH", raising=False)
    with pytest.raises(C7ControllerRootPreparationError, match="PATH"):
        module._safe_environment()
    monkeypatch.setattr(module.os, "environ", {"PATH": "x" * (32 * 1024 + 1)})
    with pytest.raises(C7ControllerRootPreparationError, match="PATH"):
        module._safe_environment()


def test_path_chain_rejects_symlink_component(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(C7ControllerRootPreparationError, match="symlink"):
        module._check_path_chain(link / "missing", "test")


@pytest.mark.parametrize("error", [OSError("git"), subprocess.TimeoutExpired("git", 60)])
def test_run_git_wraps_process_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    monkeypatch.setattr(
        module.subprocess, "run", lambda *_args, **_kwargs: (_ for _ in ()).throw(error)
    )
    with pytest.raises(C7ControllerRootPreparationError, match="Git identity"):
        module._run_git(tmp_path, "status")


def test_git_snapshot_rejects_root_dirty_and_malformed_identities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(module, "_run_git", lambda *_args: str(tmp_path / "wrong"))
    with pytest.raises(C7ControllerRootPreparationError, match="Git root"):
        module._git_snapshot(tmp_path)
    outputs = iter([str(tmp_path), "dirty"])
    monkeypatch.setattr(module, "_run_git", lambda *_args: next(outputs))
    with pytest.raises(C7ControllerRootPreparationError, match="dirty"):
        module._git_snapshot(tmp_path)
    outputs = iter([str(tmp_path), "", "bad", "c" * 40])
    monkeypatch.setattr(module, "_run_git", lambda *_args: next(outputs))
    with pytest.raises(C7ControllerRootPreparationError, match="commit"):
        module._git_snapshot(tmp_path)


def test_extract_archive_rejects_duplicate_and_unsupported(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.tar"
    with tarfile.open(duplicate, "w") as handle:
        for _ in range(2):
            info = tarfile.TarInfo("same")
            info.size = 1
            handle.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(C7ControllerRootPreparationError, match="duplicate"):
        module._extract_archive(duplicate, tmp_path / "out")
    special = tmp_path / "special.tar"
    with tarfile.open(special, "w") as handle:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "outside"
        handle.addfile(info)
    with pytest.raises(C7ControllerRootPreparationError, match="unsupported"):
        module._extract_archive(special, tmp_path / "out2")


def test_observe_workspace_source_rejects_bad_workspace_and_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(C7ControllerRootPreparationError, match="regular directory"):
        observe_workspace_source(missing)
    workspace = tmp_path / "repo"
    workspace.mkdir()
    monkeypatch.setattr(module, "_git_snapshot", lambda _workspace: ("a" * 40, "b" * 40))

    def fake_git(_workspace: Path, *args: str) -> str:
        if "--output" in args:
            output = Path(args[args.index("--output") + 1])
            with tarfile.open(output, "w"):
                pass
        return ""

    monkeypatch.setattr(module, "_run_git", fake_git)
    monkeypatch.setattr(module, "_extract_archive", lambda *_args: None)
    monkeypatch.setattr(module, "source_tree_digest", lambda _path: D)
    snapshots = iter([("a" * 40, "b" * 40), ("c" * 40, "b" * 40)])
    monkeypatch.setattr(module, "_git_snapshot", lambda _workspace: next(snapshots))
    with pytest.raises(C7ControllerRootPreparationError, match="changed"):
        observe_workspace_source(workspace)


def test_write_create_once_rejects_size_symlink_and_conflict(tmp_path: Path) -> None:
    path = tmp_path / "root.json"
    with pytest.raises(C7ControllerRootPreparationError, match="size"):
        module._write_create_once(path, b"x" * (module.MAX_CONTROLLER_ROOT_BYTES + 1))
    target = tmp_path / "target"
    target.write_bytes(b"target")
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(C7ControllerRootPreparationError, match="symlink"):
        module._write_create_once(path, b"x")
    path.unlink()
    path.write_bytes(b"old")
    with pytest.raises(C7ControllerRootPreparationError, match="conflicting"):
        module._write_create_once(path, b"new")


@pytest.mark.parametrize(
    "field",
    [
        "operation_id",
        "repository_digest",
        "protocol_digest",
        "configuration_digest",
        "policy_digest",
        "activation_digest",
        "nonce",
    ],
)
def test_prepare_rejects_malformed_digest(field: str, tmp_path: Path) -> None:
    with pytest.raises(C7ControllerRootPreparationError, match="sha256"):
        prepare_controller_root(**_base(tmp_path, **{field: "bad"}))


def test_prepare_rejects_invalid_root_after_observer(tmp_path: Path) -> None:
    with pytest.raises(C7ControllerRootPreparationError, match="schema"):
        prepare_controller_root(
            **_base(tmp_path, observer=lambda _path: WorkspaceSourceIdentity("bad", "c" * 40, D))
        )
