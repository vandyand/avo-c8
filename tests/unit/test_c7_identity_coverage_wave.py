# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportUnknownMemberType=false, reportArgumentType=false
"""Additional branch coverage for the fail-closed C7 identity probes.

These tests deliberately exercise rejection paths that are difficult to reach
through the normal installed runtime (malformed RECORD metadata, hostile
archive members, and bounded subprocess failures).
"""

from __future__ import annotations

import io
import json
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest

import avo_correlate.application.main_graduation_offline_identity as module
from avo_correlate.application.main_graduation_offline_identity import (
    C7WorkspaceIdentityError,
    child_environment_identity,
    resolve_uv_path,
)


def _runner_error(exc: BaseException):
    def runner(*_args: Any, **_kwargs: Any) -> Any:
        raise exc

    return runner


def test_child_environment_identity_rejects_unsafe_and_oversized_values() -> None:
    with pytest.raises(C7WorkspaceIdentityError, match="unsafe"):
        child_environment_identity({"PATH": "ok", "OPENAI_API_KEY": "secret"})
    with pytest.raises(C7WorkspaceIdentityError, match="exceeds bound"):
        child_environment_identity({"PATH": "x" * (128 * 1024)})


@pytest.mark.parametrize(
    ("which", "expected"),
    [
        (None, "unavailable"),
        ("missing", None),
    ],
)
def test_resolve_uv_path_rejects_unavailable_launcher(
    monkeypatch: pytest.MonkeyPatch, which: str | None, expected: str | None
) -> None:
    monkeypatch.setattr(module.shutil, "which", lambda *_args, **_kwargs: which)
    if expected is None:
        with pytest.raises(OSError):
            resolve_uv_path({"PATH": "test"})
    else:
        with pytest.raises(C7WorkspaceIdentityError, match=expected):
            resolve_uv_path({"PATH": "test"})


def test_resolve_uv_path_rejects_directory_and_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "uv"
    directory.mkdir()
    monkeypatch.setattr(module.shutil, "which", lambda *_args, **_kwargs: str(directory))
    with pytest.raises(C7WorkspaceIdentityError, match="unavailable"):
        resolve_uv_path({"PATH": "test"})
    target = tmp_path / "real-uv"
    target.write_bytes(b"uv")
    link = tmp_path / "linked-uv"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    monkeypatch.setattr(module.shutil, "which", lambda *_args, **_kwargs: str(link))
    # resolve(strict=True) follows the link, but the resulting digest path is
    # still a regular executable candidate; this is intentionally accepted.
    assert resolve_uv_path({"PATH": "test"}) == target.resolve()


@pytest.mark.parametrize(
    "payload",
    [
        "not-json",
        json.dumps({"python": "x"}),
        json.dumps(
            {
                "python": "x",
                "implementation": "CPython",
                "version": "3",
                "pytest": "x",
                "pytest_version": "1",
                "pytest_launcher": "x",
                "plugins": [],
                "pytest_distribution": {},
                "plugin_distributions": [],
            }
        ),
    ],
)
def test_uv_runtime_identity_rejects_malformed_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: str
) -> None:
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda argv, **_kwargs: subprocess.CompletedProcess(argv, 0, stdout=payload, stderr=""),
    )
    with pytest.raises(C7WorkspaceIdentityError, match="probe failed"):
        module._uv_runtime_identity(tmp_path, tmp_path / "uv", {"PATH": "x"})


def test_uv_runtime_identity_rejects_stderr_and_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda argv, **_kwargs: subprocess.CompletedProcess(
            argv, 0, stdout="{}", stderr="diagnostic"
        ),
    )
    with pytest.raises(C7WorkspaceIdentityError, match="probe failed"):
        module._uv_runtime_identity(tmp_path, tmp_path / "uv", {"PATH": "x"})
    monkeypatch.setattr(
        module.subprocess, "run", _runner_error(subprocess.TimeoutExpired("uv", 60))
    )
    with pytest.raises(C7WorkspaceIdentityError, match="probe failed"):
        module._uv_runtime_identity(tmp_path, tmp_path / "uv", {"PATH": "x"})


@pytest.mark.parametrize(
    ("function", "value"),
    [
        (module._runtime_regular_root, "relative"),
        (module._runtime_regular_root, None),
        (module._runtime_relative_path, "../escape"),
        (module._runtime_relative_path, "bad\\windows"),
        (module._runtime_record_path, "../" * 9 + "record"),
    ],
)
def test_runtime_path_helpers_reject_hostile_values(function: Any, value: object) -> None:
    with pytest.raises(ValueError):
        function(value)


def test_runtime_member_rejects_symlink_and_escape(tmp_path: Path) -> None:
    root = tmp_path / "runtime"
    root.mkdir()
    safe = root / "safe"
    safe.write_bytes(b"safe")
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    link = root / "link"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation unavailable")
    # Resolving an outward-pointing symlink may reject it either as the symlink
    # itself or, on POSIX, at the earlier containment fence. Both are the same
    # fail-closed boundary.
    with pytest.raises(ValueError, match=r"symlink|escapes"):
        module._runtime_member(root, "link")
    with pytest.raises(ValueError, match="escapes"):
        module._runtime_member(root, "../outside", tmp_path)


def test_runtime_distribution_rejects_malformed_record_and_missing_self(tmp_path: Path) -> None:
    root = tmp_path / "site-packages"
    info = root / "x-1.dist-info"
    info.mkdir(parents=True)
    (root / "x.py").write_bytes(b"x")
    record = info / "RECORD"
    record.write_text("x.py,,\n", encoding="utf-8")
    with pytest.raises(ValueError, match="does not record itself"):
        module._runtime_distribution_identity(
            {"name": "x", "version": "1", "root": str(root), "record": "x-1.dist-info/RECORD"},
            tmp_path,
        )
    record.write_bytes(b"bad,row\n")
    with pytest.raises(ValueError, match="row is malformed"):
        module._runtime_distribution_identity(
            {"name": "x", "version": "1", "root": str(root), "record": "x-1.dist-info/RECORD"},
            tmp_path,
        )


def test_extract_archive_rejects_unsafe_duplicate_and_special_members(tmp_path: Path) -> None:
    def archive(name: str, member_type: str = "file") -> Path:
        path = tmp_path / (name.replace("/", "_") + ".tar")
        with tarfile.open(path, "w") as handle:
            info = tarfile.TarInfo(name)
            if member_type == "dir":
                info.type = tarfile.DIRTYPE
            elif member_type == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "outside"
            else:
                data = b"x"
                info.size = len(data)
                handle.addfile(info, io.BytesIO(data))
                return path
            handle.addfile(info)
        return path

    for name in ("../escape", "/absolute"):
        with pytest.raises(C7WorkspaceIdentityError, match="unsafe"):
            module.C7WorkspaceIdentityVerifier._extract_archive(archive(name), tmp_path / "out")
    with pytest.raises(C7WorkspaceIdentityError, match="unsupported"):
        module.C7WorkspaceIdentityVerifier._extract_archive(
            archive("link", "symlink"), tmp_path / "out"
        )


def test_identity_git_probe_wraps_failures_and_output_bounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    verifier = module.C7WorkspaceIdentityVerifier(tmp_path)
    monkeypatch.setattr(module, "sanitized_child_environment", lambda: {"PATH": "x"})
    verifier._command_runner = _runner_error(OSError("no git"))
    with pytest.raises(C7WorkspaceIdentityError, match="Git identity"):
        verifier._git("status")
    verifier._command_runner = lambda *_args, **_kwargs: subprocess.CompletedProcess(
        [], 0, stdout="x" * (module._MAX_COMMAND_OUTPUT + 1), stderr=""
    )
    with pytest.raises(C7WorkspaceIdentityError, match="output"):
        verifier._git("status")
