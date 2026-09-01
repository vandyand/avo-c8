# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false
"""Local-only preparation of a C7 controller-root artifact.

The operator supplies every authority binding.  This module contributes only
the source identity observed from a clean local Git worktree and the
controller-root semantic digest.  It has no provider, network, or test-runner
capability.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from avo_correlate.application.c7_controller_root import (
    MAX_CONTROLLER_ROOT_BYTES,
    MAX_CONTROLLER_ROOT_WINDOW_SECONDS,
    C7ControllerRoot,
    C7ControllerRootArtifact,
)
from avo_correlate.contracts.main_graduation_offline_drill import GitObject
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest, source_tree_digest

MIN_TTL_SECONDS = 1
MAX_TTL_SECONDS = MAX_CONTROLLER_ROOT_WINDOW_SECONDS
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 100_000
MAX_ARCHIVE_FILE_BYTES = 64 * 1024 * 1024
MAX_COMMAND_OUTPUT = 1024 * 1024
_ZERO_DIGEST = "sha256:" + "0" * 64


class C7ControllerRootPreparationError(RuntimeError):
    """The local worktree or operator inputs cannot produce a safe root."""


@dataclass(frozen=True, slots=True)
class WorkspaceSourceIdentity:
    """The committed source identity observed from one clean worktree."""

    source_commit: GitObject
    source_tree: GitObject
    source_tree_digest: str


def _safe_environment() -> dict[str, str]:
    """Provide Git no credential or prompt environment for local inspection."""
    path = os.environ.get("PATH", "")
    if not path or len(path) > 32 * 1024:
        raise C7ControllerRootPreparationError("local Git environment PATH is unavailable")
    values = {"PATH": path, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"}
    for name in ("SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"):
        value = os.environ.get(name)
        if value:
            values[name] = value
    return values


def _is_reparse(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise C7ControllerRootPreparationError(f"path cannot be inspected safely: {path}") from exc
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & 0x400
    )


def _check_path_chain(path: Path, label: str) -> None:
    """Reject symlinks/reparse points in every existing path component."""
    current = Path(path)
    missing: list[Path] = []
    while True:
        try:
            exists = current.exists()
            is_link = current.is_symlink()
        except OSError as exc:
            raise C7ControllerRootPreparationError(f"{label} path cannot be inspected") from exc
        if exists or is_link:
            if _is_reparse(current):
                raise C7ControllerRootPreparationError(f"{label} path cannot contain a symlink")
            break
        missing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent


def _run_git(workspace: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            shell=False,
            env=_safe_environment(),
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise C7ControllerRootPreparationError("Git identity inspection failed") from exc
    if max(
        len(result.stdout.encode("utf-8")), len(result.stderr.encode("utf-8"))
    ) > MAX_COMMAND_OUTPUT:
        raise C7ControllerRootPreparationError("Git identity output exceeded bound")
    return result.stdout.strip()


def _git_snapshot(workspace: Path) -> tuple[str, str]:
    top = Path(_run_git(workspace, "rev-parse", "--show-toplevel")).resolve()
    if top != workspace.resolve():
        raise C7ControllerRootPreparationError("workspace is not the Git root")
    if _run_git(workspace, "status", "--porcelain=v2", "--untracked-files=all"):
        raise C7ControllerRootPreparationError("Git worktree is dirty")
    commit = _run_git(workspace, "rev-parse", "--verify", "--end-of-options", "HEAD^{commit}")
    tree = _run_git(workspace, "rev-parse", "--verify", "--end-of-options", "HEAD^{tree}")
    if len(commit) not in {40, 64} or any(char not in "0123456789abcdef" for char in commit):
        raise C7ControllerRootPreparationError("Git commit identity is invalid")
    if len(tree) not in {40, 64} or any(char not in "0123456789abcdef" for char in tree):
        raise C7ControllerRootPreparationError("Git tree identity is invalid")
    try:
        _run_git(workspace, "diff", "--quiet", "--exit-code", "--")
        _run_git(workspace, "diff", "--cached", "--quiet", "--exit-code", "--")
    except C7ControllerRootPreparationError as exc:
        raise C7ControllerRootPreparationError("Git worktree is dirty") from exc
    return commit, tree


def _extract_archive(archive: Path, destination: Path) -> None:
    seen: set[str] = set()
    total_bytes = 0
    try:
        with tarfile.open(archive, mode="r:") as handle:
            for index, member in enumerate(handle):
                if index >= MAX_ARCHIVE_ENTRIES:
                    raise C7ControllerRootPreparationError(
                        "Git source archive has too many entries"
                    )
                relative = PurePosixPath(member.name)
                if (
                    relative.is_absolute()
                    or not relative.parts
                    or any(part in {"", ".", ".."} for part in relative.parts)
                ):
                    raise C7ControllerRootPreparationError("Git source archive path is unsafe")
                normalized = "/".join(relative.parts)
                if normalized in seen:
                    raise C7ControllerRootPreparationError("Git source archive has duplicate paths")
                seen.add(normalized)
                target = destination.joinpath(*relative.parts)
                if not target.resolve().is_relative_to(destination.resolve()):
                    raise C7ControllerRootPreparationError("Git source archive escapes workspace")
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile() or member.size > MAX_ARCHIVE_FILE_BYTES:
                    raise C7ControllerRootPreparationError(
                        "Git source archive contains unsupported file"
                    )
                total_bytes += member.size
                if total_bytes > MAX_ARCHIVE_BYTES:
                    raise C7ControllerRootPreparationError("Git source archive exceeds bound")
                target.parent.mkdir(parents=True, exist_ok=True)
                source = handle.extractfile(member)
                if source is None:
                    raise C7ControllerRootPreparationError("Git source archive file is unreadable")
                with source, target.open("wb") as output:
                    while chunk := source.read(1024 * 1024):
                        output.write(chunk)
    except (OSError, tarfile.TarError) as exc:
        raise C7ControllerRootPreparationError("Git source archive is malformed") from exc


def observe_workspace_source(workspace: Path) -> WorkspaceSourceIdentity:
    """Observe exact commit, tree, and committed source digest from a clean Git root."""
    _check_path_chain(workspace, "workspace")
    if not workspace.is_dir() or _is_reparse(workspace):
        raise C7ControllerRootPreparationError("workspace must be a regular directory")
    workspace = workspace.resolve(strict=True)
    commit, tree = _git_snapshot(workspace)
    with tempfile.TemporaryDirectory(prefix="avo-c7-root-") as temporary:
        archive = Path(temporary) / "source.tar"
        _run_git(workspace, "archive", "--format=tar", "--output", str(archive), commit)
        if not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE_BYTES:
            raise C7ControllerRootPreparationError("Git source archive exceeds bound")
        destination = Path(temporary) / "source"
        destination.mkdir()
        _extract_archive(archive, destination)
        try:
            digest = source_tree_digest(destination)
        except (OSError, ValueError) as exc:
            raise C7ControllerRootPreparationError("source tree digest failed") from exc
    if _git_snapshot(workspace) != (commit, tree):
        raise C7ControllerRootPreparationError("workspace changed during source observation")
    return WorkspaceSourceIdentity(commit, tree, digest)


def _write_create_once(path: Path, data: bytes) -> str:
    if len(data) > MAX_CONTROLLER_ROOT_BYTES:
        raise C7ControllerRootPreparationError("controller root exceeds size bound")
    _check_path_chain(path.parent, "controller root output parent")
    path.parent.mkdir(parents=True, exist_ok=True)
    _check_path_chain(path, "controller root output")
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if path.exists():
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size > MAX_CONTROLLER_ROOT_BYTES
        ):
            raise C7ControllerRootPreparationError(
                "controller root output must be a regular file"
            )
        try:
            existing = path.read_bytes()
        except OSError as exc:
            raise C7ControllerRootPreparationError("controller root output is unreadable") from exc
        if existing != data:
            raise C7ControllerRootPreparationError("conflicting controller root already exists")
        return digest
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", suffix=".partial", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                raise C7ControllerRootPreparationError(
                    "conflicting controller root already exists"
                ) from None
        return digest
    except OSError as exc:
        raise C7ControllerRootPreparationError("controller root could not be published") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _build_root(values: dict[str, Any]) -> C7ControllerRoot:
    stub = C7ControllerRoot.model_construct(
        **values, controller_authority_digest=_ZERO_DIGEST
    )
    values["controller_authority_digest"] = canonical_digest(
        {
            "domain": "avo-004.7-c7/controller-root/v1",
            "value": stub.model_dump(
                exclude={"controller_authority_digest"}, mode="json"
            ),
        }
    )
    try:
        return C7ControllerRoot.model_validate(values)
    except ValueError as exc:
        raise C7ControllerRootPreparationError("controller root schema validation failed") from exc


def prepare_controller_root(
    workspace: Path,
    output_file: Path,
    *,
    operation_id: str,
    repository_digest: str,
    issuer_identity: str,
    protocol_digest: str,
    configuration_digest: str,
    policy_digest: str,
    activation_digest: str,
    authorized_at: datetime,
    ttl_seconds: int,
    nonce: str,
    observer: Callable[[Path], WorkspaceSourceIdentity] = observe_workspace_source,
) -> C7ControllerRootArtifact:
    """Build and create-once publish one operator-supplied controller root."""
    if authorized_at.tzinfo is None or authorized_at.utcoffset() is None:
        raise C7ControllerRootPreparationError("authorized_at must be timezone-aware")
    if not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
        raise C7ControllerRootPreparationError(
            f"ttl_seconds must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS}"
        )
    for name, value in (
        ("operation_id", operation_id),
        ("repository_digest", repository_digest),
        ("protocol_digest", protocol_digest),
        ("configuration_digest", configuration_digest),
        ("policy_digest", policy_digest),
        ("activation_digest", activation_digest),
        ("nonce", nonce),
    ):
        if len(value) != 71 or not value.startswith("sha256:") or any(
            char not in "0123456789abcdef" for char in value[7:]
        ):
            raise C7ControllerRootPreparationError(f"{name} must be a sha256 digest")
    identity = observer(workspace)
    expires_at = authorized_at + timedelta(seconds=ttl_seconds)
    root = _build_root(
        {
            "operation_id": operation_id,
            "repository_digest": repository_digest,
            "target_ref": "refs/heads/main",
            "issuer_identity": issuer_identity,
            "source_commit": identity.source_commit,
            "source_tree": identity.source_tree,
            "source_tree_digest": identity.source_tree_digest,
            "protocol_digest": protocol_digest,
            "configuration_digest": configuration_digest,
            "policy_digest": policy_digest,
            "activation_digest": activation_digest,
            "authorized_at": authorized_at,
            "expires_at": expires_at,
            "nonce": nonce,
        }
    )
    data = canonical_bytes(root.model_dump(mode="json"))
    digest = _write_create_once(output_file, data)
    return C7ControllerRootArtifact(root=root, raw_digest=digest, path=output_file)


__all__ = [
    "MAX_ARCHIVE_BYTES",
    "MAX_CONTROLLER_ROOT_BYTES",
    "MAX_CONTROLLER_ROOT_WINDOW_SECONDS",
    "MAX_TTL_SECONDS",
    "MIN_TTL_SECONDS",
    "C7ControllerRootPreparationError",
    "WorkspaceSourceIdentity",
    "observe_workspace_source",
    "prepare_controller_root",
]
