"""Read-only, bounded identity checks for the C7 hermetic executor.

The authority is supplied by a controller.  This module never creates or
updates an authority; it only recomputes local facts and compares them with
that authority.  All external inspection is local (Git and the current Python
installation), with shell execution disabled and bounded output/timeouts.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from avo_correlate.contracts.main_graduation_offline_drill import (
    FROZEN_OFFLINE_EXECUTION_NODE_IDS,
    FROZEN_OFFLINE_EXECUTION_PARAMETER_IDS,
    MainGraduationOfflineExecutionAuthority,
)
from avo_correlate.domain.canonical import canonical_digest, file_digest, source_tree_digest

FROZEN_OFFLINE_EXECUTION_ARGV: tuple[str, ...] = (
    "uv",
    "run",
    "pytest",
    "--disable-warnings",
    "-q",
    "{junitxml}",
)

_HEX_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_MAX_COMMAND_OUTPUT = 1024 * 1024
_COMMAND_TIMEOUT_SECONDS = 30
_MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
_MAX_ARCHIVE_ENTRIES = 100_000
_MAX_ARCHIVE_FILE_BYTES = 64 * 1024 * 1024


class C7WorkspaceIdentityError(RuntimeError):
    """The local workspace/toolchain cannot prove the supplied authority."""


@dataclass(frozen=True, slots=True)
class C7WorkspaceIdentity:
    """The independently observed local identity used by C7."""

    source_commit: str
    source_tree: str
    source_tree_digest: str
    lockfile_digest: str
    interpreter_digest: str
    pytest_digest: str
    plugin_set_digest: str
    toolchain_digest: str


class C7WorkspaceIdentityVerifier:
    """Recompute and exact-match the identity required by C7.

    No value is learned from the authority except the values to compare.  The
    optional ``command_runner`` exists for deterministic unit tests; the
    production default always uses the bounded local subprocess implementation.
    """

    def __init__(
        self,
        workspace: Path,
        *,
        command_runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        self.workspace = workspace.resolve()
        self._command_runner = command_runner or subprocess.run

    def __call__(self, authority: MainGraduationOfflineExecutionAuthority) -> None:
        self.verify(authority)

    def verify(self, authority: MainGraduationOfflineExecutionAuthority) -> None:
        """Raise if any local identity fact differs from the authority."""
        if tuple(authority.argv) != FROZEN_OFFLINE_EXECUTION_ARGV:
            raise C7WorkspaceIdentityError("authority argv differs from frozen pytest command")
        node_ids = tuple(node.node_id for node in authority.nodes)
        parameter_ids = tuple(node.parameter_id for node in authority.nodes)
        if node_ids != FROZEN_OFFLINE_EXECUTION_NODE_IDS:
            raise C7WorkspaceIdentityError("authority nodes differ from frozen C7 nodes")
        if parameter_ids != FROZEN_OFFLINE_EXECUTION_PARAMETER_IDS:
            raise C7WorkspaceIdentityError("authority parameters differ from frozen C7 nodes")

        observed = self.observe()
        expected = (
            ("source_commit", authority.source_commit, observed.source_commit),
            ("source_tree", authority.source_tree, observed.source_tree),
            ("source_tree_digest", authority.source_tree_digest, observed.source_tree_digest),
            ("lockfile_digest", authority.lockfile_digest, observed.lockfile_digest),
            ("interpreter_digest", authority.interpreter_digest, observed.interpreter_digest),
            ("pytest_digest", authority.pytest_digest, observed.pytest_digest),
            ("plugin_set_digest", authority.plugin_set_digest, observed.plugin_set_digest),
            ("toolchain_digest", authority.toolchain_digest, observed.toolchain_digest),
        )
        for name, supplied, actual in expected:
            if supplied != actual:
                raise C7WorkspaceIdentityError(f"workspace identity mismatch: {name}")

    def observe(self) -> C7WorkspaceIdentity:
        """Observe identity from the local workspace and interpreter."""
        commit, tree = self._git_identity()
        lockfile = self.workspace / "uv.lock"
        if not lockfile.is_file() or lockfile.is_symlink():
            raise C7WorkspaceIdentityError("uv.lock is unavailable")
        source_digest = self._source_tree_digest(commit)
        lockfile_digest = file_digest(lockfile)
        interpreter_digest = _interpreter_digest()
        pytest_digest = _pytest_digest()
        plugin_digest = _plugin_set_digest()
        toolchain_digest = canonical_digest(
            {
                "domain": "avo-004.7-c7/toolchain/v1",
                "value": {
                    "lockfile_digest": lockfile_digest,
                    "interpreter_digest": interpreter_digest,
                    "pytest_digest": pytest_digest,
                    "plugin_set_digest": plugin_digest,
                },
            }
        )
        return C7WorkspaceIdentity(
            source_commit=commit,
            source_tree=tree,
            source_tree_digest=source_digest,
            lockfile_digest=lockfile_digest,
            interpreter_digest=interpreter_digest,
            pytest_digest=pytest_digest,
            plugin_set_digest=plugin_digest,
            toolchain_digest=toolchain_digest,
        )

    def _git_identity(self) -> tuple[str, str]:
        root = self._git("rev-parse", "--show-toplevel")
        if Path(root).resolve() != self.workspace:
            raise C7WorkspaceIdentityError("workspace is not the Git root")
        status = self._git("status", "--porcelain=v2", "--untracked-files=all")
        if status:
            raise C7WorkspaceIdentityError("Git worktree is dirty")
        commit = self._git("rev-parse", "--verify", "--end-of-options", "HEAD^{commit}")
        tree = self._git("rev-parse", "--verify", "--end-of-options", "HEAD^{tree}")
        if not _HEX_OBJECT.fullmatch(commit) or not _HEX_OBJECT.fullmatch(tree):
            raise C7WorkspaceIdentityError("Git commit/tree identity is invalid")
        # These are read-only checks.  They also catch an index/worktree state
        # that status porcelain cannot represent consistently on older Git.
        self._git("diff", "--quiet", "--exit-code", "--")
        self._git("diff", "--cached", "--quiet", "--exit-code", "--")
        return commit, tree

    def _git(self, *args: str) -> str:
        try:
            result = self._command_runner(
                ["git", *args],
                cwd=self.workspace,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_COMMAND_TIMEOUT_SECONDS,
                shell=False,
                env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"},
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise C7WorkspaceIdentityError("Git identity inspection failed") from exc
        if len(result.stdout.encode("utf-8")) > _MAX_COMMAND_OUTPUT:
            raise C7WorkspaceIdentityError("Git identity output exceeded bound")
        return result.stdout.strip()

    def _source_tree_digest(self, commit: str) -> str:
        """Hash the committed tree using the repository canonical convention."""
        with tempfile.TemporaryDirectory(prefix="avo-c7-source-") as temporary:
            archive = Path(temporary) / "tree.tar"
            try:
                self._command_runner(
                    ["git", "archive", "--format=tar", "--output", str(archive), commit],
                    cwd=self.workspace,
                    check=True,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=_COMMAND_TIMEOUT_SECONDS,
                    shell=False,
                    env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"},
                )
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                raise C7WorkspaceIdentityError("Git source archive failed") from exc
            if not archive.is_file() or archive.stat().st_size > _MAX_ARCHIVE_BYTES:
                raise C7WorkspaceIdentityError("Git source archive exceeds bound")
            destination = Path(temporary) / "tree"
            destination.mkdir()
            self._extract_archive(archive, destination)
            try:
                return source_tree_digest(destination)
            except (OSError, ValueError) as exc:
                raise C7WorkspaceIdentityError("source tree digest failed") from exc

    @staticmethod
    def _extract_archive(archive: Path, destination: Path) -> None:
        seen: set[str] = set()
        total_bytes = 0
        try:
            with tarfile.open(archive, mode="r:") as handle:
                for index, member in enumerate(handle):
                    if index >= _MAX_ARCHIVE_ENTRIES:
                        raise C7WorkspaceIdentityError("Git source archive has too many entries")
                    relative = PurePosixPath(member.name)
                    if (
                        relative.is_absolute()
                        or not relative.parts
                        or any(part in {"", ".", ".."} for part in relative.parts)
                    ):
                        raise C7WorkspaceIdentityError("Git source archive path is unsafe")
                    normalized = "/".join(relative.parts)
                    if normalized in seen:
                        raise C7WorkspaceIdentityError("Git source archive has duplicate paths")
                    seen.add(normalized)
                    target = destination.joinpath(*relative.parts)
                    if not target.resolve().is_relative_to(destination.resolve()):
                        raise C7WorkspaceIdentityError("Git source archive escapes workspace")
                    if member.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    if not member.isfile() or member.size > _MAX_ARCHIVE_FILE_BYTES:
                        raise C7WorkspaceIdentityError(
                            "Git source archive contains unsupported file"
                        )
                    total_bytes += member.size
                    if total_bytes > _MAX_ARCHIVE_BYTES:
                        raise C7WorkspaceIdentityError("Git source archive exceeds bound")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = handle.extractfile(member)
                    if source is None:
                        raise C7WorkspaceIdentityError("Git source archive file is unreadable")
                    with source, target.open("wb") as output:
                        while chunk := source.read(1024 * 1024):
                            output.write(chunk)
        except (OSError, tarfile.TarError) as exc:
            raise C7WorkspaceIdentityError("Git source archive is malformed") from exc


def _interpreter_digest() -> str:
    executable = Path(sys.executable).resolve()
    if not executable.is_file() or executable.is_symlink():
        raise C7WorkspaceIdentityError("interpreter executable is unavailable")
    probe = _probe(
        [
            str(executable),
            "-I",
            "-S",
            "-c",
            "import platform,sys; print(platform.python_implementation()); "
            "print(platform.python_version()); print(sys.version_info.release)",
        ],
        "interpreter",
    )
    lines = probe.splitlines()
    if len(lines) != 3 or not all(lines):
        raise C7WorkspaceIdentityError("interpreter identity probe is invalid")
    return canonical_digest(
        {
            "domain": "avo-004.7-c7/interpreter/v1",
            "value": {
                "executable": str(executable),
                "executable_digest": file_digest(executable),
                "implementation": lines[0],
                "version": lines[1],
                "release": lines[2],
            },
        }
    )


def _pytest_digest() -> str:
    spec = importlib.util.find_spec("pytest")
    if spec is None or not spec.origin or spec.origin in {"built-in", "frozen"}:
        raise C7WorkspaceIdentityError("pytest installation is unavailable")
    origin = Path(spec.origin).resolve()
    if not origin.is_file():
        raise C7WorkspaceIdentityError("pytest identity path is unavailable")
    try:
        version = importlib.metadata.version("pytest")
    except importlib.metadata.PackageNotFoundError as exc:
        raise C7WorkspaceIdentityError("pytest version is unavailable") from exc
    return canonical_digest(
        {
            "domain": "avo-004.7-c7/pytest/v1",
            "value": {
                "module": str(origin),
                "module_digest": file_digest(origin),
                "version": version,
            },
        }
    )


def _plugin_set_digest() -> str:
    try:
        entries = importlib.metadata.entry_points(group="pytest11")
    except (TypeError, ValueError) as exc:
        raise C7WorkspaceIdentityError("pytest plugin set is unavailable") from exc
    values: list[dict[str, str]] = []
    for entry in entries:
        distribution = entry.dist
        values.append(
            {
                "name": entry.name,
                "value": entry.value,
                "distribution": distribution.name if distribution is not None else "",
                "version": distribution.version if distribution is not None else "",
            }
        )
    values.sort(
        key=lambda item: (
            item["name"],
            item["distribution"],
            item["version"],
            item["value"],
        )
    )
    return canonical_digest(
        {"domain": "avo-004.7-c7/pytest-plugins/v1", "value": values}
    )


def _probe(argv: list[str], label: str) -> str:
    try:
        result = subprocess.run(
            argv,
            cwd=Path.cwd(),
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=_COMMAND_TIMEOUT_SECONDS,
            shell=False,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise C7WorkspaceIdentityError(f"{label} identity probe failed") from exc
    if result.stderr or len(result.stdout.encode("utf-8")) > _MAX_COMMAND_OUTPUT:
        raise C7WorkspaceIdentityError(f"{label} identity probe output is invalid")
    return result.stdout.strip()


__all__ = [
    "FROZEN_OFFLINE_EXECUTION_ARGV",
    "C7WorkspaceIdentity",
    "C7WorkspaceIdentityError",
    "C7WorkspaceIdentityVerifier",
]
