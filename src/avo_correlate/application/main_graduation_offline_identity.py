# pyright: reportUnusedFunction=false
"""Read-only, bounded identity checks for the C7 hermetic executor.

The authority is supplied by a controller.  This module never creates or
updates an authority; it only recomputes local facts and compares them with
that authority.  All external inspection is local (Git and the current Python
installation), with shell execution disabled and bounded output/timeouts.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from avo_correlate.contracts.main_graduation_offline_drill import (
    FROZEN_OFFLINE_EXECUTION_NODE_IDS,
    FROZEN_OFFLINE_EXECUTION_PARAMETER_IDS,
    MainGraduationOfflineExecutionAuthority,
)
from avo_correlate.domain.canonical import canonical_digest, file_digest, source_tree_digest

FROZEN_OFFLINE_EXECUTION_ARGV: tuple[str, ...] = (
    "uv",
    "run",
    "--locked",
    "--offline",
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
    # These are deliberately required.  A missing environment or uv pin must
    # fail closed; a zero/default digest would make an old authority appear
    # equivalent to a measured toolchain.
    environment_identity_digest: str
    uv_digest: str


_SAFE_CHILD_ENV_KEYS = frozenset(
    {
        "PATH",
        "SystemRoot",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "VIRTUAL_ENV",
        "UV_CACHE_DIR",
    }
)


def sanitized_child_environment() -> dict[str, str]:
    """Return a bounded environment with provider credentials excluded."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in _SAFE_CHILD_ENV_KEYS
    }
    path = environment.get("PATH")
    if not path:
        raise C7WorkspaceIdentityError("scrubbed child environment has no PATH")
    if len(path) > 32 * 1024:
        raise C7WorkspaceIdentityError("scrubbed child environment PATH exceeds bound")
    return environment


def child_environment_identity(environment: dict[str, str] | None = None) -> str:
    values = environment if environment is not None else sanitized_child_environment()
    if not values.get("PATH"):
        raise C7WorkspaceIdentityError("scrubbed child environment has no PATH")
    if any(key not in _SAFE_CHILD_ENV_KEYS for key in values) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in values.items()
    ):
        raise C7WorkspaceIdentityError("child environment contains an unsafe value")
    if sum(len(key) + len(value) for key, value in values.items()) > 128 * 1024:
        raise C7WorkspaceIdentityError("scrubbed child environment exceeds bound")
    bounded = tuple(sorted((key, value) for key, value in values.items()))
    return canonical_digest(
        {"domain": "avo-004.7-c7/child-environment/v1", "value": bounded}
    )


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
        self._last_uv_path: Path | None = None

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
        pinned_environment = getattr(authority, "environment_identity_digest", None)
        if not isinstance(pinned_environment, str) or (
            pinned_environment != observed.environment_identity_digest
        ):
            raise C7WorkspaceIdentityError(
                "workspace identity mismatch: environment_identity_digest"
            )
        pinned_uv = getattr(authority, "uv_digest", None)
        if not isinstance(pinned_uv, str) or pinned_uv != observed.uv_digest:
            raise C7WorkspaceIdentityError("workspace identity mismatch: uv_digest")

    def observe(self) -> C7WorkspaceIdentity:
        """Observe identity from the local workspace and interpreter."""
        commit, tree = self._git_identity()
        lockfile = self.workspace / "uv.lock"
        if not lockfile.is_file() or lockfile.is_symlink():
            raise C7WorkspaceIdentityError("uv.lock is unavailable")
        source_digest = self._source_tree_digest(commit)
        lockfile_digest = file_digest(lockfile)
        environment = sanitized_child_environment()
        uv_path = resolve_uv_path(environment)
        interpreter_digest, pytest_digest, plugin_digest = _uv_runtime_identity(
            self.workspace, uv_path, environment
        )
        environment_identity_digest = child_environment_identity(environment)
        uv_digest = _uv_digest(uv_path)
        self._last_uv_path = uv_path
        toolchain_digest = canonical_digest(
            {
                "domain": "avo-004.7-c7/toolchain/v2",
                "value": {
                    "lockfile_digest": lockfile_digest,
                    "interpreter_digest": interpreter_digest,
                    "pytest_digest": pytest_digest,
                    "plugin_set_digest": plugin_digest,
                    "environment_identity_digest": environment_identity_digest,
                    "uv_digest": uv_digest,
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
            environment_identity_digest=environment_identity_digest,
            uv_digest=uv_digest,
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
                env={
                    **sanitized_child_environment(),
                    "GIT_OPTIONAL_LOCKS": "0",
                    "GIT_TERMINAL_PROMPT": "0",
                },
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            raise C7WorkspaceIdentityError("Git identity inspection failed") from exc
        if max(
            len(result.stdout.encode("utf-8")), len(result.stderr.encode("utf-8"))
        ) > _MAX_COMMAND_OUTPUT:
            raise C7WorkspaceIdentityError("Git identity output exceeded bound")
        return result.stdout.strip()

    def _source_tree_digest(self, commit: str) -> str:
        """Hash the committed tree using the repository canonical convention."""
        with tempfile.TemporaryDirectory(prefix="avo-c7-source-") as temporary:
            archive = Path(temporary) / "tree.tar"
            try:
                result = self._command_runner(
                    ["git", "archive", "--format=tar", "--output", str(archive), commit],
                    cwd=self.workspace,
                    check=True,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=_COMMAND_TIMEOUT_SECONDS,
                    shell=False,
                    env={
                        **sanitized_child_environment(),
                        "GIT_OPTIONAL_LOCKS": "0",
                        "GIT_TERMINAL_PROMPT": "0",
                    },
                )
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                raise C7WorkspaceIdentityError("Git source archive failed") from exc
            if max(
                len(result.stdout.encode("utf-8")), len(result.stderr.encode("utf-8"))
            ) > _MAX_COMMAND_OUTPUT:
                raise C7WorkspaceIdentityError("Git source archive output exceeded bound")
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


def resolve_uv_path(environment: dict[str, str] | None = None) -> Path:
    """Resolve one absolute uv executable used by both probes and execution."""
    values = environment if environment is not None else sanitized_child_environment()
    path_value = values.get("PATH")
    if not path_value:
        raise C7WorkspaceIdentityError("scrubbed child environment has no PATH")
    launcher = shutil.which("uv", path=path_value)
    if not launcher:
        raise C7WorkspaceIdentityError("uv launcher is unavailable")
    path = Path(launcher).resolve(strict=True)
    if not path.is_file():
        raise C7WorkspaceIdentityError("uv launcher path is unavailable")
    return path


def _uv_digest(path: Path) -> str:
    return canonical_digest(
        {
            "domain": "avo-004.7-c7/uv/v1",
            "value": {"path": str(path), "digest": file_digest(path)},
        }
    )


def _uv_runtime_identity(
    workspace: Path, launcher: Path, environment: dict[str, str]
) -> tuple[str, str, str]:
    """Measure the interpreter and pytest stack inside the locked uv child."""
    probe = (
        "import importlib.metadata as m, importlib.util, json, platform, sys; "
        "plugins=sorted((e.name,e.value,getattr(e.dist,'name',''),"
        "getattr(e.dist,'version','')) for e in m.entry_points(group='pytest11')); "
        "p=importlib.util.find_spec('pytest'); "
        "print(json.dumps({'python':sys.executable,'implementation':platform.python_implementation(),"
        "'version':platform.python_version(),'pytest':p.origin if p else '',"
        "'pytest_version':m.version('pytest'),'plugins':plugins},sort_keys=True))"
    )
    try:
        result = subprocess.run(
            [str(launcher), "run", "--locked", "--offline", "python", "-I", "-c", probe],
            cwd=workspace,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=_COMMAND_TIMEOUT_SECONDS,
            shell=False,
            env=environment,
        )
        if result.stderr or len(result.stdout.encode("utf-8")) > _MAX_COMMAND_OUTPUT:
            raise ValueError("uv runtime probe output is invalid")
        payload: dict[str, Any] = json.loads(result.stdout.strip())
        if type(payload) is not dict or any(
            not isinstance(payload.get(key), str)
            for key in ("python", "implementation", "version", "pytest", "pytest_version")
        ) or not isinstance(payload.get("plugins"), list):
            raise ValueError("uv runtime probe shape is invalid")
        python_path = Path(str(payload["python"])).resolve()
        pytest_path = Path(str(payload["pytest"])).resolve()
        if not python_path.is_file() or not pytest_path.is_file():
            raise ValueError("uv runtime paths are unavailable")
        if any(
            type(item) is not list
            or len(item) != 4
            or not all(isinstance(value, str) for value in item)
            for item in payload["plugins"]
        ):
            raise ValueError("uv runtime plugin identity is invalid")
        interpreter = canonical_digest(
            {"domain": "avo-004.7-c7/interpreter-uv/v1", "value": {
                "path": str(python_path), "digest": file_digest(python_path),
                "implementation": payload["implementation"], "version": payload["version"]}}
        )
        pytest = canonical_digest(
            {"domain": "avo-004.7-c7/pytest-uv/v1", "value": {
                "path": str(pytest_path), "digest": file_digest(pytest_path),
                "version": payload["pytest_version"]}}
        )
        plugins = canonical_digest(
            {"domain": "avo-004.7-c7/pytest-plugins-uv/v1", "value": payload["plugins"]}
        )
        return interpreter, pytest, plugins
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise C7WorkspaceIdentityError("uv runtime identity probe failed") from exc
__all__ = [
    "FROZEN_OFFLINE_EXECUTION_ARGV",
    "C7WorkspaceIdentity",
    "C7WorkspaceIdentityError",
    "C7WorkspaceIdentityVerifier",
    "child_environment_identity",
    "resolve_uv_path",
    "sanitized_child_environment",
]
