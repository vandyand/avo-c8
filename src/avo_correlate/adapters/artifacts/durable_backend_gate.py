"""Fail-closed qualification of a local filesystem for durable journal state.

This module is intentionally narrower than an artifact store.  It does not
create files, issue ``fsync`` calls, rename paths, or expose a provider/HTTP
capability.  It only checks the operating system's mount facts needed before a
later journal implementation may do those things.

The gate trusts only facts read from the current process's kernel mount table
and ``stat(2)``.  Callers cannot assert that a path is local or durable with a
boolean override.  Qualification is deliberately conservative: only Linux
mounts whose effective filesystem is an explicitly allowlisted local ext4,
xfs, or btrfs block-device mount are accepted.
"""

from __future__ import annotations

import os
import platform
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath
from typing import cast

_MOUNTINFO_PATH = Path("/proc/self/mountinfo")
_ALLOWED_FILESYSTEMS = frozenset({"ext4", "xfs", "btrfs"})
_KNOWN_FORBIDDEN_FILESYSTEMS = frozenset(
    {
        "9p",
        "cifs",
        "drvfs",
        "fuse",
        "fuseblk",
        "nfs",
        "nfs4",
        "overlay",
        "smbfs",
        "tmpfs",
        "v9fs",
    }
)
_DEVICE_RE = re.compile(r"^[0-9]+:[0-9]+$")
_VALID_ESCAPES = {"011": "\t", "012": "\n", "040": " ", "134": "\\"}


class DurableBackendGateError(RuntimeError):
    """The requested root does not meet the narrow durable-backend gate."""


@dataclass(frozen=True)
class MountFacts:
    """Kernel-derived facts for one parsed ``mountinfo`` entry."""

    mount_id: int
    parent_id: int
    device: str
    root: str
    mount_point: PurePath
    mount_options: frozenset[str]
    filesystem_type: str
    source: str
    super_options: frozenset[str]


@dataclass(frozen=True)
class DurableBackendQualification:
    """A read-only, explanatory result from :func:`qualify_durable_backend`."""

    root: Path
    qualified: bool
    reason: str
    filesystem_type: str | None = None
    mount_point: PurePath | None = None
    mount_id: int | None = None
    device: str | None = None
    wsl_kernel: bool = False


def qualify_durable_backend(root: Path) -> DurableBackendQualification:
    """Return whether ``root`` is safe to use for a future durable journal.

    This function performs no writes and never returns a positive result based
    on caller-supplied platform, filesystem, or locality flags.  It fails
    closed for unsupported platforms, malformed kernel facts, symlinked roots,
    and any mount outside the explicit local block-device allowlist.
    """

    candidate = Path(root)
    wsl_kernel = _is_wsl_kernel()
    if sys.platform.startswith("win"):
        return _rejected(candidate, "native_windows", wsl_kernel=wsl_kernel)
    if wsl_kernel:
        return _rejected(candidate, "unsupported_wsl", wsl_kernel=True)
    if sys.platform != "linux":
        return _rejected(candidate, "unsupported_platform", wsl_kernel=wsl_kernel)

    try:
        resolved = _canonical_directory(candidate)
        entries = _parse_mountinfo(_read_mountinfo())
        device = _path_device(resolved)
    except (OSError, ValueError) as exc:
        return _rejected(candidate, f"untrusted_os_facts:{exc}", wsl_kernel=wsl_kernel)

    mount = _mount_for_path(resolved, entries)
    if mount is None:
        return _rejected(resolved, "path_has_no_matching_mount", wsl_kernel=wsl_kernel)
    common = {
        "filesystem_type": mount.filesystem_type,
        "mount_point": mount.mount_point,
        "mount_id": mount.mount_id,
        "device": mount.device,
        "wsl_kernel": wsl_kernel,
    }
    if mount.filesystem_type in _KNOWN_FORBIDDEN_FILESYSTEMS:
        return _rejected(resolved, "forbidden_filesystem_type", **common)
    if mount.filesystem_type not in _ALLOWED_FILESYSTEMS:
        return _rejected(resolved, "filesystem_type_not_allowlisted", **common)
    if mount.device != device:
        return _rejected(resolved, "mount_device_does_not_match_stat", **common)
    if "ro" in mount.mount_options or "ro" in mount.super_options:
        return _rejected(resolved, "mount_is_read_only", **common)
    if not _is_local_block_device(mount.source):
        return _rejected(resolved, "mount_source_is_not_local_block_device", **common)
    return DurableBackendQualification(
        root=resolved,
        qualified=True,
        reason="qualified_local_block_filesystem",
        **common,
    )


def require_durable_backend(root: Path) -> DurableBackendQualification:
    """Raise if ``root`` is not qualified; never mutates the filesystem.

    A successful result establishes the backend preconditions for the next
    journal stage: an existing canonical directory, a uniquely selected
    kernel mount, a matching ``stat(2)`` device identity, a writable mount,
    and an explicitly allowlisted local block filesystem.  The journal must
    still fsync each record, fsync its containing directory after publication,
    and keep create-once temporary files and atomic renames on this same mount.
    """

    result = qualify_durable_backend(root)
    if not result.qualified:
        raise DurableBackendGateError(
            f"durable backend rejected for {result.root}: {result.reason}"
        )
    return result


def _rejected(
    root: Path,
    reason: str,
    *,
    filesystem_type: str | None = None,
    mount_point: PurePath | None = None,
    mount_id: int | None = None,
    device: str | None = None,
    wsl_kernel: bool = False,
) -> DurableBackendQualification:
    return DurableBackendQualification(
        root=root,
        qualified=False,
        reason=reason,
        filesystem_type=filesystem_type,
        mount_point=mount_point,
        mount_id=mount_id,
        device=device,
        wsl_kernel=wsl_kernel,
    )


def _is_wsl_kernel() -> bool:
    release = platform.release().lower()
    return "microsoft" in release or "wsl" in release


def _canonical_directory(path: Path) -> Path:
    absolute = path if path.is_absolute() else Path.cwd() / path
    for component in [*reversed(absolute.parents), absolute]:
        if component.is_symlink():
            raise ValueError("path contains a symlink component")
    resolved = absolute.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("path is not a directory")
    return resolved


def _read_mountinfo() -> str:
    return _MOUNTINFO_PATH.read_text(encoding="utf-8")


def _parse_mountinfo(text: str) -> tuple[MountFacts, ...]:
    """Parse the kernel's mountinfo format, rejecting malformed input."""

    entries: list[MountFacts] = []
    mount_ids: set[int] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            if line.count(" - ") != 1:
                raise ValueError("separator count")
            prefix, suffix = line.split(" - ", 1)
            left = prefix.split()
            right = suffix.split()
            if len(left) < 6 or len(right) < 3:
                raise ValueError("field count")
            mount_id = int(left[0])
            parent_id = int(left[1])
            device = left[2]
            if (
                mount_id < 1
                or parent_id < 1
                or mount_id in mount_ids
                or not _DEVICE_RE.fullmatch(device)
            ):
                raise ValueError("mount identity")
            root = _decode_mountinfo_path(left[3])
            mount_point = PurePosixPath(_decode_mountinfo_path(left[4]))
            if not root.startswith("/") or not mount_point.is_absolute():
                raise ValueError("mount paths must be absolute")
            entries.append(
                MountFacts(
                    mount_id=mount_id,
                    parent_id=parent_id,
                    device=device,
                    root=root,
                    mount_point=mount_point,
                    mount_options=_parse_options(left[5]),
                    filesystem_type=right[0],
                    source=_decode_mountinfo_path(right[1]),
                    super_options=_parse_options(right[2]),
                )
            )
            mount_ids.add(mount_id)
        except (IndexError, TypeError, ValueError) as exc:
            raise ValueError(f"malformed mountinfo line {line_number}") from exc
    if not entries:
        raise ValueError("mountinfo is empty")
    return tuple(entries)


def _decode_mountinfo_path(value: str) -> str:
    result: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "\\":
            result.append(value[index])
            index += 1
            continue
        escape = value[index + 1 : index + 4]
        decoded = _VALID_ESCAPES.get(escape)
        if decoded is None:
            raise ValueError("invalid mountinfo escape")
        result.append(decoded)
        index += 4
    return "".join(result)


def _parse_options(value: str) -> frozenset[str]:
    options = frozenset(option for option in value.split(",") if option)
    if not options:
        raise ValueError("empty mount option set")
    return options


def _path_device(path: Path) -> str:
    stat_result = os.stat(path, follow_symlinks=False)
    major_attr = getattr(os, "major", None)
    minor_attr = getattr(os, "minor", None)
    if not callable(major_attr) or not callable(minor_attr):
        raise OSError("Linux device-number helpers are unavailable")
    major = cast(Callable[[int], int], major_attr)
    minor = cast(Callable[[int], int], minor_attr)
    return f"{major(stat_result.st_dev)}:{minor(stat_result.st_dev)}"


def _mount_for_path(path: Path, entries: tuple[MountFacts, ...]) -> MountFacts | None:
    candidates = tuple(
        entry for entry in entries if path == entry.mount_point or entry.mount_point in path.parents
    )
    if not candidates:
        return None
    longest = max(len(entry.mount_point.parts) for entry in candidates)
    matches = tuple(entry for entry in candidates if len(entry.mount_point.parts) == longest)
    return matches[0] if len(matches) == 1 else None


def _is_local_block_device(source: str) -> bool:
    """Require an unambiguous Linux block-device source, not a remote label."""

    if not source.startswith("/dev/"):
        return False
    lowered = source.lower()
    return not any(marker in lowered for marker in ("://", "\\\\", "//"))


__all__ = [
    "DurableBackendGateError",
    "DurableBackendQualification",
    "MountFacts",
    "qualify_durable_backend",
    "require_durable_backend",
]
