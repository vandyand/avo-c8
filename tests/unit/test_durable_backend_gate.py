"""Adversarial tests for the read-only Stage 2B durable-backend gate."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportUnknownMemberType=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false, reportMissingImports=false, reportUntypedFunctionDecorator=false, reportUnknownLambdaType=false

from __future__ import annotations

import inspect
from pathlib import Path, PurePosixPath

import pytest

from avo_correlate.adapters.artifacts import durable_backend_gate as gate


def _mountinfo(
    mount_point: str = "/srv/avo",
    *,
    mount_id: int = 36,
    parent_id: int = 29,
    filesystem_type: str = "ext4",
    source: str = "/dev/vda1",
    device: str = "8:1",
    mount_options: str = "rw,relatime",
    super_options: str = "rw,data=ordered",
) -> str:
    return (
        f"{mount_id} {parent_id} {device} / {mount_point} {mount_options} "
        f"- {filesystem_type} {source} {super_options}\n"
    )


def _linux_probe(
    monkeypatch: pytest.MonkeyPatch,
    *,
    mountinfo: str,
    device: str = "8:1",
    wsl: bool = False,
) -> None:
    # These are OS facts patched at the boundary solely to make Linux/WSL
    # outcomes reproducible on the Windows test host.  The public gate has no
    # caller-controlled platform or filesystem booleans.
    monkeypatch.setattr(gate.sys, "platform", "linux")
    release = "6.8.0-microsoft-standard-WSL2" if wsl else "6.8.0-generic"
    monkeypatch.setattr(gate.platform, "release", lambda: release)
    monkeypatch.setattr(gate, "_canonical_directory", lambda _: PurePosixPath("/srv/avo"))
    monkeypatch.setattr(gate, "_read_mountinfo", lambda: mountinfo)
    monkeypatch.setattr(gate, "_path_device", lambda _: device)


def test_public_gate_has_no_caller_assertion_or_provider_surface() -> None:
    signature = inspect.signature(gate.qualify_durable_backend)
    assert tuple(signature.parameters) == ("root",)
    assert not hasattr(gate, "httpx")
    assert not hasattr(gate, "requests")


def test_mountinfo_parser_decodes_kernel_escapes() -> None:
    facts = gate._parse_mountinfo(
        "36 29 8:1 / /srv/my\\040repo rw,relatime - ext4 /dev/vda1 rw,data=ordered\n"
    )
    assert facts[0].mount_point == PurePosixPath("/srv/my repo")
    assert facts[0].filesystem_type == "ext4"
    assert facts[0].source == "/dev/vda1"
    assert facts[0].device == "8:1"


@pytest.mark.parametrize(
    "text",
    [
        "36 29 8:1 / /srv/avo rw,relatime ext4 /dev/vda1 rw\n",
        "36 29 8:1 / /srv/avo rw - ext4 /dev/vda1 rw - extra\n",
        "36 nope 8:1 / /srv/avo rw - ext4 /dev/vda1 rw\n",
        "36 29 not-a-device / /srv/avo rw - ext4 /dev/vda1 rw\n",
        "36 29 8:1 / /srv/avo rw - ext4 /dev/vda1 rw\n"
        "36 30 8:2 / /srv/other rw - ext4 /dev/vda2 rw\n",
        "36 29 8:1 relative /srv/avo rw - ext4 /dev/vda1 rw\n",
        "36 29 8:1 / relative rw - ext4 /dev/vda1 rw\n",
        "36 29 8:1 / /srv/avo\\999 rw - ext4 /dev/vda1 rw\n",
        "",
    ],
)
def test_mountinfo_parser_rejects_malformed_or_ambiguous_facts(text: str) -> None:
    with pytest.raises(ValueError, match="mountinfo"):
        gate._parse_mountinfo(text)


def test_native_windows_fails_closed_before_inspecting_the_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gate.sys, "platform", "win32")
    result = gate.qualify_durable_backend(Path("C:/avo-state"))
    assert not result.qualified
    assert result.reason == "native_windows"


def test_unknown_platform_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gate.sys, "platform", "darwin")
    result = gate.qualify_durable_backend(Path("/srv/avo"))
    assert not result.qualified
    assert result.reason == "unsupported_platform"


@pytest.mark.parametrize("filesystem_type", ("9p", "v9fs", "drvfs"))
def test_wsl_host_mounts_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    filesystem_type: str,
) -> None:
    _linux_probe(
        monkeypatch,
        mountinfo=_mountinfo(filesystem_type=filesystem_type, source="none"),
        wsl=True,
    )
    result = gate.qualify_durable_backend(Path("/srv/avo"))
    assert not result.qualified
    assert result.reason == "unsupported_wsl"
    assert result.wsl_kernel


@pytest.mark.parametrize(
    "filesystem_type",
    ("nfs", "nfs4", "cifs", "smbfs", "fuse", "fuseblk", "overlay", "tmpfs"),
)
def test_network_union_or_ephemeral_filesystems_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    filesystem_type: str,
) -> None:
    _linux_probe(
        monkeypatch,
        mountinfo=_mountinfo(filesystem_type=filesystem_type, source="server:/share"),
    )
    result = gate.qualify_durable_backend(Path("/srv/avo"))
    assert not result.qualified
    assert result.reason == "forbidden_filesystem_type"


@pytest.mark.parametrize("filesystem_type", ("ext4", "xfs", "btrfs"))
def test_allowlisted_local_filesystems_are_qualified(
    monkeypatch: pytest.MonkeyPatch,
    filesystem_type: str,
) -> None:
    _linux_probe(monkeypatch, mountinfo=_mountinfo(filesystem_type=filesystem_type))
    result = gate.qualify_durable_backend(Path("/srv/avo"))
    assert result.qualified
    assert result.reason == "qualified_local_block_filesystem"
    assert result.filesystem_type == filesystem_type
    assert result.mount_id == 36
    assert result.mount_point == PurePosixPath("/srv/avo")


@pytest.mark.parametrize("filesystem_type", ("ext4", "xfs", "btrfs"))
def test_wsl_kernel_is_rejected_even_for_allowlisted_local_filesystems(
    monkeypatch: pytest.MonkeyPatch,
    filesystem_type: str,
) -> None:
    _linux_probe(
        monkeypatch,
        mountinfo=_mountinfo(filesystem_type=filesystem_type),
        wsl=True,
    )
    result = gate.qualify_durable_backend(Path("/srv/avo"))
    assert not result.qualified
    assert result.reason == "unsupported_wsl"
    assert result.wsl_kernel


@pytest.mark.parametrize(
    ("mountinfo", "device"),
    [
        (_mountinfo(mount_options="ro,relatime"), "8:1"),
        (_mountinfo(super_options="ro,data=ordered"), "8:1"),
        (_mountinfo(), "8:2"),
        (_mountinfo(source="UUID=local-but-unverified"), "8:1"),
        (_mountinfo(source="/dev/remote://volume"), "8:1"),
    ],
)
def test_local_candidate_still_requires_writable_matching_block_mount(
    monkeypatch: pytest.MonkeyPatch,
    mountinfo: str,
    device: str,
) -> None:
    _linux_probe(monkeypatch, mountinfo=mountinfo, device=device)
    result = gate.qualify_durable_backend(Path("/srv/avo"))
    assert not result.qualified
    assert result.reason in {
        "mount_is_read_only",
        "mount_device_does_not_match_stat",
        "mount_source_is_not_local_block_device",
    }


def test_longest_matching_mount_wins_and_nested_tmpfs_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = _mountinfo() + _mountinfo(
        "/srv/avo/state",
        mount_id=37,
        parent_id=36,
        filesystem_type="tmpfs",
        source="tmpfs",
        device="0:42",
    )
    _linux_probe(monkeypatch, mountinfo=text, device="0:42")
    monkeypatch.setattr(gate, "_canonical_directory", lambda _: PurePosixPath("/srv/avo/state"))
    result = gate.qualify_durable_backend(Path("/srv/avo/state"))
    assert not result.qualified
    assert result.reason == "forbidden_filesystem_type"
    assert result.mount_point == PurePosixPath("/srv/avo/state")


def test_ambiguous_equal_depth_mounts_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = _mountinfo() + _mountinfo(
        "/srv/avo",
        mount_id=37,
        parent_id=29,
        filesystem_type="xfs",
        source="/dev/vda2",
        device="8:2",
    )
    _linux_probe(monkeypatch, mountinfo=text, device="8:1")
    result = gate.qualify_durable_backend(Path("/srv/avo"))
    assert not result.qualified
    assert result.reason == "path_has_no_matching_mount"


def test_missing_mount_and_malformed_mount_table_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _linux_probe(monkeypatch, mountinfo=_mountinfo("/other"))
    result = gate.qualify_durable_backend(Path("/srv/avo"))
    assert not result.qualified
    assert result.reason == "path_has_no_matching_mount"

    _linux_probe(monkeypatch, mountinfo="malformed")
    result = gate.qualify_durable_backend(Path("/srv/avo"))
    assert not result.qualified
    assert result.reason.startswith("untrusted_os_facts:")


def test_require_raises_without_writing_or_exposing_mutation_capabilities(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _linux_probe(monkeypatch, mountinfo=_mountinfo(filesystem_type="tmpfs", source="tmpfs"))
    before = sorted(path.name for path in tmp_path.iterdir())
    with pytest.raises(gate.DurableBackendGateError, match="durable backend rejected"):
        gate.require_durable_backend(tmp_path)
    assert sorted(path.name for path in tmp_path.iterdir()) == before
