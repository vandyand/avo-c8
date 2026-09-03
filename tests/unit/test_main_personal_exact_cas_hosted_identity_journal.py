"""Canaries for the durable, offline hosted identity evidence journal."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from avo_correlate.adapters.artifacts import (
    main_personal_exact_cas_hosted_identity_journal as module,
)
from avo_correlate.adapters.artifacts.durable_backend_gate import DurableBackendQualification
from avo_correlate.adapters.artifacts.main_personal_exact_cas_hosted_identity_journal import (
    MainPersonalExactCasHostedIdentityJournal,
    MainPersonalExactCasHostedIdentityJournalError,
)
from avo_correlate.domain.canonical import canonical_bytes
from tests.unit.test_main_personal_exact_cas_hosted_identity_bundle import (
    _observer,
    _writer,
)


def _qualified(root: Path) -> DurableBackendQualification:
    return DurableBackendQualification(
        root=root.resolve(),
        qualified=True,
        reason="test-qualified",
        filesystem_type="ext4",
        mount_id=1,
        device="8:0",
    )


@pytest.fixture
def journal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> MainPersonalExactCasHostedIdentityJournal:
    monkeypatch.setattr(module, "require_durable_backend", _qualified)
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)
    monkeypatch.setattr(module, "_fsync_store_ancestors", lambda _path, _root: None)
    return MainPersonalExactCasHostedIdentityJournal(tmp_path / "journal")


def test_bind_replay_reopen_is_deterministic_without_provider_io(
    journal: MainPersonalExactCasHostedIdentityJournal,
) -> None:
    writer = _writer()
    observer, configuration = _observer()
    root = journal.bind(writer, observer, configuration)
    assert journal.bind(writer, observer, configuration) == root
    loaded = journal.read()
    assert loaded is not None
    bundle, reread_root = loaded
    assert reread_root == root
    assert bundle.is_authoritative is False
    assert bundle.is_terminal is False
    reopened = MainPersonalExactCasHostedIdentityJournal(journal.root)
    assert reopened.read() == loaded


def test_root_and_child_drift_fail_closed(
    journal: MainPersonalExactCasHostedIdentityJournal,
) -> None:
    writer = _writer()
    observer, configuration = _observer()
    root = journal.bind(writer, observer, configuration)
    path = journal.root_path
    path.write_bytes(canonical_bytes(root.model_copy(update={"root_digest": "sha256:" + "0" * 64})))
    with pytest.raises(MainPersonalExactCasHostedIdentityJournalError):
        journal.read()


def test_bounded_fd_read_does_not_consume_an_unbounded_hostile_file(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    path.write_bytes(b"x" * 32)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="bounded read"):
            module._read_regular_fd(descriptor, max_bytes=8)
    finally:
        os.close(descriptor)


def test_oversized_root_is_rejected_before_json_reparse(
    journal: MainPersonalExactCasHostedIdentityJournal,
) -> None:
    root = journal.bind(_writer(), _observer()[0], _observer()[1])
    raw = canonical_bytes(root)
    journal.root_path.write_bytes(raw + b"x")
    journal._max = len(raw)
    with pytest.raises(MainPersonalExactCasHostedIdentityJournalError):
        journal.read()


def test_oversized_child_is_rejected_by_bounded_leaf_read(
    journal: MainPersonalExactCasHostedIdentityJournal,
) -> None:
    root = journal.bind(_writer(), _observer()[0], _observer()[1])
    name = "writer_diagnostic_artifact"
    reference = getattr(root, name)
    path = journal.artifact_store.path_for_digest(reference.digest)
    raw = path.read_bytes()
    path.write_bytes(raw + b"x")
    journal._max = len(raw)
    with pytest.raises(ValueError, match="bounded read"):
        journal._read_child(name, reference)


def test_existing_child_reuse_failure_is_not_reported_as_success(
    journal: MainPersonalExactCasHostedIdentityJournal,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = _writer()
    observer, configuration = _observer()
    journal.bind(writer, observer, configuration)

    if journal._descriptor_mode:
        def fail_fd_sync(_: object) -> None:
            raise OSError("injected child reuse fsync failure")

        monkeypatch.setattr(module, "_fsync_fd", fail_fd_sync)
    else:
        def fail_ancestor_sync(_: Path, __: Path) -> None:
            raise OSError("injected child reuse fsync failure")

        monkeypatch.setattr(module, "_fsync_store_ancestors", fail_ancestor_sync)
    with pytest.raises(MainPersonalExactCasHostedIdentityJournalError):
        journal.bind(writer, observer, configuration)


def test_existing_root_reuse_failure_is_not_reported_as_success(
    journal: MainPersonalExactCasHostedIdentityJournal,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = _writer()
    observer, configuration = _observer()
    journal.bind(writer, observer, configuration)

    def fail_sync() -> None:
        raise OSError("injected root reuse fsync failure")

    monkeypatch.setattr(journal, "_sync_reused_root", fail_sync)
    with pytest.raises(MainPersonalExactCasHostedIdentityJournalError):
        journal.bind(writer, observer, configuration)


def test_descriptor_read_does_not_create_missing_fanout(
    journal: MainPersonalExactCasHostedIdentityJournal,
) -> None:
    if not journal._descriptor_mode:
        pytest.skip("descriptor anchoring is Linux-only")
    digest = "sha256:" + "f" * 64
    fanout = journal._store.root / "objects" / "sha256" / "ff"
    assert not fanout.exists()
    with pytest.raises(OSError):
        journal._open_child_fanout(digest, create=False)
    assert not fanout.exists()


def test_descriptor_leaf_open_rejects_symlinked_fanout(
    journal: MainPersonalExactCasHostedIdentityJournal,
    tmp_path: Path,
) -> None:
    if not journal._descriptor_mode:
        pytest.skip("descriptor anchoring is Linux-only")
    objects = journal._store.root / "objects"
    objects.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    link = objects / "sha256"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    with pytest.raises(OSError):
        journal._open_child_fanout("sha256:" + "a" * 64, create=False)


def test_descriptor_writes_are_relative_nofollow_operations(
    journal: MainPersonalExactCasHostedIdentityJournal,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not journal._descriptor_mode:
        pytest.skip("descriptor anchoring is Linux-only")
    original_open = module.os.open
    calls: list[tuple[object, int, int | None]] = []

    def anchored_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if dir_fd is not None:
            calls.append((path, flags, dir_fd))
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(module.os, "open", anchored_open)
    journal.bind(_writer(), _observer()[0], _observer()[1])
    assert calls
    assert all(dir_fd is not None for _, _, dir_fd in calls)
    assert all(flags & module._O_NOFOLLOW for _, flags, _ in calls)


def test_descriptor_checks_each_opened_directory_device(
    journal: MainPersonalExactCasHostedIdentityJournal,
) -> None:
    if not journal._descriptor_mode or journal._root_fd is None:
        pytest.skip("descriptor anchoring is Linux-only")
    root_fd = journal._root_fd

    def fake_fstat(descriptor: int) -> SimpleNamespace:
        return SimpleNamespace(st_dev=1 if descriptor == root_fd else 2)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(module.os, "fstat", fake_fstat)
        with pytest.raises(ValueError, match="nested mount/device"):
            journal._check_descriptor_backend(root_fd + 1)


def test_descriptor_mount_id_parser_is_strict_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if module.sys.platform != "linux":
        pytest.skip("fdinfo mount IDs are Linux-only")
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: 99)
    monkeypatch.setattr(module.os, "close", lambda _fd: None)
    monkeypatch.setattr(
        module,
        "_read_descriptor_bytes",
        lambda _fd, _max: b"pos:\t0\nmnt_id:\t42\nflags:\t0100000\n",
    )
    assert module._fd_mount_id(7) == 42


@pytest.mark.parametrize(
    "payload",
    [b"mnt_id: 0\n", b"mnt_id: 4\nmnt_id: 5\n", b"mnt_id: nope\n"],
)
def test_descriptor_mount_id_parser_rejects_malformed_values(
    monkeypatch: pytest.MonkeyPatch, payload: bytes
) -> None:
    if module.sys.platform != "linux":
        pytest.skip("fdinfo mount IDs are Linux-only")
    monkeypatch.setattr(module.os, "open", lambda *_args, **_kwargs: 99)
    monkeypatch.setattr(module.os, "close", lambda _fd: None)
    monkeypatch.setattr(module, "_read_descriptor_bytes", lambda _fd, _max: payload)
    with pytest.raises(ValueError, match="mount ID"):
        module._fd_mount_id(7)


def test_close_is_idempotent_and_blocks_operations(
    journal: MainPersonalExactCasHostedIdentityJournal,
) -> None:
    retained = tuple(
        descriptor
        for descriptor in (journal._root_fd, journal._artifacts_fd, journal._indexes_fd)
        if descriptor is not None
    )
    journal.close()
    journal.close()
    assert journal._closed is True
    for descriptor in retained:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    with pytest.raises(MainPersonalExactCasHostedIdentityJournalError, match="closed"):
        journal.read()
    with pytest.raises(MainPersonalExactCasHostedIdentityJournalError, match="closed"):
        journal.bind(_writer(), _observer()[0], _observer()[1])


def test_context_manager_closes_retained_descriptors(
    journal: MainPersonalExactCasHostedIdentityJournal,
) -> None:
    with journal as entered:
        assert entered is journal
    assert journal._closed is True


def test_descriptor_rejects_root_rename_and_recreate(
    journal: MainPersonalExactCasHostedIdentityJournal,
) -> None:
    if not journal._descriptor_mode:
        pytest.skip("descriptor anchoring is Linux-only")
    original = journal.root
    moved = original.with_name("moved-journal")
    original.rename(moved)
    original.mkdir()
    (original / "artifacts").mkdir()
    (original / "main-personal-exact-cas-hosted-identity-index").mkdir()
    with pytest.raises(MainPersonalExactCasHostedIdentityJournalError):
        journal.read()


def test_descriptor_fanout_requalification_fails_closed(
    journal: MainPersonalExactCasHostedIdentityJournal,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not journal._descriptor_mode:
        pytest.skip("descriptor anchoring is Linux-only")
    original = journal._check_descriptor_backend
    checks = 0

    def reject_nested_mount(descriptor: int) -> None:
        nonlocal checks
        checks += 1
        if checks == 3:
            raise ValueError("nested mount/device differs")
        original(descriptor)

    monkeypatch.setattr(journal, "_check_descriptor_backend", reject_nested_mount)
    with pytest.raises(MainPersonalExactCasHostedIdentityJournalError):
        journal.bind(_writer(), _observer()[0], _observer()[1])
    assert checks >= 3
    assert not journal.root_path.exists()


def test_public_surface_is_offline_and_non_authoritative() -> None:
    names = set(dir(MainPersonalExactCasHostedIdentityJournal))
    assert not {"apply", "exchange", "publish", "record_receipt"}.intersection(names)
    source = Path(
        "src/avo_correlate/adapters/artifacts/main_personal_exact_cas_hosted_identity_journal.py"
    ).read_text(encoding="utf-8")
    assert "GitHubMainBaseReaderCredentials" not in source
    assert "MainPersonalExactCasReceipt" not in source
    assert "PATCH" not in source and "DELETE" not in source
