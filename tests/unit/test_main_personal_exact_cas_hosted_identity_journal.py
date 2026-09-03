"""Canaries for the durable, offline hosted identity evidence journal."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false

from __future__ import annotations

from pathlib import Path

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


def test_public_surface_is_offline_and_non_authoritative() -> None:
    names = set(dir(MainPersonalExactCasHostedIdentityJournal))
    assert not {"apply", "exchange", "publish", "record_receipt"}.intersection(names)
    source = Path(
        "src/avo_correlate/adapters/artifacts/main_personal_exact_cas_hosted_identity_journal.py"
    ).read_text(encoding="utf-8")
    assert "GitHubMainBaseReaderCredentials" not in source
    assert "MainPersonalExactCasReceipt" not in source
    assert "PATCH" not in source and "DELETE" not in source
