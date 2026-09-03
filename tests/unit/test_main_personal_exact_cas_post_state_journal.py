"""Fast adversarial coverage for durable nonterminal post-state storage."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from avo_correlate.adapters.artifacts import (
    main_personal_exact_cas_post_state as module,
)
from avo_correlate.adapters.artifacts.durable_backend_gate import DurableBackendQualification
from avo_correlate.adapters.artifacts.main_personal_exact_cas_journal import (
    MainPersonalExactCasJournal,
)
from avo_correlate.adapters.artifacts.main_personal_exact_cas_post_state import (
    MainPersonalExactCasPostStateJournalConflictError,
    MainPersonalExactCasPostStateJournalError,
    MainPersonalExactCasReadOnlyPostStateJournal,
)
from avo_correlate.adapters.hosted_git.github import github_repository_digest
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_post_state import (
    MainPersonalExactCasGitHubPostStateReader,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_github_main_base_reader import _responses as _base_responses
from tests.unit.test_main_personal_exact_cas_observer_post_state import _reader as _app_reader
from tests.unit.test_main_personal_exact_cas_response_evidence import _chain

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _qualified(root: Path) -> DurableBackendQualification:
    return DurableBackendQualification(
        root=root.resolve(),
        qualified=True,
        reason="test-qualified",
        filesystem_type="ext4",
        mount_id=1,
        device="8:0",
    )


def _no_fsync(_path: Path) -> None:
    return None


def _authority(intent: Any, marker: Any) -> MainPersonalExactCasJournal:
    authority = object.__new__(MainPersonalExactCasJournal)

    def read_intent(operation_id: str):
        del operation_id
        return intent, None

    def read_dispatch_started(operation_id: str):
        del operation_id
        return marker, None

    untyped = cast(Any, authority)
    untyped.read_intent = read_intent
    untyped.read_dispatch_started = read_dispatch_started
    return authority


def _configured(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[MainPersonalExactCasReadOnlyPostStateJournal, Any, Any, Any]:
    intent, marker = _chain()
    sha = "3" * 40
    reader = _app_reader(monkeypatch, _base_responses(commit=sha, fence=sha, tree="4" * 40))
    monkeypatch.setattr(module, "require_durable_backend", _qualified)
    monkeypatch.setattr(module, "_fsync_directory", _no_fsync)
    journal = MainPersonalExactCasReadOnlyPostStateJournal(
        tmp_path / "post-state", authority_journal=_authority(intent, marker), reader=reader
    )
    return journal, reader, intent, marker


def test_capture_reopen_and_read_are_create_once_and_nonterminal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, reader, intent, marker = _configured(monkeypatch, tmp_path)
    reference = journal.capture(intent.operation_id)
    assert len(reader._reader._transport.calls) == 7
    assert journal.capture(intent.operation_id) == reference
    assert len(reader._reader._transport.calls) == 7
    result = journal.read(intent.operation_id)
    assert result is not None
    observation, returned = result
    assert returned == reference
    assert observation.is_terminal is False
    assert observation.is_authoritative is False

    reopened = MainPersonalExactCasReadOnlyPostStateJournal(
        journal.root,
        authority_journal=_authority(intent, marker),
        reader=reader,
    )
    assert reopened.read(intent.operation_id) == result
    assert len(reader._reader._transport.calls) == 7


def test_divergent_timestamp_or_topology_conflicts_without_replacing_winner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, reader, intent, _marker = _configured(monkeypatch, tmp_path)
    journal.capture(intent.operation_id)
    stored = journal.read(intent.operation_id)
    assert stored is not None
    # Re-arm the concrete base reader's owned transport seam for a divergent
    # second observation while preserving its exact type and configuration.
    reader._reader._transport._responses = _base_responses(
        commit="3" * 40, fence="3" * 40, tree="5" * 40
    )
    original_read = journal.read

    def _race_missed_existing(_operation_id: str):
        return None

    cast(Any, journal).read = _race_missed_existing
    with pytest.raises(MainPersonalExactCasPostStateJournalConflictError):
        journal.capture(intent.operation_id)
    cast(Any, journal).read = original_read
    reread = journal.read(intent.operation_id)
    assert reread is not None and reread[0] == stored[0]


def test_wrong_requested_operation_fails_before_reader_or_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, reader, _intent, _marker = _configured(monkeypatch, tmp_path)
    wrong_operation = "sha256:" + "9" * 64
    with pytest.raises(MainPersonalExactCasPostStateJournalError):
        journal.capture(wrong_operation)
    assert len(reader._reader._transport.calls) == 0
    assert not list(journal.root.glob("artifacts/objects/sha256/*/*"))


def test_reference_timestamp_is_bound_on_reopen(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, _reader_instance, intent, _marker = _configured(monkeypatch, tmp_path)
    journal.capture(intent.operation_id)
    loaded = journal.read(intent.operation_id)
    assert loaded is not None
    changed = loaded[1].model_copy(
        update={"created_at": loaded[0].finished_at + timedelta(seconds=1)}
    )
    journal._index_path(intent.operation_id).write_bytes(canonical_bytes(changed))
    with pytest.raises(MainPersonalExactCasPostStateJournalError):
        journal.read(intent.operation_id)


def test_capture_fsyncs_qualified_root_after_object_and_index(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, _reader_instance, intent, _marker = _configured(monkeypatch, tmp_path)
    calls: list[Path] = []

    def record_fsync(path: Path) -> None:
        calls.append(path.resolve())

    monkeypatch.setattr(module, "_fsync_directory", record_fsync)
    journal.capture(intent.operation_id)
    assert calls.count(journal.root) >= 2
    assert calls[-1] == journal.root


def test_symlinked_index_is_rejected_before_following_external_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, _reader_instance, intent, _marker = _configured(monkeypatch, tmp_path)
    journal.capture(intent.operation_id)
    index = journal._index_path(intent.operation_id)
    outside = tmp_path / "outside-index.json"
    outside.write_bytes(index.read_bytes())
    index.unlink()
    try:
        index.symlink_to(outside)
    except OSError:
        pytest.skip("directory symlink privilege is unavailable")
    with pytest.raises(MainPersonalExactCasPostStateJournalError):
        journal.read(intent.operation_id)


def test_symlinked_object_is_rejected_before_index_publication(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, _reader_instance, intent, _marker = _configured(monkeypatch, tmp_path)
    probe_reader = _app_reader(monkeypatch, _base_responses(commit="3" * 40, fence="3" * 40))
    observation = probe_reader.observe(intent)
    object_path = journal.artifact_store.path_for_digest(canonical_digest(observation))
    object_path.parent.mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside-post-state.json"
    outside.write_bytes(canonical_bytes(observation))
    try:
        object_path.symlink_to(outside)
    except OSError:
        pytest.skip("file symlink privilege is unavailable")
    with pytest.raises(MainPersonalExactCasPostStateJournalError):
        journal.capture(intent.operation_id)
    assert not list(journal.root.glob("main-personal-exact-cas-post-state-index/*/*.json"))


def test_secret_reader_failure_is_code_only_and_does_not_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, reader, intent, _marker = _configured(monkeypatch, tmp_path)

    reader._reader._transport._responses = [(200, RuntimeError("Bearer TOKEN-secret"))]
    with pytest.raises(MainPersonalExactCasPostStateJournalError) as raised:
        journal.capture(intent.operation_id)
    assert "TOKEN" not in repr(raised.value)
    assert raised.value.__cause__ is None and raised.value.__context__ is None
    assert not list(journal.root.glob("artifacts/objects/sha256/*/*"))


def test_missing_or_tampered_object_and_index_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, _reader_instance, intent, _marker = _configured(monkeypatch, tmp_path)
    reference = journal.capture(intent.operation_id)
    journal.artifact_store.path_for_digest(reference.digest).unlink()
    with pytest.raises(MainPersonalExactCasPostStateJournalError) as raised:
        journal.read(intent.operation_id)
    assert raised.value.__cause__ is None and raised.value.__context__ is None

    journal, _reader_instance, intent, _marker = _configured(monkeypatch, tmp_path / "again")
    journal.capture(intent.operation_id)
    index = journal._index_path(intent.operation_id)
    index.write_bytes(b"{}")
    with pytest.raises(MainPersonalExactCasPostStateJournalError):
        journal.read(intent.operation_id)


def test_malformed_base_reader_output_is_rejected_before_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, reader, intent, _marker = _configured(monkeypatch, tmp_path)
    reader._reader._transport._responses = [(200, {})]
    with pytest.raises(MainPersonalExactCasPostStateJournalError):
        journal.capture(intent.operation_id)
    assert not list(journal.root.glob("artifacts/objects/sha256/*/*"))


def test_constructor_requires_exact_authority_and_reader_types(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    intent, marker = _chain()
    reader = _app_reader(monkeypatch, [])
    monkeypatch.setattr(module, "require_durable_backend", _qualified)
    with pytest.raises(ValueError):
        MainPersonalExactCasReadOnlyPostStateJournal(
            tmp_path / "authority",
            authority_journal=cast(Any, object()),
            reader=reader,
        )
    with pytest.raises(ValueError):
        MainPersonalExactCasReadOnlyPostStateJournal(
            tmp_path / "reader",
            authority_journal=_authority(intent, marker),
            reader=cast(Any, object()),
        )


def test_constructor_rejects_legacy_raw_credential_reader(
    tmp_path: Path,
) -> None:
    legacy = MainPersonalExactCasGitHubPostStateReader(
        owner="fixture",
        repo="repo",
        repository_digest=github_repository_digest("fixture", "repo"),
        token="legacy-secret",
        trusted_clock=lambda: NOW,
    )
    intent, marker = _chain()
    with pytest.raises(ValueError, match="fixed post-state reader"):
        MainPersonalExactCasReadOnlyPostStateJournal(
            tmp_path / "legacy",
            authority_journal=_authority(intent, marker),
            reader=legacy,  # type: ignore[arg-type]
        )


def test_public_surface_has_no_mutation_or_receipt_capability() -> None:
    names = set(dir(MainPersonalExactCasReadOnlyPostStateJournal))
    assert not {"apply", "exchange", "record_receipt"}.intersection(names)
    source = Path(
        "src/avo_correlate/adapters/artifacts/main_personal_exact_cas_post_state.py"
    ).read_text(encoding="utf-8")
    assert "MainPersonalExactCasReceipt" not in source
    assert "MainPersonalExactCasPostStateObservation" not in source
    assert "PATCH" not in source and "DELETE" not in source
