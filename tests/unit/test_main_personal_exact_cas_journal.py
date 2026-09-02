"""Focused adversarial coverage for the offline personal exact-CAS journal."""

# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportArgumentType=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts import main_personal_exact_cas_journal as journal_module
from avo_correlate.adapters.artifacts.durable_backend_gate import DurableBackendQualification
from avo_correlate.adapters.artifacts.main_personal_exact_cas_journal import (
    MainPersonalExactCasJournal,
    MainPersonalExactCasJournalError,
)
from avo_correlate.contracts.main_personal_exact_cas import (
    MainPersonalExactCasActivation,
    MainPersonalExactCasAuthorization,
    MainPersonalExactCasCompletion,
    MainPersonalExactCasDispatchStarted,
    MainPersonalExactCasIntent,
    MainPersonalExactCasPostStateObservation,
    MainPersonalExactCasReceipt,
    MainPersonalExactCasReconciliation,
    personal_cas_claim_digest,
    personal_cas_operation_id,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_trusted_main_graduation_source import _configured_reader

NOW = datetime(2026, 1, 1, tzinfo=UTC)
LEASE = NOW + timedelta(hours=1)


class Authority:
    def verify_activation(self, _activation: Any, evidence: Any) -> bool:
        return bool(evidence.accepted and evidence.evidence_ref is not None)

    def verify_authorization(self, *_values: Any) -> bool:
        return True

    def verify_post_state(self, *_values: Any) -> bool:
        return True

    def verify_reconciliation(self, *_values: Any) -> bool:
        return True

    def verify_completion(self, *_values: Any) -> bool:
        return True


def _qualified(root: Path) -> DurableBackendQualification:
    return DurableBackendQualification(
        root=root.resolve(),
        qualified=True,
        reason="test-qualified",
        filesystem_type="ext4",
        mount_id=1,
        device="8:0",
    )


def _no_directory_fsync(_path: Path) -> None:
    return None


def _no_store_fsync(*_values: Any) -> None:
    return None


def _journal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[Any, Any, MainPersonalExactCasJournal]:
    source_journal, reader, operation_id = _configured_reader(tmp_path / "source")
    state_root = tmp_path / "state"
    state_root.mkdir()
    monkeypatch.setattr(journal_module, "require_durable_backend", _qualified)
    # Windows cannot fsync directory handles; production construction is
    # rejected by the durable-backend gate before this seam is reachable.
    monkeypatch.setattr(journal_module, "_fsync_directory", _no_directory_fsync)
    journal = MainPersonalExactCasJournal(
        state_root, authority_verifier=Authority(), trusted_source_reader=reader
    )
    source = reader.read(operation_id)
    assert source.accepted and source.evidence_ref is not None
    return source_journal, source, journal


def _activation(source_journal: Any, source: Any) -> MainPersonalExactCasActivation:
    evidence = source.evidence_ref
    assert evidence is not None
    return MainPersonalExactCasActivation.build(
        repository_digest=source_journal._composition_repository_digest,
        source_operation_id=evidence.operation_id,
        source_plan_digest=evidence.plan_digest,
        source_plan_artifact=evidence.plan_ref,
        source_package_digest=evidence.package_digest,
        source_composition_digest=evidence.composition_digest,
        base_commit=evidence.base_commit,
        base_tree=evidence.base_tree,
        candidate_commit=evidence.candidate_commit,
        candidate_tree=evidence.candidate_tree,
        candidate_ref=evidence.candidate_ref,
        candidate_parents=(evidence.base_commit,),
        protection_ruleset_digest=canonical_digest({"rules": "fixture"}),
        writer_app_id=1,
        writer_installation_id=2,
        writer_identity="fixture-controller",
        activated_at=NOW,
    )


def _scope(activation: MainPersonalExactCasActivation, operation_id: str) -> dict[str, Any]:
    return {
        "activation_digest": activation.activation_digest,
        "operation_id": operation_id,
        "repository_digest": activation.repository_digest,
        "target_ref": "refs/heads/main",
        "source_operation_id": activation.source_operation_id,
        "source_plan_digest": activation.source_plan_digest,
        "source_package_digest": activation.source_package_digest,
        "source_composition_digest": activation.source_composition_digest,
        "base_commit": activation.base_commit,
        "base_tree": activation.base_tree,
        "candidate_commit": activation.candidate_commit,
        "candidate_tree": activation.candidate_tree,
        "candidate_ref": activation.candidate_ref,
        "candidate_parents": activation.candidate_parents,
        "protection_ruleset_digest": activation.protection_ruleset_digest,
        "writer_app_id": activation.writer_app_id,
        "writer_installation_id": activation.writer_installation_id,
        "writer_identity": activation.writer_identity,
        "lease_identity": "lease-fixture",
        "lease_digest": canonical_digest({"lease": "fixture"}),
        "lease_expires_at": LEASE,
        "claim_nonce": "nonce-fixture",
    }


def _chain(activation: MainPersonalExactCasActivation) -> tuple[Any, ...]:
    lease_values = _scope(activation, "sha256:" + "0" * 64)
    operation_identity = {
        key: value
        for key, value in lease_values.items()
        if key not in {"operation_id", "target_ref", "source_package_digest"}
    }
    lease_values["operation_id"] = personal_cas_operation_id(
        target_ref="refs/heads/main", **operation_identity
    )
    lease_values["claim_digest"] = personal_cas_claim_digest(
        operation_id=lease_values["operation_id"],
        lease_identity=lease_values["lease_identity"],
        lease_digest=lease_values["lease_digest"],
        lease_expires_at=LEASE,
        claim_nonce=lease_values["claim_nonce"],
    )
    authorization = MainPersonalExactCasAuthorization.build(
        **lease_values, authorized_at=NOW + timedelta(minutes=1)
    )
    intent = MainPersonalExactCasIntent.build(
        **lease_values,
        authorization_digest=authorization.authorization_digest,
        recorded_at=NOW + timedelta(minutes=2),
    )
    marker = MainPersonalExactCasDispatchStarted.build(
        **lease_values,
        intent_digest=intent.intent_digest,
        started_at=NOW + timedelta(minutes=3),
    )
    receipt = MainPersonalExactCasReceipt.build(
        **lease_values,
        authorization_digest=authorization.authorization_digest,
        intent_digest=intent.intent_digest,
        dispatch_marker_digest=marker.dispatch_marker_digest,
        response_digest=canonical_digest({"response": "fixture"}),
        outcome="applied",
        dispatch_started=True,
        observed_at=NOW + timedelta(minutes=4),
    )
    observation = MainPersonalExactCasPostStateObservation.build(
        **lease_values,
        authorization_digest=authorization.authorization_digest,
        intent_digest=intent.intent_digest,
        receipt_digest=receipt.receipt_digest,
        receipt_outcome="applied",
        observed_ref="refs/heads/main",
        observed_commit=activation.candidate_commit,
        observed_tree=activation.candidate_tree,
        observed_parents=(activation.base_commit,),
        observed_at=NOW + timedelta(minutes=5),
    )
    completion = MainPersonalExactCasCompletion.build(
        activation_digest=activation.activation_digest,
        operation_id=intent.operation_id,
        receipt_digest=receipt.receipt_digest,
        post_state_observation_digest=canonical_digest(observation),
        outcome="applied",
        completed_at=NOW + timedelta(minutes=6),
    )
    return authorization, intent, marker, receipt, observation, completion


def test_constructor_requires_concrete_pinned_source_reader(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(journal_module, "require_durable_backend", _qualified)
    root = tmp_path / "state"
    root.mkdir()
    with pytest.raises(ValueError, match="source reader"):
        MainPersonalExactCasJournal(
            root, authority_verifier=Authority(), trusted_source_reader=object()
        )


def test_genuine_source_drives_activation_and_full_chain(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_journal, source, journal = _journal(monkeypatch, tmp_path)
    activation = _activation(source_journal, source)
    journal.record_activation(activation, object())
    authorization, intent, marker, receipt, observation, completion = _chain(activation)
    journal.record_authorization(authorization)
    journal.record_intent(intent)
    journal.record_dispatch_started(marker)
    journal.record_receipt(receipt)
    journal.record_post_state(observation)
    journal.record_completion(completion)
    assert journal.read_completion(intent.operation_id) is not None


def test_forged_activation_binding_is_rejected_even_with_accepted_dto(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_journal, source, journal = _journal(monkeypatch, tmp_path)
    activation = _activation(source_journal, source).model_copy(
        update={"candidate_commit": "f" * 40, "candidate_parents": ("f" * 40,)}
    )
    with pytest.raises(MainPersonalExactCasJournalError):
        journal.record_activation(activation, source)


def test_arbitrary_cross_store_artifact_root_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _source_journal, reader, _ = _configured_reader(tmp_path / "source")
    root = tmp_path / "state"
    root.mkdir()
    foreign = tmp_path / "foreign"
    monkeypatch.setattr(journal_module, "require_durable_backend", _qualified)
    from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore

    with pytest.raises(ValueError, match="artifact store"):
        MainPersonalExactCasJournal(
            root,
            authority_verifier=Authority(),
            trusted_source_reader=reader,
            artifact_store=FilesystemArtifactStore(foreign),
        )


def test_completion_cannot_use_ambiguous_receipt_without_reconciliation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_journal, source, journal = _journal(monkeypatch, tmp_path)
    activation = _activation(source_journal, source)
    journal.record_activation(activation, source)
    authorization, intent, marker, receipt, observation, completion = _chain(activation)
    journal.record_authorization(authorization)
    journal.record_intent(intent)
    journal.record_dispatch_started(marker)
    receipt_values = receipt.model_dump(exclude={"receipt_digest"})
    receipt_values.update(
        response_digest=canonical_digest({"response": "ambiguous"}), outcome="ambiguous"
    )
    ambiguous = MainPersonalExactCasReceipt.build(**receipt_values)
    journal.record_receipt(ambiguous)
    ambiguous_observation = observation.model_copy(
        update={"receipt_digest": ambiguous.receipt_digest, "receipt_outcome": "ambiguous"}
    )
    ambiguous_observation = MainPersonalExactCasPostStateObservation.build(
        **ambiguous_observation.model_dump(exclude={"observation_digest"})
    )
    journal.record_post_state(ambiguous_observation)
    with pytest.raises(MainPersonalExactCasJournalError):
        journal.record_completion(completion)
    assert journal.read_completion(intent.operation_id) is None
    reconciliation = MainPersonalExactCasReconciliation.build(
        activation_digest=activation.activation_digest,
        operation_id=intent.operation_id,
        ambiguous_receipt=ambiguous,
        observation=ambiguous_observation,
        outcome="applied",
        reconciled_at=NOW + timedelta(minutes=7),
    )
    journal.record_reconciliation(reconciliation)
    recovered_completion = MainPersonalExactCasCompletion.build(
        activation_digest=activation.activation_digest,
        operation_id=intent.operation_id,
        receipt_digest=ambiguous.receipt_digest,
        post_state_observation_digest=canonical_digest(ambiguous_observation),
        reconciliation_digest=canonical_digest(reconciliation),
        outcome="applied",
        completed_at=NOW + timedelta(minutes=8),
    )
    journal.record_completion(recovered_completion)
    assert journal.read_completion(intent.operation_id) is not None


def test_object_directory_fsync_failure_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_journal, source, journal = _journal(monkeypatch, tmp_path)
    activation = _activation(source_journal, source)

    def fail(_path: Path) -> None:
        raise OSError("fsync unavailable")

    monkeypatch.setattr(journal_module, "_fsync_directory", fail)
    with pytest.raises(MainPersonalExactCasJournalError, match="not durably committed"):
        journal.record_activation(activation, source)
    assert not journal._index_path("activation", "activation").exists()


def test_index_directory_fsync_failure_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_journal, source, journal = _journal(monkeypatch, tmp_path)
    activation = _activation(source_journal, source)

    monkeypatch.setattr(journal_module, "_fsync_store_ancestors", _no_store_fsync)

    def fail(_path: Path) -> None:
        raise OSError("fsync unavailable")

    monkeypatch.setattr(journal_module, "_fsync_directory", fail)
    with pytest.raises(MainPersonalExactCasJournalError, match="not durable"):
        journal.record_activation(activation, source)
    assert not journal._index_path("activation", "activation").exists()


def test_reopened_journal_revalidates_source_and_activation_verifier(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_journal, source, journal = _journal(monkeypatch, tmp_path)
    activation = _activation(source_journal, source)
    journal.record_activation(activation, source)
    original_reader = journal._trusted_source_reader
    original_read = original_reader.read
    reader_calls = 0
    verifier_calls = 0

    def counted_read(operation_id: str) -> Any:
        nonlocal reader_calls
        reader_calls += 1
        return original_read(operation_id)

    original_verify = journal._authority.verify_activation

    def counted_verify(value: Any, evidence: Any) -> bool:
        nonlocal verifier_calls
        verifier_calls += 1
        return bool(original_verify(value, evidence))

    monkeypatch.setattr(original_reader, "read", counted_read)
    monkeypatch.setattr(journal._authority, "verify_activation", counted_verify)
    reopened = MainPersonalExactCasJournal(
        journal.root,
        authority_verifier=journal._authority,
        trusted_source_reader=original_reader,
    )
    authorization, *_ = _chain(activation)
    reopened.record_authorization(authorization)
    assert reader_calls >= 1
    assert verifier_calls >= 1

    from avo_correlate.adapters.artifacts.trusted_main_graduation_source import (
        TrustedMainGraduationOfflineResult,
    )

    def reject_read(operation_id: str) -> TrustedMainGraduationOfflineResult:
        return TrustedMainGraduationOfflineResult(
            operation_id=operation_id, accepted=False, reason="tampered source"
        )

    monkeypatch.setattr(
        original_reader,
        "read",
        reject_read,
    )
    with pytest.raises(MainPersonalExactCasJournalError):
        reopened.record_intent(_chain(activation)[1])
    with pytest.raises(MainPersonalExactCasJournalError):
        reopened.read_authorization(authorization.operation_id)


def test_model_construct_incomplete_activation_fails_at_authority_boundary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _source_journal, source, journal = _journal(monkeypatch, tmp_path)
    forged = MainPersonalExactCasActivation.model_construct(activation_digest=source.operation_id)
    with pytest.raises(MainPersonalExactCasJournalError):
        journal.record_activation(forged, source)


def test_tampered_index_metadata_and_missing_object_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_journal, source, journal = _journal(monkeypatch, tmp_path)
    activation = _activation(source_journal, source)
    reference = journal.record_activation(activation, source)
    index = journal._index_path("activation", "activation")
    tampered = reference.model_copy(update={"media_type": "application/json"})
    index.write_bytes(canonical_bytes(tampered))
    with pytest.raises(MainPersonalExactCasJournalError):
        journal.read_activation()

    tampered = reference.model_copy(update={"role": "generic-artifact"})
    index.write_bytes(canonical_bytes(tampered))
    with pytest.raises(MainPersonalExactCasJournalError):
        journal.read_activation()

    index.write_bytes(canonical_bytes(reference))
    journal.artifact_store.path_for_digest(reference.digest).unlink()
    with pytest.raises(MainPersonalExactCasJournalError):
        journal.read_activation()


def test_repeated_same_record_is_idempotent_and_conflicting_record_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_journal, source, journal = _journal(monkeypatch, tmp_path)
    activation = _activation(source_journal, source)
    first = journal.record_activation(activation, source)
    second = journal.record_activation(activation, source)
    assert first == second
    conflicting = activation.model_copy(update={"writer_identity": "different"})
    with pytest.raises(MainPersonalExactCasJournalError):
        journal.record_activation(conflicting, source)


def test_public_personal_cas_surface_has_no_transport_or_writer_capability() -> None:
    journal_names = set(vars(journal_module))
    assert not any(
        token in name.lower()
        for name in journal_names
        for token in ("http", "token", "writer", "provider")
    )
    assert not hasattr(journal_module, "MainExactCasWriter")


def test_nested_artifact_directory_must_share_qualified_mount_and_device(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _source_journal, reader, _ = _configured_reader(tmp_path / "source")
    root = tmp_path / "state"
    root.mkdir()

    def qualify(path: Path) -> DurableBackendQualification:
        resolved = path.resolve()
        nested = resolved.name == "artifacts"
        return DurableBackendQualification(
            root=resolved,
            qualified=True,
            reason="test-qualified",
            filesystem_type="ext4",
            mount_id=2 if nested else 1,
            device="8:1" if nested else "8:0",
        )

    monkeypatch.setattr(journal_module, "require_durable_backend", qualify)
    with pytest.raises(MainPersonalExactCasJournalError, match="artifact store"):
        MainPersonalExactCasJournal(
            root, authority_verifier=Authority(), trusted_source_reader=reader
        )


def test_nested_index_directory_must_share_qualified_mount_and_device(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _source_journal, reader, _ = _configured_reader(tmp_path / "source")
    root = tmp_path / "state"
    root.mkdir()

    def qualify(path: Path) -> DurableBackendQualification:
        resolved = path.resolve()
        nested = resolved.name == "main-personal-exact-cas-index"
        return DurableBackendQualification(
            root=resolved,
            qualified=True,
            reason="test-qualified",
            filesystem_type="ext4",
            mount_id=2 if nested else 1,
            device="8:1" if nested else "8:0",
        )

    monkeypatch.setattr(journal_module, "require_durable_backend", qualify)
    with pytest.raises(MainPersonalExactCasJournalError, match="index directory"):
        MainPersonalExactCasJournal(
            root, authority_verifier=Authority(), trusted_source_reader=reader
        )


def test_controlled_directory_symlink_is_rejected_before_creation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _source_journal, reader, _ = _configured_reader(tmp_path / "source")
    root = tmp_path / "state"
    root.mkdir()
    target = tmp_path / "foreign-artifacts"
    target.mkdir()
    link = root / "artifacts"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")
    monkeypatch.setattr(journal_module, "require_durable_backend", _qualified)
    with pytest.raises(ValueError, match="symlink"):
        MainPersonalExactCasJournal(
            root, authority_verifier=Authority(), trusted_source_reader=reader
        )


def test_object_fanout_directory_is_requalified_before_artifact_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_journal, source, journal = _journal(monkeypatch, tmp_path)
    activation = _activation(source_journal, source)

    def qualify(path: Path) -> DurableBackendQualification:
        resolved = path.resolve()
        nested_object = "sha256" in resolved.parts
        return DurableBackendQualification(
            root=resolved,
            qualified=True,
            reason="test-qualified",
            filesystem_type="ext4",
            mount_id=2 if nested_object else 1,
            device="8:1" if nested_object else "8:0",
        )

    monkeypatch.setattr(journal_module, "require_durable_backend", qualify)
    journal._qualification = qualify(journal.root)
    with pytest.raises(MainPersonalExactCasJournalError, match="artifact object directory"):
        journal.record_activation(activation, source)
    assert not journal._index_path("activation", "activation").exists()


def test_post_construction_artifact_store_symlink_swap_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_journal, source, journal = _journal(monkeypatch, tmp_path)
    activation = _activation(source_journal, source)
    store_root = journal.artifact_store.root
    moved = store_root.with_name("artifacts-moved")
    store_root.rename(moved)
    try:
        try:
            store_root.symlink_to(moved, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"directory symlinks unavailable: {exc}")
        with pytest.raises(
            (ValueError, MainPersonalExactCasJournalError),
            match=r"symlink|moved|invalid activation",
        ):
            journal.record_activation(activation, source)
    finally:
        if store_root.is_symlink():
            store_root.unlink()
        if moved.exists():
            moved.rename(store_root)
