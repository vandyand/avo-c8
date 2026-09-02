"""Additional high-yield recovery coverage for the main-graduation journal.

These tests deliberately exercise durable failure paths that are awkward to
reach through the public completion flow: corrupted indexes, missing CAS
objects, restart cache boundaries, and scheduler/fence recovery decisions.
They add no authority and do not alter the production coverage policy.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
    MainGraduationRecordConflictError,
    _digest_bytes,
)
from avo_correlate.contracts.main_graduation import (
    EligibilityLedgerStarted,
    MainGraduationEligibilityRecord,
)
from avo_correlate.contracts.main_graduation_phase_a import (
    MainUnresolvedMutationFence,
    main_target_scope_digest,
)
from avo_correlate.domain.canonical import canonical_bytes
from tests.unit.phase_a_test_support import TEST_PHASE_A_AUTHORITY
from tests.unit.test_main_graduation_journal_coverage import (
    D2,
    NOW,
    D,
    R,
    ref,
)
from tests.unit.test_main_graduation_journal_final_coverage import _chain
from tests.unit.test_main_graduation_phase_a_adversarial import (
    _intent,
    _receipt,
    _with_digest,
)

# These tests intentionally exercise private durable seams.
# pyright: reportPrivateUsage=false, reportArgumentType=false, reportCallIssue=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportOptionalSubscript=false


def _journal(root: Path) -> MainGraduationJournal:
    return MainGraduationJournal(root, phase_a_authority_verifier=TEST_PHASE_A_AUTHORITY)


def _ledger(sequence: int = 1, *, activation: str = D) -> EligibilityLedgerStarted:
    return EligibilityLedgerStarted(
        activation_digest=activation,
        repository_digest=R,
        controller_config_digest=D2,
        scheduler_sequence_watermark=sequence - 1,
        streak=0,
    )


def test_index_and_cas_integrity_fail_closed_after_restart(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    record = _ledger()
    reference = journal.record_ledger_started(record)
    index = tmp_path / "main-graduation-index" / "ledger-started" / f"{D[7:]}.json"

    # Noncanonical JSON is not an acceptable durable index.
    index.write_text('{"size_bytes":1,"digest":"' + D + '"}', encoding="utf-8")
    with pytest.raises(MainGraduationJournalError, match="malformed"):
        MainGraduationJournal(tmp_path).read_ledger_started(D)

    # Rebuild the exact pointer, then remove the content-addressed object.
    index.write_bytes(canonical_bytes(reference))
    assert journal.delete_artifact(reference.digest)
    with pytest.raises(MainGraduationJournalError, match=r"malformed|unverifiable"):
        MainGraduationJournal(tmp_path).read_ledger_started(D)


def test_create_once_conflicts_and_reference_metadata_are_immutable(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    record = _ledger()
    first = journal.record_ledger_started(record)
    assert journal.record_ledger_started(record) == first

    conflicting = record.model_copy(update={"controller_config_digest": D})
    with pytest.raises(MainGraduationRecordConflictError):
        journal.record_ledger_started(conflicting)

    # An index whose reference points at a different digest cannot be rebound
    # merely because the operation key is the same.
    index = tmp_path / "main-graduation-index" / "ledger-started" / f"{D[7:]}.json"
    payload = json.loads(index.read_text(encoding="utf-8"))
    payload["digest"] = D2
    index.write_bytes(canonical_bytes(payload))
    with pytest.raises(MainGraduationJournalError):
        journal.read_ledger_started(D)


def test_phase_a_envelope_and_artifact_tamper_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = _journal(tmp_path)
    monkeypatch.setattr(journal, "_validate_phase_chain", lambda _kind, _record: None)
    intent = _intent()
    reference = journal.record_mutation_intent(intent)
    local = journal._phase_local_path("mutation-intent", intent.intent_digest)  # pyright: ignore[reportPrivateUsage]

    envelope = json.loads(local.read_text(encoding="utf-8"))
    envelope["key"] = D2
    local.write_bytes(canonical_bytes(envelope))
    with pytest.raises(MainGraduationJournalError, match="index"):
        journal.read_mutation_intent(intent.intent_digest)

    # Restore the pointer and prove that a missing CAS object is distinct from
    # a missing local pointer.
    local.write_bytes(
        canonical_bytes(
            journal._phase_reference_envelope(  # pyright: ignore[reportPrivateUsage]
                "mutation-intent", intent.intent_digest, intent, reference
            )
        )
    )
    assert journal.delete_artifact(reference.digest)
    with pytest.raises(MainGraduationJournalError):
        journal.read_mutation_intent(intent.intent_digest)


def test_phase_a_ambiguous_receipt_requires_verified_predecessors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = _journal(tmp_path)
    monkeypatch.setattr(journal, "_validate_phase_chain", lambda _kind, _record: None)
    intent = _intent()
    receipt = _receipt(intent)
    journal.record_mutation_intent(intent)
    journal.record_mutation_receipt(receipt)
    intent_reference = journal.read_mutation_intent(intent.intent_digest)[1]

    # The recovery path must not mint a reservation from a caller DTO when
    # the active fence is absent.
    with pytest.raises(MainGraduationJournalError, match=r"active target fence|target reservation"):
        journal._repair_target_mutation_reservation(  # pyright: ignore[reportPrivateUsage]
            intent, intent_reference
        )

    # A terminal receipt prohibits a second reservation, even on exact replay.
    terminal = receipt.model_copy(update={"outcome": "rejected", "dispatch_started": False})
    monkeypatch.setattr(journal, "_read_receipt_for_intent", lambda _digest: (terminal, ref()))
    monkeypatch.setattr(journal, "_read", lambda _kind, _key: None)
    with pytest.raises(MainGraduationRecordConflictError, match="terminal receipt"):
        journal._cas_target_mutation_reservation(  # pyright: ignore[reportPrivateUsage]
            intent, intent_reference
        )


def test_target_fence_and_resolution_reads_reject_foreign_or_missing_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = _journal(tmp_path)
    monkeypatch.setattr(journal, "_validate_phase_chain", lambda _kind, _record: None)
    intent = _intent()
    fence = cast(
        MainUnresolvedMutationFence,
        _with_digest(
            MainUnresolvedMutationFence,
            "fence_digest",
            repository_digest=R,
            target_ref="refs/heads/main",
            operation_id=intent.operation_id,
            stage=intent.stage,
            intent_digest=intent.intent_digest,
            source_receipt_digest=D2,
            external_identity_digest=intent.external_identity.identity_digest,
            lease_identity=intent.lease_identity,
            lease_digest=intent.lease_digest,
            target_scope_digest=main_target_scope_digest(R, "refs/heads/main"),
            opened_at=NOW,
        ),
    )
    reference = journal.record_unresolved_mutation_fence(fence)
    journal._cas_target_fence(fence, reference)  # pyright: ignore[reportPrivateUsage]
    assert journal.read_unresolved_mutation_fence(fence.fence_digest) is not None

    active = journal._target_fence_path(fence)  # pyright: ignore[reportPrivateUsage]
    record_path = journal._target_fence_record_path(active)  # pyright: ignore[reportPrivateUsage]
    payload = json.loads(record_path.read_text(encoding="utf-8"))
    payload["target_scope_digest"] = D2
    record_path.write_bytes(canonical_bytes(payload))
    with pytest.raises(MainGraduationJournalError):
        journal.assert_no_unresolved_mutation_fence(R, "refs/heads/main")


def test_completion_child_recovery_rechecks_every_child_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    package, _records = _chain(journal)
    monkeypatch.setattr(journal, "_verify_completion_prerequisites", lambda *_args, **_kwargs: None)
    values = journal._child_values(package)  # pyright: ignore[reportPrivateUsage]
    artifacts = [
        ref(
            _digest_bytes(canonical_bytes(value)),
            role=role,
            media_type=f"application/vnd.avo.{role}+json",
        ).model_copy(update={"size_bytes": len(canonical_bytes(value))})
        for role, value in values.items()
    ]
    object.__setattr__(package, "artifacts", artifacts)
    journal._materialize_children(package)  # pyright: ignore[reportPrivateUsage]

    # Delete one child from CAS while its completion index remains. The
    # completion read must not accept the parent as a valid summary.
    child = package.plan
    child_ref = next(item for item in package.artifacts if item.role == "main-graduation-plan")
    assert journal.delete_artifact(child_ref.digest)
    with pytest.raises(MainGraduationJournalError):
        journal._verify_children(package)  # pyright: ignore[reportPrivateUsage]
    assert child.operation_id == package.operation_id


def test_rollback_child_materialization_and_recovery_recheck_all_roles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    value = _ledger()
    field_names = (
        "attempt_authority",
        "source_completion",
        "rollback_preparation_authorization",
        "lease_evidence_record",
        "queue_configuration",
        "queue_observation",
        "protection_manifest",
        "attestation_manifest",
        "merge_group_checks",
        "merge_group_receipt",
        "admission_observation",
        "hold_observation",
        "release_authorization",
        "release_claim",
        "claimed_transition_receipt",
        "release_transition_receipt",
        "release_transition_intent",
        "release_transition_mutation_receipt",
        "composition",
        "rollback_authorization",
        "rollback_intent",
        "rollback_result",
        "post_state",
        "cleanup_intent",
        "cleanup_receipt",
        "cleanup_terminal",
    )
    package = SimpleNamespace(**{name: value for name in field_names})
    object.__setattr__(package, "cleanup_observation", value)
    object.__setattr__(package, "release_transition_fence_resolution", value)
    values = journal._rollback_child_values(package)  # pyright: ignore[reportPrivateUsage]
    package.artifacts = [
        ref(
            _digest_bytes(canonical_bytes(item)),
            role=role,
            media_type=f"application/vnd.avo.{role}+json",
        ).model_copy(update={"size_bytes": len(canonical_bytes(item))})
        for role, item in values.items()
    ]
    monkeypatch.setattr(journal, "_verify_rollback_completion_prerequisites", lambda _package: None)
    journal._materialize_rollback_children(package)  # pyright: ignore[reportPrivateUsage]
    journal._verify_rollback_children(package)  # pyright: ignore[reportPrivateUsage]

    broken = package.artifacts[0].model_copy(update={"media_type": "application/json"})
    object.__setattr__(package, "artifacts", [broken, *package.artifacts[1:]])
    with pytest.raises(MainGraduationJournalError, match="metadata"):
        journal._verify_rollback_children(package)  # pyright: ignore[reportPrivateUsage]


def test_rollback_completion_prerequisite_dispatches_every_durable_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    fields = {
        "source_completion": "completion",
        "rollback_preparation_authorization": "rollback-preparation-authorization",
        "lease_evidence_record": "lease-evidence-record",
        "queue_configuration": "queue-configuration",
        "queue_observation": "queue",
        "protection_manifest": "protection",
        "attestation_manifest": "attestations",
        "merge_group_checks": "merge-group-checks",
        "merge_group_receipt": "merge-group-webhook-receipt",
        "admission_observation": "queue-admission",
        "hold_observation": "release-hold",
        "release_authorization": "release-authorization",
        "release_claim": "release-claim",
        "claimed_transition_receipt": "claimed-release-transition",
        "release_transition_receipt": "release-transition",
        "release_transition_intent": "mutation-intent",
        "release_transition_mutation_receipt": "mutation-receipt",
        "composition": "rollback-composition",
        "rollback_authorization": "rollback-authorization",
        "rollback_intent": "rollback-intent",
        "attempt_authority": "rollback-attempt-authority",
        "rollback_result": "rollback-result",
        "post_state": "rollback-post-state-observation",
        "cleanup_intent": "rollback-cleanup-intent",
        "cleanup_receipt": "rollback-cleanup-receipt",
        "cleanup_terminal": "rollback-cleanup-terminal",
    }
    package = SimpleNamespace(
        **{name: _ledger() for name in fields},
        cleanup_observation=None,
        release_transition_fence_resolution=None,
    )
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        journal,
        "_require_exact",
        lambda kind, _record: calls.append(("exact", kind)),
    )
    monkeypatch.setattr(
        journal,
        "_require_phase_exact",
        lambda kind, _record: calls.append(("phase", kind)),
    )
    journal._verify_rollback_completion_prerequisites(package)  # pyright: ignore[reportPrivateUsage]
    assert {kind for _, kind in calls} == set(fields.values())


def test_eligibility_sequence_recovery_rejects_gaps_and_conflicts(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    first = MainGraduationEligibilityRecord(
        operation_id=D,
        repository_digest=R,
        scheduler_sequence=1,
        submission_digest=D,
        classification="excluded",
        exclusion_reason="not ordinary",
        exclusion_evidence_digest=D,
        ordinary=False,
        nonempty=True,
    )
    journal.record_eligibility(first)
    gap = first.model_copy(
        update={
            "operation_id": D2,
            "scheduler_sequence": 3,
            "previous_scheduler_sequence": 2,
        }
    )
    with pytest.raises(MainGraduationJournalError, match="predecessor"):
        journal.record_eligibility(gap)

    adjacent_watermark = first.model_copy(
        update={
            "operation_id": D2,
            "scheduler_sequence": 3,
            "previous_scheduler_sequence": None,
            "scheduler_watermark": 1,
        }
    )
    with pytest.raises(MainGraduationJournalError, match="adjacent"):
        journal.record_eligibility(adjacent_watermark)

    same_sequence_other_operation = first.model_copy(update={"operation_id": D2})
    with pytest.raises(MainGraduationRecordConflictError, match="occupied"):
        journal.record_eligibility(same_sequence_other_operation)


def test_recovery_read_context_does_not_reuse_stale_cache(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    started = _ledger()
    reference = journal.record_ledger_started(started)
    first = journal.read_ledger_started(D)
    assert first == (started, reference)

    # A fresh journal/traversal reads the durable bytes again. This guards the
    # restart boundary independently of the in-process ContextVar cache.
    restarted = MainGraduationJournal(tmp_path)
    assert restarted.read_ledger_started(D) == (started, reference)
    assert restarted.delete_artifact(reference.digest)
    with pytest.raises(MainGraduationJournalError):
        restarted.read_ledger_started(D)
