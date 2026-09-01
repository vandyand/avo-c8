"""Real-filesystem durability tests for the C6 ledger journal."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar

import pytest

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.main_graduation_ledger_journal import (
    MainGraduationLedgerJournal,
    MainGraduationLedgerJournalError,
)
from avo_correlate.contracts.base import StrictModel
from avo_correlate.contracts.main_graduation_ledger import (
    BOUNDARY_ARTIFACT_MEDIA_TYPE,
    BOUNDARY_ARTIFACT_ROLE,
    CONTENT_ARTIFACT_MEDIA_TYPE,
    CONTENT_ARTIFACT_ROLE,
    TERMINAL_ARTIFACT_MEDIA_TYPE,
    TERMINAL_ARTIFACT_ROLE,
    MainLedgerAccumulatorState,
    MainLedgerAccumulatorTransition,
    MainLedgerBoundaryResetTransition,
    MainLedgerBoundaryViolationEvidence,
    MainLedgerClassificationEvidence,
    MainLedgerEvidencePackage,
    MainLedgerSubmissionEnvelope,
    MainLedgerTerminalOutcome,
    main_ledger_genesis_state,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_main_graduation_ledger_contracts import _activation

NOW = datetime(2026, 9, 1, tzinfo=UTC)
ModelT = TypeVar("ModelT", bound=StrictModel)


class _Verifier:
    def __getattr__(self, _name: str) -> Any:
        return lambda *_args: True


def _with_digest(  # noqa: UP047
    model_type: type[ModelT], values: dict[str, Any], field: str
) -> ModelT:
    probe = model_type.model_construct(**values, **{field: "sha256:" + "1" * 64})
    return model_type.model_validate(
        {**values, field: canonical_digest(probe.model_dump(exclude={field}, mode="json"))}
    )


def _journal(tmp_path: Path) -> tuple[MainGraduationLedgerJournal, Any, Any]:
    store = FilesystemArtifactStore(
        tmp_path / "artifacts", clock=lambda: NOW - timedelta(minutes=1)
    )
    activation = _activation()
    journal = MainGraduationLedgerJournal(tmp_path, _Verifier(), artifact_store=store)
    journal.record_activation(activation)
    return journal, activation, store


def _submission(
    activation: Any, store: FilesystemArtifactStore, sequence: int, identity: str | None = None
) -> MainLedgerSubmissionEnvelope:
    identity = identity or f"submission-{sequence}"
    content = store.put_bytes(
        canonical_bytes({"sequence": sequence, "identity": identity}),
        media_type=CONTENT_ARTIFACT_MEDIA_TYPE,
        role=CONTENT_ARTIFACT_ROLE,
        max_bytes=1024 * 1024,
    )
    values = {
        "activation_digest": activation.activation_digest,
        "repository_digest": activation.repository_digest,
        "scheduler_sequence": sequence,
        "source_identity": "scheduler",
        "submission_identity": identity,
        "submission_digest": content.digest,
        "content_artifact": content,
        "operation_id": canonical_digest(
            {
                "domain": "avo.main.ledger.submission.v2",
                "activation_digest": activation.activation_digest,
                "scheduler_sequence": sequence,
                "source_identity": "scheduler",
                "submission_identity": identity,
                "submission_digest": content.digest,
            }
        ),
        "recorded_at": NOW,
    }
    return _with_digest(MainLedgerSubmissionEnvelope, values, "envelope_digest")


def _classification(
    activation: Any, submission: MainLedgerSubmissionEnvelope, store: FilesystemArtifactStore
) -> MainLedgerClassificationEvidence:
    values: dict[str, Any] = {
        "activation_digest": activation.activation_digest,
        "submission_digest": submission.submission_digest,
        "operation_id": submission.operation_id,
        "scheduler_sequence": submission.scheduler_sequence,
        "classification": "eligible",
        "empty": False,
        "ordinary": True,
        "risk_class": "ordinary",
        "paths": ["src/feature.py"],
        "path_manifest_digest": canonical_digest(["src/feature.py"]),
        "policy_digest": activation.policy_digest,
        "policy_epoch": activation.policy_epoch,
        "controller_authority": activation.controller_authority,
        "issuer_identity": activation.controller_authority.issuer_identity,
        "issuer_authority_digest": activation.controller_authority.issuer_authority_digest,
    }
    return _with_digest(MainLedgerClassificationEvidence, values, "classification_digest")


def _outcome(
    activation: Any,
    submission: MainLedgerSubmissionEnvelope,
    classification: MainLedgerClassificationEvidence,
    store: FilesystemArtifactStore,
) -> MainLedgerTerminalOutcome:
    evidence = store.put_bytes(
        canonical_bytes({"sequence": submission.scheduler_sequence, "outcome": "failure"}),
        media_type=TERMINAL_ARTIFACT_MEDIA_TYPE,
        role=TERMINAL_ARTIFACT_ROLE,
        max_bytes=1024 * 1024,
    )
    values: dict[str, Any] = {
        "activation_digest": activation.activation_digest,
        "submission_digest": submission.submission_digest,
        "classification_digest": classification.classification_digest,
        "classification": classification,
        "operation_id": submission.operation_id,
        "attempt_id": canonical_digest(
            {
                "domain": "avo.main.ledger.attempt.v2",
                "activation_digest": activation.activation_digest,
                "scheduler_sequence": submission.scheduler_sequence,
                "submission_digest": submission.submission_digest,
            }
        ),
        "scheduler_sequence": submission.scheduler_sequence,
        "outcome": "failure",
        "evidence_kind": "failure",
        "terminal_evidence_digest": evidence.digest,
        "terminal_evidence": evidence,
        "reason": "upstream failure",
        "terminal_at": NOW,
    }
    return _with_digest(MainLedgerTerminalOutcome, values, "outcome_digest")


def test_authority_is_mandatory_and_submission_is_gap_free(tmp_path: Path) -> None:
    activation = _activation()
    with pytest.raises(MainGraduationLedgerJournalError, match="verifier"):
        MainGraduationLedgerJournal(tmp_path).record_activation(activation)
    journal, activation, store = _journal(tmp_path)
    gap = _submission(activation, store, 12)
    with pytest.raises(MainGraduationLedgerJournalError, match="gap"):
        journal.record_submission(gap)
    first = _submission(activation, store, 11)
    journal.record_submission(first)
    assert journal.record_submission(first) == journal.read_submission(first.operation_id)[1]
    assert journal.list_sequences() == (11,)


def test_cas_orphan_is_not_discoverable_and_restart_finds_commit(tmp_path: Path) -> None:
    journal, activation, store = _journal(tmp_path)
    submission = _submission(activation, store, 11)
    orphan_data = canonical_bytes(submission)
    journal._put("submission", orphan_data)  # type: ignore[reportPrivateUsage]
    assert journal.read_submission(submission.operation_id) is None
    journal.record_submission(submission)
    restarted = MainGraduationLedgerJournal(tmp_path, _Verifier())
    loaded = restarted.read_submission(submission.operation_id)
    assert loaded is not None and loaded[0] == submission


def test_restart_rejects_tampered_cas_or_noncanonical_sequence_index(tmp_path: Path) -> None:
    journal, activation, store = _journal(tmp_path)
    submission = _submission(activation, store, 11)
    journal.record_submission(submission)
    artifact_path = store.path_for_digest(submission.content_artifact.digest)
    artifact_path.write_bytes(b"tampered")
    with pytest.raises(MainGraduationLedgerJournalError, match="malformed"):
        MainGraduationLedgerJournal(tmp_path, _Verifier()).read_submission(submission.operation_id)

    # Restore the CAS object, then make the authoritative sequence index
    # syntactically valid but noncanonical. Reads must still fail closed.
    artifact_path.write_bytes(canonical_bytes({"sequence": 11, "identity": "submission-11"}))
    sequence_path = next((tmp_path / "main-ledger-v2" / "sequence").rglob("11.json"))
    sequence_path.write_text(sequence_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(MainGraduationLedgerJournalError, match="sequence index"):
        MainGraduationLedgerJournal(tmp_path, _Verifier()).list_sequences()


def test_later_submission_is_recordable_while_prior_outcome_is_open(tmp_path: Path) -> None:
    journal, activation, store = _journal(tmp_path)
    first = _submission(activation, store, 11)
    second = _submission(activation, store, 12)
    journal.record_submission(first)
    journal.record_submission(second)
    classification = _classification(activation, first, store)
    journal.record_classification(classification)
    with pytest.raises(MainGraduationLedgerJournalError, match="transition"):
        journal.record_transition({})  # type: ignore[arg-type]
    assert journal.read_submission(second.operation_id) is not None


def test_duplicate_physical_content_is_rejected_across_sequences(tmp_path: Path) -> None:
    journal, activation, store = _journal(tmp_path)
    first = _submission(activation, store, 11)
    journal.record_submission(first)
    second = _submission(activation, store, 12, "different-identity")
    duplicate_probe = second.model_dump(mode="json")
    duplicate_probe["submission_digest"] = first.submission_digest
    duplicate_probe["content_artifact"] = first.content_artifact.model_dump(mode="json")
    duplicate_probe["operation_id"] = canonical_digest(
        {
            "domain": "avo.main.ledger.submission.v2",
            "activation_digest": activation.activation_digest,
            "scheduler_sequence": 12,
            "source_identity": "scheduler",
            "submission_identity": "different-identity",
            "submission_digest": first.submission_digest,
        }
    )
    duplicate_probe.pop("envelope_digest")
    duplicate = _with_digest(
        MainLedgerSubmissionEnvelope,
        duplicate_probe,
        "envelope_digest",
    )
    with pytest.raises(MainGraduationLedgerJournalError, match="physical submission content"):
        journal.record_submission(duplicate)


def test_terminal_and_transition_are_ordered_and_exact(tmp_path: Path) -> None:
    journal, activation, store = _journal(tmp_path)
    submission = _submission(activation, store, 11)
    journal.record_submission(submission)
    classification = _classification(activation, submission, store)
    journal.record_classification(classification)
    outcome = _outcome(activation, submission, classification, store)
    with pytest.raises(MainGraduationLedgerJournalError, match="transition"):
        journal.record_transition({})  # type: ignore[arg-type]
    journal.record_outcome(outcome)
    prior = main_ledger_genesis_state(
        activation.activation_digest, activation.scheduler_sequence_watermark
    )
    result = _with_digest(
        MainLedgerAccumulatorState,
        {
            **prior.model_dump(exclude={"state_digest"}),
            "last_scheduler_sequence": 11,
            "failures": 1,
            "streak": 0,
        },
        "state_digest",
    )
    transition = _with_digest(
        MainLedgerAccumulatorTransition,
        {
            "activation_digest": activation.activation_digest,
            "classification": classification,
            "prior_state": prior,
            "prior_state_digest": prior.state_digest,
            "outcome": outcome,
            "outcome_digest": outcome.outcome_digest,
            "reset_applied": True,
            "resulting_state": result,
            "resulting_state_digest": result.state_digest,
        },
        "transition_digest",
    )
    assert journal.record_transition(transition).digest
    assert journal.record_transition(transition) == journal.read_transition(11)[1]


def test_boundary_reset_and_aggregate_reload(tmp_path: Path) -> None:
    journal, activation, store = _journal(tmp_path)
    evidence_artifact = store.put_bytes(
        canonical_bytes({"kind": "starvation"}),
        media_type=BOUNDARY_ARTIFACT_MEDIA_TYPE,
        role=BOUNDARY_ARTIFACT_ROLE,
        max_bytes=1024 * 1024,
    )
    evidence = _with_digest(
        MainLedgerBoundaryViolationEvidence,
        {
            "activation_digest": activation.activation_digest,
            "controller_authority": activation.controller_authority,
            "expected_scheduler_sequence": 11,
            "current_state_digest": main_ledger_genesis_state(
                activation.activation_digest, activation.scheduler_sequence_watermark
            ).state_digest,
            "violation_kind": "starvation",
            "evidence_artifact": evidence_artifact,
            "detected_at": activation.activated_at,
        },
        "violation_digest",
    )
    prior = main_ledger_genesis_state(
        activation.activation_digest, activation.scheduler_sequence_watermark
    )
    result = _with_digest(
        MainLedgerAccumulatorState,
        {
            **prior.model_dump(exclude={"state_digest"}),
            "boundary_violations": 1,
        },
        "state_digest",
    )
    reset = _with_digest(
        MainLedgerBoundaryResetTransition,
        {
            "activation_digest": activation.activation_digest,
            "prior_state": prior,
            "prior_state_digest": prior.state_digest,
            "violation": evidence,
            "resulting_state": result,
            "resulting_state_digest": result.state_digest,
        },
        "transition_digest",
    )
    journal.record_boundary_evidence(evidence)
    journal.record_boundary_reset(reset)
    package_probe = MainLedgerEvidencePackage.model_construct(
        status="boundary_reset",
        activation=activation,
        submissions=[],
        classifications=[],
        outcomes=[],
        transitions=[],
        final_state=result,
        boundary_evidence=evidence,
        terminal_boundary_reset=reset,
        package_digest="sha256:" + "1" * 64,
    )
    package = MainLedgerEvidencePackage.model_validate(
        {
            **package_probe.model_dump(exclude={"package_digest"}, mode="json"),
            "package_digest": canonical_digest(
                package_probe.model_dump(exclude={"package_digest"}, mode="json")
            ),
        }
    )
    journal.record_package(package)
    restarted = MainGraduationLedgerJournal(tmp_path, _Verifier())
    loaded = restarted.read_package(activation.activation_digest)
    assert loaded is not None and loaded[0] == package
