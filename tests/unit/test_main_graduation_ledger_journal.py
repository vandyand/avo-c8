"""Real-filesystem durability tests for the C6 ledger journal."""

import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar

import pytest

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.main_graduation_ledger_journal import (
    MainGraduationLedgerJournal,
    MainGraduationLedgerJournalError,
)
from avo_correlate.contracts.base import ArtifactRef, StrictModel
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
    MainLedgerUnresolvedTailEntry,
    main_ledger_genesis_state,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_main_graduation_ledger_contracts import _activation

NOW = datetime(2026, 9, 1, tzinfo=UTC)
ModelT = TypeVar("ModelT", bound=StrictModel)


class _Verifier:
    def verify_activation(self, _activation: Any) -> bool:
        return True

    def verify_submission(self, _submission: Any, _activation: Any) -> bool:
        return True

    def verify_classification(
        self, _classification: Any, _activation: Any, _submission: Any
    ) -> bool:
        return True

    def verify_outcome(
        self, _outcome: Any, _activation: Any, _submission: Any, _classification: Any
    ) -> bool:
        return True

    def verify_transition(
        self, _transition: Any, _activation: Any, _classification: Any, _outcome: Any
    ) -> bool:
        return True

    def verify_package(self, _package: Any) -> bool:
        return True

    def verify_boundary_evidence(self, _evidence: Any, _activation: Any) -> bool:
        return True

    def verify_boundary_reset(self, _reset: Any, _activation: Any, _evidence: Any) -> bool:
        return True


class _MissingActivationVerifier:
    def verify_submission(self, _submission: Any, _activation: Any) -> bool:
        return True


class _WrongSignatureVerifier(_Verifier):
    def verify_activation(self, _activation: Any, _unexpected: Any) -> bool:
        return True


class _NoneVerifier(_Verifier):
    def verify_activation(self, _activation: Any) -> None:
        return None


class _FalseVerifier(_Verifier):
    def verify_activation(self, _activation: Any) -> bool:
        return False


class _ExceptionVerifier(_Verifier):
    def verify_activation(self, _activation: Any) -> bool:
        raise RuntimeError("verification failed")


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
    activation: Any,
    submission: MainLedgerSubmissionEnvelope,
    store: FilesystemArtifactStore,
    path: str = "src/feature.py",
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
        "paths": [path],
        "path_manifest_digest": canonical_digest([path]),
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
    reason: str = "upstream failure",
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
        "reason": reason,
        "terminal_at": NOW,
    }
    return _with_digest(MainLedgerTerminalOutcome, values, "outcome_digest")


def _race(first_call: Any, second_call: Any) -> tuple[Any, Any]:
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(first_call)
        second = executor.submit(second_call)
        return first.result(), second.result()


def _attempt(call: Any) -> Any:
    try:
        return call()
    except MainGraduationLedgerJournalError as exc:
        return exc


def _classification_process_worker(
    root: str,
    ready_queue: Any,
    release: Any,
    results: Any,
    classification: MainLedgerClassificationEvidence,
) -> None:
    """Spawn target: independently open the same journal and race one stage."""
    journal = MainGraduationLedgerJournal(Path(root), _Verifier())
    ready_queue.put("ready")
    release.wait(30)
    try:
        journal.record_classification(classification)
    except MainGraduationLedgerJournalError as exc:
        results.put(("conflict", str(exc)))
    else:
        results.put(("success", classification.classification_digest))


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


@pytest.mark.parametrize(
    "verifier_type",
    [
        _MissingActivationVerifier,
        _WrongSignatureVerifier,
        _NoneVerifier,
        _FalseVerifier,
        _ExceptionVerifier,
    ],
)
def test_verifier_fail_closed_on_write_read_and_restart(
    tmp_path: Path, verifier_type: type[Any]
) -> None:
    activation = _activation()
    with pytest.raises(MainGraduationLedgerJournalError, match="verifier"):
        MainGraduationLedgerJournal(tmp_path, verifier_type()).record_activation(activation)

    good, activation, store = _journal(tmp_path / "durable")
    submission = _submission(activation, store, 11)
    good.record_submission(submission)
    with pytest.raises(MainGraduationLedgerJournalError, match="verifier"):
        MainGraduationLedgerJournal(tmp_path / "durable", verifier_type()).read_submission(
            submission.operation_id
        )


def test_stage_sidecars_are_create_once_across_independent_journals(tmp_path: Path) -> None:
    first, activation, store = _journal(tmp_path)
    second_store = FilesystemArtifactStore(
        tmp_path / "artifacts", clock=lambda: NOW - timedelta(minutes=1)
    )
    second = MainGraduationLedgerJournal(tmp_path, _Verifier(), artifact_store=second_store)
    submission = _submission(activation, store, 11)
    first.record_submission(submission)

    classification = _classification(activation, submission, store)
    assert first.record_classification(classification) == second.record_classification(
        classification
    )
    divergent_classification = _classification(activation, submission, store, path="src/other.py")
    with pytest.raises(MainGraduationLedgerJournalError, match="conflicting"):
        second.record_classification(divergent_classification)
    assert first.read_classification(11)[0] == classification

    outcome = _outcome(activation, submission, classification, store)
    assert first.record_outcome(outcome) == second.record_outcome(outcome)
    divergent_outcome = _outcome(activation, submission, classification, store, reason="other")
    with pytest.raises(MainGraduationLedgerJournalError, match="conflicting"):
        second.record_outcome(divergent_outcome)
    assert first.read_outcome(11)[0] == outcome

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
    assert first.record_transition(transition) == second.record_transition(transition)
    with pytest.raises(MainGraduationLedgerJournalError, match="malformed"):
        second.record_transition(transition.model_copy(update={"outcome": None}))
    restarted = MainGraduationLedgerJournal(tmp_path, _Verifier())
    assert restarted.read_transition(11)[0] == transition


def test_stage_sidecar_conflicts_race_without_last_writer_wins(tmp_path: Path) -> None:
    first, activation, store = _journal(tmp_path)
    second_store = FilesystemArtifactStore(
        tmp_path / "artifacts", clock=lambda: NOW - timedelta(minutes=1)
    )
    second = MainGraduationLedgerJournal(tmp_path, _Verifier(), artifact_store=second_store)
    submission = _submission(activation, store, 11)
    first.record_submission(submission)

    classification_a = _classification(activation, submission, store, path="src/a.py")
    classification_b = _classification(activation, submission, store, path="src/b.py")
    results = _race(
        lambda: _attempt(lambda: first.record_classification(classification_a)),
        lambda: _attempt(lambda: second.record_classification(classification_b)),
    )
    assert sum(isinstance(item, ArtifactRef) for item in results) == 1
    assert sum(isinstance(item, MainGraduationLedgerJournalError) for item in results) == 1
    durable_classification = first.read_classification(11)
    assert durable_classification is not None

    outcome_a = _outcome(activation, submission, durable_classification[0], store, reason="a")
    outcome_b = _outcome(activation, submission, durable_classification[0], store, reason="b")
    results = _race(
        lambda: _attempt(lambda: first.record_outcome(outcome_a)),
        lambda: _attempt(lambda: second.record_outcome(outcome_b)),
    )
    assert sum(isinstance(item, ArtifactRef) for item in results) == 1
    assert sum(isinstance(item, MainGraduationLedgerJournalError) for item in results) == 1
    durable_outcome = first.read_outcome(11)
    assert durable_outcome is not None

    prior = main_ledger_genesis_state(
        activation.activation_digest, activation.scheduler_sequence_watermark
    )
    result_state = _with_digest(
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
            "classification": durable_classification[0],
            "prior_state": prior,
            "prior_state_digest": prior.state_digest,
            "outcome": durable_outcome[0],
            "outcome_digest": durable_outcome[0].outcome_digest,
            "reset_applied": True,
            "resulting_state": result_state,
            "resulting_state_digest": result_state.state_digest,
        },
        "transition_digest",
    )
    malformed = transition.model_copy(update={"outcome": None, "outcome_digest": None})
    results = _race(
        lambda: _attempt(lambda: first.record_transition(transition)),
        lambda: _attempt(lambda: second.record_transition(malformed)),
    )
    assert sum(isinstance(item, ArtifactRef) for item in results) == 1
    assert sum(isinstance(item, MainGraduationLedgerJournalError) for item in results) == 1
    restarted = MainGraduationLedgerJournal(tmp_path, _Verifier())
    durable_transition = restarted.read_transition(11)
    assert durable_transition is not None and durable_transition[0] == transition


def test_windows_spawn_process_race_has_one_classification_winner(tmp_path: Path) -> None:
    journal, activation, store = _journal(tmp_path)
    submission = _submission(activation, store, 11)
    journal.record_submission(submission)
    classification_a = _classification(activation, submission, store, path="src/process-a.py")
    classification_b = _classification(activation, submission, store, path="src/process-b.py")

    context = multiprocessing.get_context("spawn")
    ready_queue = context.Queue()
    result_queue = context.Queue()
    release = context.Event()
    processes = [
        context.Process(
            target=_classification_process_worker,
            args=(str(tmp_path), ready_queue, release, result_queue, classification_a),
        ),
        context.Process(
            target=_classification_process_worker,
            args=(str(tmp_path), ready_queue, release, result_queue, classification_b),
        ),
    ]
    try:
        for process in processes:
            process.start()
        assert ready_queue.get(timeout=15) == "ready"
        assert ready_queue.get(timeout=15) == "ready"
        release.set()
        statuses = [result_queue.get(timeout=15)[0] for _ in processes]
        assert sorted(statuses) == ["conflict", "success"]
        for process in processes:
            process.join(timeout=15)
            assert process.exitcode == 0
    finally:
        release.set()
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=15)
        ready_queue.close()
        result_queue.close()

    restarted = MainGraduationLedgerJournal(tmp_path, _Verifier())
    winner = restarted.read_classification(11)
    assert winner is not None
    assert winner[0] == classification_a or winner[0] == classification_b


def test_stage_sidecar_noncanonical_and_missing_cas_fail_closed(tmp_path: Path) -> None:
    journal, activation, store = _journal(tmp_path)
    submission = _submission(activation, store, 11)
    journal.record_submission(submission)
    classification = _classification(activation, submission, store)
    journal.record_classification(classification)
    outcome = _outcome(activation, submission, classification, store)
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
    journal.record_transition(transition)

    reads = {
        "classification": lambda fresh: fresh.read_classification(11),
        "outcome": lambda fresh: fresh.read_outcome(11),
        "transition": lambda fresh: fresh.read_transition(11),
    }
    for kind, read in reads.items():
        stage_path = journal._stage_path(  # type: ignore[reportPrivateUsage]
            activation, 11, kind
        )
        original_index = stage_path.read_bytes()
        stage_path.write_bytes(original_index + b"\n")
        with pytest.raises(MainGraduationLedgerJournalError, match="index"):
            read(MainGraduationLedgerJournal(tmp_path, _Verifier()))
        stage_path.write_bytes(original_index)

        reference = journal._stage_reference(  # type: ignore[reportPrivateUsage]
            activation, 11, kind
        )
        cas_path = store.path_for_digest(reference.digest)
        cas_bytes = cas_path.read_bytes()
        cas_path.unlink()
        with pytest.raises(MainGraduationLedgerJournalError):
            read(MainGraduationLedgerJournal(tmp_path, _Verifier()))
        cas_path.write_bytes(cas_bytes)


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


def test_boundary_package_closes_submitted_unclassified_tail(tmp_path: Path) -> None:
    journal, activation, store = _journal(tmp_path)
    submission = _submission(activation, store, 11)
    journal.record_submission(submission)
    evidence_artifact = store.put_bytes(
        canonical_bytes({"kind": "withholding"}),
        media_type=BOUNDARY_ARTIFACT_MEDIA_TYPE,
        role=BOUNDARY_ARTIFACT_ROLE,
        max_bytes=1024 * 1024,
    )
    evidence_values = {
        "activation_digest": activation.activation_digest,
        "controller_authority": activation.controller_authority,
        "expected_scheduler_sequence": 11,
        "current_state_digest": main_ledger_genesis_state(
            activation.activation_digest, activation.scheduler_sequence_watermark
        ).state_digest,
        "violation_kind": "withholding",
        "submission_digest": submission.submission_digest,
        "operation_id": submission.operation_id,
        "envelope_digest": submission.envelope_digest,
        "content_artifact": submission.content_artifact,
        "evidence_artifact": evidence_artifact,
        "detected_at": activation.activated_at,
    }
    evidence = _with_digest(
        MainLedgerBoundaryViolationEvidence, evidence_values, "violation_digest"
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
    tail = _with_digest(
        MainLedgerUnresolvedTailEntry,
        {
            "scheduler_sequence": 11,
            "submission_digest": submission.submission_digest,
            "operation_id": submission.operation_id,
            "envelope_digest": submission.envelope_digest,
            "content_artifact": submission.content_artifact,
        },
        "entry_digest",
    )
    values = {
        "status": "boundary_reset",
        "activation": activation,
        "submissions": [submission],
        "classifications": [],
        "outcomes": [],
        "transitions": [],
        "unresolved_tail": [tail],
        "final_state": result,
        "boundary_evidence": evidence,
        "terminal_boundary_reset": reset,
    }
    probe = MainLedgerEvidencePackage.model_construct(**values, package_digest="sha256:" + "1" * 64)
    package = MainLedgerEvidencePackage.model_validate(
        {
            **values,
            "package_digest": canonical_digest(
                probe.model_dump(exclude={"package_digest"}, mode="json")
            ),
        }
    )
    journal.record_package(package)
    restarted = MainGraduationLedgerJournal(tmp_path, _Verifier())
    loaded = restarted.read_package(activation.activation_digest)
    assert loaded is not None and loaded[0] == package
