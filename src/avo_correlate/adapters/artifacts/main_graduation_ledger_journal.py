"""Offline C6 main-graduation ledger journal.

The C6 contracts are deliberately data-only.  This adapter supplies the
durability boundary around them: every object is canonical and
content-addressed, while the per-sequence commit is the authoritative index.
In particular, a record object which is installed before its sequence commit
is an harmless orphan and is never discoverable as ledger history.
"""

# The journal deliberately dispatches across several Pydantic model classes;
# these diagnostics would otherwise obscure the concrete public boundary.
# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false

from __future__ import annotations

import errno
import json
import os
from pathlib import Path
from threading import RLock
from typing import Any, Protocol, cast
from uuid import uuid4

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef, StrictModel
from avo_correlate.contracts.main_graduation_ledger import (
    BOUNDARY_ARTIFACT_MEDIA_TYPE,
    BOUNDARY_ARTIFACT_ROLE,
    CONTENT_ARTIFACT_MEDIA_TYPE,
    CONTENT_ARTIFACT_ROLE,
    EXCLUSION_ARTIFACT_MEDIA_TYPE,
    EXCLUSION_ARTIFACT_ROLE,
    PACKAGE_ARTIFACT_MEDIA_TYPE,
    PACKAGE_ARTIFACT_ROLE,
    TERMINAL_ARTIFACT_MEDIA_TYPE,
    TERMINAL_ARTIFACT_ROLE,
    MainLedgerAccumulatorTransition,
    MainLedgerActivation,
    MainLedgerBoundaryResetTransition,
    MainLedgerBoundaryViolationEvidence,
    MainLedgerClassificationEvidence,
    MainLedgerEvidencePackage,
    MainLedgerSubmissionEnvelope,
    MainLedgerTerminalOutcome,
    main_ledger_genesis_state,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


class MainGraduationLedgerJournalError(RuntimeError):
    """A ledger record is missing, malformed, unverifiable, or conflicting."""


class MainGraduationLedgerRecordConflictError(MainGraduationLedgerJournalError):
    """A create-once identity is already bound to different canonical bytes."""


class MainLedgerAuthorityVerifier(Protocol):
    """Injected controller-rooted authentication for C6 records.

    Implementations must authenticate the record against the exact durable
    dependencies supplied by the journal.  Only the literal result ``True``
    is acceptance; a parsed DTO and its digest are never principal
    authentication.
    """

    def verify_activation(self, activation: MainLedgerActivation) -> object: ...

    def verify_submission(
        self, submission: MainLedgerSubmissionEnvelope, activation: MainLedgerActivation
    ) -> object: ...

    def verify_classification(
        self,
        classification: MainLedgerClassificationEvidence,
        activation: MainLedgerActivation,
        submission: MainLedgerSubmissionEnvelope,
    ) -> object: ...

    def verify_outcome(
        self,
        outcome: MainLedgerTerminalOutcome,
        activation: MainLedgerActivation,
        submission: MainLedgerSubmissionEnvelope,
        classification: MainLedgerClassificationEvidence,
    ) -> object: ...

    def verify_transition(
        self,
        transition: MainLedgerAccumulatorTransition,
        activation: MainLedgerActivation,
        classification: MainLedgerClassificationEvidence,
        outcome: MainLedgerTerminalOutcome | None,
    ) -> object: ...

    def verify_package(self, package: MainLedgerEvidencePackage) -> object: ...

    def verify_boundary_evidence(
        self, evidence: MainLedgerBoundaryViolationEvidence, activation: MainLedgerActivation
    ) -> object: ...

    def verify_boundary_reset(
        self,
        reset: MainLedgerBoundaryResetTransition,
        activation: MainLedgerActivation,
        evidence: MainLedgerBoundaryViolationEvidence,
    ) -> object: ...


_LOCK = RLock()
_SEQUENCE_SCHEMA = 2
_MAX_INDEX_BYTES = 1024 * 1024
_DEFAULT_MAX_RECORD_BYTES = 8 * 1024 * 1024
_MEDIA = "application/vnd.avo.main-ledger"
_ROLES = {
    "activation": "main-ledger-activation",
    "submission": "main-ledger-submission",
    "classification": "main-ledger-classification",
    "outcome": "main-ledger-outcome",
    "transition": "main-ledger-transition",
    "package": "main-ledger-evidence-package",
    "boundary": "main-ledger-boundary-evidence",
    "boundary-reset": "main-ledger-boundary-reset",
}


class MainGraduationLedgerJournal:
    """Create-once, filesystem-backed v2 ledger for one frozen activation."""

    def __init__(
        self,
        root: Path,
        authority_verifier: MainLedgerAuthorityVerifier | None = None,
        *,
        artifact_store: FilesystemArtifactStore | None = None,
        max_record_bytes: int = _DEFAULT_MAX_RECORD_BYTES,
    ) -> None:
        if max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        self._root = root.resolve()
        self._indexes = self._root / "main-ledger-v2"
        self._sequences = self._indexes / "sequence"
        self._stages = self._indexes / "stage"
        self._store = artifact_store or FilesystemArtifactStore(self._root / "artifacts")
        self._verifier = authority_verifier
        self._max = max_record_bytes

    @property
    def root(self) -> Path:
        return self._root

    @property
    def artifact_store(self) -> FilesystemArtifactStore:
        return self._store

    def record_activation(self, activation: MainLedgerActivation) -> ArtifactRef:
        with _LOCK:
            record = self._parse_record("activation", activation)
            self._verify("activation", record)
            data = canonical_bytes(record)
            reference = self._put("activation", data)
            index = self._indexes / "activation.json"
            return self._create_once(index, reference, data, "activation")

    record_activation_once = record_activation

    def read_activation(self) -> tuple[MainLedgerActivation, ArtifactRef] | None:
        with _LOCK:
            index = self._indexes / "activation.json"
            if not index.is_file():
                return None
            reference = self._read_reference(index, "activation")
            activation = self._read_record("activation", reference, MainLedgerActivation)
            self._verify("activation", activation)
            return activation, reference

    def record_submission(self, submission: MainLedgerSubmissionEnvelope) -> ArtifactRef:
        with _LOCK:
            record = self._parse_record("submission", submission)
            activation = self._require_activation(record.activation_digest)
            self._validate_record_artifacts(record)
            self._verify("submission", record, activation)
            if (
                record.repository_digest != activation.repository_digest
                or record.target_ref != activation.target_ref
            ):
                raise MainGraduationLedgerJournalError("submission target differs from activation")
            if record.scheduler_sequence <= activation.scheduler_sequence_watermark:
                raise MainGraduationLedgerJournalError(
                    "submission sequence is at or before activation watermark"
                )
            existing = self._sequence_entry(record.activation_digest, record.scheduler_sequence)
            if existing is not None:
                data = canonical_bytes(record)
                old = self._read_entry_submission(existing, activation)
                if canonical_bytes(old) != data or old.operation_id != record.operation_id:
                    raise MainGraduationLedgerRecordConflictError(
                        "conflicting submission for scheduler sequence"
                    )
                return self._reference(existing, "submission")
            if self._boundary_evidence_path(activation).is_file():
                raise MainGraduationLedgerJournalError(
                    "submission cannot be appended after boundary evidence"
                )
            self._require_fresh_mutation_allowed(activation, "submission")
            current_state = self._current_accumulator_state(activation)
            if record.scheduler_sequence != current_state.last_scheduler_sequence + 1:
                raise MainGraduationLedgerJournalError(
                    "submission must be the exact next unprocessed sequence; "
                    "scheduler sequence has a gap"
                )
            data = canonical_bytes(record)
            reference = self._put("submission", data)
            for entry in self._entries_for(activation):
                old = self._read_entry_submission(entry, activation)
                if (
                    old.source_identity == record.source_identity
                    and old.submission_identity == record.submission_identity
                ):
                    raise MainGraduationLedgerRecordConflictError("duplicate submission identity")
                if old.submission_digest == record.submission_digest:
                    raise MainGraduationLedgerRecordConflictError(
                        "duplicate physical submission content"
                    )
            entry = self._new_entry(record, reference)
            self._commit_entry(
                record.activation_digest,
                record.scheduler_sequence,
                entry,
            )
            committed = self._sequence_entry(record.activation_digest, record.scheduler_sequence)
            if committed is None:
                raise MainGraduationLedgerJournalError("submission commit disappeared")
            return self._reference(committed, "submission")

    record_scheduler_submission = record_submission

    def read_submission(
        self, operation_id: str
    ) -> tuple[MainLedgerSubmissionEnvelope, ArtifactRef] | None:
        with _LOCK:
            activation = self._require_activation_for_read()
            for entry in self._entries_for(activation):
                submission = self._read_entry_submission(entry, activation)
                if submission.operation_id == operation_id:
                    return submission, self._reference(entry, "submission")
            return None

    def read_submission_by_sequence(
        self, scheduler_sequence: int
    ) -> tuple[MainLedgerSubmissionEnvelope, ArtifactRef] | None:
        with _LOCK:
            activation = self._require_activation_for_read()
            for entry in self._entries_for(activation):
                if entry["scheduler_sequence"] == scheduler_sequence:
                    submission = self._read_entry_submission(entry, activation)
                    return submission, self._reference(entry, "submission")
            return None

    def list_submissions(self) -> tuple[MainLedgerSubmissionEnvelope, ...]:
        with _LOCK:
            activation = self._require_activation_for_read()
            return tuple(
                self._read_entry_submission(entry, activation)
                for entry in self._entries_for(activation)
            )

    list_scheduler_submissions = list_submissions

    def record_classification(
        self, classification: MainLedgerClassificationEvidence
    ) -> ArtifactRef:
        with _LOCK:
            record = self._parse_record("classification", classification)
            activation = self._require_activation(record.activation_digest)
            self._validate_record_artifacts(record)
            self._entries_for(activation)
            entry = self._require_entry(record.activation_digest, record.scheduler_sequence)
            submission = self._read_entry_submission(entry, activation)
            self._require_exact_classification_binding(record, activation, submission)
            self._verify("classification", record, activation, submission)
            if self._stage_exists(activation, record.scheduler_sequence, "classification"):
                data = canonical_bytes(record)
                old = self._read_entry_ref(
                    entry,
                    "classification",
                    MainLedgerClassificationEvidence,
                    activation,
                    submission,
                )
                if canonical_bytes(old) != data:
                    raise MainGraduationLedgerRecordConflictError(
                        "conflicting classification replay"
                    )
                return self._reference(entry, "classification", activation)
            if self._boundary_evidence_path(activation).is_file():
                raise MainGraduationLedgerJournalError(
                    "classification cannot be appended after boundary evidence"
                )
            self._require_fresh_mutation_allowed(activation, "classification")
            data = canonical_bytes(record)
            reference = self._put("classification", data)
            return self._create_stage_once(
                activation, record.scheduler_sequence, "classification", reference, data
            )

    record_eligibility_classification = record_classification

    def read_classification(
        self, identity: str | int
    ) -> tuple[MainLedgerClassificationEvidence, ArtifactRef] | None:
        with _LOCK:
            activation = self._require_activation_for_read()
            entries = self._entries_for(activation)
            for entry in entries:
                submission = self._read_entry_submission(entry, activation)
                if isinstance(identity, int):
                    if submission.scheduler_sequence != identity:
                        continue
                elif submission.operation_id != identity:
                    continue
                if not self._stage_exists(
                    activation, submission.scheduler_sequence, "classification"
                ):
                    return None
                classification = self._read_entry_ref(
                    entry,
                    "classification",
                    MainLedgerClassificationEvidence,
                    activation,
                    submission,
                )
                return classification, self._reference(entry, "classification", activation)
            return None

    def record_outcome(self, outcome: MainLedgerTerminalOutcome) -> ArtifactRef:
        with _LOCK:
            record = self._parse_record("outcome", outcome)
            activation = self._require_activation(record.activation_digest)
            self._validate_record_artifacts(record)
            self._entries_for(activation)
            entry = self._require_entry(record.activation_digest, record.scheduler_sequence)
            submission = self._read_entry_submission(entry, activation)
            classification = self._require_classification(entry, activation, submission)
            self._require_exact_outcome_binding(record, activation, submission, classification)
            self._verify("outcome", record, activation, submission, classification)
            if self._stage_exists(activation, record.scheduler_sequence, "outcome"):
                data = canonical_bytes(record)
                old = self._read_entry_ref(
                    entry,
                    "outcome",
                    MainLedgerTerminalOutcome,
                    activation,
                    submission,
                    classification,
                )
                if canonical_bytes(old) != data:
                    raise MainGraduationLedgerRecordConflictError(
                        "conflicting terminal outcome replay"
                    )
                return self._reference(entry, "outcome", activation)
            if self._boundary_evidence_path(activation).is_file():
                raise MainGraduationLedgerJournalError(
                    "outcome cannot be appended after boundary evidence"
                )
            self._require_fresh_mutation_allowed(activation, "outcome")
            data = canonical_bytes(record)
            reference = self._put("outcome", data)
            return self._create_stage_once(
                activation, record.scheduler_sequence, "outcome", reference, data
            )

    record_terminal_outcome = record_outcome
    record_attempt_outcome = record_outcome

    def read_outcome(
        self, identity: str | int
    ) -> tuple[MainLedgerTerminalOutcome, ArtifactRef] | None:
        with _LOCK:
            activation = self._require_activation_for_read()
            for entry in self._entries_for(activation):
                submission = self._read_entry_submission(entry, activation)
                if (isinstance(identity, int) and submission.scheduler_sequence != identity) or (
                    isinstance(identity, str) and submission.operation_id != identity
                ):
                    continue
                if not self._stage_exists(activation, submission.scheduler_sequence, "outcome"):
                    return None
                classification = self._require_classification(entry, activation, submission)
                outcome = self._read_entry_ref(
                    entry,
                    "outcome",
                    MainLedgerTerminalOutcome,
                    activation,
                    submission,
                    classification,
                )
                return outcome, self._reference(entry, "outcome", activation)
            return None

    read_terminal_outcome = read_outcome

    def record_transition(self, transition: MainLedgerAccumulatorTransition) -> ArtifactRef:
        with _LOCK:
            record = self._parse_record("transition", transition)
            activation = self._require_activation(record.activation_digest)
            self._entries_for(activation)
            sequence = record.classification.scheduler_sequence
            entry = self._require_entry(record.activation_digest, sequence)
            submission = self._read_entry_submission(entry, activation)
            classification = self._require_classification(entry, activation, submission)
            if record.classification != classification:
                raise MainGraduationLedgerJournalError(
                    "transition classification differs from durable classification"
                )
            outcome: MainLedgerTerminalOutcome | None = None
            if classification.classification == "eligible":
                outcome = self._require_outcome(entry, activation, submission, classification)
            elif record.outcome is not None:
                raise MainGraduationLedgerJournalError("excluded transition cannot carry outcome")
            self._require_exact_transition_binding(record, activation, classification, outcome)
            prior = self._prior_state(activation, sequence)
            if record.prior_state != prior:
                raise MainGraduationLedgerJournalError(
                    "transition predecessor differs from durable chain"
                )
            self._verify("transition", record, activation, classification, outcome)
            if self._stage_exists(activation, sequence, "transition"):
                data = canonical_bytes(record)
                old = self._read_entry_ref(
                    entry,
                    "transition",
                    MainLedgerAccumulatorTransition,
                    activation,
                    submission,
                    classification,
                    outcome,
                )
                if canonical_bytes(old) != data:
                    raise MainGraduationLedgerRecordConflictError(
                        "conflicting accumulator transition replay"
                    )
                return self._reference(entry, "transition", activation)
            if self._boundary_evidence_path(activation).is_file():
                raise MainGraduationLedgerJournalError(
                    "transition cannot be appended after boundary evidence"
                )
            self._require_fresh_mutation_allowed(activation, "transition")
            data = canonical_bytes(record)
            reference = self._put("transition", data)
            return self._create_stage_once(activation, sequence, "transition", reference, data)

    record_accumulator_transition = record_transition

    def read_transition(
        self, identity: str | int
    ) -> tuple[MainLedgerAccumulatorTransition, ArtifactRef] | None:
        with _LOCK:
            activation = self._require_activation_for_read()
            for entry in self._entries_for(activation):
                submission = self._read_entry_submission(entry, activation)
                if (isinstance(identity, int) and submission.scheduler_sequence != identity) or (
                    isinstance(identity, str) and submission.operation_id != identity
                ):
                    continue
                if not self._stage_exists(activation, submission.scheduler_sequence, "transition"):
                    return None
                classification = self._require_classification(entry, activation, submission)
                outcome = (
                    self._require_outcome(entry, activation, submission, classification)
                    if classification.classification == "eligible"
                    else None
                )
                transition = self._read_entry_ref(
                    entry,
                    "transition",
                    MainLedgerAccumulatorTransition,
                    activation,
                    submission,
                    classification,
                    outcome,
                )
                self._require_prior_state(activation, transition)
                return transition, self._reference(entry, "transition", activation)
            return None

    read_accumulator_transition = read_transition

    def record_boundary_evidence(
        self, evidence: MainLedgerBoundaryViolationEvidence
    ) -> ArtifactRef:
        with _LOCK:
            record = self._parse_record("boundary", evidence)
            activation = self._require_activation(record.activation_digest)
            self._validate_record_artifacts(record)
            if record.controller_authority != activation.controller_authority:
                raise MainGraduationLedgerJournalError(
                    "boundary evidence controller authority differs from activation"
                )
            data = canonical_bytes(record)
            index = self._boundary_evidence_path(activation)
            if index.is_file():
                old_reference = self._read_reference(index, "boundary")
                old_data = self._read_raw(old_reference, "boundary")
                if old_data != data:
                    raise MainGraduationLedgerRecordConflictError(
                        "conflicting boundary create-once record"
                    )
                old = self._read_record(
                    "boundary", old_reference, MainLedgerBoundaryViolationEvidence
                )
                self._verify("boundary", old, activation)
                return old_reference
            self._require_fresh_mutation_allowed(activation, "boundary evidence")
            self._validate_boundary_observation(activation, record)
            self._verify("boundary", record, activation)
            reference = self._put("boundary", data)
            return self._create_once(index, reference, data, "boundary")

    record_boundary_violation_evidence = record_boundary_evidence

    def read_boundary_evidence(
        self, activation_digest: str
    ) -> tuple[MainLedgerBoundaryViolationEvidence, ArtifactRef] | None:
        with _LOCK:
            activation = self._require_activation(activation_digest)
            index = (
                self._indexes / "boundary" / (f"{activation_digest.removeprefix('sha256:')}.json")
            )
            if not index.is_file():
                return None
            reference = self._read_reference(index, "boundary")
            evidence = self._read_record("boundary", reference, MainLedgerBoundaryViolationEvidence)
            if (
                evidence.activation_digest != activation.activation_digest
                or evidence.controller_authority != activation.controller_authority
            ):
                raise MainGraduationLedgerJournalError("boundary evidence differs from activation")
            self._verify("boundary", evidence, activation)
            return evidence, reference

    def record_boundary_reset(self, reset: MainLedgerBoundaryResetTransition) -> ArtifactRef:
        with _LOCK:
            record = self._parse_record("boundary-reset", reset)
            activation = self._require_activation(record.activation_digest)
            self._validate_record_artifacts(record)
            evidence = self._require_boundary_evidence(
                activation, record.violation.violation_digest
            )
            if record.violation != evidence:
                raise MainGraduationLedgerJournalError(
                    "boundary reset evidence differs from durable evidence"
                )
            self._validate_boundary_observation(activation, evidence)
            self._require_prior_state_for_boundary(activation, record.prior_state, evidence)
            self._verify("boundary-reset", record, activation, evidence)
            data = canonical_bytes(record)
            index = self._boundary_reset_path(activation)
            if index.is_file():
                old_reference = self._read_reference(index, "boundary-reset")
                old_data = self._read_raw(old_reference, "boundary-reset")
                if old_data != data:
                    raise MainGraduationLedgerRecordConflictError(
                        "conflicting boundary reset create-once record"
                    )
                return old_reference
            reference = self._put("boundary-reset", data)
            return self._create_once(index, reference, data, "boundary-reset")

    record_boundary_reset_transition = record_boundary_reset

    def read_boundary_reset(
        self, activation_digest: str
    ) -> tuple[MainLedgerBoundaryResetTransition, ArtifactRef] | None:
        with _LOCK:
            activation = self._require_activation(activation_digest)
            index = (
                self._indexes
                / "boundary-reset"
                / (f"{activation_digest.removeprefix('sha256:')}.json")
            )
            if not index.is_file():
                return None
            reference = self._read_reference(index, "boundary-reset")
            reset = self._read_record(
                "boundary-reset", reference, MainLedgerBoundaryResetTransition
            )
            evidence = self._require_boundary_evidence(activation, reset.violation.violation_digest)
            if reset.violation != evidence:
                raise MainGraduationLedgerJournalError(
                    "boundary reset evidence differs from durable evidence"
                )
            self._validate_boundary_observation(activation, evidence)
            self._require_prior_state_for_boundary(activation, reset.prior_state, evidence)
            self._verify("boundary-reset", reset, activation, evidence)
            return reset, reference

    def record_package(self, package: MainLedgerEvidencePackage) -> ArtifactRef:
        with _LOCK:
            record = self._parse_record("package", package)
            self._validate_record_artifacts(record)
            activation = self._require_activation(record.activation.activation_digest)
            data = canonical_bytes(record)
            index = self._package_path(activation)
            if index.is_file():
                old_reference = self._read_reference(index, "package")
                old_data = self._read_raw(old_reference, "package")
                if old_data != data:
                    raise MainGraduationLedgerRecordConflictError(
                        "conflicting package create-once record"
                    )
                old = self._read_record("package", old_reference, MainLedgerEvidencePackage)
                self._verify_package_closure(old, activation)
                self._verify("package", old)
                return old_reference
            self._require_package_write_allowed(activation)
            self._verify_package_closure(record, activation)
            self._verify("package", record)
            reference = self._put("package", data)
            return self._create_once(index, reference, data, "package")

    record_evidence_package = record_package

    def read_package(
        self, activation_or_package_digest: str
    ) -> tuple[MainLedgerEvidencePackage, ArtifactRef] | None:
        with _LOCK:
            _check_digest(activation_or_package_digest)
            self._require_verifier()
            index = (
                self._indexes
                / "package"
                / f"{activation_or_package_digest.removeprefix('sha256:')}.json"
            )
            if not index.is_file():
                directory = self._indexes / "package"
                if not directory.is_dir():
                    return None
                matches = []
                for candidate in sorted(directory.glob("*.json")):
                    if not _is_digest_stem(candidate.stem):
                        raise MainGraduationLedgerJournalError(
                            "package index identity is malformed"
                        )
                    reference = self._read_reference(candidate, "package")
                    package = self._read_record("package", reference, MainLedgerEvidencePackage)
                    if package.package_digest == activation_or_package_digest:
                        activation = self._require_activation(package.activation.activation_digest)
                        self._verify_package_closure(package, activation)
                        self._verify("package", package)
                        matches.append((package, reference))
                return matches[0] if len(matches) == 1 else None
            reference = self._read_reference(index, "package")
            package = self._read_record("package", reference, MainLedgerEvidencePackage)
            if package.activation.activation_digest != activation_or_package_digest:
                raise MainGraduationLedgerJournalError(
                    "package index identity differs from package activation"
                )
            activation = self._require_activation(package.activation.activation_digest)
            self._verify_package_closure(package, activation)
            self._verify("package", package)
            return package, reference

    read_evidence_package = read_package

    def list_sequences(self) -> tuple[int, ...]:
        with _LOCK:
            activation = self._require_activation_for_read()
            entries = self._entries_for(activation)
            for entry in entries:
                self._validate_entry(activation, entry)
            return tuple(entry["scheduler_sequence"] for entry in entries)

    def replay(self, identity: str | None = None) -> Any:
        """Read-only replay convenience; all reads re-run authority checks."""
        if identity is None:
            activation = self.read_activation()
            if activation is None:
                return None
            return self.read_package(activation[0].activation_digest)
        return self.read_submission(identity)

    replay_submission = read_submission

    # ---- durable entry and validation helpers ---------------------------------

    def _parse_record(self, kind: str, record: StrictModel) -> StrictModel:
        model: type[StrictModel]
        if kind == "activation":
            model = MainLedgerActivation
        elif kind == "submission":
            model = MainLedgerSubmissionEnvelope
        elif kind == "classification":
            model = MainLedgerClassificationEvidence
        elif kind == "outcome":
            model = MainLedgerTerminalOutcome
        elif kind == "transition":
            model = MainLedgerAccumulatorTransition
        elif kind == "boundary":
            model = MainLedgerBoundaryViolationEvidence
        elif kind == "boundary-reset":
            model = MainLedgerBoundaryResetTransition
        elif kind == "package":
            model = MainLedgerEvidencePackage
        else:
            raise ValueError("unknown ledger record kind")
        try:
            data = canonical_bytes(record)
            parsed = model.model_validate_json(data)
            if parsed.schema_version != 2:  # type: ignore[attr-defined]
                raise ValueError("legacy ledger schema is not accepted")
            return parsed
        except (TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise MainGraduationLedgerJournalError(f"malformed {kind} record") from exc

    def _put(self, kind: str, data: bytes) -> ArtifactRef:
        return self._store.put_bytes(
            data,
            media_type=f"{_MEDIA}.{kind}+json",
            role=_ROLES[kind],
            max_bytes=self._max,
        )

    def _create_once(
        self, index: Path, reference: ArtifactRef, data: bytes, kind: str
    ) -> ArtifactRef:
        index.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_bytes(reference)
        try:
            with index.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            _sync_directory(index.parent)
            return reference
        except FileExistsError:
            old = self._read_reference(index, kind)
            old_data = self._read_raw(old, kind)
            if old.digest != reference.digest or old_data != data:
                raise MainGraduationLedgerRecordConflictError(
                    f"conflicting {kind} create-once record"
                ) from None
            return old
        except OSError as exc:
            raise MainGraduationLedgerJournalError(
                f"{kind} record was not durably indexed"
            ) from exc

    def _new_entry(
        self, submission: MainLedgerSubmissionEnvelope, reference: ArtifactRef
    ) -> dict[str, Any]:
        return {
            "schema_version": _SEQUENCE_SCHEMA,
            "activation_digest": submission.activation_digest,
            "scheduler_sequence": submission.scheduler_sequence,
            "operation_id": submission.operation_id,
            "source_identity": submission.source_identity,
            "submission_identity": submission.submission_identity,
            "submission": reference.model_dump(mode="json"),
        }

    def _commit_entry(
        self,
        activation_digest: str,
        sequence: int,
        entry: dict[str, Any],
    ) -> None:
        if entry.get("schema_version") != _SEQUENCE_SCHEMA:
            raise MainGraduationLedgerJournalError("sequence index schema is unsupported")
        data = canonical_bytes(entry)
        path = self._sequence_path(activation_digest, sequence)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid4()}.partial")
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                # A hard-link install is an atomic create-once commit. It
                # cannot overwrite a submission committed by another runner.
                os.link(temporary, path)
            except FileExistsError:
                existing = self._read_sequence_file(path, activation_digest, sequence)
                if canonical_bytes(existing) != data:
                    raise MainGraduationLedgerRecordConflictError(
                        "conflicting committed sequence entry"
                    ) from None
            finally:
                temporary.unlink(missing_ok=True)
            _sync_directory(path.parent)
        except MainGraduationLedgerRecordConflictError:
            raise
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            raise MainGraduationLedgerJournalError("sequence commit was not durable") from exc

    def _all_entries(self, activation_digest: str) -> list[dict[str, Any]]:
        directory = self._sequences / activation_digest.removeprefix("sha256:")
        if not directory.is_dir():
            return []
        entries: list[dict[str, Any]] = []
        for path in sorted(
            directory.glob("*.json"), key=lambda item: int(item.stem) if item.stem.isdigit() else -1
        ):
            if not path.stem.isdigit() or str(int(path.stem)) != path.stem:
                raise MainGraduationLedgerJournalError("sequence index identity is malformed")
            sequence = int(path.stem)
            entry = self._read_sequence_file(path, activation_digest, sequence)
            entries.append(entry)
        if [int(item["scheduler_sequence"]) for item in entries] != sorted(
            item["scheduler_sequence"] for item in entries
        ):
            raise MainGraduationLedgerJournalError("sequence index ordering is malformed")
        return entries

    def _entries_for(self, activation: MainLedgerActivation) -> list[dict[str, Any]]:
        """Scan committed history and reject duplicate physical content."""
        entries = self._all_entries(activation.activation_digest)
        seen: dict[str, int] = {}
        for entry in entries:
            submission = self._read_entry_submission(entry, activation)
            previous = seen.get(submission.submission_digest)
            if previous is not None and previous != submission.scheduler_sequence:
                raise MainGraduationLedgerRecordConflictError(
                    "duplicate physical submission content"
                )
            seen[submission.submission_digest] = submission.scheduler_sequence
        return entries

    def _sequence_entry(self, activation_digest: str, sequence: int) -> dict[str, Any] | None:
        path = self._sequence_path(activation_digest, sequence)
        if not path.is_file():
            return None
        return self._read_sequence_file(path, activation_digest, sequence)

    def _read_sequence_file(
        self, path: Path, activation_digest: str, sequence: int
    ) -> dict[str, Any]:
        try:
            if path.stat().st_size > _MAX_INDEX_BYTES:
                raise ValueError("sequence index is too large")
            raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_pairs)
            if canonical_bytes(raw) != path.read_bytes():
                raise ValueError("sequence index is not canonical JSON")
            if not isinstance(raw, dict) or set(raw) != {
                "schema_version",
                "activation_digest",
                "scheduler_sequence",
                "operation_id",
                "source_identity",
                "submission_identity",
                "submission",
            }:
                raise ValueError("sequence index shape is invalid")
            if (
                raw["schema_version"] != _SEQUENCE_SCHEMA
                or raw["activation_digest"] != activation_digest
                or raw["scheduler_sequence"] != sequence
            ):
                raise ValueError("sequence index binding is invalid")
            return cast(dict[str, Any], raw)
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise MainGraduationLedgerJournalError("malformed sequence index") from exc

    def _sequence_path(self, activation_digest: str, sequence: int) -> Path:
        return self._sequences / activation_digest.removeprefix("sha256:") / f"{sequence}.json"

    def _stage_path(self, activation: MainLedgerActivation, sequence: int, kind: str) -> Path:
        if kind not in {"classification", "outcome", "transition"}:
            raise ValueError("invalid ledger stage kind")
        return (
            self._stages
            / activation.activation_digest.removeprefix("sha256:")
            / str(sequence)
            / f"{kind}.json"
        )

    def _stage_exists(self, activation: MainLedgerActivation, sequence: int, kind: str) -> bool:
        return self._stage_path(activation, sequence, kind).is_file()

    def _stage_reference(
        self, activation: MainLedgerActivation, sequence: int, kind: str
    ) -> ArtifactRef:
        path = self._stage_path(activation, sequence, kind)
        if not path.is_file():
            raise MainGraduationLedgerJournalError(f"{kind} is not durably recorded")
        return self._read_reference(path, kind)

    def _create_stage_once(
        self,
        activation: MainLedgerActivation,
        sequence: int,
        kind: str,
        reference: ArtifactRef,
        data: bytes,
    ) -> ArtifactRef:
        return self._create_once(
            self._stage_path(activation, sequence, kind), reference, data, kind
        )

    def _max_committed_sequence(self, activation: MainLedgerActivation) -> int:
        entries = self._entries_for(activation)
        if not entries:
            return activation.scheduler_sequence_watermark
        expected = activation.scheduler_sequence_watermark + 1
        for entry in entries:
            if entry["scheduler_sequence"] != expected:
                raise MainGraduationLedgerJournalError("committed scheduler sequence has a gap")
            expected += 1
        return expected - 1

    def _current_accumulator_state(self, activation: MainLedgerActivation) -> Any:
        """Reconstruct the authoritative state from the durable CAS chain."""
        state = main_ledger_genesis_state(
            activation.activation_digest, activation.scheduler_sequence_watermark
        )
        for entry in self._entries_for(activation):
            sequence = entry["scheduler_sequence"]
            self._validate_entry(activation, entry)
            submission = self._read_entry_submission(entry, activation)
            if not self._stage_exists(activation, sequence, "classification"):
                break
            classification = self._read_entry_ref(
                entry,
                "classification",
                MainLedgerClassificationEvidence,
                activation,
                submission,
            )
            outcome = None
            if classification.classification == "eligible":
                if not self._stage_exists(activation, sequence, "outcome"):
                    break
                outcome = self._require_outcome(entry, activation, submission, classification)
            if not self._stage_exists(activation, sequence, "transition"):
                break
            transition = self._read_entry_ref(
                entry,
                "transition",
                MainLedgerAccumulatorTransition,
                activation,
                submission,
                classification,
                outcome,
            )
            if transition.prior_state != state:
                raise MainGraduationLedgerJournalError(
                    "durable accumulator predecessor differs from chain"
                )
            state = transition.resulting_state
        return state

    def _require_fresh_mutation_allowed(
        self, activation: MainLedgerActivation, kind: str
    ) -> None:
        """Reject new writes after any durable terminal fence."""
        if self._current_accumulator_state(activation).threshold_complete:
            raise MainGraduationLedgerJournalError(
                f"{kind} cannot be written after threshold completion"
            )
        if self._package_path(activation).is_file():
            raise MainGraduationLedgerJournalError(
                f"{kind} cannot be written after terminal package"
            )
        if self._boundary_evidence_path(activation).is_file() or self._boundary_reset_path(
            activation
        ).is_file():
            raise MainGraduationLedgerJournalError(
                f"{kind} cannot be written after boundary fence"
            )

    def _require_package_write_allowed(self, activation: MainLedgerActivation) -> None:
        if self._boundary_evidence_path(activation).is_file() and not self._boundary_reset_path(
            activation
        ).is_file():
            raise MainGraduationLedgerJournalError(
                "package cannot be written before boundary reset"
            )
        if not (
            self._current_accumulator_state(activation).threshold_complete
            or self._boundary_reset_path(activation).is_file()
        ):
            raise MainGraduationLedgerJournalError(
                "package cannot be written before terminal state"
            )

    def _read_entry_submission(
        self, entry: dict[str, Any], activation: MainLedgerActivation
    ) -> MainLedgerSubmissionEnvelope:
        submission = self._read_entry_ref(
            entry, "submission", MainLedgerSubmissionEnvelope, activation
        )
        if (
            submission.activation_digest != activation.activation_digest
            or submission.repository_digest != activation.repository_digest
            or submission.target_ref != activation.target_ref
            or submission.scheduler_sequence <= activation.scheduler_sequence_watermark
            or submission.activation_digest != entry["activation_digest"]
            or submission.scheduler_sequence != entry["scheduler_sequence"]
            or submission.operation_id != entry["operation_id"]
            or submission.source_identity != entry["source_identity"]
            or submission.submission_identity != entry["submission_identity"]
        ):
            raise MainGraduationLedgerJournalError("sequence index does not bind submission")
        return submission

    def _validate_entry(self, activation: MainLedgerActivation, entry: dict[str, Any]) -> None:
        submission = self._read_entry_submission(entry, activation)
        classification: MainLedgerClassificationEvidence | None = None
        outcome: MainLedgerTerminalOutcome | None = None
        if self._stage_exists(activation, submission.scheduler_sequence, "classification"):
            classification = self._read_entry_ref(
                entry,
                "classification",
                MainLedgerClassificationEvidence,
                activation,
                submission,
            )
        if self._stage_exists(activation, submission.scheduler_sequence, "outcome"):
            if classification is None:
                raise MainGraduationLedgerJournalError("sequence outcome has no classification")
            outcome = self._read_entry_ref(
                entry,
                "outcome",
                MainLedgerTerminalOutcome,
                activation,
                submission,
                classification,
            )
        if self._stage_exists(activation, submission.scheduler_sequence, "transition"):
            if classification is None:
                raise MainGraduationLedgerJournalError("sequence transition has no classification")
            if classification.classification == "eligible" and outcome is None:
                raise MainGraduationLedgerJournalError(
                    "eligible sequence transition has no terminal outcome"
                )
            transition = self._read_entry_ref(
                entry,
                "transition",
                MainLedgerAccumulatorTransition,
                activation,
                submission,
                classification,
                outcome,
            )
            self._require_prior_state(activation, transition)

    def _read_entry_ref(
        self,
        entry: dict[str, Any],
        kind: str,
        model: type[Any],
        activation: MainLedgerActivation,
        submission: MainLedgerSubmissionEnvelope | None = None,
        classification: MainLedgerClassificationEvidence | None = None,
        outcome: MainLedgerTerminalOutcome | None = None,
    ) -> Any:
        reference = self._reference(entry, kind, activation)
        record = self._read_record(kind, reference, model)
        if kind == "classification":
            if submission is None:
                raise MainGraduationLedgerJournalError(
                    "classification submission dependency is missing"
                )
            self._require_exact_classification_binding(record, activation, submission)
            self._verify("classification", record, activation, submission)
        elif kind == "outcome":
            if classification is None or submission is None:
                raise MainGraduationLedgerJournalError(
                    "outcome classification dependency is missing"
                )
            self._require_exact_outcome_binding(record, activation, submission, classification)
            self._verify("outcome", record, activation, submission, classification)
        elif kind == "transition":
            if classification is None or submission is None:
                raise MainGraduationLedgerJournalError(
                    "transition classification dependency is missing"
                )
            self._require_exact_transition_binding(record, activation, classification, outcome)
            self._verify("transition", record, activation, classification, outcome)
        elif kind == "submission":
            self._verify("submission", record, activation)
        return record

    def _read_record(self, kind: str, reference: ArtifactRef, model: type[Any]) -> Any:
        data = self._read_raw(reference, kind)
        try:
            raw = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs)
            if canonical_bytes(raw) != data:
                raise ValueError("record is not canonical JSON")
            record = model.model_validate(raw)
            if record.schema_version != 2:
                raise ValueError("legacy ledger schema is not accepted")
            self._validate_record_artifacts(record)
            if canonical_digest(raw) != reference.digest:
                raise ValueError("record digest differs from CAS reference")
            return record
        except (
            OSError,
            RuntimeError,
            ValueError,
            TypeError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise MainGraduationLedgerJournalError(
                f"malformed or unverifiable ledger {kind}"
            ) from exc

    def _read_raw(self, reference: ArtifactRef, kind: str) -> bytes:
        if (
            reference.role != _ROLES[kind]
            or reference.media_type != f"{_MEDIA}.{kind}+json"
            or reference.size_bytes > self._max
        ):
            raise MainGraduationLedgerJournalError(f"{kind} artifact metadata mismatch")
        try:
            return self._store.read_bytes(reference)
        except (OSError, RuntimeError, ValueError) as exc:
            raise MainGraduationLedgerJournalError(
                f"{kind} artifact is missing or tampered"
            ) from exc

    def _validate_record_artifacts(self, record: Any) -> None:
        """Re-read every externally referenced CAS child of a ledger record."""
        if isinstance(record, MainLedgerSubmissionEnvelope):
            self._read_external(
                record.content_artifact, CONTENT_ARTIFACT_ROLE, CONTENT_ARTIFACT_MEDIA_TYPE
            )
        elif isinstance(record, MainLedgerClassificationEvidence):
            if record.independent_exclusion_evidence is not None:
                self._read_external(
                    record.independent_exclusion_evidence,
                    EXCLUSION_ARTIFACT_ROLE,
                    EXCLUSION_ARTIFACT_MEDIA_TYPE,
                )
        elif isinstance(record, MainLedgerTerminalOutcome):
            self._read_external(
                record.terminal_evidence,
                TERMINAL_ARTIFACT_ROLE,
                TERMINAL_ARTIFACT_MEDIA_TYPE,
            )
            if record.package_artifact is not None:
                self._read_external(
                    record.package_artifact, PACKAGE_ARTIFACT_ROLE, PACKAGE_ARTIFACT_MEDIA_TYPE
                )
        elif isinstance(record, MainLedgerBoundaryViolationEvidence):
            self._read_external(
                record.evidence_artifact, BOUNDARY_ARTIFACT_ROLE, BOUNDARY_ARTIFACT_MEDIA_TYPE
            )
        elif isinstance(record, MainLedgerBoundaryResetTransition):
            self._read_external(
                record.violation.evidence_artifact,
                BOUNDARY_ARTIFACT_ROLE,
                BOUNDARY_ARTIFACT_MEDIA_TYPE,
            )

    def _read_external(self, reference: ArtifactRef, role: str, media_type: str) -> bytes:
        if (
            reference.role != role
            or reference.media_type != media_type
            or reference.size_bytes <= 0
            or reference.size_bytes > self._max
        ):
            raise MainGraduationLedgerJournalError("external ledger artifact metadata mismatch")
        try:
            data = self._store.read_bytes(reference)
            raw = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs)
            if canonical_bytes(raw) != data:
                raise ValueError("external ledger artifact is not canonical JSON")
            return data
        except (
            OSError,
            RuntimeError,
            ValueError,
            TypeError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise MainGraduationLedgerJournalError(
                "external ledger artifact is missing or tampered"
            ) from exc

    def _read_reference(self, path: Path, kind: str) -> ArtifactRef:
        try:
            if path.stat().st_size > _MAX_INDEX_BYTES:
                raise ValueError("index is too large")
            data = path.read_bytes()
            raw = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs)
            if canonical_bytes(raw) != data:
                raise ValueError("index is not canonical JSON")
            return ArtifactRef.model_validate(raw)
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise MainGraduationLedgerJournalError(f"malformed {kind} index") from exc

    def _reference(
        self,
        entry: dict[str, Any],
        kind: str,
        activation: MainLedgerActivation | None = None,
    ) -> ArtifactRef:
        if kind != "submission":
            if activation is None:
                raise MainGraduationLedgerJournalError(
                    f"{kind} stage activation dependency is missing"
                )
            return self._stage_reference(activation, entry["scheduler_sequence"], kind)
        value = entry.get(kind)
        if value is None:
            raise MainGraduationLedgerJournalError(f"{kind} is not durably committed")
        try:
            return ArtifactRef.model_validate(value)
        except (TypeError, ValueError) as exc:
            raise MainGraduationLedgerJournalError(f"malformed {kind} reference") from exc

    def _require_activation(self, digest: str) -> MainLedgerActivation:
        loaded = self.read_activation()
        if loaded is None or loaded[0].activation_digest != digest:
            raise MainGraduationLedgerJournalError("ledger activation is not durably recorded")
        return loaded[0]

    def _require_activation_for_read(self) -> MainLedgerActivation:
        loaded = self.read_activation()
        if loaded is None:
            raise MainGraduationLedgerJournalError("ledger activation is not durably recorded")
        return loaded[0]

    def _require_entry(self, activation_digest: str, sequence: int) -> dict[str, Any]:
        entry = self._sequence_entry(activation_digest, sequence)
        if entry is None:
            raise MainGraduationLedgerJournalError("submission is not durably recorded")
        return entry

    def _require_classification(
        self,
        entry: dict[str, Any],
        activation: MainLedgerActivation,
        submission: MainLedgerSubmissionEnvelope,
    ) -> MainLedgerClassificationEvidence:
        if not self._stage_exists(activation, submission.scheduler_sequence, "classification"):
            raise MainGraduationLedgerJournalError("classification is not durably recorded")
        return self._read_entry_ref(
            entry, "classification", MainLedgerClassificationEvidence, activation, submission
        )

    def _require_outcome(
        self,
        entry: dict[str, Any],
        activation: MainLedgerActivation,
        submission: MainLedgerSubmissionEnvelope,
        classification: MainLedgerClassificationEvidence,
    ) -> MainLedgerTerminalOutcome:
        if not self._stage_exists(activation, submission.scheduler_sequence, "outcome"):
            raise MainGraduationLedgerJournalError("terminal outcome is not durably recorded")
        return self._read_entry_ref(
            entry, "outcome", MainLedgerTerminalOutcome, activation, submission, classification
        )

    def _prior_state(self, activation: MainLedgerActivation, sequence: int) -> Any:
        if sequence == activation.scheduler_sequence_watermark + 1:
            return main_ledger_genesis_state(
                activation.activation_digest, activation.scheduler_sequence_watermark
            )
        previous = self._require_entry(activation.activation_digest, sequence - 1)
        submission = self._read_entry_submission(previous, activation)
        classification = self._require_classification(previous, activation, submission)
        transition = self._read_entry_ref(
            previous,
            "transition",
            MainLedgerAccumulatorTransition,
            activation,
            submission,
            classification,
            self._require_outcome(previous, activation, submission, classification)
            if classification.classification == "eligible"
            else None,
        )
        return transition.resulting_state

    def _require_prior_state(
        self, activation: MainLedgerActivation, transition: MainLedgerAccumulatorTransition
    ) -> None:
        if transition.prior_state != self._prior_state(
            activation, transition.classification.scheduler_sequence
        ):
            raise MainGraduationLedgerJournalError(
                "transition predecessor differs from durable chain"
            )

    def _require_prior_state_for_boundary(
        self,
        activation: MainLedgerActivation,
        prior_state: Any,
        evidence: MainLedgerBoundaryViolationEvidence | None = None,
    ) -> None:
        if evidence is not None and prior_state.last_scheduler_sequence != (
            evidence.expected_scheduler_sequence - 1
        ):
            raise MainGraduationLedgerJournalError(
                "boundary reset predecessor does not end at expected sequence"
            )
        if prior_state.last_scheduler_sequence == activation.scheduler_sequence_watermark:
            expected = main_ledger_genesis_state(
                activation.activation_digest, activation.scheduler_sequence_watermark
            )
        else:
            expected = self._prior_state(activation, prior_state.last_scheduler_sequence + 1)
        if prior_state != expected:
            raise MainGraduationLedgerJournalError(
                "boundary reset predecessor differs from durable chain"
            )

    def _validate_boundary_observation(
        self,
        activation: MainLedgerActivation,
        evidence: MainLedgerBoundaryViolationEvidence,
    ) -> None:
        """Bind boundary evidence to the current committed prefix and tail.

        A boundary is an observation of the sequence index, rather than a
        caller-supplied claim about it.  Re-reading every prefix stage here
        also makes an evidence-before-reset crash recoverable without allowing
        a later stage to mutate the chain behind the evidence.
        """
        entries = self._entries_for(activation)
        watermark = activation.scheduler_sequence_watermark
        first = watermark + 1
        sequences = [entry["scheduler_sequence"] for entry in entries]
        if sequences != list(range(first, first + len(entries))):
            raise MainGraduationLedgerJournalError(
                "committed scheduler sequence has a gap or reordering"
            )
        expected = evidence.expected_scheduler_sequence
        if expected <= watermark or expected > (sequences[-1] + 1 if sequences else first):
            raise MainGraduationLedgerJournalError(
                "boundary expected sequence is not the next unresolved sequence"
            )
        by_sequence = {entry["scheduler_sequence"]: entry for entry in entries}
        prefix = [entry for entry in entries if entry["scheduler_sequence"] < expected]
        if [entry["scheduler_sequence"] for entry in prefix] != list(range(first, expected)):
            raise MainGraduationLedgerJournalError(
                "boundary processed prefix is not contiguous"
            )

        state = main_ledger_genesis_state(
            activation.activation_digest, activation.scheduler_sequence_watermark
        )
        for entry in prefix:
            submission = self._read_entry_submission(entry, activation)
            classification = self._require_classification(entry, activation, submission)
            outcome = (
                self._require_outcome(entry, activation, submission, classification)
                if classification.classification == "eligible"
                else None
            )
            transition = self._read_entry_ref(
                entry,
                "transition",
                MainLedgerAccumulatorTransition,
                activation,
                submission,
                classification,
                outcome,
            )
            if transition.prior_state != state:
                raise MainGraduationLedgerJournalError(
                    "boundary processed prefix predecessor differs from durable chain"
                )
            state = transition.resulting_state
        if evidence.current_state_digest != state.state_digest:
            raise MainGraduationLedgerJournalError(
                "boundary evidence state differs from durable processed prefix"
            )

        durable = by_sequence.get(expected)
        identities = (
            evidence.submission_digest,
            evidence.operation_id,
            evidence.envelope_digest,
            evidence.content_artifact,
        )
        if durable is None:
            # This is the only valid missing-envelope/starvation shape: the
            # boundary is exactly the next sequence and there is no later
            # durable sequence (the contiguous index check proves that).
            if any(item is not None for item in identities):
                raise MainGraduationLedgerJournalError(
                    "missing-envelope boundary cannot carry submission identity"
                )
            return
        submission = self._read_entry_submission(durable, activation)
        expected_identities = (
            submission.submission_digest,
            submission.operation_id,
            submission.envelope_digest,
            submission.content_artifact,
        )
        if identities != expected_identities:
            raise MainGraduationLedgerJournalError(
                "boundary evidence does not exactly bind first unresolved envelope"
            )
        # Once the unresolved sequence is observed, no later stage may be
        # considered part of the boundary package.  Durable envelopes may be
        # present in the tail, but they must remain wholly unresolved.
        for entry in entries:
            if entry["scheduler_sequence"] < expected:
                continue
            sequence = entry["scheduler_sequence"]
            if any(self._stage_exists(activation, sequence, kind) for kind in (
                "classification",
                "outcome",
                "transition",
            )):
                raise MainGraduationLedgerJournalError(
                    "boundary has a classified or transitioned unresolved sequence"
                )

    def _require_boundary_evidence(
        self, activation: MainLedgerActivation, violation_digest: str
    ) -> MainLedgerBoundaryViolationEvidence:
        loaded = self.read_boundary_evidence(activation.activation_digest)
        if loaded is None or loaded[0].violation_digest != violation_digest:
            raise MainGraduationLedgerJournalError("boundary evidence is not durably recorded")
        return loaded[0]

    def _boundary_evidence_path(self, activation: MainLedgerActivation) -> Path:
        return self._indexes / "boundary" / (
            f"{activation.activation_digest.removeprefix('sha256:')}.json"
        )

    def _boundary_reset_path(self, activation: MainLedgerActivation) -> Path:
        return self._indexes / "boundary-reset" / (
            f"{activation.activation_digest.removeprefix('sha256:')}.json"
        )

    def _package_path(self, activation: MainLedgerActivation) -> Path:
        return self._indexes / "package" / (
            f"{activation.activation_digest.removeprefix('sha256:')}.json"
        )

    @staticmethod
    def _require_exact_classification_binding(
        classification: MainLedgerClassificationEvidence,
        activation: MainLedgerActivation,
        submission: MainLedgerSubmissionEnvelope,
    ) -> None:
        if (
            classification.activation_digest != activation.activation_digest
            or classification.submission_digest != submission.submission_digest
            or classification.operation_id != submission.operation_id
            or classification.scheduler_sequence != submission.scheduler_sequence
            or classification.policy_digest != activation.policy_digest
            or classification.policy_epoch != activation.policy_epoch
            or classification.controller_authority != activation.controller_authority
        ):
            raise MainGraduationLedgerJournalError(
                "classification is not exactly bound to activation and submission"
            )

    @staticmethod
    def _require_exact_outcome_binding(
        outcome: MainLedgerTerminalOutcome,
        activation: MainLedgerActivation,
        submission: MainLedgerSubmissionEnvelope,
        classification: MainLedgerClassificationEvidence,
    ) -> None:
        if (
            outcome.activation_digest != activation.activation_digest
            or outcome.submission_digest != submission.submission_digest
            or outcome.scheduler_sequence != submission.scheduler_sequence
            or outcome.operation_id != submission.operation_id
            or outcome.classification_digest != classification.classification_digest
            or outcome.classification != classification
            or classification.classification != "eligible"
        ):
            raise MainGraduationLedgerJournalError(
                "terminal outcome is not exactly bound to eligible classification"
            )

    @staticmethod
    def _require_exact_transition_binding(
        transition: MainLedgerAccumulatorTransition,
        activation: MainLedgerActivation,
        classification: MainLedgerClassificationEvidence,
        outcome: MainLedgerTerminalOutcome | None,
    ) -> None:
        if (
            transition.activation_digest != activation.activation_digest
            or transition.classification != classification
            or transition.outcome != outcome
        ):
            raise MainGraduationLedgerJournalError(
                "transition is not exactly bound to durable classification and outcome"
            )

    def _verify_package_closure(
        self, package: MainLedgerEvidencePackage, activation: MainLedgerActivation
    ) -> None:
        if package.activation != activation:
            raise MainGraduationLedgerJournalError(
                "package activation differs from durable activation"
            )
        entries = self._entries_for(activation)
        watermark = activation.scheduler_sequence_watermark
        first = watermark + 1
        durable_sequences = [entry["scheduler_sequence"] for entry in entries]
        if durable_sequences != list(range(first, first + len(entries))):
            raise MainGraduationLedgerJournalError(
                "package sequence index has a gap, overlap, or reordering"
            )
        by_sequence = {entry["scheduler_sequence"]: entry for entry in entries}
        package_submissions = {
            item.scheduler_sequence: item for item in package.submissions
        }
        if len(package_submissions) != len(package.submissions):
            raise MainGraduationLedgerJournalError("package contains duplicate submissions")
        for sequence, submission in package_submissions.items():
            entry = by_sequence.get(sequence)
            if entry is None:
                raise MainGraduationLedgerJournalError(
                    "package references a missing durable submission"
                )
            durable_submission = self._read_entry_submission(entry, activation)
            self._validate_record_artifacts(submission)
            if durable_submission != submission:
                raise MainGraduationLedgerJournalError(
                    "package submission differs from durable record"
                )

        outcomes = {item.scheduler_sequence: item for item in package.outcomes}
        transitions = {item.classification.scheduler_sequence: item for item in package.transitions}
        if len(outcomes) != len(package.outcomes) or len(transitions) != len(package.transitions):
            raise MainGraduationLedgerJournalError("package contains duplicate stage records")

        if package.status == "boundary_reset":
            if package.boundary_evidence is None or package.terminal_boundary_reset is None:
                raise MainGraduationLedgerJournalError(
                    "boundary-reset package is missing terminal evidence"
                )
            durable_evidence = self._require_boundary_evidence(
                activation, package.boundary_evidence.violation_digest
            )
            if durable_evidence != package.boundary_evidence:
                raise MainGraduationLedgerJournalError(
                    "package boundary evidence differs from durable record"
                )
            durable_reset = self.read_boundary_reset(activation.activation_digest)
            if durable_reset is None or durable_reset[0] != package.terminal_boundary_reset:
                raise MainGraduationLedgerJournalError(
                    "package boundary reset differs from durable record"
                )
            evidence = durable_evidence
            self._validate_boundary_observation(activation, evidence)
            expected = evidence.expected_scheduler_sequence
            prefix_sequences = list(range(first, expected))
            durable_tail = [sequence for sequence in durable_sequences if sequence >= expected]

            # ``submissions`` is the durable envelope inventory for entries
            # represented by identity-only tail records.  A tail envelope can
            # instead carry the envelope itself exactly once.
            if [sequence for sequence in package_submissions if sequence < expected] != (
                prefix_sequences
            ):
                raise MainGraduationLedgerJournalError(
                    "package processed submissions are not a contiguous prefix"
                )
            tail_by_sequence = {
                item.scheduler_sequence: item for item in package.unresolved_tail
            }
            if len(tail_by_sequence) != len(package.unresolved_tail):
                raise MainGraduationLedgerJournalError("package unresolved tail overlaps")
            if durable_tail:
                if list(tail_by_sequence) != durable_tail:
                    raise MainGraduationLedgerJournalError(
                        "package unresolved tail does not represent every durable sequence"
                    )
                for sequence in durable_tail:
                    entry = by_sequence[sequence]
                    durable_submission = self._read_entry_submission(entry, activation)
                    tail_entry = tail_by_sequence[sequence]
                    if tail_entry.envelope is not None:
                        if sequence in package_submissions or tail_entry.envelope != (
                            durable_submission
                        ):
                            raise MainGraduationLedgerJournalError(
                                "unresolved tail envelope differs from durable envelope"
                            )
                        self._validate_record_artifacts(tail_entry.envelope)
                        self._verify("submission", tail_entry.envelope, activation)
                    elif tail_entry.has_envelope_identity:
                        if sequence not in package_submissions:
                            raise MainGraduationLedgerJournalError(
                                "unresolved tail identity has no package envelope"
                            )
                        identity = (
                            durable_submission.submission_digest,
                            durable_submission.operation_id,
                            durable_submission.envelope_digest,
                            durable_submission.content_artifact,
                        )
                        supplied = (
                            tail_entry.submission_digest,
                            tail_entry.operation_id,
                            tail_entry.envelope_digest,
                            tail_entry.content_artifact,
                        )
                        if supplied != identity:
                            raise MainGraduationLedgerJournalError(
                                "unresolved tail identity differs from durable envelope"
                            )
                    else:
                        raise MainGraduationLedgerJournalError(
                            "durable unresolved sequence has no envelope binding"
                        )
                    if any(
                        self._stage_exists(activation, sequence, kind)
                        for kind in ("classification", "outcome", "transition")
                    ):
                        raise MainGraduationLedgerJournalError(
                            "package contains a stage after the first unresolved sequence"
                        )
            else:
                # Missing-envelope starvation is valid only at exactly the
                # next sequence after the durable prefix, with no later index.
                if expected != first + len(entries):
                    raise MainGraduationLedgerJournalError(
                        "missing-envelope boundary is not at the next sequence"
                    )
                if package.unresolved_tail:
                    if len(package.unresolved_tail) != 1 or (
                        package.unresolved_tail[0].scheduler_sequence != expected
                    ):
                        raise MainGraduationLedgerJournalError(
                            "missing-envelope tail is not the exact next sequence"
                        )
                    if package.unresolved_tail[0].has_envelope_identity or (
                        package.unresolved_tail[0].envelope is not None
                    ):
                        raise MainGraduationLedgerJournalError(
                            "missing-envelope starvation carries an envelope identity"
                        )
            prefix_submissions = [package_submissions[sequence] for sequence in prefix_sequences]
            normal_final_state = (
                package.transitions[-1].resulting_state
                if package.transitions
                else main_ledger_genesis_state(
                    activation.activation_digest, activation.scheduler_sequence_watermark
                )
            )
            if package.terminal_boundary_reset.prior_state != normal_final_state:
                raise MainGraduationLedgerJournalError(
                    "boundary reset predecessor differs from processed prefix"
                )
            if package.final_state != package.terminal_boundary_reset.resulting_state:
                raise MainGraduationLedgerJournalError(
                    "boundary package final state differs from durable reset"
                )
            if package.final_state.threshold_complete:
                raise MainGraduationLedgerJournalError(
                    "boundary-reset package cannot complete threshold"
                )
        else:
            if package.unresolved_tail:
                raise MainGraduationLedgerJournalError(
                    "threshold-complete package contains unresolved tail"
                )
            if list(package_submissions) != durable_sequences:
                raise MainGraduationLedgerJournalError(
                    "threshold package does not represent every durable submission"
                )
            prefix_submissions = [package_submissions[sequence] for sequence in durable_sequences]

        if len(package.classifications) != len(prefix_submissions) or len(
            package.transitions
        ) != len(prefix_submissions):
            raise MainGraduationLedgerJournalError(
                "package does not close every processed durable sequence"
            )
        for submission, classification in zip(
            prefix_submissions, package.classifications, strict=True
        ):
            entry = by_sequence[submission.scheduler_sequence]
            durable_classification = self._require_classification(
                entry, activation, submission
            )
            if durable_classification != classification:
                raise MainGraduationLedgerJournalError(
                    "package classification differs from durable record"
                )
            if classification.scheduler_sequence in outcomes:
                if classification.classification != "eligible":
                    raise MainGraduationLedgerJournalError(
                        "excluded package submission has an outcome"
                    )
                durable_outcome = self._require_outcome(
                    entry, activation, submission, classification
                )
                if outcomes[classification.scheduler_sequence] != durable_outcome:
                    raise MainGraduationLedgerJournalError(
                        "package outcome differs from durable record"
                    )
            elif classification.classification == "eligible":
                raise MainGraduationLedgerJournalError(
                    "eligible package submission has no outcome"
                )
            durable_transition = self._read_entry_ref(
                entry,
                "transition",
                MainLedgerAccumulatorTransition,
                activation,
                submission,
                classification,
                outcomes.get(classification.scheduler_sequence),
            )
            if transitions.get(classification.scheduler_sequence) != durable_transition:
                raise MainGraduationLedgerJournalError(
                    "package transition differs from durable record"
                )
        if set(outcomes) != {
            item.scheduler_sequence
            for item in package.classifications
            if item.classification == "eligible"
        }:
            raise MainGraduationLedgerJournalError("package outcome coverage differs")
        if package.status == "threshold_complete":
            normal_final_state = (
                package.transitions[-1].resulting_state
                if package.transitions
                else main_ledger_genesis_state(
                    activation.activation_digest, activation.scheduler_sequence_watermark
                )
            )
            if package.final_state != normal_final_state or not (
                package.final_state.threshold_complete
            ):
                raise MainGraduationLedgerJournalError(
                    "threshold package final state does not close the transition chain"
                )

    def _verify(self, kind: str, record: Any, *dependencies: Any) -> None:
        verifier = self._require_verifier()
        try:
            if kind == "activation":
                result = verifier.verify_activation(record)
            elif kind == "submission":
                result = verifier.verify_submission(record, dependencies[0])
            elif kind == "classification":
                result = verifier.verify_classification(record, dependencies[0], dependencies[1])
            elif kind == "outcome":
                result = verifier.verify_outcome(
                    record, dependencies[0], dependencies[1], dependencies[2]
                )
            elif kind == "transition":
                result = verifier.verify_transition(
                    record, dependencies[0], dependencies[1], dependencies[2]
                )
            elif kind == "boundary":
                result = verifier.verify_boundary_evidence(record, dependencies[0])
            elif kind == "boundary-reset":
                result = verifier.verify_boundary_reset(record, dependencies[0], dependencies[1])
            elif kind == "package":
                result = verifier.verify_package(record)
            else:
                raise ValueError(f"unknown verification kind: {kind}")
            if result is not True:
                raise ValueError("authority verifier did not return True")
        except Exception as exc:
            if isinstance(exc, MainGraduationLedgerJournalError):
                raise
            raise MainGraduationLedgerJournalError(f"authority verifier rejected {kind}") from exc

    def _require_verifier(self) -> MainLedgerAuthorityVerifier:
        if self._verifier is None:
            raise MainGraduationLedgerJournalError(
                "injected main ledger authority verifier is required"
            )
        return self._verifier


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _is_digest_stem(value: str) -> bool:
    return (
        len(value) == 64
        and value == value.lower()
        and all(char in "0123456789abcdef" for char in value)
    )


def _check_digest(value: str) -> None:
    if (
        len(value) != 71
        or not value.startswith("sha256:")
        or not _is_digest_stem(value.removeprefix("sha256:"))
    ):
        raise ValueError("digest must be a SHA-256 digest")


def _sync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        if os.name == "nt" and exc.errno in {errno.EINVAL, errno.EACCES, errno.ENOTSUP, 22, 13, 95}:
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


# Compatibility aliases keep the namespace discoverable for callers that use
# the shorter contract terminology.
MainLedgerJournal = MainGraduationLedgerJournal
MainLedgerJournalError = MainGraduationLedgerJournalError
MainLedgerRecordConflictError = MainGraduationLedgerRecordConflictError

__all__ = [
    "MainGraduationLedgerJournal",
    "MainGraduationLedgerJournalError",
    "MainGraduationLedgerRecordConflictError",
    "MainLedgerAuthorityVerifier",
    "MainLedgerJournal",
    "MainLedgerJournalError",
    "MainLedgerRecordConflictError",
]
