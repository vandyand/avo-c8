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
import inspect
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

    Implementations may accept just the record, or the record followed by the
    exact durable dependencies supplied by the journal.  Returning ``False``
    is rejection; raising is also rejection.  A parsed DTO and its digest are
    never treated as principal authentication.
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

    def verify_boundary_evidence(self, evidence: MainLedgerBoundaryViolationEvidence) -> object: ...

    def verify_boundary_reset(self, reset: MainLedgerBoundaryResetTransition) -> object: ...


_LOCK = RLock()
_SEQUENCE_SCHEMA = 1
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
            activation = self._require_activation(submission.activation_digest)
            record = self._parse_record("submission", submission)
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
            data = canonical_bytes(record)
            reference = self._put("submission", data)
            existing = self._sequence_entry(record.activation_digest, record.scheduler_sequence)
            if existing is not None:
                old = self._read_entry_submission(existing, activation)
                if canonical_bytes(old) != data or old.operation_id != record.operation_id:
                    raise MainGraduationLedgerRecordConflictError(
                        "conflicting submission for scheduler sequence"
                    )
                return self._reference(existing, "submission")
            max_sequence = self._max_committed_sequence(
                activation.activation_digest, activation.scheduler_sequence_watermark
            )
            if record.scheduler_sequence != max_sequence + 1:
                raise MainGraduationLedgerJournalError("scheduler sequence has a gap")
            for entry in self._all_entries(activation.activation_digest):
                old = self._read_entry_submission(entry, activation)
                if (
                    old.source_identity == record.source_identity
                    and old.submission_identity == record.submission_identity
                ):
                    raise MainGraduationLedgerRecordConflictError("duplicate submission identity")
            entry = self._new_entry(record, reference)
            self._commit_entry(record.activation_digest, record.scheduler_sequence, entry)
            return reference

    record_scheduler_submission = record_submission

    def read_submission(
        self, operation_id: str
    ) -> tuple[MainLedgerSubmissionEnvelope, ArtifactRef] | None:
        with _LOCK:
            activation = self._require_activation_for_read()
            for entry in self._all_entries(activation.activation_digest):
                submission = self._read_entry_submission(entry, activation)
                if submission.operation_id == operation_id:
                    return submission, self._reference(entry, "submission")
            return None

    def read_submission_by_sequence(
        self, scheduler_sequence: int
    ) -> tuple[MainLedgerSubmissionEnvelope, ArtifactRef] | None:
        with _LOCK:
            activation = self._require_activation_for_read()
            entry = self._sequence_entry(activation.activation_digest, scheduler_sequence)
            if entry is None:
                return None
            submission = self._read_entry_submission(entry, activation)
            return submission, self._reference(entry, "submission")

    def list_submissions(self) -> tuple[MainLedgerSubmissionEnvelope, ...]:
        with _LOCK:
            activation = self._require_activation_for_read()
            return tuple(
                self._read_entry_submission(entry, activation)
                for entry in self._all_entries(activation.activation_digest)
            )

    list_scheduler_submissions = list_submissions

    def record_classification(
        self, classification: MainLedgerClassificationEvidence
    ) -> ArtifactRef:
        with _LOCK:
            activation = self._require_activation(classification.activation_digest)
            record = self._parse_record("classification", classification)
            self._validate_record_artifacts(record)
            entry = self._require_entry(record.activation_digest, record.scheduler_sequence)
            submission = self._read_entry_submission(entry, activation)
            self._require_exact_classification_binding(record, activation, submission)
            self._verify("classification", record, activation, submission)
            data = canonical_bytes(record)
            reference = self._put("classification", data)
            if entry["classification"] is not None:
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
                return self._reference(entry, "classification")
            entry["classification"] = reference.model_dump(mode="json")
            self._commit_entry(record.activation_digest, record.scheduler_sequence, entry)
            return reference

    record_eligibility_classification = record_classification

    def read_classification(
        self, identity: str | int
    ) -> tuple[MainLedgerClassificationEvidence, ArtifactRef] | None:
        with _LOCK:
            activation = self._require_activation_for_read()
            entries = self._all_entries(activation.activation_digest)
            for entry in entries:
                submission = self._read_entry_submission(entry, activation)
                if isinstance(identity, int):
                    if submission.scheduler_sequence != identity:
                        continue
                elif submission.operation_id != identity:
                    continue
                if entry["classification"] is None:
                    return None
                classification = self._read_entry_ref(
                    entry,
                    "classification",
                    MainLedgerClassificationEvidence,
                    activation,
                    submission,
                )
                return classification, self._reference(entry, "classification")
            return None

    def record_outcome(self, outcome: MainLedgerTerminalOutcome) -> ArtifactRef:
        with _LOCK:
            activation = self._require_activation(outcome.activation_digest)
            record = self._parse_record("outcome", outcome)
            self._validate_record_artifacts(record)
            entry = self._require_entry(record.activation_digest, record.scheduler_sequence)
            submission = self._read_entry_submission(entry, activation)
            classification = self._require_classification(entry, activation, submission)
            self._require_exact_outcome_binding(record, activation, submission, classification)
            self._verify("outcome", record, activation, submission, classification)
            data = canonical_bytes(record)
            reference = self._put("outcome", data)
            if entry["outcome"] is not None:
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
                return self._reference(entry, "outcome")
            entry["outcome"] = reference.model_dump(mode="json")
            self._commit_entry(record.activation_digest, record.scheduler_sequence, entry)
            return reference

    record_terminal_outcome = record_outcome
    record_attempt_outcome = record_outcome

    def read_outcome(
        self, identity: str | int
    ) -> tuple[MainLedgerTerminalOutcome, ArtifactRef] | None:
        with _LOCK:
            activation = self._require_activation_for_read()
            for entry in self._all_entries(activation.activation_digest):
                submission = self._read_entry_submission(entry, activation)
                if (isinstance(identity, int) and submission.scheduler_sequence != identity) or (
                    isinstance(identity, str) and submission.operation_id != identity
                ):
                    continue
                if entry["outcome"] is None:
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
                return outcome, self._reference(entry, "outcome")
            return None

    read_terminal_outcome = read_outcome

    def record_transition(self, transition: MainLedgerAccumulatorTransition) -> ArtifactRef:
        with _LOCK:
            activation = self._require_activation(transition.activation_digest)
            record = self._parse_record("transition", transition)
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
            prior = self._prior_state(activation, sequence)
            if record.prior_state != prior:
                raise MainGraduationLedgerJournalError(
                    "transition predecessor differs from durable chain"
                )
            self._verify("transition", record, activation, classification, outcome)
            data = canonical_bytes(record)
            reference = self._put("transition", data)
            if entry["transition"] is not None:
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
                return self._reference(entry, "transition")
            entry["transition"] = reference.model_dump(mode="json")
            self._commit_entry(record.activation_digest, sequence, entry)
            return reference

    record_accumulator_transition = record_transition

    def read_transition(
        self, identity: str | int
    ) -> tuple[MainLedgerAccumulatorTransition, ArtifactRef] | None:
        with _LOCK:
            activation = self._require_activation_for_read()
            for entry in self._all_entries(activation.activation_digest):
                submission = self._read_entry_submission(entry, activation)
                if (isinstance(identity, int) and submission.scheduler_sequence != identity) or (
                    isinstance(identity, str) and submission.operation_id != identity
                ):
                    continue
                if entry["transition"] is None:
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
                return transition, self._reference(entry, "transition")
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
            self._verify("boundary", record, activation)
            data = canonical_bytes(record)
            reference = self._put("boundary", data)
            index = (
                self._indexes
                / "boundary"
                / (f"{activation.activation_digest.removeprefix('sha256:')}.json")
            )
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
            if evidence.activation_digest != activation.activation_digest:
                raise MainGraduationLedgerJournalError(
                    "boundary evidence activation differs from index"
                )
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
            self._require_prior_state_for_boundary(activation, record.prior_state)
            self._verify("boundary-reset", record, activation, evidence)
            data = canonical_bytes(record)
            reference = self._put("boundary-reset", data)
            index = (
                self._indexes
                / "boundary-reset"
                / (f"{activation.activation_digest.removeprefix('sha256:')}.json")
            )
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
            self._require_prior_state_for_boundary(activation, reset.prior_state)
            self._verify("boundary-reset", reset, activation, evidence)
            return reset, reference

    def record_package(self, package: MainLedgerEvidencePackage) -> ArtifactRef:
        with _LOCK:
            record = self._parse_record("package", package)
            self._validate_record_artifacts(record)
            activation = self._require_activation(record.activation.activation_digest)
            self._verify_package_closure(record, activation)
            self._verify("package", record)
            data = canonical_bytes(record)
            reference = self._put("package", data)
            index = (
                self._indexes
                / "package"
                / f"{activation.activation_digest.removeprefix('sha256:')}.json"
            )
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
                        matches.append((package, reference))
                return matches[0] if len(matches) == 1 else None
            reference = self._read_reference(index, "package")
            package = self._read_record("package", reference, MainLedgerEvidencePackage)
            activation = self._require_activation(package.activation.activation_digest)
            self._verify_package_closure(package, activation)
            self._verify("package", package)
            if package.package_digest != reference.digest:
                raise MainGraduationLedgerJournalError("package digest does not match CAS object")
            return package, reference

    read_evidence_package = read_package

    def list_sequences(self) -> tuple[int, ...]:
        with _LOCK:
            activation = self._require_activation_for_read()
            entries = self._all_entries(activation.activation_digest)
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
            "classification": None,
            "outcome": None,
            "transition": None,
        }

    def _commit_entry(self, activation_digest: str, sequence: int, entry: dict[str, Any]) -> None:
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
            os.replace(temporary, path)
            _sync_directory(path.parent)
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
                "classification",
                "outcome",
                "transition",
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

    def _max_committed_sequence(self, activation_digest: str, watermark: int) -> int:
        entries = self._all_entries(activation_digest)
        if not entries:
            return watermark
        expected = watermark + 1
        for entry in entries:
            if entry["scheduler_sequence"] != expected:
                raise MainGraduationLedgerJournalError("committed scheduler sequence has a gap")
            expected += 1
        return expected - 1

    def _read_entry_submission(
        self, entry: dict[str, Any], activation: MainLedgerActivation
    ) -> MainLedgerSubmissionEnvelope:
        submission = self._read_entry_ref(
            entry, "submission", MainLedgerSubmissionEnvelope, activation
        )
        if (
            submission.scheduler_sequence != entry["scheduler_sequence"]
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
        if entry["classification"] is not None:
            classification = self._read_entry_ref(
                entry,
                "classification",
                MainLedgerClassificationEvidence,
                activation,
                submission,
            )
        if entry["outcome"] is not None:
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
        if entry["transition"] is not None:
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
        reference = self._reference(entry, kind)
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
            return ArtifactRef.model_validate(
                json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_pairs)
            )
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise MainGraduationLedgerJournalError(f"malformed {kind} index") from exc

    def _reference(self, entry: dict[str, Any], kind: str) -> ArtifactRef:
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
        if entry["classification"] is None:
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
        if entry["outcome"] is None:
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
        self, activation: MainLedgerActivation, prior_state: Any
    ) -> None:
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

    def _require_boundary_evidence(
        self, activation: MainLedgerActivation, violation_digest: str
    ) -> MainLedgerBoundaryViolationEvidence:
        loaded = self.read_boundary_evidence(activation.activation_digest)
        if loaded is None or loaded[0].violation_digest != violation_digest:
            raise MainGraduationLedgerJournalError("boundary evidence is not durably recorded")
        return loaded[0]

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

    def _verify_package_closure(
        self, package: MainLedgerEvidencePackage, activation: MainLedgerActivation
    ) -> None:
        if package.activation != activation:
            raise MainGraduationLedgerJournalError(
                "package activation differs from durable activation"
            )
        if len(package.submissions) != len(package.classifications) or len(
            package.transitions
        ) != len(package.submissions):
            raise MainGraduationLedgerJournalError("package does not close every durable sequence")
        by_sequence = {
            entry["scheduler_sequence"]: entry
            for entry in self._all_entries(activation.activation_digest)
        }
        for submission, classification in zip(
            package.submissions, package.classifications, strict=True
        ):
            entry = by_sequence.get(submission.scheduler_sequence)
            if entry is None:
                raise MainGraduationLedgerJournalError(
                    "package references a missing durable submission"
                )
            durable_submission = self._read_entry_submission(entry, activation)
            if durable_submission != submission:
                raise MainGraduationLedgerJournalError(
                    "package submission differs from durable record"
                )
            durable_classification = self._require_classification(
                entry, activation, durable_submission
            )
            if durable_classification != classification:
                raise MainGraduationLedgerJournalError(
                    "package classification differs from durable record"
                )
        outcomes = {item.scheduler_sequence: item for item in package.outcomes}
        transitions = {item.classification.scheduler_sequence: item for item in package.transitions}
        for submission in package.submissions:
            entry = by_sequence[submission.scheduler_sequence]
            classification = self._require_classification(entry, activation, submission)
            if classification.classification == "eligible":
                durable_outcome = self._require_outcome(
                    entry, activation, submission, classification
                )
                if outcomes.get(submission.scheduler_sequence) != durable_outcome:
                    raise MainGraduationLedgerJournalError(
                        "package outcome differs from durable record"
                    )
            elif submission.scheduler_sequence in outcomes:
                raise MainGraduationLedgerJournalError("excluded package submission has an outcome")
            durable_transition = self._read_entry_ref(
                entry,
                "transition",
                MainLedgerAccumulatorTransition,
                activation,
                submission,
                classification,
                outcomes.get(submission.scheduler_sequence),
            )
            if transitions.get(submission.scheduler_sequence) != durable_transition:
                raise MainGraduationLedgerJournalError(
                    "package transition differs from durable record"
                )
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

    def _verify(self, kind: str, record: Any, *dependencies: Any) -> None:
        verifier = self._require_verifier()
        names = {
            "activation": ("verify_activation",),
            "submission": ("verify_submission",),
            "classification": ("verify_classification",),
            "outcome": ("verify_outcome", "verify_terminal_outcome"),
            "transition": ("verify_transition", "verify_accumulator_transition"),
            "package": ("verify_package", "verify_evidence_package"),
            "boundary": ("verify_boundary_evidence",),
            "boundary-reset": ("verify_boundary_reset",),
        }[kind]
        method = next(
            (
                getattr(verifier, name, None)
                for name in names
                if callable(getattr(verifier, name, None))
            ),
            None,
        )
        if method is None:
            raise MainGraduationLedgerJournalError(f"authority verifier lacks {names[0]}")
        candidates = (record, *dependencies)
        try:
            signature = inspect.signature(method)
            args = candidates
            if not any(
                parameter.kind == inspect.Parameter.VAR_POSITIONAL
                for parameter in signature.parameters.values()
            ):
                while args and _cannot_bind(signature, args):
                    args = args[:-1]
            result = method(*args)
            if result is False:
                raise ValueError("authority verifier rejected record")
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


def _cannot_bind(signature: inspect.Signature, args: tuple[Any, ...]) -> bool:
    try:
        signature.bind(*args)
    except TypeError:
        return True
    return False


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
