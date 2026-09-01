"""Controller-owned orchestration for the offline C6 graduation ledger.

The journal is the durability and authentication boundary.  This module only
derives records from the frozen activation, trusted time, and controller
capabilities; it deliberately has no provider or hosted-main capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from avo_correlate.adapters.artifacts.main_graduation_ledger_journal import (
    MainGraduationLedgerJournal,
    MainGraduationLedgerJournalError,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation_ledger import (
    MainLedgerAccumulatorState,
    MainLedgerAccumulatorTransition,
    MainLedgerActivation,
    MainLedgerBoundaryResetTransition,
    MainLedgerBoundaryViolationEvidence,
    MainLedgerClassificationEvidence,
    MainLedgerControllerAuthority,
    MainLedgerEvidencePackage,
    MainLedgerSubmissionEnvelope,
    MainLedgerTerminalOutcome,
    main_ledger_genesis_state,
)
from avo_correlate.domain.canonical import canonical_digest


class TrustedClock(Protocol):
    def now(self) -> datetime: ...


class SubmissionContentResolver(Protocol):
    def resolve(self, artifact: ArtifactRef) -> object: ...


class MainGraduationClassifier(Protocol):
    def classify(
        self,
        content: object,
        activation: MainLedgerActivation,
        submission: MainLedgerSubmissionEnvelope,
    ) -> MainLedgerClassificationEvidence | dict[str, Any]: ...


@dataclass(frozen=True)
class MainLedgerStatus:
    activation: MainLedgerActivation
    state: MainLedgerAccumulatorState
    submissions: tuple[MainLedgerSubmissionEnvelope, ...]
    classifications: tuple[MainLedgerClassificationEvidence | None, ...]
    outcomes: tuple[MainLedgerTerminalOutcome | None, ...]
    transitions: tuple[MainLedgerAccumulatorTransition | None, ...]
    package: MainLedgerEvidencePackage | None = None
    boundary_evidence: MainLedgerBoundaryViolationEvidence | None = None
    boundary_reset: MainLedgerBoundaryResetTransition | None = None


class MainGraduationLedgerService:
    """Build and durably append C6 records for one activation."""

    def __init__(
        self,
        journal: MainGraduationLedgerJournal,
        clock: TrustedClock | None = None,
        resolver: SubmissionContentResolver | None = None,
        classifier: MainGraduationClassifier | None = None,
        *,
        trusted_clock: TrustedClock | None = None,
        content_resolver: SubmissionContentResolver | None = None,
        controller_classifier: MainGraduationClassifier | None = None,
    ) -> None:
        self._journal = journal
        self._clock = clock or trusted_clock
        self._resolver = resolver or content_resolver
        self._classifier = classifier or controller_classifier
        if self._clock is None:
            raise ValueError("a trusted clock is required")

    @property
    def journal(self) -> MainGraduationLedgerJournal:
        return self._journal

    def activate(self, activation: MainLedgerActivation) -> ArtifactRef:
        """Recheck the frozen authority window immediately before journaling."""
        now = self._now()
        authority = activation.controller_authority
        if not authority.authorized_at <= now <= authority.expires_at:
            raise MainGraduationLedgerJournalError("trusted clock is outside authority window")
        if not authority.authorized_at <= activation.freshness_cutoff <= activation.activated_at:
            raise MainGraduationLedgerJournalError("activation freshness cutoff is invalid")
        if not authority.authorized_at <= activation.activated_at <= authority.expires_at:
            raise MainGraduationLedgerJournalError("activation time is outside authority window")
        if activation.freshness_cutoff > now or activation.activated_at > now:
            raise MainGraduationLedgerJournalError(
                "activation freshness or activated_at is in the future"
            )
        existing = self._journal.read_activation()
        if existing is not None:
            if existing[0] != activation:
                raise MainGraduationLedgerJournalError("a different activation is already recorded")
            # A completed activation cannot be silently re-opened/replaced.
            if self._journal.read_package(activation.activation_digest) is not None:
                raise MainGraduationLedgerJournalError("activation is already terminal")
            if self._journal.read_boundary_reset(activation.activation_digest) is not None:
                raise MainGraduationLedgerJournalError("activation is already terminal")
            return existing[1]
        return self._journal.record_activation(activation)

    def submit(
        self,
        scheduler_sequence: int,
        source_identity: str,
        submission_identity: str,
        submission_digest: str,
        content_artifact: ArtifactRef,
        *,
        recorded_at: datetime | None = None,
        activation: MainLedgerActivation | None = None,
    ) -> MainLedgerSubmissionEnvelope:
        """Persist an envelope before resolving or inspecting submission content.

        Exact operation identity is independent of ``recorded_at``.  Looking up
        that identity first makes a retry with a changed timestamp adopt the
        original durable envelope rather than conflict with it.
        """
        active = activation or self._required_activation()
        operation_id = canonical_digest(
            {
                "domain": "avo.main.ledger.submission.v2",
                "activation_digest": active.activation_digest,
                "scheduler_sequence": scheduler_sequence,
                "source_identity": source_identity,
                "submission_identity": submission_identity,
                "submission_digest": submission_digest,
            }
        )
        existing = self._journal.read_submission(operation_id)
        if existing is not None:
            old = existing[0]
            if (
                old.scheduler_sequence != scheduler_sequence
                or old.source_identity != source_identity
                or old.submission_identity != submission_identity
                or old.submission_digest != submission_digest
                or old.content_artifact != content_artifact
            ):
                raise MainGraduationLedgerJournalError("conflicting submission retry")
            return old
        self._ensure_not_terminal(active)
        timestamp = recorded_at if recorded_at is not None else self._now()
        envelope_values: dict[str, Any] = {
            "activation_digest": active.activation_digest,
            "repository_digest": active.repository_digest,
            "scheduler_sequence": scheduler_sequence,
            "source_identity": source_identity,
            "submission_identity": submission_identity,
            "submission_digest": submission_digest,
            "content_artifact": content_artifact,
            "operation_id": operation_id,
            "recorded_at": timestamp,
            "content_inspected": False,
        }
        envelope = MainLedgerSubmissionEnvelope.model_validate(
            {
                **envelope_values,
                "envelope_digest": self._digest_model(
                    MainLedgerSubmissionEnvelope, envelope_values, "envelope_digest"
                ),
            }
        )
        # The journal verifies and commits the scheduler envelope.  Only after
        # this call may the resolver/classifier be invoked by classify().
        self._journal.record_submission(envelope)
        return envelope

    def classify(
        self,
        identity: str | int,
        *,
        resolver: SubmissionContentResolver | None = None,
        classifier: MainGraduationClassifier | None = None,
    ) -> MainLedgerClassificationEvidence:
        active = self._required_activation()
        loaded = (
            self._journal.read_submission(identity)
            if isinstance(identity, str)
            else self._journal.read_submission_by_sequence(identity)
        )
        if loaded is None and isinstance(identity, int):
            loaded = self._journal.read_submission_by_sequence(identity)
        if loaded is None:
            raise MainGraduationLedgerJournalError("submission is not durably recorded")
        submission = loaded[0]
        durable = self._journal.read_classification(submission.scheduler_sequence)
        if durable is not None:
            return durable[0]
        self._ensure_not_terminal(active)
        content_resolver = resolver or self._resolver
        content_classifier = classifier or self._classifier
        if content_resolver is None or content_classifier is None:
            raise MainGraduationLedgerJournalError("content resolver and classifier are required")
        # This is intentionally after the durable envelope lookup/commit.
        content = content_resolver.resolve(submission.content_artifact)
        result = content_classifier.classify(content, active, submission)
        classification = self._derive_classification(result, active, submission)
        self._journal.record_classification(classification)
        return classification

    def record_outcome(
        self,
        identity: str | int,
        outcome: str,
        terminal_evidence: ArtifactRef | None = None,
        *,
        package_artifact: ArtifactRef | None = None,
        package_digest: str | None = None,
        reason: str | None = None,
        terminal_at: datetime | None = None,
        evidence_artifact: ArtifactRef | None = None,
        package: ArtifactRef | None = None,
    ) -> MainLedgerTerminalOutcome:
        active = self._required_activation()
        submission = self._find_submission(identity)
        classification_loaded = self._journal.read_classification(submission.scheduler_sequence)
        if classification_loaded is None:
            raise MainGraduationLedgerJournalError("classification is not durably recorded")
        classification = classification_loaded[0]
        if classification.classification != "eligible":
            raise MainGraduationLedgerJournalError("excluded submission cannot receive an outcome")
        terminal_evidence = terminal_evidence or evidence_artifact
        package_artifact = package_artifact or package
        if terminal_evidence is None:
            raise MainGraduationLedgerJournalError("terminal evidence is required")
        if package_artifact is not None and package_digest is None:
            package_digest = package_artifact.digest
        if package_digest is not None and package_artifact is None:
            raise MainGraduationLedgerJournalError(
                "package artifact is required with package digest"
            )
        operation_id = submission.operation_id
        attempt_id = canonical_digest(
            {
                "domain": "avo.main.ledger.attempt.v2",
                "activation_digest": active.activation_digest,
                "scheduler_sequence": submission.scheduler_sequence,
                "submission_digest": submission.submission_digest,
            }
        )
        values: dict[str, Any] = {
            "activation_digest": active.activation_digest,
            "submission_digest": submission.submission_digest,
            "classification_digest": classification.classification_digest,
            "classification": classification,
            "operation_id": operation_id,
            "attempt_id": attempt_id,
            "scheduler_sequence": submission.scheduler_sequence,
            "outcome": outcome,
            "evidence_kind": outcome,
            "terminal_evidence_digest": terminal_evidence.digest,
            "terminal_evidence": terminal_evidence,
            "package_digest": package_digest,
            "package_artifact": package_artifact,
            "package_binding_digest": (
                canonical_digest(
                    {
                        "activation_digest": active.activation_digest,
                        "classification_digest": classification.classification_digest,
                        "operation_id": operation_id,
                        "package_digest": package_digest,
                        "submission_digest": submission.submission_digest,
                    }
                )
                if package_digest is not None
                else None
            ),
            "reason": reason,
            "terminal_at": terminal_at if terminal_at is not None else self._now(),
        }
        outcome_record = MainLedgerTerminalOutcome.model_validate(
            {
                **values,
                "outcome_digest": self._digest_model(
                    MainLedgerTerminalOutcome, values, "outcome_digest"
                ),
            }
        )
        self._journal.record_outcome(outcome_record)
        return outcome_record

    def advance(
        self, identity: str | int | None = None
    ) -> MainLedgerAccumulatorTransition | MainLedgerAccumulatorState | None:
        """Apply at most the next contiguous, fully terminal sequence."""
        active = self._required_activation()
        state = self._current_state(active)
        if self._journal.read_boundary_reset(active.activation_digest) is not None:
            return state
        if state.threshold_complete:
            return state
        expected = state.last_scheduler_sequence + 1
        if identity is not None:
            requested = self._find_submission(identity)
            if requested.scheduler_sequence != expected:
                raise MainGraduationLedgerJournalError(
                    "advance cannot skip the next scheduler sequence"
                )
        submission = self._journal.read_submission_by_sequence(expected)
        if submission is None:
            return None
        existing = self._journal.read_transition(expected)
        if existing is not None:
            return existing[0]
        classification_loaded = self._journal.read_classification(expected)
        if classification_loaded is None:
            return None
        classification = classification_loaded[0]
        outcome: MainLedgerTerminalOutcome | None = None
        if classification.classification == "eligible":
            outcome_loaded = self._journal.read_outcome(expected)
            if outcome_loaded is None:
                return None
            outcome = outcome_loaded[0]
        result = self._next_state(state, classification.classification, outcome)
        values: dict[str, Any] = {
            "activation_digest": active.activation_digest,
            "classification": classification,
            "prior_state": state,
            "prior_state_digest": state.state_digest,
            "outcome": outcome,
            "outcome_digest": outcome.outcome_digest if outcome is not None else None,
            "reset_applied": outcome is not None and outcome.outcome != "success",
            "resulting_state": result,
            "resulting_state_digest": result.state_digest,
        }
        transition = MainLedgerAccumulatorTransition.model_validate(
            {
                **values,
                "transition_digest": self._digest_model(
                    MainLedgerAccumulatorTransition, values, "transition_digest"
                ),
            }
        )
        self._journal.record_transition(transition)
        return transition

    def record_boundary_violation(
        self,
        violation_kind: str,
        evidence_artifact: ArtifactRef,
        *,
        expected_scheduler_sequence: int | None = None,
        detected_at: datetime | None = None,
    ) -> tuple[MainLedgerBoundaryViolationEvidence, MainLedgerBoundaryResetTransition]:
        active = self._required_activation()
        existing = self._journal.read_boundary_evidence(active.activation_digest)
        reset_existing = self._journal.read_boundary_reset(active.activation_digest)
        if existing is not None and reset_existing is not None:
            return existing[0], reset_existing[0]
        self._ensure_not_terminal(active)
        state = self._current_state(active)
        detected = detected_at if detected_at is not None else self._now()
        authority = active.controller_authority
        if not authority.authorized_at <= detected <= authority.expires_at:
            raise MainGraduationLedgerJournalError("boundary timestamp is outside authority window")
        sequence = state.last_scheduler_sequence + 1
        if expected_scheduler_sequence is not None and expected_scheduler_sequence != sequence:
            raise MainGraduationLedgerJournalError(
                "boundary expected sequence differs from current ledger state"
            )
        evidence_values: dict[str, Any] = {
            "activation_digest": active.activation_digest,
            "controller_authority": authority,
            "expected_scheduler_sequence": sequence,
            "current_state_digest": state.state_digest,
            "violation_kind": violation_kind,
            "evidence_artifact": evidence_artifact,
            "detected_at": detected,
        }
        evidence = MainLedgerBoundaryViolationEvidence.model_validate(
            {
                **evidence_values,
                "violation_digest": self._digest_model(
                    MainLedgerBoundaryViolationEvidence,
                    evidence_values,
                    "violation_digest",
                ),
            }
        )
        self._journal.record_boundary_evidence(evidence)
        result = self._boundary_state(state)
        reset_values: dict[str, Any] = {
            "activation_digest": active.activation_digest,
            "prior_state": state,
            "prior_state_digest": state.state_digest,
            "violation": evidence,
            "resulting_state": result,
            "resulting_state_digest": result.state_digest,
        }
        reset = MainLedgerBoundaryResetTransition.model_validate(
            {
                **reset_values,
                "transition_digest": self._digest_model(
                    MainLedgerBoundaryResetTransition, reset_values, "transition_digest"
                ),
            }
        )
        self._journal.record_boundary_reset(reset)
        return evidence, reset

    def record_boundary_reset(
        self,
        reset: MainLedgerBoundaryResetTransition | None = None,
        **kwargs: Any,
    ) -> MainLedgerBoundaryResetTransition:
        """Record a pre-built reset, or derive one with violation arguments.

        The derivation form returns the reset half of
        :meth:`record_boundary_violation`; accepting the typed form keeps this
        boundary useful during crash recovery without invoking the clock.
        """
        if reset is not None:
            self._journal.record_boundary_reset(reset)
            return reset
        _, derived = self.record_boundary_violation(**kwargs)
        return derived

    def package(self) -> MainLedgerEvidencePackage:
        active = self._required_activation()
        existing = self._journal.read_package(active.activation_digest)
        if existing is not None:
            return existing[0]
        status_state = self._current_state(active)
        evidence_loaded = self._journal.read_boundary_evidence(active.activation_digest)
        reset_loaded = self._journal.read_boundary_reset(active.activation_digest)
        if reset_loaded is not None:
            if evidence_loaded is None:
                raise MainGraduationLedgerJournalError("boundary reset has no evidence")
            status = "boundary_reset"
        elif status_state.threshold_complete:
            status = "threshold_complete"
        else:
            raise MainGraduationLedgerJournalError(
                "ledger has not reached a packageable terminal state"
            )
        submissions = self._journal.list_submissions()
        classifications = tuple(
            self._required_classification(s.scheduler_sequence) for s in submissions
        )
        outcomes_list: list[MainLedgerTerminalOutcome] = []
        for submission, classification in zip(submissions, classifications, strict=True):
            if classification.classification == "eligible":
                outcomes_list.append(self._required_outcome(submission.scheduler_sequence))
        outcomes = tuple(outcomes_list)
        transitions = tuple(self._required_transition(s.scheduler_sequence) for s in submissions)
        final_state = reset_loaded[0].resulting_state if reset_loaded is not None else status_state
        values: dict[str, Any] = {
            "status": status,
            "activation": active,
            "submissions": list(submissions),
            "classifications": list(classifications),
            "outcomes": list(outcomes),
            "transitions": list(transitions),
            "final_state": final_state,
            "boundary_evidence": evidence_loaded[0] if evidence_loaded is not None else None,
            "terminal_boundary_reset": reset_loaded[0] if reset_loaded is not None else None,
        }
        record = MainLedgerEvidencePackage.model_validate(
            {
                **values,
                "package_digest": self._digest_model(
                    MainLedgerEvidencePackage, values, "package_digest"
                ),
            }
        )
        self._journal.record_package(record)
        return record

    build_package = package
    record_submission = submit
    record_classification = classify
    record_terminal_outcome = record_outcome
    record_accumulator_transition = advance
    build_evidence_package = package

    def read_status(self) -> MainLedgerStatus:
        active = self._required_activation()
        submissions = self._journal.list_submissions()
        classifications_list: list[MainLedgerClassificationEvidence | None] = []
        outcomes_list: list[MainLedgerTerminalOutcome | None] = []
        transitions_list: list[MainLedgerAccumulatorTransition | None] = []
        for submission in submissions:
            classification_loaded = self._journal.read_classification(submission.scheduler_sequence)
            outcome_loaded = self._journal.read_outcome(submission.scheduler_sequence)
            transition_loaded = self._journal.read_transition(submission.scheduler_sequence)
            classifications_list.append(
                classification_loaded[0] if classification_loaded is not None else None
            )
            outcomes_list.append(outcome_loaded[0] if outcome_loaded is not None else None)
            transitions_list.append(transition_loaded[0] if transition_loaded is not None else None)
        classifications = tuple(classifications_list)
        outcomes = tuple(outcomes_list)
        transitions = tuple(transitions_list)
        package_loaded = self._journal.read_package(active.activation_digest)
        evidence_loaded = self._journal.read_boundary_evidence(active.activation_digest)
        reset_loaded = self._journal.read_boundary_reset(active.activation_digest)
        return MainLedgerStatus(
            activation=active,
            state=self._current_state(active),
            submissions=submissions,
            classifications=classifications,
            outcomes=outcomes,
            transitions=transitions,
            package=package_loaded[0] if package_loaded is not None else None,
            boundary_evidence=evidence_loaded[0] if evidence_loaded is not None else None,
            boundary_reset=reset_loaded[0] if reset_loaded is not None else None,
        )

    status = read_status

    def replay(self) -> MainLedgerEvidencePackage | None:
        """Read-only byte-identical package replay."""
        active = self._journal.read_activation()
        if active is None:
            return None
        loaded = self._journal.read_package(active[0].activation_digest)
        return loaded[0] if loaded is not None else None

    read_replay = replay

    def _required_activation(self) -> MainLedgerActivation:
        loaded = self._journal.read_activation()
        if loaded is None:
            raise MainGraduationLedgerJournalError("ledger activation is not durably recorded")
        return loaded[0]

    def _ensure_not_terminal(self, active: MainLedgerActivation) -> None:
        if self._journal.read_package(active.activation_digest) is not None:
            raise MainGraduationLedgerJournalError("activation is already terminal")
        if self._journal.read_boundary_reset(active.activation_digest) is not None:
            raise MainGraduationLedgerJournalError("activation is already terminal")

    def _find_submission(self, identity: str | int) -> MainLedgerSubmissionEnvelope:
        loaded = (
            self._journal.read_submission(identity)
            if isinstance(identity, str)
            else self._journal.read_submission_by_sequence(identity)
        )
        if loaded is None:
            raise MainGraduationLedgerJournalError("submission is not durably recorded")
        return loaded[0]

    def _required_classification(self, sequence: int) -> MainLedgerClassificationEvidence:
        loaded = self._journal.read_classification(sequence)
        if loaded is None:
            raise MainGraduationLedgerJournalError("classification is not durably recorded")
        return loaded[0]

    def _required_outcome(self, sequence: int) -> MainLedgerTerminalOutcome:
        loaded = self._journal.read_outcome(sequence)
        if loaded is None:
            raise MainGraduationLedgerJournalError("terminal outcome is not durably recorded")
        return loaded[0]

    def _required_transition(self, sequence: int) -> MainLedgerAccumulatorTransition:
        loaded = self._journal.read_transition(sequence)
        if loaded is None:
            raise MainGraduationLedgerJournalError("transition is not durably recorded")
        return loaded[0]

    def _current_state(self, active: MainLedgerActivation) -> MainLedgerAccumulatorState:
        state = main_ledger_genesis_state(
            active.activation_digest, active.scheduler_sequence_watermark
        )
        for sequence in self._journal.list_sequences():
            loaded = self._journal.read_transition(sequence)
            if loaded is None:
                break
            transition = loaded[0]
            if transition.prior_state != state:
                raise MainGraduationLedgerJournalError(
                    "accumulator transition chain is not contiguous"
                )
            state = transition.resulting_state
            if state.threshold_complete:
                break
        boundary = self._journal.read_boundary_reset(active.activation_digest)
        if boundary is not None:
            if boundary[0].prior_state != state:
                raise MainGraduationLedgerJournalError(
                    "boundary reset predecessor differs from state"
                )
            state = boundary[0].resulting_state
        return state

    @staticmethod
    def _next_state(
        prior: MainLedgerAccumulatorState,
        classification: str,
        outcome: MainLedgerTerminalOutcome | None,
    ) -> MainLedgerAccumulatorState:
        if classification == "excluded":
            values = {
                **prior.model_dump(exclude={"state_digest"}),
                "last_scheduler_sequence": prior.last_scheduler_sequence + 1,
            }
        else:
            if outcome is None:
                raise MainGraduationLedgerJournalError("eligible sequence has no outcome")
            success = outcome.outcome == "success"
            values = {
                **prior.model_dump(exclude={"state_digest"}),
                "last_scheduler_sequence": prior.last_scheduler_sequence + 1,
                "streak": prior.streak + 1 if success else 0,
                "successes": prior.successes + 1 if success else prior.successes,
                "failures": prior.failures if success else prior.failures + 1,
                "threshold_complete": success and prior.streak + 1 == 12,
            }
        values.pop("state_digest", None)
        return MainLedgerAccumulatorState.model_validate(
            {
                **values,
                "state_digest": MainGraduationLedgerService._digest_model(
                    MainLedgerAccumulatorState, values, "state_digest"
                ),
            }
        )

    @staticmethod
    def _boundary_state(prior: MainLedgerAccumulatorState) -> MainLedgerAccumulatorState:
        values = {
            **prior.model_dump(exclude={"state_digest"}),
            "streak": 0,
            "boundary_violations": prior.boundary_violations + 1,
            "threshold_complete": False,
        }
        return MainLedgerAccumulatorState.model_validate(
            {
                **values,
                "state_digest": MainGraduationLedgerService._digest_model(
                    MainLedgerAccumulatorState, values, "state_digest"
                ),
            }
        )

    @staticmethod
    def _derive_classification(
        result: MainLedgerClassificationEvidence | dict[str, Any],
        activation: MainLedgerActivation,
        submission: MainLedgerSubmissionEnvelope,
    ) -> MainLedgerClassificationEvidence:
        data = dict(
            result.model_dump(mode="python")
            if isinstance(result, MainLedgerClassificationEvidence)
            else result
        )
        if isinstance(data.get("controller_authority"), dict):
            data["controller_authority"] = MainLedgerControllerAuthority.model_validate(
                data["controller_authority"]
            )
        expected = {
            "activation_digest": activation.activation_digest,
            "submission_digest": submission.submission_digest,
            "operation_id": submission.operation_id,
            "scheduler_sequence": submission.scheduler_sequence,
            "policy_digest": activation.policy_digest,
            "policy_epoch": activation.policy_epoch,
            "controller_authority": activation.controller_authority,
            "issuer_identity": activation.controller_authority.issuer_identity,
            "issuer_authority_digest": activation.controller_authority.issuer_authority_digest,
            "issuer_domain": "controller-policy",
        }
        for key, value in expected.items():
            if key in data and data[key] != value and key != "controller_authority":
                raise MainGraduationLedgerJournalError(
                    f"classifier output {key} is not activation-bound"
                )
            data[key] = value
        if (
            "controller_authority" in data
            and data["controller_authority"] != activation.controller_authority
        ):
            raise MainGraduationLedgerJournalError(
                "classifier output controller authority is not activation-bound"
            )
        if "paths" not in data or "classification" not in data or "risk_class" not in data:
            raise MainGraduationLedgerJournalError("classifier output lacks policy classification")
        data["path_manifest_digest"] = (
            canonical_digest(data["paths"])
            if "path_manifest_digest" not in data
            else data["path_manifest_digest"]
        )
        if data["path_manifest_digest"] != canonical_digest(data["paths"]):
            raise MainGraduationLedgerJournalError("classifier path manifest is not exact")
        data["empty"] = len(data["paths"]) == 0
        data["ordinary"] = data["risk_class"] == "ordinary"
        data.pop("classification_digest", None)
        return MainLedgerClassificationEvidence.model_validate(
            {
                **data,
                "classification_digest": MainGraduationLedgerService._digest_model(
                    MainLedgerClassificationEvidence, data, "classification_digest"
                ),
            }
        )

    @staticmethod
    def _digest_model(model_type: type[Any], values: dict[str, Any], field: str) -> str:
        probe_values = {key: value for key, value in values.items() if key != field}
        probe = model_type.model_construct(**probe_values, **{field: "sha256:" + "0" * 64})
        return canonical_digest(probe.model_dump(exclude={field}, mode="json"))

    def _now(self) -> datetime:
        clock = self._clock
        if clock is None:  # guarded by the constructor; keeps the port narrow
            raise MainGraduationLedgerJournalError("trusted clock is unavailable")
        value = clock.now()
        if value.tzinfo is None or value.utcoffset() is None:
            raise MainGraduationLedgerJournalError("trusted clock returned a naive timestamp")
        return value


__all__ = [
    "MainGraduationClassifier",
    "MainGraduationLedgerService",
    "MainLedgerStatus",
    "SubmissionContentResolver",
    "TrustedClock",
]
