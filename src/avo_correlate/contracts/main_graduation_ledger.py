"""Offline C6 campaign-runner and eligibility-ledger contracts.

The C6 ledger is deliberately a separate, versioned namespace.  The v1
``EligibilityLedgerStarted``/eligibility/attempt records predate the frozen
activation and CAS protocol and remain historical wire contracts.

These records are data-only.  JSON Schema describes the wire shape; the
cross-record and digest rules are enforced by the Pydantic validators below
and by the aggregate package validator.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)

from avo_correlate.contracts.base import (
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.contracts.promotion_policy import is_valid_promotion_path, path_manifest_digest
from avo_correlate.domain.canonical import canonical_digest

LedgerPath = Annotated[str, StringConstraints(min_length=1)]
LedgerOutcome = Literal["success", "failure", "quarantine", "reconciliation", "reset"]


def _aware(value: datetime) -> datetime:
    return require_aware_datetime(value)


def _paths(value: list[str]) -> list[str]:
    if value != sorted(value, key=lambda item: (item.casefold(), item)):
        raise ValueError("classification paths must be sorted")
    if len({item.casefold() for item in value}) != len(value):
        raise ValueError("classification paths must be unique")
    if any(not is_valid_promotion_path(item) for item in value):
        raise ValueError("classification paths must be normalized relative POSIX paths")
    return value


class MainLedgerHostedRollbackProof(StrictModel):
    """Fresh hosted main rollback proof required before ledger activation."""

    schema_version: Literal[2] = 2
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/main"] = "refs/heads/main"
    completion_state: Literal["successful"] = "successful"
    fresh_hosted: Literal[True] = True
    proof_artifact_digest: Sha256Digest
    rollback_authority_identity: NonEmptyString
    rollback_authority_digest: Sha256Digest
    result_evidence_digest: Sha256Digest
    completed_at: datetime
    proof_digest: Sha256Digest
    deploy_performed: Literal[False] = False

    _aware_completed_at = field_validator("completed_at")(_aware)

    @model_validator(mode="after")
    def validate_digest(self) -> MainLedgerHostedRollbackProof:
        if self.proof_digest != canonical_digest(
            self.model_dump(exclude={"proof_digest"}, mode="json")
        ):
            raise ValueError("hosted rollback proof digest mismatch")
        return self


class MainLedgerC8CapabilityEvidence(StrictModel):
    """Controller-observed hosting, queue, validation, and release capability."""

    schema_version: Literal[2] = 2
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/main"] = "refs/heads/main"
    hosting_authority_identity: NonEmptyString
    queue_configuration_digest: Sha256Digest
    queue_generation_digest: Sha256Digest
    queue_required: Literal[True] = True
    max_entries_per_group: Literal[1] = 1
    direct_merge_allowed: Literal[False] = False
    bypass_allowed: Literal[False] = False
    validation_app_id: Literal[15368] = 15368
    release_issuer_identity: NonEmptyString
    release_issuer_app_id: StrictInt = Field(gt=0)
    release_issuer_authority_digest: Sha256Digest
    release_issuer_isolated: Literal[True] = True
    observed_at: datetime
    evidence_digest: Sha256Digest

    _aware_observed_at = field_validator("observed_at")(_aware)

    @model_validator(mode="after")
    def validate_capability(self) -> MainLedgerC8CapabilityEvidenceV2:
        if self.release_issuer_app_id == self.validation_app_id:
            raise ValueError("validation App 15368 cannot be the release issuer")
        if self.evidence_digest != canonical_digest(
            self.model_dump(exclude={"evidence_digest"}, mode="json")
        ):
            raise ValueError("C8 capability evidence digest mismatch")
        return self


class MainLedgerActivation(StrictModel):
    """Frozen controller root for one 12-success campaign."""

    schema_version: Literal[2] = 2
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/main"] = "refs/heads/main"
    protocol_digest: Sha256Digest
    controller_config_digest: Sha256Digest
    policy_digest: Sha256Digest
    policy_epoch: Sha256Digest
    controller_issuer_identity: NonEmptyString
    controller_issuer_authority_digest: Sha256Digest
    threshold: Literal[12] = 12
    initial_streak: Literal[0] = 0
    scheduler_sequence_watermark: StrictInt = Field(ge=0)
    hosted_rollback_proof_digest: Sha256Digest
    hosted_rollback_artifact_digest: Sha256Digest
    rollback_authority_identity: NonEmptyString
    c8_capability_evidence_digest: Sha256Digest
    activated_at: datetime
    activation_digest: Sha256Digest
    deploy_performed: Literal[False] = False

    _aware_activated_at = field_validator("activated_at")(_aware)

    @model_validator(mode="after")
    def validate_activation(self) -> MainLedgerActivation:
        if self.activation_digest != canonical_digest(
            self.model_dump(exclude={"activation_digest"}, mode="json")
        ):
            raise ValueError("ledger activation digest mismatch")
        if self.initial_streak != 0 or self.threshold != 12:
            raise ValueError("ledger activation must start at streak zero with threshold 12")
        return self


class MainLedgerSubmissionEnvelope(StrictModel):
    """Immutable scheduler receipt written before candidate content inspection."""

    schema_version: Literal[2] = 2
    activation_digest: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/main"] = "refs/heads/main"
    scheduler_sequence: StrictInt = Field(gt=0)
    source_identity: NonEmptyString
    submission_identity: NonEmptyString
    submission_digest: Sha256Digest
    operation_id: Sha256Digest
    recorded_at: datetime
    content_inspected: Literal[False] = False
    envelope_digest: Sha256Digest
    deploy_performed: Literal[False] = False

    _aware_recorded_at = field_validator("recorded_at")(_aware)

    @model_validator(mode="after")
    def validate_envelope(self) -> MainLedgerSubmissionEnvelope:
        expected_operation = canonical_digest(
            {
                "domain": "avo.main.ledger.submission.v2",
                "activation_digest": self.activation_digest,
                "scheduler_sequence": self.scheduler_sequence,
                "source_identity": self.source_identity,
                "submission_identity": self.submission_identity,
                "submission_digest": self.submission_digest,
            }
        )
        if self.operation_id != expected_operation:
            raise ValueError("scheduler submission operation identity mismatch")
        if self.envelope_digest != canonical_digest(
            self.model_dump(exclude={"envelope_digest"}, mode="json")
        ):
            raise ValueError("scheduler submission envelope digest mismatch")
        return self


class MainLedgerClassificationEvidence(StrictModel):
    """Controller-owned classification; exclusions require independent proof."""

    schema_version: Literal[2] = 2
    activation_digest: Sha256Digest
    submission_digest: Sha256Digest
    operation_id: Sha256Digest
    scheduler_sequence: StrictInt = Field(gt=0)
    classification: Literal["eligible", "excluded"]
    empty: StrictBool
    ordinary: StrictBool
    paths: list[LedgerPath]
    path_manifest_digest: Sha256Digest
    policy_digest: Sha256Digest
    policy_epoch: Sha256Digest
    issuer_identity: NonEmptyString
    issuer_authority_digest: Sha256Digest
    issuer_domain: Literal["controller-policy"] = "controller-policy"
    exclusion_reason: Literal["empty", "nonordinary"] | None = None
    independent_exclusion_evidence_digest: Sha256Digest | None = None
    classification_digest: Sha256Digest
    deploy_performed: Literal[False] = False

    _valid_paths = field_validator("paths")(_paths)

    @model_validator(mode="after")
    def validate_classification(self) -> MainLedgerClassificationEvidence:
        if self.path_manifest_digest != path_manifest_digest(self.paths):
            raise ValueError("classification path manifest digest mismatch")
        if self.classification == "eligible" and (self.empty or not self.ordinary):
            raise ValueError("only ordinary nonempty submissions are eligible")
        excluded_empty = self.empty
        excluded_nonordinary = not self.ordinary
        if self.classification == "excluded":
            if not (excluded_empty or excluded_nonordinary):
                raise ValueError("ordinary nonempty submissions cannot be excluded")
            expected_reason = "empty" if excluded_empty else "nonordinary"
            if (
                self.exclusion_reason != expected_reason
                or self.independent_exclusion_evidence_digest is None
            ):
                raise ValueError("exclusions require independent controller evidence")
        elif (
            self.exclusion_reason is not None
            or self.independent_exclusion_evidence_digest is not None
        ):
            raise ValueError("eligible classification cannot carry exclusion evidence")
        if self.classification_digest != canonical_digest(
            self.model_dump(exclude={"classification_digest"}, mode="json")
        ):
            raise ValueError("classification evidence digest mismatch")
        return self


class MainLedgerTerminalOutcome(StrictModel):
    """One append-only terminal outcome for one eligible scheduler submission."""

    schema_version: Literal[2] = 2
    activation_digest: Sha256Digest
    submission_digest: Sha256Digest
    classification_digest: Sha256Digest
    operation_id: Sha256Digest
    attempt_id: Sha256Digest
    scheduler_sequence: StrictInt = Field(gt=0)
    outcome: LedgerOutcome
    evidence_kind: LedgerOutcome
    terminal_evidence_digest: Sha256Digest
    package_digest: Sha256Digest | None = None
    package_binding_digest: Sha256Digest | None = None
    reason: NonEmptyString | None = None
    terminal_at: datetime
    outcome_digest: Sha256Digest
    deploy_performed: Literal[False] = False

    _aware_terminal_at = field_validator("terminal_at")(_aware)

    @model_validator(mode="after")
    def validate_outcome(self) -> MainLedgerTerminalOutcome:
        if self.outcome != self.evidence_kind:
            raise ValueError("terminal outcome discriminator differs from evidence kind")
        expected_attempt = canonical_digest(
            {
                "domain": "avo.main.ledger.attempt.v2",
                "activation_digest": self.activation_digest,
                "scheduler_sequence": self.scheduler_sequence,
                "submission_digest": self.submission_digest,
            }
        )
        if self.attempt_id != expected_attempt:
            raise ValueError("attempt identity is not bound to activation and submission")
        if self.outcome == "success" and self.package_digest is None:
            raise ValueError("successful outcome requires a canonical package")
        if (self.package_digest is None) != (self.package_binding_digest is None):
            raise ValueError("package digest and package binding must be supplied together")
        if self.outcome_digest != canonical_digest(
            self.model_dump(exclude={"outcome_digest"}, mode="json")
        ):
            raise ValueError("terminal outcome digest mismatch")
        return self


class MainLedgerAccumulatorState(StrictModel):
    """Content-addressed state used as the CAS predecessor of a transition."""

    schema_version: Literal[2] = 2
    activation_digest: Sha256Digest
    last_scheduler_sequence: StrictInt = Field(ge=0)
    streak: StrictInt = Field(ge=0, le=12)
    successes: StrictInt = Field(ge=0)
    failures: StrictInt = Field(ge=0)
    boundary_violations: StrictInt = Field(ge=0)
    threshold_complete: StrictBool
    state_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_state(self) -> MainLedgerAccumulatorState:
        if self.threshold_complete != (self.streak == 12):
            raise ValueError("threshold completion does not match streak")
        if self.state_digest != canonical_digest(
            self.model_dump(exclude={"state_digest"}, mode="json")
        ):
            raise ValueError("accumulator state digest mismatch")
        return self


class MainLedgerAccumulatorTransition(StrictModel):
    """CAS transition: exactly one eligible outcome and no scheduler gaps."""

    schema_version: Literal[2] = 2
    activation_digest: Sha256Digest
    prior_state: MainLedgerAccumulatorState
    prior_state_digest: Sha256Digest
    outcome: MainLedgerTerminalOutcome
    outcome_digest: Sha256Digest
    reset_applied: StrictBool
    resulting_state: MainLedgerAccumulatorState
    resulting_state_digest: Sha256Digest
    transition_digest: Sha256Digest
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_transition(self) -> MainLedgerAccumulatorTransition:
        if self.prior_state_digest != self.prior_state.state_digest:
            raise ValueError("CAS prior state digest mismatch")
        if self.outcome_digest != self.outcome.outcome_digest:
            raise ValueError("CAS outcome digest mismatch")
        if (
            self.activation_digest != self.prior_state.activation_digest
            or self.activation_digest != self.outcome.activation_digest
        ):
            raise ValueError("CAS activation binding differs")
        if self.outcome.scheduler_sequence != self.prior_state.last_scheduler_sequence + 1:
            raise ValueError("scheduler sequence has a gap")
        if self.resulting_state_digest != self.resulting_state.state_digest:
            raise ValueError("CAS resulting state digest mismatch")
        if self.resulting_state.activation_digest != self.activation_digest:
            raise ValueError("CAS resulting state activation differs")
        if self.outcome.outcome == "success":
            if self.reset_applied:
                raise ValueError("successful transition cannot apply a reset")
            if (
                self.prior_state.streak >= 12
                or self.resulting_state.streak != self.prior_state.streak + 1
            ):
                raise ValueError("success must increment a non-complete threshold streak")
        else:
            if not self.reset_applied or self.resulting_state.streak != 0:
                raise ValueError("non-success outcome must apply a threshold reset")
        if self.resulting_state.last_scheduler_sequence != self.outcome.scheduler_sequence:
            raise ValueError("resulting state sequence differs from outcome")
        if self.resulting_state.threshold_complete != (self.resulting_state.streak == 12):
            raise ValueError("threshold completion mismatch")
        if self.transition_digest != canonical_digest(
            self.model_dump(exclude={"transition_digest"}, mode="json")
        ):
            raise ValueError("accumulator transition digest mismatch")
        return self


class MainLedgerEvidencePackage(StrictModel):
    """Closed aggregate proving activation, accounting, terminality, and CAS."""

    schema_version: Literal[2] = 2
    activation: MainLedgerActivation
    submissions: list[MainLedgerSubmissionEnvelope] = Field(min_length=1)
    classifications: list[MainLedgerClassificationEvidence] = Field(min_length=1)
    outcomes: list[MainLedgerTerminalOutcome] = Field(
        default_factory=list[MainLedgerTerminalOutcome]
    )
    transitions: list[MainLedgerAccumulatorTransition] = Field(
        default_factory=list[MainLedgerAccumulatorTransition]
    )
    final_state: MainLedgerAccumulatorState
    package_digest: Sha256Digest
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_package(self) -> MainLedgerEvidencePackage:
        if self.activation.activation_digest != self.final_state.activation_digest:
            raise ValueError("ledger final state activation differs")
        if len(self.submissions) != len(self.classifications):
            raise ValueError("every submission requires controller classification")
        ordered = sorted(self.submissions, key=lambda item: item.scheduler_sequence)
        if ordered != self.submissions:
            raise ValueError("submissions must be in scheduler order")
        expected = self.activation.scheduler_sequence_watermark + 1
        by_submission = {item.submission_digest: item for item in self.submissions}
        for submission, classification in zip(self.submissions, self.classifications, strict=True):
            if submission.activation_digest != self.activation.activation_digest:
                raise ValueError("submission activation differs")
            if submission.scheduler_sequence != expected:
                raise ValueError("ledger scheduler sequence has a gap")
            if classification.activation_digest != self.activation.activation_digest:
                raise ValueError("classification activation differs")
            if (
                classification.scheduler_sequence != submission.scheduler_sequence
                or classification.submission_digest != submission.submission_digest
            ):
                raise ValueError("classification does not bind submission")
            if classification.operation_id != submission.operation_id:
                raise ValueError("classification operation does not bind submission")
            if (
                classification.policy_epoch != self.activation.policy_epoch
                or classification.policy_digest != self.activation.policy_digest
            ):
                raise ValueError("classification policy does not bind activation")
            expected += 1
        if len({item.scheduler_sequence for item in self.outcomes}) != len(self.outcomes):
            raise ValueError("terminal outcomes must be unique per scheduler sequence")
        if len({item.outcome.scheduler_sequence for item in self.transitions}) != len(
            self.transitions
        ):
            raise ValueError("CAS transitions must be unique per scheduler sequence")
        outcome_by_sequence = {item.scheduler_sequence: item for item in self.outcomes}
        eligible_sequences = {
            item.scheduler_sequence
            for item in self.classifications
            if item.classification == "eligible"
        }
        if set(outcome_by_sequence) != eligible_sequences:
            raise ValueError("each eligible classification requires exactly one terminal outcome")
        if any(item.submission_digest not in by_submission for item in self.outcomes):
            raise ValueError("outcome references an unknown submission")
        expected_state = self.activation.scheduler_sequence_watermark
        for transition in self.transitions:
            if transition.prior_state.last_scheduler_sequence != expected_state:
                raise ValueError("CAS transitions are not contiguous")
            if transition.outcome.scheduler_sequence not in outcome_by_sequence:
                raise ValueError("CAS transition references an unknown outcome")
            if (
                transition.outcome.operation_id
                != by_submission[transition.outcome.submission_digest].operation_id
            ):
                raise ValueError("outcome operation does not bind submission")
            expected_state = transition.resulting_state.last_scheduler_sequence
        if self.outcomes and len(self.transitions) != len(self.outcomes):
            raise ValueError("every terminal outcome requires one CAS transition")
        if self.final_state.last_scheduler_sequence != expected_state:
            raise ValueError("final state does not close CAS transition chain")
        if self.package_digest != canonical_digest(
            self.model_dump(exclude={"package_digest"}, mode="json")
        ):
            raise ValueError("ledger evidence package digest mismatch")
        return self


# Short names are public convenience aliases; the versioned classes above are
# the canonical schema owners.
MainLedgerHostedRollbackProofV2 = MainLedgerHostedRollbackProof
MainLedgerC8CapabilityEvidenceV2 = MainLedgerC8CapabilityEvidence
MainLedgerActivationV2 = MainLedgerActivation
MainLedgerSubmissionEnvelopeV2 = MainLedgerSubmissionEnvelope
MainLedgerClassificationEvidenceV2 = MainLedgerClassificationEvidence
MainLedgerTerminalOutcomeV2 = MainLedgerTerminalOutcome
MainLedgerAccumulatorStateV2 = MainLedgerAccumulatorState
MainLedgerAccumulatorTransitionV2 = MainLedgerAccumulatorTransition
MainLedgerEvidencePackageV2 = MainLedgerEvidencePackage
LedgerActivationV2 = MainLedgerActivation
LedgerSubmissionEnvelopeV2 = MainLedgerSubmissionEnvelope
ControllerClassificationEvidenceV2 = MainLedgerClassificationEvidence
LedgerTerminalOutcomeV2 = MainLedgerTerminalOutcome
ThresholdAccumulatorStateV2 = MainLedgerAccumulatorState
ThresholdAccumulatorTransitionV2 = MainLedgerAccumulatorTransition
LedgerEvidencePackageV2 = MainLedgerEvidencePackage
MainGraduationHostedRollbackProof = MainLedgerHostedRollbackProof
MainGraduationHostedRollbackProofV2 = MainLedgerHostedRollbackProof
MainGraduationC8CapabilityEvidence = MainLedgerC8CapabilityEvidence
MainGraduationC8CapabilityEvidenceV2 = MainLedgerC8CapabilityEvidence
MainGraduationLedgerActivation = MainLedgerActivation
MainGraduationLedgerActivationV2 = MainLedgerActivation
MainGraduationSubmissionEnvelope = MainLedgerSubmissionEnvelope
MainGraduationSubmissionEnvelopeV2 = MainLedgerSubmissionEnvelope
MainGraduationClassificationEvidence = MainLedgerClassificationEvidence
MainGraduationClassificationEvidenceV2 = MainLedgerClassificationEvidence
MainGraduationTerminalOutcome = MainLedgerTerminalOutcome
MainGraduationTerminalOutcomeV2 = MainLedgerTerminalOutcome
MainGraduationAccumulatorState = MainLedgerAccumulatorState
MainGraduationAccumulatorStateV2 = MainLedgerAccumulatorState
MainGraduationAccumulatorTransition = MainLedgerAccumulatorTransition
MainGraduationAccumulatorTransitionV2 = MainLedgerAccumulatorTransition
MainGraduationEvidencePackage = MainLedgerEvidencePackage
MainGraduationEvidencePackageV2 = MainLedgerEvidencePackage

__all__ = [
    "ControllerClassificationEvidenceV2",
    "LedgerActivationV2",
    "LedgerEvidencePackageV2",
    "LedgerOutcome",
    "LedgerSubmissionEnvelopeV2",
    "LedgerTerminalOutcomeV2",
    "MainGraduationAccumulatorState",
    "MainGraduationAccumulatorStateV2",
    "MainGraduationAccumulatorTransition",
    "MainGraduationAccumulatorTransitionV2",
    "MainGraduationC8CapabilityEvidence",
    "MainGraduationC8CapabilityEvidenceV2",
    "MainGraduationClassificationEvidence",
    "MainGraduationClassificationEvidenceV2",
    "MainGraduationEvidencePackage",
    "MainGraduationEvidencePackageV2",
    "MainGraduationHostedRollbackProof",
    "MainGraduationHostedRollbackProofV2",
    "MainGraduationLedgerActivation",
    "MainGraduationLedgerActivationV2",
    "MainGraduationSubmissionEnvelope",
    "MainGraduationSubmissionEnvelopeV2",
    "MainGraduationTerminalOutcome",
    "MainGraduationTerminalOutcomeV2",
    "MainLedgerAccumulatorState",
    "MainLedgerAccumulatorStateV2",
    "MainLedgerAccumulatorTransition",
    "MainLedgerAccumulatorTransitionV2",
    "MainLedgerActivation",
    "MainLedgerActivationV2",
    "MainLedgerC8CapabilityEvidence",
    "MainLedgerC8CapabilityEvidenceV2",
    "MainLedgerClassificationEvidence",
    "MainLedgerClassificationEvidenceV2",
    "MainLedgerEvidencePackage",
    "MainLedgerEvidencePackageV2",
    "MainLedgerHostedRollbackProof",
    "MainLedgerHostedRollbackProofV2",
    "MainLedgerSubmissionEnvelope",
    "MainLedgerSubmissionEnvelopeV2",
    "MainLedgerTerminalOutcome",
    "MainLedgerTerminalOutcomeV2",
    "ThresholdAccumulatorStateV2",
    "ThresholdAccumulatorTransitionV2",
]
