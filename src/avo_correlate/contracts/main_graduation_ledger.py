"""Offline C6 campaign-runner and eligibility-ledger contracts.

The C6 ledger is deliberately a separate, versioned namespace.  The v1
``EligibilityLedgerStarted``/eligibility/attempt records predate the frozen
activation and CAS protocol and remain historical wire contracts.

These records are data-only.  JSON Schema describes the wire shape; the
cross-record and digest rules are enforced by the Pydantic validators below
and by the aggregate package validator.

Parsed DTOs and their self-digests are not principal authentication.  A
persistence or service adapter must invoke an injected, controller-rooted
verifier for issuer/authority evidence before accepting these records; this
module intentionally does not invent signature or cryptographic principal
verification.
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


class MainLedgerControllerAuthority(StrictModel):
    """Self-contained controller root, not an authentication primitive.

    Persistence and service callers must supply an injected verifier that
    authenticates this authority and its issuer before using this DTO.
    """

    schema_version: Literal[2] = 2
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/main"] = "refs/heads/main"
    protocol_digest: Sha256Digest
    controller_config_digest: Sha256Digest
    policy_digest: Sha256Digest
    policy_epoch: Sha256Digest
    issuer_identity: NonEmptyString
    issuer_authority_digest: Sha256Digest
    authorized_at: datetime
    expires_at: datetime
    authority_digest: Sha256Digest

    _aware_authorized_at = field_validator("authorized_at")(_aware)
    _aware_expires_at = field_validator("expires_at")(_aware)

    @model_validator(mode="after")
    def validate_authority(self) -> MainLedgerControllerAuthority:
        if self.expires_at <= self.authorized_at:
            raise ValueError("controller authority expiry must follow authorization")
        if self.authority_digest != canonical_digest(
            self.model_dump(exclude={"authority_digest"}, mode="json")
        ):
            raise ValueError("controller authority digest mismatch")
        return self


class MainLedgerHostedRollbackProof(StrictModel):
    """Fresh hosted main rollback proof required before ledger activation."""

    schema_version: Literal[2] = 2
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/main"] = "refs/heads/main"
    completion_state: Literal["successful"] = "successful"
    fresh_hosted: Literal[True] = True
    proof_artifact_digest: Sha256Digest
    controller_authority_digest: Sha256Digest
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
    controller_authority_digest: Sha256Digest
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
    freshness_cutoff: datetime
    controller_authority: MainLedgerControllerAuthority
    hosted_rollback_proof: MainLedgerHostedRollbackProof
    c8_capability_evidence: MainLedgerC8CapabilityEvidence
    hosted_rollback_proof_digest: Sha256Digest
    hosted_rollback_artifact_digest: Sha256Digest
    rollback_authority_identity: NonEmptyString
    rollback_authority_digest: Sha256Digest
    c8_capability_evidence_digest: Sha256Digest
    activated_at: datetime
    activation_digest: Sha256Digest
    deploy_performed: Literal[False] = False

    _aware_activated_at = field_validator("activated_at")(_aware)
    _aware_freshness_cutoff = field_validator("freshness_cutoff")(_aware)

    @model_validator(mode="after")
    def validate_activation(self) -> MainLedgerActivation:
        authority = self.controller_authority
        if (
            self.repository_digest != authority.repository_digest
            or self.target_ref != authority.target_ref
        ):
            raise ValueError("activation target differs from controller authority")
        if (
            self.protocol_digest != authority.protocol_digest
            or self.controller_config_digest != authority.controller_config_digest
            or self.policy_digest != authority.policy_digest
            or self.policy_epoch != authority.policy_epoch
            or self.controller_issuer_identity != authority.issuer_identity
            or self.controller_issuer_authority_digest != authority.issuer_authority_digest
        ):
            raise ValueError("activation configuration differs from controller authority")
        if not authority.authorized_at <= self.activated_at <= authority.expires_at:
            raise ValueError("activation is outside controller authority window")
        if not authority.authorized_at <= self.freshness_cutoff <= self.activated_at:
            raise ValueError("activation freshness cutoff is outside authority window")
        proof = self.hosted_rollback_proof
        if (
            proof.proof_digest != self.hosted_rollback_proof_digest
            or proof.proof_artifact_digest != self.hosted_rollback_artifact_digest
            or proof.rollback_authority_identity != self.rollback_authority_identity
            or proof.rollback_authority_digest != self.rollback_authority_digest
            or proof.repository_digest != self.repository_digest
            or proof.target_ref != self.target_ref
            or proof.controller_authority_digest != authority.authority_digest
            or not self.freshness_cutoff <= proof.completed_at <= self.activated_at
        ):
            raise ValueError("activation hosted rollback proof is not fresh and authority-bound")
        capability = self.c8_capability_evidence
        if (
            capability.evidence_digest != self.c8_capability_evidence_digest
            or capability.repository_digest != self.repository_digest
            or capability.target_ref != self.target_ref
            or capability.controller_authority_digest != authority.authority_digest
            or not self.freshness_cutoff <= capability.observed_at <= self.activated_at
        ):
            raise ValueError("activation C8 capability evidence is not authority-bound")
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
    risk_class: Literal["ordinary", "nonordinary"]
    paths: list[LedgerPath]
    path_manifest_digest: Sha256Digest
    policy_digest: Sha256Digest
    policy_epoch: Sha256Digest
    controller_authority: MainLedgerControllerAuthority
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
        authority = self.controller_authority
        if (
            self.issuer_identity != authority.issuer_identity
            or self.issuer_authority_digest != authority.issuer_authority_digest
            or self.policy_digest != authority.policy_digest
            or self.policy_epoch != authority.policy_epoch
        ):
            raise ValueError("classification issuer or policy is not controller-bound")
        if self.path_manifest_digest != path_manifest_digest(self.paths):
            raise ValueError("classification path manifest digest mismatch")
        if self.empty != (len(self.paths) == 0):
            raise ValueError("classification empty flag must exactly match paths")
        if self.ordinary != (self.risk_class == "ordinary"):
            raise ValueError("classification risk does not match trusted policy result")
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
    classification: MainLedgerClassificationEvidence
    operation_id: Sha256Digest
    attempt_id: Sha256Digest
    scheduler_sequence: StrictInt = Field(gt=0)
    outcome: LedgerOutcome
    evidence_kind: LedgerOutcome
    terminal_evidence_digest: Sha256Digest
    package_digest: Sha256Digest | None = None
    package_binding_digest: Sha256Digest | None = None
    boundary_violation: StrictBool = False
    boundary_violation_evidence_digest: Sha256Digest | None = None
    reason: NonEmptyString | None = None
    terminal_at: datetime
    outcome_digest: Sha256Digest
    deploy_performed: Literal[False] = False

    _aware_terminal_at = field_validator("terminal_at")(_aware)

    @model_validator(mode="after")
    def validate_outcome(self) -> MainLedgerTerminalOutcome:
        if self.outcome != self.evidence_kind:
            raise ValueError("terminal outcome discriminator differs from evidence kind")
        if self.classification.classification != "eligible":
            raise ValueError("terminal outcome requires an eligible classification")
        if self.classification_digest != self.classification.classification_digest:
            raise ValueError("terminal outcome classification digest mismatch")
        if (
            self.classification.operation_id != self.operation_id
            or self.classification.submission_digest != self.submission_digest
            or self.classification.scheduler_sequence != self.scheduler_sequence
        ):
            raise ValueError("terminal outcome does not bind exact classification submission")
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
        if self.package_digest is not None:
            expected_package_binding = canonical_digest(
                {
                    "activation_digest": self.activation_digest,
                    "classification_digest": self.classification_digest,
                    "operation_id": self.operation_id,
                    "package_digest": self.package_digest,
                    "submission_digest": self.submission_digest,
                }
            )
            if self.package_binding_digest != expected_package_binding:
                raise ValueError("package binding does not bind exact terminal outcome")
        if self.boundary_violation != (self.boundary_violation_evidence_digest is not None):
            raise ValueError("boundary violation requires typed evidence")
        if self.boundary_violation and self.outcome == "success":
            raise ValueError("successful outcome cannot be a boundary violation")
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


def main_ledger_genesis_state(
    activation_digest: Sha256Digest, scheduler_sequence_watermark: int
) -> MainLedgerAccumulatorState:
    """Derive the only valid accumulator state at a frozen activation watermark."""

    values = {
        "schema_version": 2,
        "activation_digest": activation_digest,
        "last_scheduler_sequence": scheduler_sequence_watermark,
        "streak": 0,
        "successes": 0,
        "failures": 0,
        "boundary_violations": 0,
        "threshold_complete": False,
    }
    return MainLedgerAccumulatorState.model_validate(
        {**values, "state_digest": canonical_digest(values)}
    )


class MainLedgerAccumulatorTransition(StrictModel):
    """CAS transition for every submission, including an exclusion."""

    schema_version: Literal[2] = 2
    activation_digest: Sha256Digest
    classification: MainLedgerClassificationEvidence
    prior_state: MainLedgerAccumulatorState
    prior_state_digest: Sha256Digest
    outcome: MainLedgerTerminalOutcome | None = None
    outcome_digest: Sha256Digest | None = None
    reset_applied: StrictBool
    resulting_state: MainLedgerAccumulatorState
    resulting_state_digest: Sha256Digest
    transition_digest: Sha256Digest
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_transition(self) -> MainLedgerAccumulatorTransition:
        if self.prior_state_digest != self.prior_state.state_digest:
            raise ValueError("CAS prior state digest mismatch")
        if self.activation_digest != self.prior_state.activation_digest:
            raise ValueError("CAS activation binding differs")
        if self.classification.activation_digest != self.activation_digest:
            raise ValueError("CAS classification activation differs")
        if self.classification.scheduler_sequence != self.prior_state.last_scheduler_sequence + 1:
            raise ValueError("scheduler sequence has a gap")
        if self.resulting_state_digest != self.resulting_state.state_digest:
            raise ValueError("CAS resulting state digest mismatch")
        if self.resulting_state.activation_digest != self.activation_digest:
            raise ValueError("CAS resulting state activation differs")
        if self.classification.classification == "excluded":
            if self.outcome is not None or self.outcome_digest is not None or self.reset_applied:
                raise ValueError("excluded submission cannot have an outcome or reset")
            self._require_exclusion_counter_closure()
        else:
            if self.outcome is None or self.outcome_digest != self.outcome.outcome_digest:
                raise ValueError("eligible transition requires exactly one terminal outcome")
            if self.outcome.classification_digest != self.classification.classification_digest:
                raise ValueError("CAS outcome classification differs")
            if self.outcome.scheduler_sequence != self.classification.scheduler_sequence:
                raise ValueError("CAS outcome sequence differs from classification")
            self._validate_eligible_delta()
        if self.resulting_state.last_scheduler_sequence != self.classification.scheduler_sequence:
            raise ValueError("resulting state sequence differs from classification")
        if self.transition_digest != canonical_digest(
            self.model_dump(exclude={"transition_digest"}, mode="json")
        ):
            raise ValueError("accumulator transition digest mismatch")
        return self

    def _require_exclusion_counter_closure(self) -> None:
        prior = self.prior_state
        result = self.resulting_state
        if (
            result.streak != prior.streak
            or result.successes != prior.successes
            or result.failures != prior.failures
            or result.boundary_violations != prior.boundary_violations
            or result.threshold_complete != prior.threshold_complete
        ):
            raise ValueError("excluded transition must leave counters and streak unchanged")

    def _validate_eligible_delta(self) -> None:
        assert self.outcome is not None
        prior = self.prior_state
        result = self.resulting_state
        if self.outcome.boundary_violation:
            if not self.reset_applied or result.streak != 0:
                raise ValueError("boundary violation must reset threshold streak")
            if result.boundary_violations != prior.boundary_violations + 1:
                raise ValueError("boundary violation counter delta is not exact")
            if result.successes != prior.successes or result.failures != prior.failures:
                raise ValueError("boundary violation must not increment success/failure")
        elif self.outcome.outcome == "success":
            if self.reset_applied or prior.streak >= 12:
                raise ValueError("success must increment a non-complete threshold streak")
            if result.streak != prior.streak + 1 or result.successes != prior.successes + 1:
                raise ValueError("success streak/counter delta is not exact")
            if (
                result.failures != prior.failures
                or result.boundary_violations != prior.boundary_violations
            ):
                raise ValueError("success changed unrelated counters")
        else:
            if not self.reset_applied or result.streak != 0:
                raise ValueError("eligible non-success must reset threshold streak")
            if result.failures != prior.failures + 1:
                raise ValueError("eligible failure counter delta is not exact")
            if (
                result.successes != prior.successes
                or result.boundary_violations != prior.boundary_violations
            ):
                raise ValueError("eligible failure changed unrelated counters")


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
        identity_keys = [
            (
                item.activation_digest,
                item.source_identity,
                item.submission_identity,
            )
            for item in self.submissions
        ]
        if len(set(identity_keys)) != len(identity_keys):
            raise ValueError("duplicate scheduler submission identity")
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
            if classification.controller_authority != self.activation.controller_authority:
                raise ValueError("classification controller authority differs")
            expected += 1
        if len({item.scheduler_sequence for item in self.outcomes}) != len(self.outcomes):
            raise ValueError("terminal outcomes must be unique per scheduler sequence")
        if len({item.classification.scheduler_sequence for item in self.transitions}) != len(
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
        if len(self.transitions) != len(self.submissions):
            raise ValueError("every scheduler submission requires one CAS transition")
        genesis = main_ledger_genesis_state(
            self.activation.activation_digest,
            self.activation.scheduler_sequence_watermark,
        )
        expected_state = self.activation.scheduler_sequence_watermark
        transitions_by_sequence = {
            item.classification.scheduler_sequence: item for item in self.transitions
        }
        for index, transition in enumerate(self.transitions):
            if transition.prior_state.last_scheduler_sequence != expected_state:
                raise ValueError("CAS transitions are not contiguous")
            if index == 0 and transition.prior_state != genesis:
                raise ValueError("first CAS predecessor is not the canonical genesis state")
            if index > 0 and transition.prior_state != self.transitions[index - 1].resulting_state:
                raise ValueError("CAS predecessor differs from prior resulting state")
            expected_classification = self.classifications[
                transition.classification.scheduler_sequence
                - self.activation.scheduler_sequence_watermark
                - 1
            ]
            if transition.classification != expected_classification:
                raise ValueError("CAS transition classification differs")
            if transition.outcome is not None:
                if transition.outcome.scheduler_sequence not in outcome_by_sequence:
                    raise ValueError("CAS transition references an unknown outcome")
                if (
                    transition.outcome
                    != outcome_by_sequence[transition.classification.scheduler_sequence]
                ):
                    raise ValueError("CAS transition outcome differs")
            expected_state = transition.resulting_state.last_scheduler_sequence
        if set(transitions_by_sequence) != set(
            item.scheduler_sequence for item in self.submissions
        ):
            raise ValueError("CAS transitions do not cover every submission")
        transition_outcomes = {
            item.classification.scheduler_sequence: item.outcome
            for item in self.transitions
            if item.outcome is not None
        }
        if set(transition_outcomes) != set(outcome_by_sequence):
            raise ValueError("CAS outcome coverage differs from terminal outcome coverage")
        for sequence, outcome in transition_outcomes.items():
            if outcome != outcome_by_sequence[sequence]:
                raise ValueError("CAS outcome does not equal aggregate terminal outcome")
        if self.final_state.last_scheduler_sequence != expected_state:
            raise ValueError("final state does not close CAS transition chain")
        if self.final_state != self.transitions[-1].resulting_state:
            raise ValueError("final state does not equal the last CAS result")
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
MainLedgerActivationRecord = MainLedgerActivation
MainSchedulerSubmissionEnvelope = MainLedgerSubmissionEnvelope
MainControllerClassificationEvidence = MainLedgerClassificationEvidence
MainLedgerAttemptOutcome = MainLedgerTerminalOutcome
MainGraduationAttemptOutcome = MainLedgerTerminalOutcome
MainGraduationEligibilityOutcome = MainLedgerTerminalOutcome
MainLedgerThresholdAccumulatorState = MainLedgerAccumulatorState
MainLedgerThresholdAccumulatorTransition = MainLedgerAccumulatorTransition

__all__ = [
    "ControllerClassificationEvidenceV2",
    "LedgerActivationV2",
    "LedgerEvidencePackageV2",
    "LedgerOutcome",
    "LedgerSubmissionEnvelopeV2",
    "LedgerTerminalOutcomeV2",
    "MainControllerClassificationEvidence",
    "MainGraduationAccumulatorState",
    "MainGraduationAccumulatorStateV2",
    "MainGraduationAccumulatorTransition",
    "MainGraduationAccumulatorTransitionV2",
    "MainGraduationAttemptOutcome",
    "MainGraduationC8CapabilityEvidence",
    "MainGraduationC8CapabilityEvidenceV2",
    "MainGraduationClassificationEvidence",
    "MainGraduationClassificationEvidenceV2",
    "MainGraduationEligibilityOutcome",
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
    "MainLedgerActivationRecord",
    "MainLedgerActivationV2",
    "MainLedgerAttemptOutcome",
    "MainLedgerC8CapabilityEvidence",
    "MainLedgerC8CapabilityEvidenceV2",
    "MainLedgerClassificationEvidence",
    "MainLedgerClassificationEvidenceV2",
    "MainLedgerControllerAuthority",
    "MainLedgerEvidencePackage",
    "MainLedgerEvidencePackageV2",
    "MainLedgerHostedRollbackProof",
    "MainLedgerHostedRollbackProofV2",
    "MainLedgerSubmissionEnvelope",
    "MainLedgerSubmissionEnvelopeV2",
    "MainLedgerTerminalOutcome",
    "MainLedgerTerminalOutcomeV2",
    "MainLedgerThresholdAccumulatorState",
    "MainLedgerThresholdAccumulatorTransition",
    "MainSchedulerSubmissionEnvelope",
    "ThresholdAccumulatorStateV2",
    "ThresholdAccumulatorTransitionV2",
    "main_ledger_genesis_state",
]
