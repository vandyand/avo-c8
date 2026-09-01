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
    ArtifactRef,
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.contracts.promotion_policy import is_valid_promotion_path, path_manifest_digest
from avo_correlate.domain.canonical import canonical_digest

LedgerPath = Annotated[str, StringConstraints(min_length=1)]
LedgerOutcome = Literal["success", "failure", "quarantine", "reconciliation", "reset"]

CONTENT_ARTIFACT_ROLE = "scheduler-submission-content"
CONTENT_ARTIFACT_MEDIA_TYPE = "application/vnd.avo.scheduler-submission+json"
EXCLUSION_ARTIFACT_ROLE = "ledger-classification-exclusion-evidence"
EXCLUSION_ARTIFACT_MEDIA_TYPE = "application/vnd.avo.ledger-exclusion-evidence+json"
TERMINAL_ARTIFACT_ROLE = "ledger-terminal-evidence"
TERMINAL_ARTIFACT_MEDIA_TYPE = "application/vnd.avo.ledger-terminal-evidence+json"
BOUNDARY_ARTIFACT_ROLE = "ledger-boundary-violation-evidence"
BOUNDARY_ARTIFACT_MEDIA_TYPE = "application/vnd.avo.ledger-boundary-violation+json"
PACKAGE_ARTIFACT_ROLE = "integration-campaign-package"
PACKAGE_ARTIFACT_MEDIA_TYPE = "application/vnd.avo.integration-campaign+json"


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
    content_artifact: ArtifactRef
    operation_id: Sha256Digest
    recorded_at: datetime
    content_inspected: Literal[False] = False
    envelope_digest: Sha256Digest
    deploy_performed: Literal[False] = False

    _aware_recorded_at = field_validator("recorded_at")(_aware)

    @model_validator(mode="after")
    def validate_envelope(self) -> MainLedgerSubmissionEnvelope:
        if self.submission_digest != self.content_artifact.digest:
            raise ValueError("submission digest differs from content artifact")
        if self.content_artifact.role != CONTENT_ARTIFACT_ROLE:
            raise ValueError("submission content artifact has the wrong role")
        if self.content_artifact.media_type != CONTENT_ARTIFACT_MEDIA_TYPE:
            raise ValueError("submission content artifact has the wrong media type")
        if self.content_artifact.size_bytes <= 0:
            raise ValueError("submission content artifact cannot be empty")
        if self.content_artifact.created_at > self.recorded_at:
            raise ValueError("submission content artifact postdates its envelope")
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
    independent_exclusion_evidence: ArtifactRef | None = None
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
                or self.independent_exclusion_evidence is None
            ):
                raise ValueError("exclusions require independent controller evidence")
            evidence = self.independent_exclusion_evidence
            if (
                evidence.digest != self.independent_exclusion_evidence_digest
                or evidence.role != EXCLUSION_ARTIFACT_ROLE
                or evidence.media_type != EXCLUSION_ARTIFACT_MEDIA_TYPE
                or evidence.size_bytes <= 0
            ):
                raise ValueError("exclusion evidence artifact binding is invalid")
        elif (
            self.exclusion_reason is not None
            or self.independent_exclusion_evidence_digest is not None
            or self.independent_exclusion_evidence is not None
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
    terminal_evidence: ArtifactRef
    package_digest: Sha256Digest | None = None
    package_artifact: ArtifactRef | None = None
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
        if self.classification.classification != "eligible":
            raise ValueError("terminal outcome requires an eligible classification")
        if self.activation_digest != self.classification.activation_digest:
            raise ValueError("terminal outcome activation differs from classification")
        if self.terminal_evidence.digest != self.terminal_evidence_digest:
            raise ValueError("terminal evidence digest differs from artifact")
        if (
            self.terminal_evidence.role != TERMINAL_ARTIFACT_ROLE
            or self.terminal_evidence.media_type != TERMINAL_ARTIFACT_MEDIA_TYPE
            or self.terminal_evidence.size_bytes <= 0
        ):
            raise ValueError("terminal evidence artifact binding is invalid")
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
        if (self.package_digest is None) != (self.package_artifact is None):
            raise ValueError("package digest and package artifact must be supplied together")
        if self.package_digest is not None:
            assert self.package_artifact is not None
            if (
                self.package_artifact.digest != self.package_digest
                or self.package_artifact.role != PACKAGE_ARTIFACT_ROLE
                or self.package_artifact.media_type != PACKAGE_ARTIFACT_MEDIA_TYPE
                or self.package_artifact.size_bytes <= 0
            ):
                raise ValueError("package artifact binding is invalid")
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


class MainLedgerUnresolvedTailEntry(StrictModel):
    """One scheduler sequence which is intentionally left unresolved.

    An entry can carry the envelope itself (the compact prefix/tail form), or
    bind an envelope which is present in ``EvidencePackage.submissions`` by
    its immutable identities.  The latter form keeps each durable envelope in
    the package exactly once while still making the unresolved tail explicit.
    An entry with no envelope or identities is the missing-envelope
    (starvation) form.
    """

    schema_version: Literal[2] = 2
    scheduler_sequence: StrictInt = Field(gt=0)
    envelope: MainLedgerSubmissionEnvelope | None = None
    submission_digest: Sha256Digest | None = None
    operation_id: Sha256Digest | None = None
    envelope_digest: Sha256Digest | None = None
    content_artifact: ArtifactRef | None = None
    entry_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_tail_entry(self) -> MainLedgerUnresolvedTailEntry:
        supplied = (
            self.submission_digest,
            self.operation_id,
            self.envelope_digest,
            self.content_artifact,
        )
        if self.envelope is None:
            if any(item is not None for item in supplied) and not all(
                item is not None for item in supplied
            ):
                raise ValueError("unresolved envelope identity is incomplete")
            if all(item is not None for item in supplied):
                assert self.content_artifact is not None
                if self.content_artifact.digest != self.submission_digest:
                    raise ValueError("unresolved content artifact differs from submission")
        else:
            expected = (
                self.envelope.submission_digest,
                self.envelope.operation_id,
                self.envelope.envelope_digest,
                self.envelope.content_artifact,
            )
            if any(item is not None for item in supplied) and supplied != expected:
                raise ValueError("unresolved envelope identity differs from envelope")
        if self.entry_digest != canonical_digest(
            self.model_dump(exclude={"entry_digest"}, mode="json")
        ):
            raise ValueError("unresolved tail entry digest mismatch")
        return self

    @property
    def has_envelope_identity(self) -> bool:
        return self.envelope is not None or self.submission_digest is not None


# The shorter name is useful to callers and preserves the terminology used
# by the ledger runbook.  Both names refer to the same canonical schema.
MainLedgerUnresolvedSubmission = MainLedgerUnresolvedTailEntry


class MainLedgerBoundaryViolationEvidence(StrictModel):
    """Controller-owned, out-of-band proof that an activation must terminate."""

    schema_version: Literal[2] = 2
    activation_digest: Sha256Digest
    controller_authority: MainLedgerControllerAuthority
    expected_scheduler_sequence: StrictInt = Field(gt=0)
    current_state_digest: Sha256Digest
    violation_kind: Literal[
        "starvation",
        "withholding",
        "silent_exclusion",
        "scheduler_gap",
        "operator_intervention",
    ]
    # These are deliberately identity-only references.  The journal's
    # verifier remains authoritative; these fields merely make the boundary
    # evidence unambiguous when a durable envelope is being withheld.
    submission_digest: Sha256Digest | None = None
    operation_id: Sha256Digest | None = None
    envelope_digest: Sha256Digest | None = None
    content_artifact: ArtifactRef | None = None
    evidence_artifact: ArtifactRef
    detected_at: datetime
    violation_digest: Sha256Digest

    _aware_detected_at = field_validator("detected_at")(_aware)

    @model_validator(mode="after")
    def validate_violation(self) -> MainLedgerBoundaryViolationEvidence:
        authority = self.controller_authority
        if not authority.authorized_at <= self.detected_at <= authority.expires_at:
            raise ValueError("boundary evidence is outside controller authority window")
        if self.expected_scheduler_sequence <= 0:
            raise ValueError("boundary evidence expected sequence must be positive")
        identities = (
            self.submission_digest,
            self.operation_id,
            self.envelope_digest,
            self.content_artifact,
        )
        if any(item is not None for item in identities) and not all(
            item is not None for item in identities
        ):
            raise ValueError("boundary envelope identity is incomplete")
        if (
            self.content_artifact is not None
            and self.content_artifact.digest != self.submission_digest
        ):
            raise ValueError("boundary content artifact differs from submission")
        evidence = self.evidence_artifact
        if (
            evidence.role != BOUNDARY_ARTIFACT_ROLE
            or evidence.media_type != BOUNDARY_ARTIFACT_MEDIA_TYPE
            or evidence.size_bytes <= 0
            or evidence.created_at > self.detected_at
        ):
            raise ValueError("boundary evidence artifact binding is invalid")
        if self.violation_digest != canonical_digest(
            self.model_dump(exclude={"violation_digest"}, mode="json")
        ):
            raise ValueError("boundary violation digest mismatch")
        return self


class MainLedgerBoundaryResetTransition(StrictModel):
    """Terminal CAS reset that preserves sequence and increments only boundaries."""

    schema_version: Literal[2] = 2
    activation_digest: Sha256Digest
    prior_state: MainLedgerAccumulatorState
    prior_state_digest: Sha256Digest
    violation: MainLedgerBoundaryViolationEvidence
    resulting_state: MainLedgerAccumulatorState
    resulting_state_digest: Sha256Digest
    transition_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_reset(self) -> MainLedgerBoundaryResetTransition:
        if self.prior_state_digest != self.prior_state.state_digest:
            raise ValueError("boundary reset prior state digest mismatch")
        if self.activation_digest != self.prior_state.activation_digest:
            raise ValueError("boundary reset activation differs from prior state")
        if self.violation.activation_digest != self.activation_digest:
            raise ValueError("boundary violation activation differs from reset")
        if self.violation.current_state_digest != self.prior_state.state_digest:
            raise ValueError("boundary violation current state differs from reset predecessor")
        if self.violation.expected_scheduler_sequence <= self.prior_state.last_scheduler_sequence:
            raise ValueError("boundary violation expected sequence is not after current state")
        if self.resulting_state_digest != self.resulting_state.state_digest:
            raise ValueError("boundary reset resulting state digest mismatch")
        if (
            self.resulting_state.activation_digest != self.activation_digest
            or self.resulting_state.last_scheduler_sequence
            != self.prior_state.last_scheduler_sequence
            or self.resulting_state.streak != 0
            or self.resulting_state.successes != self.prior_state.successes
            or self.resulting_state.failures != self.prior_state.failures
            or self.resulting_state.boundary_violations != self.prior_state.boundary_violations + 1
            or self.resulting_state.threshold_complete
        ):
            raise ValueError("boundary reset state delta is not exact")
        if self.transition_digest != canonical_digest(
            self.model_dump(exclude={"transition_digest"}, mode="json")
        ):
            raise ValueError("boundary reset transition digest mismatch")
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
        if self.prior_state.threshold_complete:
            raise ValueError("CAS transition cannot follow threshold completion")
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
            if self.outcome.activation_digest != self.activation_digest:
                raise ValueError("CAS outcome activation differs from transition")
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
        if self.outcome.outcome == "success":
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
    status: Literal["threshold_complete", "boundary_reset"]
    activation: MainLedgerActivation
    submissions: list[MainLedgerSubmissionEnvelope] = Field(
        default_factory=list[MainLedgerSubmissionEnvelope]
    )
    classifications: list[MainLedgerClassificationEvidence] = Field(
        default_factory=list[MainLedgerClassificationEvidence]
    )
    outcomes: list[MainLedgerTerminalOutcome] = Field(
        default_factory=list[MainLedgerTerminalOutcome]
    )
    transitions: list[MainLedgerAccumulatorTransition] = Field(
        default_factory=list[MainLedgerAccumulatorTransition]
    )
    # Durable envelopes after the processed prefix are represented here as a
    # typed unresolved tail.  ``submissions`` remains the durable envelope
    # inventory, so identity-only entries do not duplicate those envelopes.
    unresolved_tail: list[MainLedgerUnresolvedTailEntry] = Field(
        default_factory=list[MainLedgerUnresolvedTailEntry]
    )
    final_state: MainLedgerAccumulatorState
    boundary_evidence: MainLedgerBoundaryViolationEvidence | None = None
    terminal_boundary_reset: MainLedgerBoundaryResetTransition | None = None
    package_digest: Sha256Digest
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_package(self) -> MainLedgerEvidencePackage:
        if self.status == "threshold_complete" and (
            self.boundary_evidence is not None
            or self.terminal_boundary_reset is not None
            or self.unresolved_tail
        ):
            raise ValueError(
                "threshold-complete package cannot contain unresolved boundary evidence"
            )
        if self.status == "boundary_reset" and (
            self.boundary_evidence is None or self.terminal_boundary_reset is None
        ):
            raise ValueError("boundary-reset package requires boundary evidence and reset")
        if self.activation.activation_digest != self.final_state.activation_digest:
            raise ValueError("ledger final state activation differs")
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
        submission_digests = [item.submission_digest for item in self.submissions]
        content_digests = [item.content_artifact.digest for item in self.submissions]
        if len(set(submission_digests)) != len(submission_digests):
            raise ValueError("duplicate physical submission content")
        if len(set(content_digests)) != len(content_digests):
            raise ValueError("duplicate physical submission artifact")
        watermark = self.activation.scheduler_sequence_watermark
        first_expected = watermark + 1
        expected = first_expected
        by_sequence = {item.scheduler_sequence: item for item in self.submissions}
        if len(by_sequence) != len(self.submissions):
            raise ValueError("duplicate scheduler submission sequence")
        by_submission = {item.submission_digest: item for item in self.submissions}
        for submission in self.submissions:
            if submission.activation_digest != self.activation.activation_digest:
                raise ValueError("submission activation differs")
            if (
                submission.repository_digest != self.activation.repository_digest
                or submission.target_ref != self.activation.target_ref
            ):
                raise ValueError("submission repository target differs from activation")
            if submission.scheduler_sequence != expected:
                raise ValueError("ledger scheduler sequence has a gap")
            expected += 1
        # A boundary package's classifications/transitions are exactly the
        # processed prefix.  A threshold package has no unresolved tail and
        # therefore retains the original all-submissions closure.
        if self.status == "boundary_reset":
            assert self.boundary_evidence is not None
            first_unresolved = self.boundary_evidence.expected_scheduler_sequence
            prefix_count = first_unresolved - watermark - 1
            if prefix_count < 0:
                raise ValueError("boundary expected sequence precedes activation watermark")
            prefix_submissions = [
                item for item in self.submissions if item.scheduler_sequence < first_unresolved
            ]
            if [item.scheduler_sequence for item in prefix_submissions] != list(
                range(first_expected, first_unresolved)
            ):
                raise ValueError("processed submissions are not a contiguous prefix")
            if any(item.scheduler_sequence >= first_unresolved for item in prefix_submissions):
                raise ValueError("unresolved submission precedes processed prefix")
            expected_classified_count = prefix_count
        else:
            prefix_submissions = self.submissions
            expected_classified_count = len(self.submissions)
            if [item.scheduler_sequence for item in self.submissions] != list(
                range(first_expected, first_expected + len(self.submissions))
            ):
                raise ValueError("ledger scheduler sequence has a gap")
        if len(self.classifications) != expected_classified_count:
            if self.status == "boundary_reset":
                raise ValueError("every processed submission requires controller classification")
            raise ValueError("every submission requires controller classification")
        for submission, classification in zip(
            prefix_submissions, self.classifications, strict=True
        ):
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
        if len(self.transitions) != expected_classified_count:
            raise ValueError("every processed submission requires one CAS transition")
        genesis = main_ledger_genesis_state(
            self.activation.activation_digest,
            self.activation.scheduler_sequence_watermark,
        )
        expected_state = self.activation.scheduler_sequence_watermark
        classification_by_sequence = {
            item.scheduler_sequence: item for item in self.classifications
        }
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
            expected_classification = classification_by_sequence.get(
                transition.classification.scheduler_sequence
            )
            if expected_classification is None:
                raise ValueError("CAS transition references an unknown classification")
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
        if set(transitions_by_sequence) != {
            item.scheduler_sequence for item in prefix_submissions
        }:
            raise ValueError("CAS transitions do not cover every processed submission")
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
        normal_final_state = self.transitions[-1].resulting_state if self.transitions else genesis
        if self.status == "boundary_reset":
            assert self.boundary_evidence is not None
            assert self.terminal_boundary_reset is not None
            tail = self.unresolved_tail
            tail_sequences = [item.scheduler_sequence for item in tail]
            if tail_sequences != list(
                range(self.boundary_evidence.expected_scheduler_sequence,
                      self.boundary_evidence.expected_scheduler_sequence + len(tail))
            ) and (tail or self.boundary_evidence.expected_scheduler_sequence != watermark + 1):
                # Keep the empty pre-submission closure accepted for the
                # historical boundary-reset form; all non-empty tails must
                # be explicit and contiguous.
                raise ValueError("unresolved tail is not contiguous from expected sequence")
            tail_digests: set[str] = set()
            tail_content_digests: set[str] = set()
            for entry in tail:
                if entry.envelope is not None:
                    if entry.envelope.scheduler_sequence != entry.scheduler_sequence:
                        raise ValueError("unresolved envelope sequence differs from tail")
                    if entry.scheduler_sequence in by_sequence:
                        raise ValueError("unresolved envelope is duplicated in submissions")
                    if (
                        entry.envelope.activation_digest != self.activation.activation_digest
                        or entry.envelope.repository_digest != self.activation.repository_digest
                        or entry.envelope.target_ref != self.activation.target_ref
                    ):
                        raise ValueError("unresolved envelope target differs from activation")
                    if (
                        entry.envelope.submission_digest in by_submission
                        or entry.envelope.submission_digest in tail_digests
                    ):
                        raise ValueError("duplicate unresolved submission content")
                    if entry.envelope.content_artifact.digest in tail_content_digests or any(
                        item.content_artifact.digest == entry.envelope.content_artifact.digest
                        for item in self.submissions
                    ):
                        raise ValueError("duplicate unresolved submission artifact")
                    tail_digests.add(entry.envelope.submission_digest)
                    tail_content_digests.add(entry.envelope.content_artifact.digest)
                elif entry.has_envelope_identity:
                    envelope = by_sequence.get(entry.scheduler_sequence)
                    if envelope is None:
                        raise ValueError(
                            "unresolved envelope identity references unknown submission"
                        )
                    identity = (
                        envelope.submission_digest,
                        envelope.operation_id,
                        envelope.envelope_digest,
                        envelope.content_artifact,
                    )
                    if (
                        entry.submission_digest,
                        entry.operation_id,
                        entry.envelope_digest,
                        entry.content_artifact,
                    ) != identity:
                        raise ValueError("unresolved envelope identity does not match submission")
                elif entry.scheduler_sequence > self.boundary_evidence.expected_scheduler_sequence:
                    raise ValueError("missing envelope may only be the first unresolved sequence")
            if (
                tail
                and tail[0].envelope is None
                and not tail[0].has_envelope_identity
                and len(tail) > 1
            ):
                raise ValueError("missing envelope may only be the first unresolved sequence")
            # A durable envelope after the prefix must appear in the tail;
            # envelopes in the prefix are the only permitted inventory before
            # the boundary.
            for sequence in by_sequence:
                if (
                    sequence >= self.boundary_evidence.expected_scheduler_sequence
                    and sequence not in {item.scheduler_sequence for item in tail}
                ):
                    raise ValueError("durable unresolved submission is omitted from tail")
            first = tail[0] if tail else None
            first_identity = (None, None, None, None)
            if first is not None:
                if first.envelope is not None:
                    envelope = first.envelope
                    first_identity = (
                        envelope.submission_digest,
                        envelope.operation_id,
                        envelope.envelope_digest,
                        envelope.content_artifact,
                    )
                elif first.has_envelope_identity:
                    first_identity = (
                        first.submission_digest,
                        first.operation_id,
                        first.envelope_digest,
                        first.content_artifact,
                    )
            evidence_identity = (
                self.boundary_evidence.submission_digest,
                self.boundary_evidence.operation_id,
                self.boundary_evidence.envelope_digest,
                self.boundary_evidence.content_artifact,
            )
            if first_identity != evidence_identity:
                raise ValueError("boundary evidence does not bind first unresolved submission")
            if (
                self.boundary_evidence.activation_digest != self.activation.activation_digest
                or self.boundary_evidence.controller_authority
                != self.activation.controller_authority
                or self.boundary_evidence.detected_at < self.activation.freshness_cutoff
                or self.boundary_evidence.detected_at < self.activation.activated_at
                or self.boundary_evidence.detected_at
                > self.activation.controller_authority.expires_at
            ):
                raise ValueError("boundary evidence is not bound to active controller root")
            if self.boundary_evidence != self.terminal_boundary_reset.violation:
                raise ValueError("boundary evidence differs from terminal reset violation")
            if self.terminal_boundary_reset.prior_state != normal_final_state:
                raise ValueError("boundary reset predecessor differs from normal ledger state")
            if self.final_state != self.terminal_boundary_reset.resulting_state:
                raise ValueError("final state does not equal terminal boundary reset")
            if self.final_state.threshold_complete:
                raise ValueError("boundary-reset package cannot complete threshold")
        else:
            if self.final_state != normal_final_state:
                raise ValueError("final state does not equal the last CAS result")
            if not self.final_state.threshold_complete:
                raise ValueError("threshold-complete package has not reached threshold")
        if self.final_state.last_scheduler_sequence != expected_state and (
            self.status != "boundary_reset"
            or self.final_state.last_scheduler_sequence
            != normal_final_state.last_scheduler_sequence
        ):
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
    "MainLedgerBoundaryResetTransition",
    "MainLedgerBoundaryViolationEvidence",
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
    "MainLedgerUnresolvedSubmission",
    "MainLedgerUnresolvedTailEntry",
    "MainSchedulerSubmissionEnvelope",
    "ThresholdAccumulatorStateV2",
    "ThresholdAccumulatorTransitionV2",
    "main_ledger_genesis_state",
]
