"""Offline contracts for one controller-authorized personal main CAS.

These records are deliberately separate from the hosted transport DTOs.  They
describe the durable authority and recovery chain around one exact, non-force
compare-and-swap of ``refs/heads/main`` from B to C.  They contain no token,
HTTP, provider, queue, hold, release, or generic-ref capability.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal, cast

from pydantic import (
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)

from avo_correlate.contracts.base import ArtifactRef, NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.domain.canonical import canonical_digest

MainRef = Literal["refs/heads/main"]
GitObject = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")]
CandidateRef = Annotated[str, StringConstraints(pattern=r"^refs/heads/avo/candidate/[0-9a-f]{64}$")]
PersonalCasOutcome = Literal["applied", "rejected", "ambiguous"]
PersonalCasErrorCode = Literal[
    "cas_conflict",
    "auth_failed",
    "protection_failed",
    "configuration_failed",
    "lease_expired",
    "malformed_response",
    "stale_response",
    "server_ambiguous",
    "transport_ambiguous",
    "reconciliation_unverified",
]
_ZERO = "sha256:" + "0" * 64


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value


def personal_cas_claim_digest(
    *,
    operation_id: str,
    lease_identity: str,
    lease_digest: str,
    lease_expires_at: datetime,
    claim_nonce: str,
) -> Sha256Digest:
    return canonical_digest(
        {
            "operation_id": operation_id,
            "lease_identity": lease_identity,
            "lease_digest": lease_digest,
            "lease_expires_at": lease_expires_at.isoformat(),
            "claim_nonce": claim_nonce,
            "one_use": True,
        }
    )


def personal_cas_operation_id(
    *,
    activation_digest: str,
    repository_digest: str,
    target_ref: str,
    source_operation_id: str,
    source_plan_digest: str,
    source_composition_digest: str,
    base_commit: str,
    base_tree: str,
    candidate_commit: str,
    candidate_tree: str,
    candidate_ref: str,
    candidate_parents: tuple[str, ...],
    protection_ruleset_digest: str,
    writer_app_id: int,
    writer_installation_id: int,
    writer_identity: str,
    lease_identity: str,
    lease_digest: str,
    lease_expires_at: datetime,
    claim_nonce: str,
) -> Sha256Digest:
    return canonical_digest(
        {
            "activation_digest": activation_digest,
            "repository_digest": repository_digest,
            "target_ref": target_ref,
            "source_operation_id": source_operation_id,
            "source_plan_digest": source_plan_digest,
            "source_composition_digest": source_composition_digest,
            "base_commit": base_commit,
            "base_tree": base_tree,
            "candidate_commit": candidate_commit,
            "candidate_tree": candidate_tree,
            "candidate_ref": candidate_ref,
            "candidate_parents": list(candidate_parents),
            "protection_ruleset_digest": protection_ruleset_digest,
            "writer_app_id": writer_app_id,
            "writer_installation_id": writer_installation_id,
            "writer_identity": writer_identity,
            "lease_identity": lease_identity,
            "lease_digest": lease_digest,
            "lease_expires_at": lease_expires_at.isoformat(),
            "claim_nonce": claim_nonce,
        }
    )


def _build_digest(model: type[StrictModel], values: dict[str, object], field: str) -> StrictModel:
    probe_values = dict(values)
    probe_values[field] = _ZERO
    probe = cast(Any, model).model_construct(**probe_values)
    return model.model_validate(
        values | {field: canonical_digest(probe.model_dump(exclude={field}, mode="json"))}
    )


class MainPersonalExactCasActivation(StrictModel):
    """Frozen activation binding an accepted trusted source to personal CAS."""

    schema_version: Literal[1] = 1
    activation_digest: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"
    source_operation_id: Sha256Digest
    source_plan_digest: Sha256Digest
    source_plan_artifact: ArtifactRef
    source_package_digest: Sha256Digest
    source_composition_digest: Sha256Digest
    base_commit: GitObject
    base_tree: GitObject
    candidate_commit: GitObject
    candidate_tree: GitObject
    candidate_ref: CandidateRef
    candidate_parents: tuple[GitObject, ...]
    candidate_ref_immutable: StrictBool = True
    candidate_reachable: StrictBool = True
    protection_ruleset_digest: Sha256Digest
    writer_app_id: StrictInt = Field(gt=0)
    writer_installation_id: StrictInt = Field(gt=0)
    writer_identity: NonEmptyString
    activated_at: datetime
    deploy_performed: Literal[False] = False

    _aware_activated_at = field_validator("activated_at")(_aware)

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasActivation:
        return cast(MainPersonalExactCasActivation, _build_digest(cls, values, "activation_digest"))

    @model_validator(mode="after")
    def validate_activation(self) -> MainPersonalExactCasActivation:
        if self.candidate_parents != (self.base_commit,):
            raise ValueError("personal CAS candidate must have B as its sole parent")
        if not self.candidate_ref_immutable or not self.candidate_reachable:
            raise ValueError("personal CAS candidate ref must be immutable and reachable")
        if (
            self.source_plan_artifact.digest != self.source_plan_digest
            or self.source_plan_artifact.role != "main-graduation-plan"
            or self.source_plan_artifact.media_type
            != "application/vnd.avo.main-graduation-plan+json"
        ):
            raise ValueError("trusted source plan artifact is not exact")
        if self.activation_digest != canonical_digest(
            self.model_dump(exclude={"activation_digest"}, mode="json")
        ):
            raise ValueError("personal CAS activation digest mismatch")
        return self


class _PersonalExactCasOperationBinding(StrictModel):
    """Shared immutable operation/source/topology scope."""

    schema_version: Literal[1] = 1
    activation_digest: Sha256Digest
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"
    source_operation_id: Sha256Digest
    source_plan_digest: Sha256Digest
    source_package_digest: Sha256Digest
    source_composition_digest: Sha256Digest
    base_commit: GitObject
    base_tree: GitObject
    candidate_commit: GitObject
    candidate_tree: GitObject
    candidate_ref: CandidateRef
    candidate_parents: tuple[GitObject, ...]
    protection_ruleset_digest: Sha256Digest
    writer_app_id: StrictInt = Field(gt=0)
    writer_installation_id: StrictInt = Field(gt=0)
    writer_identity: NonEmptyString
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    lease_expires_at: datetime
    claim_nonce: NonEmptyString
    claim_digest: Sha256Digest
    one_use: Literal[True] = True
    deploy_performed: Literal[False] = False

    _aware_lease_expires_at = field_validator("lease_expires_at")(_aware)

    @model_validator(mode="after")
    def validate_scope(self) -> _PersonalExactCasOperationBinding:
        if self.candidate_parents != (self.base_commit,):
            raise ValueError("personal CAS candidate must have B as its sole parent")
        if self.claim_digest != personal_cas_claim_digest(
            operation_id=self.operation_id,
            lease_identity=self.lease_identity,
            lease_digest=self.lease_digest,
            lease_expires_at=self.lease_expires_at,
            claim_nonce=self.claim_nonce,
        ):
            raise ValueError("personal CAS claim digest mismatch")
        if self.operation_id != personal_cas_operation_id(
            activation_digest=self.activation_digest,
            repository_digest=self.repository_digest,
            target_ref=self.target_ref,
            source_operation_id=self.source_operation_id,
            source_plan_digest=self.source_plan_digest,
            source_composition_digest=self.source_composition_digest,
            base_commit=self.base_commit,
            base_tree=self.base_tree,
            candidate_commit=self.candidate_commit,
            candidate_tree=self.candidate_tree,
            candidate_ref=self.candidate_ref,
            candidate_parents=self.candidate_parents,
            protection_ruleset_digest=self.protection_ruleset_digest,
            writer_app_id=self.writer_app_id,
            writer_installation_id=self.writer_installation_id,
            writer_identity=self.writer_identity,
            lease_identity=self.lease_identity,
            lease_digest=self.lease_digest,
            lease_expires_at=self.lease_expires_at,
            claim_nonce=self.claim_nonce,
        ):
            raise ValueError("personal CAS operation identity mismatch")
        return self


class MainPersonalExactCasAuthorization(_PersonalExactCasOperationBinding):
    """Controller-issued precondition/authorization; not dispatch authority."""

    authorized_at: datetime
    authorization_digest: Sha256Digest

    _aware_authorized_at = field_validator("authorized_at")(_aware)

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasAuthorization:
        return cast(
            MainPersonalExactCasAuthorization, _build_digest(cls, values, "authorization_digest")
        )

    @model_validator(mode="after")
    def validate_authorization(self) -> MainPersonalExactCasAuthorization:
        if self.authorized_at >= self.lease_expires_at:
            raise ValueError("authorization must precede lease expiry")
        if self.authorization_digest != canonical_digest(
            self.model_dump(exclude={"authorization_digest"}, mode="json")
        ):
            raise ValueError("personal CAS authorization digest mismatch")
        return self


class MainPersonalExactCasIntent(_PersonalExactCasOperationBinding):
    """Intent committed before any dispatch-start marker can exist."""

    authorization_digest: Sha256Digest
    recorded_at: datetime
    intent_digest: Sha256Digest

    _aware_recorded_at = field_validator("recorded_at")(_aware)

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasIntent:
        return cast(MainPersonalExactCasIntent, _build_digest(cls, values, "intent_digest"))

    @model_validator(mode="after")
    def validate_intent(self) -> MainPersonalExactCasIntent:
        if self.recorded_at >= self.lease_expires_at:
            raise ValueError("intent must precede lease expiry")
        if self.intent_digest != canonical_digest(
            self.model_dump(exclude={"intent_digest"}, mode="json")
        ):
            raise ValueError("personal CAS intent digest mismatch")
        return self


class MainPersonalExactCasDispatchStarted(_PersonalExactCasOperationBinding):
    """Durable marker proving the sole provider dispatch may have started."""

    intent_digest: Sha256Digest
    started_at: datetime
    dispatch_marker_digest: Sha256Digest

    _aware_started_at = field_validator("started_at")(_aware)

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasDispatchStarted:
        return cast(
            MainPersonalExactCasDispatchStarted,
            _build_digest(cls, values, "dispatch_marker_digest"),
        )

    @model_validator(mode="after")
    def validate_marker(self) -> MainPersonalExactCasDispatchStarted:
        if self.started_at >= self.lease_expires_at:
            raise ValueError("dispatch marker must precede lease expiry")
        if self.dispatch_marker_digest != canonical_digest(
            self.model_dump(exclude={"dispatch_marker_digest"}, mode="json")
        ):
            raise ValueError("dispatch marker digest mismatch")
        return self


class MainPersonalExactCasReceipt(_PersonalExactCasOperationBinding):
    """Create-once dispatch outcome; ambiguity remains unresolved."""

    authorization_digest: Sha256Digest
    intent_digest: Sha256Digest
    dispatch_marker_digest: Sha256Digest
    response_digest: Sha256Digest
    outcome: PersonalCasOutcome
    dispatch_started: StrictBool
    error_code: PersonalCasErrorCode | None = None
    http_status: StrictInt | None = Field(default=None, ge=100, le=599)
    request_id: NonEmptyString | None = None
    observed_at: datetime
    receipt_digest: Sha256Digest

    _aware_observed_at = field_validator("observed_at")(_aware)

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasReceipt:
        return cast(MainPersonalExactCasReceipt, _build_digest(cls, values, "receipt_digest"))

    @model_validator(mode="after")
    def validate_receipt(self) -> MainPersonalExactCasReceipt:
        if self.observed_at < self.lease_expires_at and not self.dispatch_started:
            # A pre-dispatch rejection is valid, but it may not claim a started call.
            pass
        if self.outcome == "ambiguous" and not self.dispatch_started:
            raise ValueError("ambiguous receipt requires dispatch-start marker")
        if self.outcome == "applied" and not self.dispatch_started:
            raise ValueError("applied receipt requires dispatch-start marker")
        if self.receipt_digest != canonical_digest(
            self.model_dump(exclude={"receipt_digest"}, mode="json")
        ):
            raise ValueError("personal CAS receipt digest mismatch")
        return self


class MainPersonalExactCasPostStateObservation(_PersonalExactCasOperationBinding):
    """Authenticated read-only observation of main after dispatch."""

    authorization_digest: Sha256Digest
    intent_digest: Sha256Digest
    receipt_digest: Sha256Digest
    receipt_outcome: PersonalCasOutcome
    observed_ref: MainRef
    observed_commit: GitObject
    observed_tree: GitObject
    observed_parents: tuple[GitObject, ...]
    observed_at: datetime
    observation_digest: Sha256Digest

    _aware_observed_at = field_validator("observed_at")(_aware)

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasPostStateObservation:
        return cast(
            MainPersonalExactCasPostStateObservation,
            _build_digest(cls, values, "observation_digest"),
        )

    @model_validator(mode="after")
    def validate_post_state(self) -> MainPersonalExactCasPostStateObservation:
        if self.receipt_outcome == "applied" and (
            self.observed_commit != self.candidate_commit
            or self.observed_tree != self.candidate_tree
            or self.observed_parents != (self.base_commit,)
        ):
            raise ValueError("applied post-state is not exact B-to-C topology")
        if self.observation_digest != canonical_digest(
            self.model_dump(exclude={"observation_digest"}, mode="json")
        ):
            raise ValueError("personal CAS post-state digest mismatch")
        return self


class MainPersonalExactCasReconciliation(StrictModel):
    """Read-only recovery result preserving the original ambiguous receipt."""

    schema_version: Literal[1] = 1
    activation_digest: Sha256Digest
    operation_id: Sha256Digest
    ambiguous_receipt: MainPersonalExactCasReceipt
    observation: MainPersonalExactCasPostStateObservation
    outcome: Literal["applied", "ambiguous"]
    reconciled_at: datetime
    reconciliation_digest: Sha256Digest

    _aware_reconciled_at = field_validator("reconciled_at")(_aware)

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasReconciliation:
        return cast(
            MainPersonalExactCasReconciliation,
            _build_digest(cls, values, "reconciliation_digest"),
        )

    @model_validator(mode="after")
    def validate_reconciliation(self) -> MainPersonalExactCasReconciliation:
        if (
            self.ambiguous_receipt.outcome != "ambiguous"
            or self.operation_id != self.ambiguous_receipt.operation_id
            or self.activation_digest != self.ambiguous_receipt.activation_digest
            or self.observation.operation_id != self.operation_id
            or self.observation.receipt_digest != self.ambiguous_receipt.receipt_digest
        ):
            raise ValueError("personal CAS reconciliation binding differs")
        exact = (
            self.observation.observed_commit == self.observation.candidate_commit
            and self.observation.observed_tree == self.observation.candidate_tree
            and self.observation.observed_parents == (self.observation.base_commit,)
        )
        if self.outcome == "applied" and not exact:
            raise ValueError("applied reconciliation lacks exact topology")
        if self.reconciliation_digest != canonical_digest(
            self.model_dump(exclude={"reconciliation_digest"}, mode="json")
        ):
            raise ValueError("personal CAS reconciliation digest mismatch")
        return self


class MainPersonalExactCasCompletion(StrictModel):
    """Terminal evidence that cannot be self-attested as successful."""

    schema_version: Literal[1] = 1
    activation_digest: Sha256Digest
    operation_id: Sha256Digest
    receipt_digest: Sha256Digest
    post_state_observation_digest: Sha256Digest
    reconciliation_digest: Sha256Digest | None = None
    outcome: Literal["applied"]
    completed_at: datetime
    completion_digest: Sha256Digest

    _aware_completed_at = field_validator("completed_at")(_aware)

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasCompletion:
        return cast(MainPersonalExactCasCompletion, _build_digest(cls, values, "completion_digest"))

    @model_validator(mode="after")
    def validate_completion(self) -> MainPersonalExactCasCompletion:
        if self.completion_digest != canonical_digest(
            self.model_dump(exclude={"completion_digest"}, mode="json")
        ):
            raise ValueError("personal CAS completion digest mismatch")
        return self


__all__ = [
    "CandidateRef",
    "GitObject",
    "MainPersonalExactCasActivation",
    "MainPersonalExactCasAuthorization",
    "MainPersonalExactCasCompletion",
    "MainPersonalExactCasDispatchStarted",
    "MainPersonalExactCasIntent",
    "MainPersonalExactCasPostStateObservation",
    "MainPersonalExactCasReceipt",
    "MainPersonalExactCasReconciliation",
    "MainRef",
    "PersonalCasErrorCode",
    "PersonalCasOutcome",
    "personal_cas_claim_digest",
    "personal_cas_operation_id",
]
