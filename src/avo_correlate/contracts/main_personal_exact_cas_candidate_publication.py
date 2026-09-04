"""Offline, non-authoritative contracts for one candidate-ref creation.

The operation-derived ref and commit are immutable inputs.  These records do
not grant readiness, completion, deployment, or any other authority.
"""
# ruff: noqa: E501

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Self, cast

from pydantic import Field, StrictInt, field_validator, model_validator

from avo_correlate.contracts.base import (
    ArtifactRef,
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.contracts.main_personal_exact_cas import GitObject
from avo_correlate.contracts.main_personal_exact_cas_candidate_observation import (
    candidate_ref_for_operation,
)
from avo_correlate.domain.canonical import canonical_digest

_ZERO = "sha256:" + "0" * 64


def candidate_publication_request_digest(
    *, repository_digest: str, repository_id: int, candidate_ref: str, candidate_commit: str
) -> Sha256Digest:
    return canonical_digest(
        {
            "repository_digest": repository_digest,
            "repository_id": repository_id,
            "method": "POST",
            "path": "/repos/vandyand/avo-c8/git/refs",
            "body": {"ref": candidate_ref, "sha": candidate_commit},
        }
    )


class CandidatePublisherRequestTrace(StrictModel):
    method: Literal["GET", "POST"]
    path: NonEmptyString
    credential_role: Literal["app_jwt", "installation_token"]


class MainPersonalExactCasCandidatePublicationIntent(StrictModel):
    """Create-once intent for exactly one candidate namespace ref."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    repository_id: StrictInt = Field(gt=0)
    candidate_ref: NonEmptyString
    base_commit: GitObject
    candidate_commit: GitObject
    candidate_tree: GitObject
    candidate_parents: tuple[GitObject, ...]
    source_composition_digest: Sha256Digest
    verified_policy_digest: Sha256Digest
    configuration_digest: Sha256Digest
    publisher_app_id: StrictInt = Field(gt=0)
    publisher_installation_id: StrictInt = Field(gt=0)
    publisher_identity: Literal["avo-c8-candidate-publisher-vandyand"]
    intent_created_at: datetime
    is_authoritative: Literal[False] = False
    readiness_authorized: Literal[False] = False
    is_terminal: Literal[False] = False
    completion_authorized: Literal[False] = False
    receipt_issued: Literal[False] = False
    mutation_performed: Literal[False] = False
    deploy_performed: Literal[False] = False
    intent_digest: Sha256Digest

    _aware_created = field_validator("intent_created_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if self.candidate_ref != candidate_ref_for_operation(self.operation_id):
            raise ValueError("candidate ref is not operation-derived")
        if self.candidate_parents != (self.base_commit,):
            raise ValueError("candidate publication must have the composed base as sole parent")
        if self.intent_digest != canonical_digest(
            self.model_dump(exclude={"intent_digest"}, mode="json")
        ):
            raise ValueError("candidate publication intent digest mismatch")
        return self

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasCandidatePublicationIntent:
        payload = dict(values, intent_digest=_ZERO)
        probe = cast(Any, cls).model_construct(**payload)
        payload["intent_digest"] = canonical_digest(
            cast(StrictModel, probe).model_dump(exclude={"intent_digest"}, mode="json")
        )
        return cls.model_validate(payload, strict=True)


class MainPersonalExactCasCandidatePublicationDispatchStarted(StrictModel):
    """Durable ownership marker.  Its create-once index fences redispatch."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    candidate_ref: NonEmptyString
    intent_digest: Sha256Digest
    configuration_digest: Sha256Digest
    started_at: datetime
    is_authoritative: Literal[False] = False
    readiness_authorized: Literal[False] = False
    is_terminal: Literal[False] = False
    completion_authorized: Literal[False] = False
    mutation_performed: Literal[False] = False
    deploy_performed: Literal[False] = False
    dispatch_marker_digest: Sha256Digest

    _aware_started = field_validator("started_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_binding(self) -> Self:
        if self.candidate_ref != candidate_ref_for_operation(self.operation_id):
            raise ValueError("dispatch ref is not operation-derived")
        if self.dispatch_marker_digest != canonical_digest(
            self.model_dump(exclude={"dispatch_marker_digest"}, mode="json")
        ):
            raise ValueError("dispatch marker digest mismatch")
        return self

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasCandidatePublicationDispatchStarted:
        payload = dict(values, dispatch_marker_digest=_ZERO)
        probe = cast(Any, cls).model_construct(**payload)
        payload["dispatch_marker_digest"] = canonical_digest(
            cast(StrictModel, probe).model_dump(exclude={"dispatch_marker_digest"}, mode="json")
        )
        return cls.model_validate(payload, strict=True)


CandidatePublicationResponseClass = Literal[
    "created",
    "conflict_or_rejected",
    "configuration_or_validation_rejected",
    "authentication_or_authorization_rejected",
    "rate_limited",
    "ambiguous",
    "unverifiable",
]


class MainPersonalExactCasCandidatePublicationResponseEvidence(StrictModel):
    """Sanitized provider evidence; never a receipt or terminal outcome."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    repository_id: int = Field(gt=0)
    candidate_ref: NonEmptyString
    candidate_commit: GitObject
    intent_digest: Sha256Digest
    dispatch_marker_digest: Sha256Digest
    publisher_app_id: StrictInt = Field(gt=0)
    publisher_installation_id: StrictInt = Field(gt=0)
    publisher_identity: Literal["avo-c8-candidate-publisher-vandyand"]
    configuration_digest: Sha256Digest
    request_digest: Sha256Digest
    response_status: StrictInt = Field(ge=100, le=599)
    response_classification: CandidatePublicationResponseClass
    response_ref: NonEmptyString | None = None
    response_sha: GitObject | None = None
    response_payload_digest: Sha256Digest
    response_request_id: NonEmptyString | None = None
    response_metadata: dict[str, str] = Field(default_factory=dict)
    requests: tuple[CandidatePublisherRequestTrace, ...]
    observed_at: datetime
    is_authoritative: Literal[False] = False
    readiness_authorized: Literal[False] = False
    is_terminal: Literal[False] = False
    completion_authorized: Literal[False] = False
    mutation_performed: Literal[False] = False
    deploy_performed: Literal[False] = False
    evidence_digest: Sha256Digest

    _aware_observed = field_validator("observed_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if self.candidate_ref != candidate_ref_for_operation(self.operation_id):
            raise ValueError("response ref is not operation-derived")
        if self.request_digest != candidate_publication_request_digest(
            repository_digest=self.repository_digest,
            repository_id=self.repository_id,
            candidate_ref=self.candidate_ref,
            candidate_commit=self.candidate_commit,
        ):
            raise ValueError("response request digest mismatch")
        if self.publisher_identity != "avo-c8-candidate-publisher-vandyand":
            raise ValueError("response publisher identity differs")
        expected_trace = (
            ("GET", "/app", "app_jwt"),
            ("GET", f"/app/installations/{self.publisher_installation_id}", "app_jwt"),
            ("POST", f"/app/installations/{self.publisher_installation_id}/access_tokens", "app_jwt"),
            ("GET", "/repositories/1354880741", "installation_token"),
            ("POST", "/repos/vandyand/avo-c8/git/refs", "installation_token"),
        )
        actual_trace = tuple(
            (item.method, item.path, item.credential_role) for item in self.requests
        )
        if actual_trace != expected_trace[: len(actual_trace)] or not actual_trace:
            raise ValueError("response request trace is outside fixed publisher surface")
        if self.response_status == 201 and actual_trace != expected_trace:
            raise ValueError("successful response trace is not exact")
        expected: CandidatePublicationResponseClass = (
            "created"
            if self.response_status == 201
            else "conflict_or_rejected"
            if self.response_status in {409, 422}
            else "authentication_or_authorization_rejected"
            if self.response_status in {401, 403}
            else "rate_limited"
            if self.response_status == 429
            else "ambiguous"
            if self.response_status >= 500
            else "unverifiable"
        )
        if self.response_classification != expected:
            raise ValueError("response status classification mismatch")
        if self.response_classification == "created":
            if (
                self.response_ref != self.candidate_ref
                or self.response_sha != self.candidate_commit
            ):
                raise ValueError("created response does not echo exact candidate")
        elif self.response_ref is not None or self.response_sha is not None:
            raise ValueError("non-created response contains mutation evidence")
        if self.evidence_digest != canonical_digest(
            self.model_dump(exclude={"evidence_digest"}, mode="json")
        ):
            raise ValueError("response evidence digest mismatch")
        return self

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasCandidatePublicationResponseEvidence:
        payload = dict(values, evidence_digest=_ZERO)
        probe = cast(Any, cls).model_construct(**payload)
        payload["evidence_digest"] = canonical_digest(
            cast(StrictModel, probe).model_dump(exclude={"evidence_digest"}, mode="json")
        )
        return cls.model_validate(payload, strict=True)


class MainPersonalExactCasCandidatePublicationReconciliation(StrictModel):
    """Read-only exact-ref reconciliation after a response or ambiguity."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    candidate_ref: NonEmptyString
    candidate_commit: GitObject
    candidate_tree: GitObject
    candidate_parents: tuple[GitObject, ...]
    initial_ref_digest: Sha256Digest
    final_ref_digest: Sha256Digest
    response_evidence_digest: Sha256Digest
    observer_provenance_digest: Sha256Digest
    observed_at: datetime
    is_authoritative: Literal[False] = False
    readiness_authorized: Literal[False] = False
    is_terminal: Literal[False] = False
    completion_authorized: Literal[False] = False
    mutation_performed: Literal[False] = False
    deploy_performed: Literal[False] = False
    reconciliation_digest: Sha256Digest

    _aware_observed = field_validator("observed_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_reconciliation(self) -> Self:
        if self.candidate_ref != candidate_ref_for_operation(self.operation_id):
            raise ValueError("reconciliation ref is not operation-derived")
        if self.initial_ref_digest != self.final_ref_digest:
            raise ValueError("reconciliation ref fence differs")
        if len(self.candidate_parents) != 1:
            raise ValueError("reconciliation candidate topology is not exact")
        if self.reconciliation_digest != canonical_digest(
            self.model_dump(exclude={"reconciliation_digest"}, mode="json")
        ):
            raise ValueError("reconciliation digest mismatch")
        return self

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasCandidatePublicationReconciliation:
        payload = dict(values, reconciliation_digest=_ZERO)
        probe = cast(Any, cls).model_construct(**payload)
        payload["reconciliation_digest"] = canonical_digest(
            cast(StrictModel, probe).model_dump(exclude={"reconciliation_digest"}, mode="json")
        )
        return cls.model_validate(payload, strict=True)


class MainPersonalExactCasCandidatePublicationAuthorityRoot(StrictModel):
    """Resolved, operation-specific offline dependency closure.

    This root is only buildable by the resolver after it has reopened every
    required journal.  It carries complete canonical references to each
    preparation authorization and hosted policy identity leaf, but it is not
    publication authority: a future controller must perform a fresh hosted
    policy/readiness check and trusted-clock lease check before dispatch.
    """

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    candidate_ref: NonEmptyString
    base_commit: GitObject
    base_tree: GitObject
    candidate_commit: GitObject
    candidate_tree: GitObject
    candidate_parents: tuple[GitObject, ...]
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    lease_expires_at: datetime
    configuration_digest: Sha256Digest
    publisher_app_id: StrictInt = Field(gt=0)
    publisher_installation_id: StrictInt = Field(gt=0)
    publisher_identity: Literal["avo-c8-candidate-publisher-vandyand"]
    owner_id: StrictInt = Field(gt=0)
    composition_digest: Sha256Digest
    composition_artifact: ArtifactRef
    preparation_authorization_record_digest: Sha256Digest
    preparation_authorization_digest: Sha256Digest
    preparation_authorization_artifact: ArtifactRef
    hosted_identity_root_digest: Sha256Digest
    hosted_identity_root_artifact: ArtifactRef
    hosted_identity_bundle_digest: Sha256Digest
    candidate_policy_digest: Sha256Digest
    candidate_policy_artifact: ArtifactRef
    candidate_policy_ruleset_digests: tuple[Sha256Digest, ...]
    dependencies_bound: Literal[True] = True
    candidate_publication_authorized: Literal[False] = False
    offline_only: Literal[True] = True
    is_authoritative: Literal[False] = False
    readiness_authorized: Literal[False] = False
    is_terminal: Literal[False] = False
    receipt_issued: Literal[False] = False
    completion_claimed: Literal[False] = False
    mutation_performed: Literal[False] = False
    deploy_performed: Literal[False] = False
    root_digest: Sha256Digest

    _aware_lease_expires_at = field_validator("lease_expires_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_root(self) -> Self:
        expected_refs = (
            (
                self.composition_artifact,
                "main-graduation-composition",
                "application/vnd.avo.main-graduation-composition+json",
            ),
            (
                self.preparation_authorization_artifact,
                "main-graduation-preparation-authorization",
                "application/vnd.avo.main-graduation-preparation-authorization+json",
            ),
            (
                self.hosted_identity_root_artifact,
                "main-personal-exact-cas-hosted-identity-root",
                "application/vnd.avo.main-personal-exact-cas-hosted-identity-root+json",
            ),
            (
                self.candidate_policy_artifact,
                "main-personal-exact-cas-hosted-configuration-diagnostic",
                "application/vnd.avo.main-personal-exact-cas-hosted-configuration-diagnostic+json",
            ),
        )
        for reference, role, media_type in expected_refs:
            if (
                type(reference) is not ArtifactRef
                or reference.role != role
                or reference.media_type != media_type
                or reference.size_bytes <= 0
            ):
                raise ValueError("authority root artifact reference is not exact")
        if self.composition_artifact.digest != self.composition_digest:
            raise ValueError("authority root composition artifact digest differs")
        if self.preparation_authorization_record_digest != self.preparation_authorization_artifact.digest:
            raise ValueError("authority root preparation record digest differs")
        if self.hosted_identity_root_artifact.digest != self.hosted_identity_root_digest:
            raise ValueError("authority root identity artifact digest differs")
        if self.candidate_ref != candidate_ref_for_operation(self.operation_id):
            raise ValueError("authority root candidate ref is not operation-derived")
        if self.candidate_parents != (self.base_commit,):
            raise ValueError("authority root candidate topology differs")
        if len(self.candidate_policy_ruleset_digests) != 5 or len(
            set(self.candidate_policy_ruleset_digests)
        ) != 5:
            raise ValueError("authority root requires five distinct policy rulesets")
        if self.candidate_policy_digest != canonical_digest(
            {
                "writer_ruleset": self.candidate_policy_ruleset_digests[0],
                "safety_ruleset": self.candidate_policy_ruleset_digests[1],
                "rollback_ruleset": self.candidate_policy_ruleset_digests[2],
                "candidate_creation_ruleset": self.candidate_policy_ruleset_digests[3],
                "candidate_immutable_ruleset": self.candidate_policy_ruleset_digests[4],
            }
        ):
            raise ValueError("authority root policy digest differs")
        if self.root_digest != canonical_digest(
            self.model_dump(exclude={"root_digest"}, mode="json")
        ):
            raise ValueError("authority root digest mismatch")
        return self

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasCandidatePublicationAuthorityRoot:
        payload = dict(values, root_digest=_ZERO)
        probe = cast(Any, cls).model_construct(**payload)
        payload["root_digest"] = canonical_digest(
            cast(StrictModel, probe).model_dump(exclude={"root_digest"}, mode="json")
        )
        return cls.model_validate(payload, strict=True)


__all__ = [
    "CandidatePublicationResponseClass",
    "CandidatePublisherRequestTrace",
    "MainPersonalExactCasCandidatePublicationAuthorityRoot",
    "MainPersonalExactCasCandidatePublicationDispatchStarted",
    "MainPersonalExactCasCandidatePublicationIntent",
    "MainPersonalExactCasCandidatePublicationReconciliation",
    "MainPersonalExactCasCandidatePublicationResponseEvidence",
    "candidate_publication_request_digest",
]
