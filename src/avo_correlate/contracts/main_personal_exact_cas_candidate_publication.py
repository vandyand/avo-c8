"""Offline, non-authoritative contracts for one candidate-ref creation.

The operation-derived ref and commit are immutable inputs.  These records do
not grant readiness, completion, deployment, or any other authority.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal, Self, cast

from pydantic import Field, StrictInt, field_validator, model_validator

from avo_correlate.contracts.base import (
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
    readiness_authorized: Literal[False] = False
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
        if any(
            item.method not in {"GET", "POST"}
            or not (
                item.path == "/app"
                or re.fullmatch(r"/app/installations/[1-9][0-9]*", item.path)
                or re.fullmatch(r"/app/installations/[1-9][0-9]*/access_tokens", item.path)
                or item.path == "/repositories/1354880741"
                or item.path == "/repos/vandyand/avo-c8/git/refs"
            )
            or item.credential_role not in {"app_jwt", "installation_token"}
            for item in self.requests
        ):
            raise ValueError("response request trace is outside fixed publisher surface")
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


__all__ = [
    "CandidatePublicationResponseClass",
    "CandidatePublisherRequestTrace",
    "MainPersonalExactCasCandidatePublicationDispatchStarted",
    "MainPersonalExactCasCandidatePublicationIntent",
    "MainPersonalExactCasCandidatePublicationReconciliation",
    "MainPersonalExactCasCandidatePublicationResponseEvidence",
    "candidate_publication_request_digest",
]
