"""Narrow executor capabilities for protected-main graduation C4.

These interfaces describe *which* external operation a provider may perform.  A
coordinator can receive several capabilities, but no capability in this module
can update ``refs/heads/main`` or expose a generic merge operation.  Provider
responses are evidence only; controller-owned verification remains outside the
provider protocols.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Protocol

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from avo_correlate.contracts.base import (
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.contracts.main_graduation import GitObject, MainRef

MutationOutcome = Literal[
    "applied", "already_applied", "ambiguous", "rejected", "reconciliation_required"
]
ObservationOutcome = Literal["observed", "not_found", "ambiguous", "invalid"]


class C4Request(StrictModel):
    """Exact identity shared by every executor request."""

    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"
    lease_epoch_digest: Sha256Digest
    request_digest: Sha256Digest


class CandidatePublicationRequest(C4Request):
    candidate_ref: NonEmptyString
    candidate_commit: GitObject
    publication_identity: Sha256Digest


class PullRequestPreparationRequest(C4Request):
    candidate_ref: NonEmptyString
    candidate_commit: GitObject
    pull_request_number: StrictInt = Field(gt=0)
    preparation_authorization_digest: Sha256Digest


class QueueEnqueueRequest(C4Request):
    pull_request_number: StrictInt = Field(gt=0)
    pull_request_head: GitObject
    queue_generation_digest: Sha256Digest
    preparation_authorization_digest: Sha256Digest


class AdmissionIssueRequest(C4Request):
    pull_request_number: StrictInt = Field(gt=0)
    pull_request_head: GitObject
    admission_identity: Sha256Digest
    issuer_identity: NonEmptyString


class GroupHoldIssueRequest(C4Request):
    pull_request_number: StrictInt = Field(gt=0)
    group_sha: GitObject
    group_tree: GitObject
    hold_run_id: NonEmptyString
    hold_nonce: NonEmptyString
    queue_generation_digest: Sha256Digest
    issuer_identity: NonEmptyString


class ReleaseIssueRequest(C4Request):
    group_sha: GitObject
    hold_run_id: NonEmptyString
    hold_nonce: NonEmptyString
    queue_generation_digest: Sha256Digest
    release_authorization_digest: Sha256Digest
    release_claim_digest: Sha256Digest
    issuer_identity: NonEmptyString


class MutationResult(StrictModel):
    """Provider response, deliberately not an authority decision."""

    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"
    outcome: MutationOutcome
    external_identity: Sha256Digest
    response_digest: Sha256Digest
    observed_at: datetime
    dispatch_started: StrictBool

    _aware_observed_at = field_validator("observed_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_dispatch_outcome(self) -> MutationResult:
        if self.outcome == "rejected" and self.dispatch_started:
            raise ValueError("rejected result cannot claim dispatch started")
        if self.outcome != "rejected" and not self.dispatch_started:
            raise ValueError("non-rejected result requires dispatch_started")
        return self


class ObservationRequest(C4Request):
    external_identity: Sha256Digest
    object_kind: Literal[
        "candidate", "pull_request", "admission", "queue", "group_hold", "release", "main"
    ]
    object_key: NonEmptyString


class ObservationResult(StrictModel):
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"
    external_identity: Sha256Digest
    outcome: ObservationOutcome
    evidence_digest: Sha256Digest | None = None
    observed_at: datetime

    _aware_observed_at = field_validator("observed_at")(require_aware_datetime)


class TrustedClock(Protocol):
    """Controller-owned time source used for last-moment authorization checks."""

    def now(self) -> datetime: ...


class LeaseFence(Protocol):
    """Controller-owned lease epoch check performed immediately before writes."""

    def assert_current(self, *, operation_id: str, lease_epoch_digest: str) -> None: ...


class CandidatePublicationCapability(Protocol):
    def publish_candidate(self, request: CandidatePublicationRequest) -> MutationResult: ...


class PullRequestPreparationCapability(Protocol):
    def prepare_pull_request(self, request: PullRequestPreparationRequest) -> MutationResult: ...


class PullRequestReconciliationCapability(Protocol):
    """Read-only reconciliation for an uncertain PR preparation boundary."""

    def reconcile_pull_request(self, request: ObservationRequest) -> ObservationResult: ...


class QueueEnqueueCapability(Protocol):
    def enqueue(self, request: QueueEnqueueRequest) -> MutationResult: ...


class AdmissionIssuerCapability(Protocol):
    def issue_admission(self, request: AdmissionIssueRequest) -> MutationResult: ...


class GroupHoldIssuerCapability(Protocol):
    def issue_group_hold(self, request: GroupHoldIssueRequest) -> MutationResult: ...


class ReleaseIssuerCapability(Protocol):
    def issue_release(self, request: ReleaseIssueRequest) -> MutationResult: ...


class ReadOnlyObservationCapability(Protocol):
    def observe(self, request: ObservationRequest) -> ObservationResult: ...

    def reconcile(self, request: ObservationRequest) -> ObservationResult: ...


type MutationCapability = (
    CandidatePublicationCapability
    | PullRequestPreparationCapability
    | QueueEnqueueCapability
    | AdmissionIssuerCapability
    | GroupHoldIssuerCapability
    | ReleaseIssuerCapability
)


__all__ = [
    "AdmissionIssueRequest",
    "AdmissionIssuerCapability",
    "C4Request",
    "CandidatePublicationCapability",
    "CandidatePublicationRequest",
    "GitObject",
    "GroupHoldIssueRequest",
    "GroupHoldIssuerCapability",
    "LeaseFence",
    "MutationCapability",
    "MutationOutcome",
    "MutationResult",
    "ObservationOutcome",
    "ObservationRequest",
    "ObservationResult",
    "PullRequestPreparationCapability",
    "PullRequestPreparationRequest",
    "PullRequestReconciliationCapability",
    "QueueEnqueueCapability",
    "QueueEnqueueRequest",
    "ReadOnlyObservationCapability",
    "ReleaseIssueRequest",
    "ReleaseIssuerCapability",
    "TrustedClock",
]
