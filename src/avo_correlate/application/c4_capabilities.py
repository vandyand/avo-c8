"""Narrow, evidence-producing executor capabilities for C4.

The coordinator may compose these capabilities, but none can merge, update a
ref, or otherwise mutate ``refs/heads/main``. Provider results and observations
are DTOs; controller-owned verifiers decide whether they are authoritative.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Protocol, Self, cast

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from avo_correlate.contracts.base import (
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.contracts.main_graduation import (
    GitObject,
    MainMutationStage,
    MainRef,
    main_release_external_identity_digest,
    main_stage_identity_digest,
)
from avo_correlate.domain.canonical import canonical_digest

MutationOutcome = Literal[
    "applied", "already_applied", "ambiguous", "rejected", "reconciliation_required"
]
ObservationOutcome = Literal["observed", "not_found", "ambiguous", "invalid"]
Stage = Literal[
    "candidate_publication", "pull_request_open", "admission_check",
    "queue_enqueue", "merge_group_hold", "release_transition"
]
_DIGEST_ZERO = "sha256:" + "0" * 64


def _expected_candidate_ref(operation_id: str) -> str:
    return f"refs/heads/avo/candidate/{operation_id.removeprefix('sha256:')}"


class C4Request(StrictModel):
    """Exact identity shared by all requests, including an idempotent digest."""

    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"
    lease_epoch_digest: Sha256Digest
    request_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_request_digest(self) -> Self:
        expected = canonical_digest(self.model_dump(exclude={"request_digest"}, mode="json"))
        if self.request_digest != expected:
            raise ValueError("request digest mismatch")
        return self

    @classmethod
    def build(cls, **values: object) -> Self:
        """Build a request with its canonical digest; callers cannot omit it."""

        supplied: dict[str, Any] = dict(values)
        supplied.setdefault("target_ref", "refs/heads/main")
        temporary = cls.model_construct(**supplied, request_digest=_DIGEST_ZERO)
        supplied["request_digest"] = canonical_digest(
            temporary.model_dump(exclude={"request_digest"}, mode="json")
        )
        return cls.model_validate(supplied)


class StageRequest(C4Request):
    stage: str
    external_key: NonEmptyString
    external_identity: Sha256Digest
    queue_generation_digest: Sha256Digest | None = None

    @classmethod
    def build(cls, **values: object) -> Self:
        """Build a stage request and derive its external and request identities."""

        supplied: dict[str, Any] = dict(values)
        supplied.setdefault("target_ref", "refs/heads/main")
        stage = supplied.get("stage", cls.model_fields["stage"].default)
        if not isinstance(stage, str):
            raise ValueError("stage is required")
        if stage == "release_transition":
            external_identity = main_release_external_identity_digest(
                operation_id=str(supplied["operation_id"]),
                repository_digest=str(supplied["repository_digest"]),
                target_ref=str(supplied["target_ref"]),
                authorization_digest=str(supplied["release_authorization_digest"]),
                hold_observation_digest=str(supplied["hold_observation_digest"]),
                group_sha=str(supplied["group_sha"]),
                hold_run_id=str(supplied["hold_run_id"]),
                hold_nonce=str(supplied["hold_nonce"]),
                queue_generation_digest=str(supplied["queue_generation_digest"]),
                release_check_context="avo-main-release",
                release_issuer_app_id=int(supplied["issuer_app_id"]),
            )
        else:
            external_identity = main_stage_identity_digest(
                str(supplied["operation_id"]), cast(MainMutationStage, stage),
                str(supplied["external_key"]),
                queue_generation_digest=supplied.get("queue_generation_digest"),
                repository_digest=str(supplied["repository_digest"]),
                target_ref=str(supplied["target_ref"]),
            )
        supplied["external_identity"] = external_identity
        temporary = cls.model_construct(**supplied, request_digest=_DIGEST_ZERO)
        supplied["request_digest"] = canonical_digest(
            temporary.model_dump(exclude={"request_digest"}, mode="json")
        )
        return cls.model_validate(supplied)

    @model_validator(mode="after")
    def validate_external_identity(self) -> Self:
        expected_stage = self.__class__.model_fields["stage"].default
        if isinstance(expected_stage, str) and self.stage != expected_stage:
            raise ValueError("request stage does not match its dedicated type")
        queue_bound = {"admission_check", "queue_enqueue", "merge_group_hold", "release_transition"}
        if self.stage in queue_bound and self.queue_generation_digest is None:
            raise ValueError("queue-bound request requires queue generation")
        if self.stage not in queue_bound and self.queue_generation_digest is not None:
            raise ValueError("non-queue request cannot carry queue generation")
        if self.stage != "release_transition":
            expected = main_stage_identity_digest(
                self.operation_id, cast(MainMutationStage, self.stage), self.external_key,
                queue_generation_digest=self.queue_generation_digest,
                repository_digest=self.repository_digest, target_ref=self.target_ref,
            )
            if self.external_identity != expected:
                raise ValueError("external identity mismatch")
        return self


class CandidatePublicationRequest(StageRequest):
    stage: str = "candidate_publication"
    candidate_ref: NonEmptyString
    candidate_commit: GitObject
    preparation_authorization_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_candidate(self) -> Self:
        if self.candidate_ref != _expected_candidate_ref(self.operation_id):
            raise ValueError("candidate ref is not operation-derived")
        return self


class PullRequestCreateRequest(StageRequest):
    stage: str = "pull_request_open"
    candidate_ref: NonEmptyString
    candidate_commit: GitObject
    base_commit: GitObject
    base_tree: GitObject
    preparation_authorization_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_create(self) -> Self:
        if self.candidate_ref != _expected_candidate_ref(self.operation_id):
            raise ValueError("pull request candidate ref is not operation-derived")
        if self.candidate_commit == self.base_commit:
            raise ValueError("pull request head must differ from base")
        return self


class PullRequestReconcileRequest(C4Request):
    """Read-only exact lookup for a possibly-created pull request."""

    stage: str = "pull_request_open"
    pull_request_number: StrictInt = Field(gt=0)
    candidate_ref: NonEmptyString
    head_commit: GitObject
    base_commit: GitObject
    repository_name: NonEmptyString

    @model_validator(mode="after")
    def validate_reconcile_target(self) -> Self:
        if self.stage != "pull_request_open":
            raise ValueError("reconcile stage mismatch")
        if self.candidate_ref != _expected_candidate_ref(self.operation_id):
            raise ValueError("reconcile candidate ref is not operation-derived")
        if self.head_commit == self.base_commit:
            raise ValueError("reconcile head must differ from base")
        return self


class QueueEnqueueRequest(StageRequest):
    stage: str = "queue_enqueue"
    pull_request_number: StrictInt = Field(gt=0)
    pull_request_head: GitObject
    preparation_authorization_digest: Sha256Digest
    admission_observation_digest: Sha256Digest


class AdmissionIssueRequest(StageRequest):
    stage: str = "admission_check"
    preparation_authorization_digest: Sha256Digest
    pull_request_number: StrictInt = Field(gt=0)
    pull_request_head: GitObject
    admission_run_id: NonEmptyString
    admission_nonce: NonEmptyString
    issuer_identity: NonEmptyString
    issuer_app_id: StrictInt = Field(gt=0)
    issuer_isolation_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_admission_issuer(self) -> Self:
        if self.issuer_app_id == 15368:
            raise ValueError("validation App 15368 cannot issue admission")
        return self


class GroupHoldIssueRequest(StageRequest):
    stage: str = "merge_group_hold"
    admission_observation_digest: Sha256Digest
    pull_request_number: StrictInt = Field(gt=0)
    group_sha: GitObject
    group_tree: GitObject
    group_parents: list[GitObject] = Field(min_length=1)
    base_commit: GitObject
    base_tree: GitObject
    queue_members: list[StrictInt] = Field(min_length=1, max_length=1)
    hold_run_id: NonEmptyString
    hold_nonce: NonEmptyString
    issuer_identity: NonEmptyString
    issuer_app_id: StrictInt = Field(gt=0)
    issuer_isolation_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_group(self) -> Self:
        if self.queue_members != [self.pull_request_number]:
            raise ValueError("group hold requires exactly the authorized PR")
        if not self.group_parents or self.group_parents[0] != self.base_commit:
            raise ValueError("group parents must start at the exact base")
        if len(set(self.group_parents)) != len(self.group_parents):
            raise ValueError("group parents must be complete and unique")
        if self.issuer_app_id == 15368:
            raise ValueError("validation App 15368 cannot issue group hold")
        return self


class ReleaseIssueRequest(StageRequest):
    stage: str = "release_transition"
    hold_observation_digest: Sha256Digest
    group_sha: GitObject
    group_tree: GitObject
    group_parents: list[GitObject] = Field(min_length=1)
    hold_run_id: NonEmptyString
    hold_nonce: NonEmptyString
    release_authorization_digest: Sha256Digest
    release_claim_digest: Sha256Digest
    issuer_identity: NonEmptyString
    issuer_app_id: StrictInt = Field(gt=0)
    issuer_isolation_digest: Sha256Digest
    authorization_expires_at: datetime

    _aware_expiry = field_validator("authorization_expires_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_release(self) -> Self:
        if self.issuer_app_id == 15368:
            raise ValueError("validation App 15368 cannot issue release")
        if self.queue_generation_digest is None:
            raise ValueError("release requires queue generation")
        expected = main_release_external_identity_digest(
            operation_id=self.operation_id, repository_digest=self.repository_digest,
            target_ref=self.target_ref, authorization_digest=self.release_authorization_digest,
            hold_observation_digest=self.hold_observation_digest, group_sha=self.group_sha,
            hold_run_id=self.hold_run_id, hold_nonce=self.hold_nonce,
            queue_generation_digest=self.queue_generation_digest,
            release_check_context="avo-main-release", release_issuer_app_id=self.issuer_app_id,
        )
        if self.external_identity != expected:
            raise ValueError("release external identity mismatch")
        return self


class MutationResult(StrictModel):
    """Provider response, never an authority decision."""

    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"
    stage: str
    request_digest: Sha256Digest
    external_identity: Sha256Digest
    external_key: NonEmptyString
    queue_generation_digest: Sha256Digest | None = None
    hold_observation_digest: Sha256Digest | None = None
    group_sha: GitObject | None = None
    hold_run_id: NonEmptyString | None = None
    hold_nonce: NonEmptyString | None = None
    release_authorization_digest: Sha256Digest | None = None
    issuer_app_id: StrictInt | None = Field(default=None, gt=0)
    outcome: MutationOutcome
    response_digest: Sha256Digest
    observed_at: datetime
    dispatch_started: StrictBool

    _aware_observed_at = field_validator("observed_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.outcome == "rejected" and self.dispatch_started:
            raise ValueError("rejected result cannot claim dispatch started")
        if self.outcome != "rejected" and not self.dispatch_started:
            raise ValueError("non-rejected result requires dispatch_started")
        expected = main_stage_identity_digest(
            self.operation_id, cast(MainMutationStage, self.stage), self.external_key,
            queue_generation_digest=self.queue_generation_digest,
            repository_digest=self.repository_digest, target_ref=self.target_ref,
        )
        if self.stage == "release_transition":
            if (
                self.hold_observation_digest is None or self.group_sha is None
                or self.hold_run_id is None or self.hold_nonce is None
                or self.release_authorization_digest is None or self.issuer_app_id is None
                or self.queue_generation_digest is None
            ):
                raise ValueError("release result requires exact release identity fields")
            expected = main_release_external_identity_digest(
                operation_id=self.operation_id, repository_digest=self.repository_digest,
                target_ref=self.target_ref,
                authorization_digest=self.release_authorization_digest,
                hold_observation_digest=self.hold_observation_digest, group_sha=self.group_sha,
                hold_run_id=self.hold_run_id, hold_nonce=self.hold_nonce,
                queue_generation_digest=self.queue_generation_digest,
                release_check_context="avo-main-release", release_issuer_app_id=self.issuer_app_id,
            )
        if self.external_identity != expected:
            raise ValueError("mutation result external identity mismatch")
        return self


class StageObservationRequest(StageRequest):
    """Base for stage-specific, read-only observation lookups."""

    object_id: NonEmptyString


class CandidateObservationRequest(StageObservationRequest):
    stage: str = "candidate_publication"


class PullRequestObservationRequest(StageObservationRequest):
    stage: str = "pull_request_open"
    pull_request_number: StrictInt = Field(gt=0)
    candidate_ref: NonEmptyString
    head_commit: GitObject
    base_commit: GitObject


class AdmissionObservationRequest(StageObservationRequest):
    stage: str = "admission_check"
    pull_request_number: StrictInt = Field(gt=0)
    pull_request_head: GitObject
    admission_run_id: NonEmptyString
    admission_nonce: NonEmptyString


class QueueObservationRequest(StageObservationRequest):
    stage: str = "queue_enqueue"
    pull_request_number: StrictInt = Field(gt=0)


class GroupHoldObservationRequest(StageObservationRequest):
    stage: str = "merge_group_hold"
    pull_request_number: StrictInt = Field(gt=0)
    group_sha: GitObject
    hold_run_id: NonEmptyString
    hold_nonce: NonEmptyString


class ReleaseObservationRequest(StageObservationRequest):
    stage: str = "release_transition"
    group_sha: GitObject
    hold_observation_digest: Sha256Digest
    release_authorization_digest: Sha256Digest


class StageObservationResult(StrictModel):
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"
    stage: str
    request_digest: Sha256Digest
    external_identity: Sha256Digest
    external_key: NonEmptyString
    queue_generation_digest: Sha256Digest | None = None
    hold_observation_digest: Sha256Digest | None = None
    group_sha: GitObject | None = None
    hold_run_id: NonEmptyString | None = None
    hold_nonce: NonEmptyString | None = None
    release_authorization_digest: Sha256Digest | None = None
    issuer_app_id: StrictInt | None = Field(default=None, gt=0)
    outcome: ObservationOutcome
    evidence_digest: Sha256Digest
    observed_at: datetime

    _aware_observed_at = field_validator("observed_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_observation_identity(self) -> Self:
        expected_stage = self.__class__.model_fields["stage"].default
        if isinstance(expected_stage, str) and self.stage != expected_stage:
            raise ValueError("result stage does not match its dedicated type")
        queue_bound = {"admission_check", "queue_enqueue", "merge_group_hold", "release_transition"}
        if self.stage in queue_bound and self.queue_generation_digest is None:
            raise ValueError("queue-bound observation requires queue generation")
        if self.stage not in queue_bound and self.queue_generation_digest is not None:
            raise ValueError("non-queue observation cannot carry queue generation")
        expected = main_stage_identity_digest(
            self.operation_id, cast(MainMutationStage, self.stage), self.external_key,
            queue_generation_digest=self.queue_generation_digest,
            repository_digest=self.repository_digest,
            target_ref=self.target_ref,
        )
        if self.stage == "release_transition":
            if (
                self.hold_observation_digest is None or self.group_sha is None
                or self.hold_run_id is None or self.hold_nonce is None
                or self.release_authorization_digest is None or self.issuer_app_id is None
                or self.queue_generation_digest is None
            ):
                raise ValueError("release observation requires exact release identity fields")
            expected = main_release_external_identity_digest(
                operation_id=self.operation_id, repository_digest=self.repository_digest,
                target_ref=self.target_ref,
                authorization_digest=self.release_authorization_digest,
                hold_observation_digest=self.hold_observation_digest, group_sha=self.group_sha,
                hold_run_id=self.hold_run_id, hold_nonce=self.hold_nonce,
                queue_generation_digest=self.queue_generation_digest,
                release_check_context="avo-main-release", release_issuer_app_id=self.issuer_app_id,
            )
        if self.external_identity != expected:
            raise ValueError("observation external identity mismatch")
        return self


class CandidateObservationResult(StageObservationResult):
    stage: str = "candidate_publication"


class PullRequestObservationResult(StageObservationResult):
    stage: str = "pull_request_open"


class AdmissionObservationResult(StageObservationResult):
    stage: str = "admission_check"


class QueueObservationResult(StageObservationResult):
    stage: str = "queue_enqueue"


class GroupHoldObservationResult(StageObservationResult):
    stage: str = "merge_group_hold"


class ReleaseObservationResult(StageObservationResult):
    stage: str = "release_transition"


class TrustedClock(Protocol):
    """Controller-owned time source for final authorization checks."""

    def now(self) -> datetime: ...


class LeaseFence(Protocol):
    """Controller-owned lease epoch check immediately before every write."""

    def assert_current(
        self, *, operation_id: Sha256Digest, lease_epoch_digest: Sha256Digest
    ) -> None: ...


class CandidatePublicationCapability(Protocol):
    def publish_candidate(self, request: CandidatePublicationRequest) -> MutationResult: ...


class PullRequestPreparationCapability(Protocol):
    def create_pull_request(self, request: PullRequestCreateRequest) -> MutationResult: ...


class PullRequestReconciliationCapability(Protocol):
    def reconcile_pull_request(
        self, request: PullRequestReconcileRequest
    ) -> PullRequestObservationResult: ...


class QueueEnqueueCapability(Protocol):
    def enqueue(self, request: QueueEnqueueRequest) -> MutationResult: ...


class AdmissionIssuerCapability(Protocol):
    def issue_admission(self, request: AdmissionIssueRequest) -> MutationResult: ...


class GroupHoldIssuerCapability(Protocol):
    def issue_group_hold(self, request: GroupHoldIssueRequest) -> MutationResult: ...


class ReleaseIssuerCapability(Protocol):
    def issue_release(self, request: ReleaseIssueRequest) -> MutationResult: ...


class ReadOnlyObservationCapability(Protocol):
    def observe_candidate(
        self, request: CandidateObservationRequest
    ) -> CandidateObservationResult: ...

    def observe_pull_request(
        self, request: PullRequestObservationRequest
    ) -> PullRequestObservationResult: ...

    def observe_admission(
        self, request: AdmissionObservationRequest
    ) -> AdmissionObservationResult: ...

    def observe_queue(self, request: QueueObservationRequest) -> QueueObservationResult: ...

    def observe_group_hold(
        self, request: GroupHoldObservationRequest
    ) -> GroupHoldObservationResult: ...

    def observe_release(self, request: ReleaseObservationRequest) -> ReleaseObservationResult: ...


__all__ = [
    "AdmissionIssueRequest", "AdmissionIssuerCapability", "AdmissionObservationRequest",
    "AdmissionObservationResult", "C4Request", "CandidateObservationRequest",
    "CandidateObservationResult", "CandidatePublicationCapability", "CandidatePublicationRequest",
    "GitObject", "GroupHoldIssueRequest", "GroupHoldIssuerCapability",
    "GroupHoldObservationRequest", "GroupHoldObservationResult", "LeaseFence", "MutationOutcome",
    "MutationResult", "PullRequestCreateRequest", "PullRequestObservationRequest",
    "PullRequestObservationResult", "PullRequestPreparationCapability",
    "PullRequestReconcileRequest",
    "PullRequestReconciliationCapability", "QueueEnqueueCapability", "QueueEnqueueRequest",
    "QueueObservationRequest", "QueueObservationResult", "ReadOnlyObservationCapability",
    "ReleaseIssueRequest", "ReleaseIssuerCapability", "ReleaseObservationRequest",
    "ReleaseObservationResult", "Stage", "StageObservationRequest", "StageObservationResult",
    "StageRequest", "TrustedClock",
]
