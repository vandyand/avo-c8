"""Strict, evidence-producing C4 executor capabilities (never main mutation)."""
# pyright: reportIncompatibleVariableOverride=false, reportUnsupportedDunderAll=false

from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar, Literal, Protocol, Self

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
    MainQueueConfigurationObservation,
    MainRef,
    main_release_external_key,
    main_stage_identity_digest,
)
from avo_correlate.domain.canonical import canonical_digest

MutationOutcome = Literal[
    "applied", "already_applied", "ambiguous", "rejected", "reconciliation_required"
]
ObservationOutcome = Literal["observed", "not_found", "ambiguous", "invalid"]
Stage = MainMutationStage
_ZERO = "sha256:" + "0" * 64
_QUEUE = frozenset({"admission_check", "queue_enqueue", "merge_group_hold", "release_transition"})
_ISSUER = frozenset({"admission_check", "merge_group_hold", "release_transition"})


def candidate_ref_for_operation(op: str, operation_kind: str = "graduation") -> str:
    prefix = "main-rollback" if operation_kind == "rollback" else "candidate"
    return f"refs/heads/avo/{prefix}/{op.removeprefix('sha256:')}"


def _pull_request_identity(
    operation_id: str, repository_digest: str, pull_request_number: int, pull_request_url: str
) -> Sha256Digest:
    return canonical_digest(
        {
            "operation_id": operation_id,
            "repository_digest": repository_digest,
            "pull_request_number": pull_request_number,
            "pull_request_url": pull_request_url,
        }
    )


class C4Request(StrictModel):
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"
    lease_epoch_digest: Sha256Digest
    request_digest: Sha256Digest
    _exclude_request: ClassVar[frozenset[str]] = frozenset()

    def _request(self) -> dict[str, Any]:
        return self.model_dump(exclude={"request_digest", *self._exclude_request}, mode="json")

    @model_validator(mode="after")
    def valid_request(self) -> Self:
        if self.request_digest != canonical_digest(self._request()):
            raise ValueError("request digest mismatch")
        return self

    @classmethod
    def build(cls, **values: object) -> Self:
        d: dict[str, Any] = dict(values)
        d.setdefault("target_ref", "refs/heads/main")
        d["request_digest"] = canonical_digest(
            cls.model_construct(**d, request_digest=_ZERO)._request()
        )
        return cls.model_validate(d)


class StageBound(C4Request):
    # Rollback reuses the same phase-A stage protocol but has a dedicated
    # candidate namespace.  The explicit discriminator prevents a rollback
    # ref from being smuggled into ordinary graduation requests.
    operation_kind: Literal["graduation", "rollback"] = "graduation"
    stage: Stage
    external_key: NonEmptyString
    external_identity: Sha256Digest
    queue_generation_digest: Sha256Digest | None = None
    queue_configuration_digest: Sha256Digest | None = None
    _exclude_external: ClassVar[frozenset[str]] = frozenset()

    def _request(self) -> dict[str, Any]:
        payload = super()._request()
        # Preserve the historical graduation request digest exactly. Rollback
        # is the only branch that adds the discriminator to durable identity.
        if self.operation_kind == "graduation":
            payload.pop("operation_kind", None)
        return payload

    def _object(self) -> dict[str, Any]:
        payload = self.model_dump(
            exclude={
                "operation_id",
                "repository_digest",
                "target_ref",
                "lease_epoch_digest",
                "request_digest",
                "external_key",
                "external_identity",
                *self._exclude_external,
            },
            mode="json",
        )
        if self.operation_kind == "graduation":
            payload.pop("operation_kind", None)
        return payload

    def _key(self) -> Sha256Digest:
        return canonical_digest({"stage": self.stage, "object": self._object()})

    @model_validator(mode="after")
    def valid_identity(self) -> Self:
        post_queue_observation = self.__class__.__name__ in {
            "QueueObservationRequest",
            "QueueObservationResult",
        }
        if self.stage in {"admission_check", "queue_enqueue"} and not post_queue_observation:
            if self.queue_configuration_digest is None:
                raise ValueError("pre-enqueue queue configuration is required")
            if self.queue_generation_digest is not None:
                raise ValueError("pre-enqueue stages cannot bind a queue generation")
        elif self.stage in {"merge_group_hold", "release_transition"}:
            if self.queue_generation_digest is None:
                raise ValueError("post-enqueue queue generation is required")
        elif post_queue_observation:
            if self.queue_generation_digest is None:
                raise ValueError("post-enqueue queue generation is required")
            if self.queue_configuration_digest is None:
                raise ValueError("post-enqueue queue configuration is required")
        elif not post_queue_observation and (
            self.queue_generation_digest is not None
            or self.queue_configuration_digest is not None
        ):
            raise ValueError("queue identity is not valid for this stage")
        if self.external_key != self._key():
            raise ValueError("external key mismatch")
        expected = main_stage_identity_digest(
            self.operation_id,
            self.stage,
            self.external_key,
            queue_generation_digest=self.queue_generation_digest,
            repository_digest=self.repository_digest,
            target_ref=self.target_ref,
        )
        if self.external_identity != expected:
            raise ValueError("external identity mismatch")
        if self.stage in _ISSUER and getattr(self, "issuer_app_id", None) == 15368:
            raise ValueError("validation App 15368 cannot issue C4 authority")
        return self


class StageRequest(StageBound):
    @classmethod
    def build(cls, **values: object) -> Self:
        d: dict[str, Any] = dict(values)
        d.setdefault("target_ref", "refs/heads/main")
        d.pop("external_key", None)
        d.pop("external_identity", None)
        d.pop("request_digest", None)
        t = cls.model_construct(
            **d, external_key="x", external_identity=_ZERO, request_digest=_ZERO
        )
        d["external_key"] = t._key()
        t = cls.model_construct(**d, external_identity=_ZERO, request_digest=_ZERO)
        d["external_identity"] = main_stage_identity_digest(
            t.operation_id,
            t.stage,
            t.external_key,
            queue_generation_digest=t.queue_generation_digest,
            repository_digest=t.repository_digest,
            target_ref=t.target_ref,
        )
        d["request_digest"] = canonical_digest(
            cls.model_construct(**d, request_digest=_ZERO)._request()
        )
        return cls.model_validate(d)


class CandidatePublicationRequest(StageRequest):
    stage: Literal["candidate_publication"] = "candidate_publication"
    candidate_ref: NonEmptyString
    candidate_commit: GitObject
    preparation_authorization_digest: Sha256Digest

    @model_validator(mode="after")
    def candidate(self) -> Self:
        if self.candidate_ref != candidate_ref_for_operation(
            self.operation_id, self.operation_kind
        ):
            raise ValueError("candidate ref is not operation-derived")
        return self


class PullRequestCreateRequest(StageRequest):
    stage: Literal["pull_request_open"] = "pull_request_open"
    candidate_ref: NonEmptyString
    candidate_commit: GitObject
    candidate_tree: GitObject
    base_commit: GitObject
    base_tree: GitObject
    preparation_authorization_digest: Sha256Digest

    @model_validator(mode="after")
    def pr(self) -> Self:
        if self.candidate_ref != candidate_ref_for_operation(
            self.operation_id, self.operation_kind
        ):
            raise ValueError("pull request candidate ref is not operation-derived")
        if self.candidate_commit == self.base_commit or self.candidate_tree == self.base_tree:
            raise ValueError("pull request head must differ from base")
        return self


class PullRequestReconcileRequest(StageRequest):
    stage: Literal["pull_request_open"] = "pull_request_open"
    pull_request_number: StrictInt = Field(gt=0)
    candidate_ref: NonEmptyString
    head_commit: GitObject
    head_tree: GitObject
    base_commit: GitObject
    base_tree: GitObject
    repository_name: NonEmptyString

    @model_validator(mode="after")
    def reconcile(self) -> Self:
        if (
            self.candidate_ref
            != candidate_ref_for_operation(self.operation_id, self.operation_kind)
            or self.head_commit == self.base_commit
            or self.head_tree == self.base_tree
        ):
            raise ValueError("reconcile target is not exact")
        return self


class PullRequestLookupRequest(StageRequest):
    """Read-only lookup target for an operation-derived candidate branch."""

    stage: Literal["pull_request_open"] = "pull_request_open"
    candidate_ref: NonEmptyString
    candidate_commit: GitObject
    candidate_tree: GitObject
    base_commit: GitObject
    base_tree: GitObject

    @model_validator(mode="after")
    def lookup(self) -> Self:
        if self.candidate_ref != candidate_ref_for_operation(
            self.operation_id, self.operation_kind
        ):
            raise ValueError("pull request lookup ref is not operation-derived")
        if self.candidate_commit == self.base_commit or self.candidate_tree == self.base_tree:
            raise ValueError("pull request lookup head must differ from base")
        return self


class AdmissionIssueRequest(StageRequest):
    stage: Literal["admission_check"] = "admission_check"
    preparation_authorization_digest: Sha256Digest
    pull_request_number: StrictInt = Field(gt=0)
    pull_request_head: GitObject
    pull_request_tree: GitObject
    base_commit: GitObject
    base_tree: GitObject
    admission_run_id: NonEmptyString
    admission_nonce: NonEmptyString
    issuer_identity: NonEmptyString
    issuer_app_id: StrictInt = Field(gt=0)
    issuer_isolation_digest: Sha256Digest
    check_context: Literal["avo-main-release"] = "avo-main-release"
    check_state: Literal["completed"] = "completed"
    check_conclusion: Literal["success"] = "success"


class QueueEnqueueRequest(StageRequest):
    stage: Literal["queue_enqueue"] = "queue_enqueue"
    pull_request_number: StrictInt = Field(gt=0)
    pull_request_url: NonEmptyString
    pull_request_identity: Sha256Digest
    pull_request_head: GitObject
    pull_request_tree: GitObject
    base_commit: GitObject
    base_tree: GitObject
    preparation_authorization_digest: Sha256Digest
    admission_observation_digest: Sha256Digest

    @model_validator(mode="after")
    def queue_pr_identity(self) -> Self:
        if self.pull_request_url.startswith("https://") is False:
            raise ValueError("queue requires canonical HTTPS pull request URL")
        if self.pull_request_identity != _pull_request_identity(
            self.operation_id,
            self.repository_digest,
            self.pull_request_number,
            self.pull_request_url,
        ):
            raise ValueError("queue pull request identity mismatch")
        return self


class GroupFields(StageRequest):
    pull_request_number: StrictInt = Field(gt=0)
    pull_request_head: GitObject
    pull_request_tree: GitObject
    group_sha: GitObject
    group_tree: GitObject
    expected_group_tree: GitObject
    group_parents: list[GitObject] = Field(min_length=1)
    expected_group_parents: list[GitObject] = Field(min_length=1)
    group_topology_digest: Sha256Digest
    base_commit: GitObject
    base_tree: GitObject
    queue_members: list[StrictInt] = Field(min_length=1, max_length=1)
    hold_run_id: NonEmptyString
    hold_nonce: NonEmptyString
    issuer_identity: NonEmptyString
    issuer_app_id: StrictInt = Field(gt=0)
    issuer_isolation_digest: Sha256Digest

    def valid_group(self) -> None:
        if self.queue_members != [self.pull_request_number]:
            raise ValueError("group requires singleton PR membership")
        if self.group_sha == self.pull_request_head:
            raise ValueError("merge-group SHA must differ from PR head")
        if self.group_tree != self.expected_group_tree:
            raise ValueError("group tree must equal the deterministic expected group tree")
        if (
            self.group_parents != self.expected_group_parents
            or not self.group_parents
            or self.group_parents[0] != self.base_commit
            or len(set(self.group_parents)) != len(self.group_parents)
        ):
            raise ValueError("group topology is not complete and expected")
        # ``group_topology_digest`` is provider-bound queue evidence.  Its
        # payload is defined by ``MainQueueObservation`` and includes provider
        # identity/API and the queue manifest, so this capability cannot
        # recompute it from the controller's group fields.  The completion
        # coordinator binds this value to the validated queue observation and
        # the durable journal checks that binding again.


class GroupHoldIssueRequest(GroupFields):
    stage: Literal["merge_group_hold"] = "merge_group_hold"
    admission_observation_digest: Sha256Digest
    check_context: Literal["avo-main-release"] = "avo-main-release"
    check_state: Literal["in_progress"] = "in_progress"
    check_conclusion: Literal["pending"] = "pending"

    @model_validator(mode="after")
    def group(self) -> Self:
        self.valid_group()
        return self


class ReleaseFields(GroupFields):
    hold_observation_digest: Sha256Digest
    admission_observation_digest: Sha256Digest
    release_authorization_digest: Sha256Digest
    release_claim_digest: Sha256Digest
    pending_check_context: Literal["avo-main-release"] = "avo-main-release"
    pending_check_state: Literal["in_progress"] = "in_progress"
    pending_check_conclusion: Literal["pending"] = "pending"
    check_context: Literal["avo-main-release"] = "avo-main-release"
    check_state: Literal["completed"] = "completed"
    check_conclusion: Literal["success"] = "success"
    authorization_expires_at: datetime
    _expiry = field_validator("authorization_expires_at")(require_aware_datetime)

    def _key(self) -> Sha256Digest:
        return main_release_external_key(
            operation_id=self.operation_id,
            repository_digest=self.repository_digest,
            target_ref=self.target_ref,
            authorization_digest=self.release_authorization_digest,
            hold_observation_digest=self.hold_observation_digest,
            group_sha=self.group_sha,
            hold_run_id=self.hold_run_id,
            hold_nonce=self.hold_nonce,
            queue_generation_digest=self.queue_generation_digest or "",
            release_check_context=self.check_context,
            release_issuer_app_id=self.issuer_app_id,
        )

    @model_validator(mode="after")
    def release(self) -> Self:
        self.valid_group()
        return self


class ReleaseIssueRequest(ReleaseFields):
    stage: Literal["release_transition"] = "release_transition"


class StageMutationResult(StageBound):
    outcome: MutationOutcome
    response_digest: Sha256Digest
    observed_at: datetime
    dispatch_started: StrictBool
    _exclude_request: ClassVar[frozenset[str]] = frozenset(
        {"outcome", "response_digest", "observed_at", "dispatch_started"}
    )
    _exclude_external: ClassVar[frozenset[str]] = _exclude_request
    _time = field_validator("observed_at")(require_aware_datetime)

    @classmethod
    def build(cls, **values: object) -> Self:
        """Build a provider DTO with the exact request-equivalent identity."""

        d: dict[str, Any] = dict(values)
        d.setdefault("target_ref", "refs/heads/main")
        d.pop("external_key", None)
        d.pop("external_identity", None)
        d.pop("request_digest", None)
        temporary = cls.model_construct(
            **d, external_key="x", external_identity=_ZERO, request_digest=_ZERO
        )
        d["external_key"] = temporary._key()
        temporary = cls.model_construct(**d, external_identity=_ZERO, request_digest=_ZERO)
        d["external_identity"] = main_stage_identity_digest(
            temporary.operation_id,
            temporary.stage,
            temporary.external_key,
            queue_generation_digest=temporary.queue_generation_digest,
            repository_digest=temporary.repository_digest,
            target_ref=temporary.target_ref,
        )
        d["request_digest"] = canonical_digest(
            cls.model_construct(**d, request_digest=_ZERO)._request()
        )
        return cls.model_validate(d)

    @model_validator(mode="after")
    def mutation(self) -> Self:
        if (self.outcome == "rejected") == self.dispatch_started:
            raise ValueError("dispatch state does not match outcome")
        return self


class CandidatePublicationResult(StageMutationResult):
    stage: Literal["candidate_publication"] = "candidate_publication"
    candidate_ref: NonEmptyString
    candidate_commit: GitObject
    preparation_authorization_digest: Sha256Digest

    @model_validator(mode="after")
    def candidate(self) -> Self:
        if self.candidate_ref != candidate_ref_for_operation(
            self.operation_id, self.operation_kind
        ):
            raise ValueError("candidate result ref is not operation-derived")
        return self


class PullRequestCreateResult(StageMutationResult):
    stage: Literal["pull_request_open"] = "pull_request_open"
    candidate_ref: NonEmptyString
    candidate_commit: GitObject
    candidate_tree: GitObject
    base_commit: GitObject
    base_tree: GitObject
    preparation_authorization_digest: Sha256Digest
    pull_request_number: StrictInt = Field(gt=0)
    pull_request_url: NonEmptyString
    pull_request_identity: Sha256Digest
    _exclude_request: ClassVar[frozenset[str]] = (
        StageMutationResult._exclude_request
        | frozenset({"pull_request_number", "pull_request_url", "pull_request_identity"})
    )
    _exclude_external: ClassVar[frozenset[str]] = _exclude_request

    @model_validator(mode="after")
    def pull_request(self) -> Self:
        if self.candidate_ref != candidate_ref_for_operation(
            self.operation_id, self.operation_kind
        ):
            raise ValueError("pull request result ref is not operation-derived")
        if self.candidate_commit == self.base_commit or self.candidate_tree == self.base_tree:
            raise ValueError("pull request result head must differ from base")
        if not self.pull_request_url.startswith("https://"):
            raise ValueError("pull request result URL must use HTTPS")
        if self.pull_request_identity != _pull_request_identity(
            self.operation_id,
            self.repository_digest,
            self.pull_request_number,
            self.pull_request_url,
        ):
            raise ValueError("pull request result identity mismatch")
        return self


class AdmissionIssueResult(AdmissionIssueRequest, StageMutationResult):
    _exclude_request = StageMutationResult._exclude_request
    _exclude_external = _exclude_request


class QueueEnqueueResult(QueueEnqueueRequest, StageMutationResult):
    _exclude_request = StageMutationResult._exclude_request
    _exclude_external = _exclude_request


class GroupHoldIssueResult(GroupHoldIssueRequest, StageMutationResult):
    _exclude_request = StageMutationResult._exclude_request
    _exclude_external = _exclude_request


class ReleaseIssueResult(ReleaseIssueRequest, StageMutationResult):
    _exclude_request = StageMutationResult._exclude_request
    _exclude_external = _exclude_request


class StageObservationRequest(StageRequest):
    object_id: NonEmptyString


class CandidateObservationRequest(CandidatePublicationRequest, StageObservationRequest):
    pass


class PullRequestObservationRequest(StageObservationRequest):
    stage: Literal["pull_request_open"] = "pull_request_open"
    pull_request_number: StrictInt = Field(gt=0)
    candidate_ref: NonEmptyString
    head_commit: GitObject
    head_tree: GitObject
    base_commit: GitObject
    base_tree: GitObject

    @model_validator(mode="after")
    def pull_request(self) -> Self:
        if self.candidate_ref != candidate_ref_for_operation(
            self.operation_id, self.operation_kind
        ):
            raise ValueError("pull request observation ref is not operation-derived")
        if self.head_commit == self.base_commit or self.head_tree == self.base_tree:
            raise ValueError("pull request observation head must differ from base")
        return self


class AdmissionObservationRequest(AdmissionIssueRequest, StageObservationRequest):
    pass


class QueueObservationRequest(QueueEnqueueRequest, StageObservationRequest):
    """Read-only evidence of the singleton created by enqueue."""



class GroupHoldObservationRequest(GroupHoldIssueRequest, StageObservationRequest):
    pass


class ReleaseObservationRequest(ReleaseIssueRequest, StageObservationRequest):
    pass


class StageObservationResult(StageBound):
    outcome: ObservationOutcome
    evidence_digest: Sha256Digest
    observed_at: datetime
    _exclude_request: ClassVar[frozenset[str]] = frozenset(
        {"outcome", "evidence_digest", "observed_at"}
    )
    _exclude_external: ClassVar[frozenset[str]] = _exclude_request
    _time = field_validator("observed_at")(require_aware_datetime)


class CandidateObservationResult(CandidateObservationRequest, StageObservationResult):
    _exclude_request = StageObservationResult._exclude_request
    _exclude_external = _exclude_request


class PullRequestObservationResult(PullRequestObservationRequest, StageObservationResult):
    _exclude_request = StageObservationResult._exclude_request
    _exclude_external = _exclude_request


class AdmissionObservationResult(AdmissionObservationRequest, StageObservationResult):
    _exclude_request = StageObservationResult._exclude_request
    _exclude_external = _exclude_request


class QueueObservationResult(QueueObservationRequest, StageObservationResult):
    _exclude_request = StageObservationResult._exclude_request
    _exclude_external = _exclude_request


class GroupHoldObservationResult(GroupHoldObservationRequest, StageObservationResult):
    _exclude_request = StageObservationResult._exclude_request
    _exclude_external = _exclude_request


class ReleaseObservationResult(ReleaseObservationRequest, StageObservationResult):
    _exclude_request = StageObservationResult._exclude_request
    _exclude_external = _exclude_request


class TrustedClock(Protocol):
    def now(self) -> datetime: ...


class LeaseFence(Protocol):
    def assert_current(
        self, *, operation_id: Sha256Digest, lease_epoch_digest: Sha256Digest
    ) -> None: ...


class CandidatePublicationCapability(Protocol):
    def publish_candidate(
        self, request: CandidatePublicationRequest
    ) -> CandidatePublicationResult: ...


class PullRequestPreparationCapability(Protocol):
    def create_pull_request(self, request: PullRequestCreateRequest) -> PullRequestCreateResult: ...


class PullRequestReconciliationCapability(Protocol):
    def reconcile_pull_request(
        self, request: PullRequestReconcileRequest
    ) -> PullRequestObservationResult: ...


class PullRequestLookupCapability(Protocol):
    def lookup_pull_request(
        self, request: PullRequestLookupRequest
    ) -> PullRequestObservationResult: ...


class QueueEnqueueCapability(Protocol):
    def enqueue(self, request: QueueEnqueueRequest) -> QueueEnqueueResult: ...


class QueueConfigurationObservationCapability(Protocol):
    """Read-only pre-enqueue queue policy capability."""

    def observe_queue_configuration(self) -> MainQueueConfigurationObservation: ...


class AdmissionIssuerCapability(Protocol):
    def issue_admission(self, request: AdmissionIssueRequest) -> AdmissionIssueResult: ...


class GroupHoldIssuerCapability(Protocol):
    def issue_group_hold(self, request: GroupHoldIssueRequest) -> GroupHoldIssueResult: ...


class ReleaseIssuerCapability(Protocol):
    def issue_release(self, request: ReleaseIssueRequest) -> ReleaseIssueResult: ...


class ReadOnlyObservationCapability(Protocol):
    def observe_queue_configuration(self) -> MainQueueConfigurationObservation: ...

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


__all__ = [n for n, v in globals().items() if isinstance(v, type) and v.__module__ == __name__]
