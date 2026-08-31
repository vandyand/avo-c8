"""Durable, capability-separated execution of one C4 mutation stage.

This module deliberately knows nothing about the protected-main chronology.  A
coordinator gives it an already-authorized intent and the exact request for one
stage.  The kernel owns the small (but important) write protocol around that
request: durable intent, last-moment fencing, one provider call, receipt, and
read-only reconciliation of an uncertain call.
"""
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnnecessaryCast=false, reportAttributeAccessIssue=false, reportIndexIssue=false

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, Literal, Protocol, cast

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
)
from avo_correlate.application.c4_capabilities import (
    AdmissionIssueRequest,
    AdmissionObservationRequest,
    CandidateObservationRequest,
    CandidatePublicationRequest,
    GroupHoldIssueRequest,
    GroupHoldObservationRequest,
    PullRequestCreateRequest,
    PullRequestObservationRequest,
    QueueEnqueueRequest,
    QueueObservationRequest,
    ReadOnlyObservationCapability,
    ReleaseIssueRequest,
    ReleaseObservationRequest,
    StageMutationResult,
    StageObservationRequest,
    StageObservationResult,
    StageRequest,
    TrustedClock,
)
from avo_correlate.contracts.base import NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.contracts.main_graduation import MainBound
from avo_correlate.contracts.main_graduation_phase_a import (
    MainMutationFenceResolution,
    MainMutationIntent,
    MainMutationOutcome,
    MainMutationReceipt,
    MainUnresolvedMutationFence,
    main_target_scope_digest,
)
from avo_correlate.domain.canonical import canonical_digest


class StageLeaseFence(Protocol):
    def assert_current(
        self, *, operation_id: Sha256Digest, lease_epoch_digest: Sha256Digest
    ) -> None: ...


class StageAuthorityVerifier(Protocol):
    """Optional controller-owned checks over provider evidence.

    The Phase-A journal verifier remains the authority for persisted receipts
    and resolutions.  A C4 controller may additionally implement either pair
    of methods below to authenticate a provider DTO before the DTO is copied
    into a durable record.  ``...`` is intentional: this protocol is a narrow
    structural seam and does not prescribe provider-specific evidence.
    """

    def verify_stage_result(
        self, result: StageMutationResult, request: StageRequest, intent: MainMutationIntent
    ) -> None: ...

    def verify_stage_observation(
        self,
        result: StageObservationResult,
        request: StageObservationRequest,
        intent: MainMutationIntent,
    ) -> None: ...


class C4StageExecutionError(RuntimeError):
    """A stage cannot safely be executed or recovered."""


EffectiveStageOutcome = MainMutationOutcome | Literal["not_applied"]


@dataclass(frozen=True)
class C4StageExecutionResult:
    """The effective, read-only result of one stage execution or recovery.

    ``receipt`` is always the original durable mutation receipt.  In
    particular, an ambiguous receipt is never rewritten after a fence is
    resolved.  When an authoritative observed resolution exists,
    ``effective_outcome`` is the outcome established by that observation and
    ``parent_resolution_digest`` is the proof a coordinator may embed in the
    next intent.
    """

    receipt: MainMutationReceipt
    effective_outcome: EffectiveStageOutcome
    authoritative_resolution: MainMutationFenceResolution | None = None
    parent_resolution_digest: Sha256Digest | None = None

    @property
    def has_authoritative_resolution(self) -> bool:
        """Whether a durable, verifier-approved fence resolution was found."""

        return self.authoritative_resolution is not None

    @property
    def can_advance_parent(self) -> bool:
        """Whether this result authorizes a successor stage intent."""

        return self.parent_resolution_digest is not None


_MUTATION_REQUESTS: dict[str, tuple[type[StageRequest], str]] = {
    "candidate_publication": (CandidatePublicationRequest, "publish_candidate"),
    "pull_request_open": (PullRequestCreateRequest, "create_pull_request"),
    "admission_check": (AdmissionIssueRequest, "issue_admission"),
    "queue_enqueue": (QueueEnqueueRequest, "enqueue"),
    "merge_group_hold": (GroupHoldIssueRequest, "issue_group_hold"),
    "release_transition": (ReleaseIssueRequest, "issue_release"),
}
_OBSERVATION_REQUESTS: dict[str, type[StageObservationRequest]] = {
    "candidate_publication": CandidateObservationRequest,
    "pull_request_open": PullRequestObservationRequest,
    "admission_check": AdmissionObservationRequest,
    "queue_enqueue": QueueObservationRequest,
    "merge_group_hold": GroupHoldObservationRequest,
    "release_transition": ReleaseObservationRequest,
}
_LOCK_GUARD = Lock()
_DISPATCH_LOCKS: dict[str, Lock] = {}


@contextmanager
def _operation_lock(operation_id: str):
    """Serialize local duplicate runners while the journal provides CAS."""

    with _LOCK_GUARD:
        lock = _DISPATCH_LOCKS.setdefault(operation_id, Lock())
    with lock:
        yield


def _canonical_model(model: StrictModel) -> StrictModel:
    """Reparse a DTO at the execution boundary (never trust constructed DTOs)."""

    return type(model).model_validate_json(model.model_dump_json())


def _digest_record(model: type[StrictModel], values: dict[str, Any], field: str) -> StrictModel:
    values = dict(values)
    probe_values = {**values, field: "sha256:" + "0" * 64}
    probe = cast(Any, model).model_construct(**probe_values)
    values[field] = canonical_digest(probe.model_dump(exclude={field}, mode="json"))
    return model.model_validate(values)


def _same_binding(intent: MainMutationIntent, request: StageRequest) -> None:
    if (
        request.operation_id != intent.operation_id
        or request.repository_digest != intent.repository_digest
        or request.target_ref != intent.target_ref
        or request.stage != intent.stage
        or request.lease_epoch_digest != intent.lease_epoch_digest
        or request.request_digest != intent.request_digest
        or request.external_identity != intent.external_identity.identity_digest
    ):
        raise C4StageExecutionError("stage request does not exactly match mutation intent")


def _same_observation_binding(intent: MainMutationIntent, request: StageObservationRequest) -> None:
    if (
        request.operation_id != intent.operation_id
        or request.repository_digest != intent.repository_digest
        or request.target_ref != intent.target_ref
        or request.stage != intent.stage
        or request.lease_epoch_digest != intent.lease_epoch_digest
    ):
        raise C4StageExecutionError("observation request does not match mutation intent")


def _immutable_stage_projection(request: StageRequest) -> dict[str, Any]:
    """Return request fields that identify the intended stage object.

    Operation/lease/request/external identity fields are checked separately.
    ``object_id`` and the PR server-assigned number are intentionally handled
    by the stage-specific binding below.
    """

    projection = request.model_dump(
        exclude={
            "operation_id",
            "repository_digest",
            "target_ref",
            "lease_epoch_digest",
            "request_digest",
            "external_key",
            "external_identity",
            "stage",
            "object_id",
        },
        mode="json",
    )
    if request.stage == "pull_request_open":
        projection.pop("pull_request_number", None)
        projection.pop("preparation_authorization_digest", None)
    return projection


def _check_observation_object_binding(
    original: StageRequest,
    observation: StageObservationRequest,
    provider_repository: str | None,
) -> None:
    """Bind a read target to the original mutation request.

    Pull-request creation is the one stage where the provider assigns the
    object number after dispatch.  Its immutable head/base/candidate
    projection is still derived from the original request; the observation
    object id is restricted to the assigned PR number.  Other stages expose
    a deterministic provider object id in their mutation request.
    """

    expected_projection = _immutable_stage_projection(original)
    observed_projection = _immutable_stage_projection(observation)
    # Queue generation is intentionally absent from the enqueue mutation
    # request and is first known from the post-enqueue observation.  The
    # queue-configuration digest remains the immutable pre-enqueue binding.
    if original.stage == "queue_enqueue":
        expected_projection.pop("queue_generation_digest", None)
        observed_projection.pop("queue_generation_digest", None)
    if original.stage == "pull_request_open":
        # PullRequestObservationRequest uses head_* for the create request's
        # candidate_* fields.  These are the same immutable provider object.
        expected_projection["head_commit"] = expected_projection.pop("candidate_commit")
        expected_projection["head_tree"] = expected_projection.pop("candidate_tree")
    if expected_projection != observed_projection:
        raise C4StageExecutionError("observation target differs from original stage request")

    expected_object_id: str | None = {
        "candidate_publication": getattr(original, "candidate_ref", None),
        "admission_check": getattr(original, "admission_run_id", None),
        "queue_enqueue": getattr(original, "pull_request_url", None),
        "merge_group_hold": getattr(original, "hold_run_id", None),
        "release_transition": getattr(original, "hold_run_id", None),
    }.get(original.stage)
    if original.stage == "pull_request_open":
        number = str(getattr(observation, "pull_request_number", ""))
        # GitHub's durable PR object key is ``owner/repository:pull/<n>``.
        # Require the configured repository prefix as well as the assigned
        # number; a caller cannot select another repository's PR.
        expected_object_id = (
            f"{provider_repository}:pull/{number}" if provider_repository and number else None
        )
        if expected_object_id is None or observation.object_id != expected_object_id:
            raise C4StageExecutionError(
                "observation object identity is not derived from assigned pull request"
            )
    elif expected_object_id is None or observation.object_id != expected_object_id:
        raise C4StageExecutionError("observation object identity is not derived from stage request")


class C4StageExecutor:
    """Execute/recover one already-authorized C4 stage.

    ``capability`` must expose exactly the method for ``intent.stage``.  The
    executor never accepts a generic mutation callable, which prevents a
    coordinator from accidentally handing a release capability to another
    stage.  Recovery takes an observation request explicitly because creation
    requests (notably pull-request creation) do not contain enough provider
    object identity to manufacture an observation request safely.
    """

    def __init__(
        self,
        *,
        journal: MainGraduationJournal,
        clock: TrustedClock,
        lease_fence: StageLeaseFence,
        capability: object,
        observation_capability: ReadOnlyObservationCapability | None = None,
        authority_verifier: StageAuthorityVerifier,
        provider_identity: str | None = None,
        provider_api_version: str | None = None,
        provider_repository: str | None = None,
    ) -> None:
        self.journal = journal
        self.clock = clock
        self.lease_fence = lease_fence
        self.capability = capability
        self.observation_capability = observation_capability
        self.authority_verifier = authority_verifier
        self.provider_identity = provider_identity or cast(
            str | None, getattr(capability, "provider_identity", None)
        )
        self.provider_api_version = provider_api_version or cast(
            str | None, getattr(capability, "provider_api_version", None)
        )
        self.provider_repository = provider_repository or cast(
            str | None, getattr(capability, "repository_name", None)
        )
        if self.provider_repository is None:
            owner = getattr(capability, "owner", None)
            repo = getattr(capability, "repo", None)
            if isinstance(owner, str) and isinstance(repo, str):
                self.provider_repository = f"{owner}/{repo}"

    def execute(self, intent: MainMutationIntent, request: StageRequest) -> MainMutationReceipt:
        intent = cast(MainMutationIntent, _canonical_model(intent))
        request = cast(StageRequest, _canonical_model(request))
        with _operation_lock(intent.intent_digest):
            return self._execute_locked(intent, request)

    def execute_effective(
        self, intent: MainMutationIntent, request: StageRequest
    ) -> C4StageExecutionResult:
        """Execute once and return the effective result for a coordinator.

        This is a compatibility-preserving wrapper around :meth:`execute`.
        The ordinary receipt API continues to return the immutable source
        receipt; callers that need to advance after authoritative recovery use
        this typed result instead.
        """

        receipt = self.execute(intent, request)
        return self.effective_result(intent, receipt)

    def _execute_locked(
        self, intent: MainMutationIntent, request: StageRequest
    ) -> MainMutationReceipt:
        self._check_request(intent, request)

        prior = self._read_receipt_for_intent(intent.intent_digest)
        if prior is not None:
            self._check_receipt_binding(prior, intent)
            return prior

        # An intent written by an earlier runner without a receipt is a
        # durable indication that dispatch ownership was already claimed (or
        # that its crash point is unknown).  It must go through recovery;
        # allowing execute() to continue here would permit a duplicate write.
        existing_intent = self.journal.read_mutation_intent(intent.intent_digest)
        if existing_intent is not None:
            if existing_intent[0] != intent:
                raise C4StageExecutionError("durable mutation intent differs")
            raise C4StageExecutionError("mutation intent has no receipt; recovery is required")

        self._check_prerequisites(intent)
        try:
            self.journal.record_mutation_intent(intent)
        except Exception as exc:
            # A create-once winner is safe to replay; an occupied target is
            # deliberately surfaced as a fail-closed execution error.
            prior = self._read_receipt_for_intent(intent.intent_digest)
            if prior is not None:
                self._check_receipt_binding(prior, intent)
                return prior
            raise C4StageExecutionError("mutation intent was not durably recorded") from exc

        try:
            self._last_moment_authority(intent, request)
        except C4StageExecutionError:
            raise
        except Exception as exc:
            raise C4StageExecutionError("last-moment authority check failed") from exc
        if not self._claim_dispatch_owner(intent, request):
            raise C4StageExecutionError(
                "mutation dispatch owner is already claimed; recovery is required"
            )
        # The ownership CAS itself can take time.  Re-run the trusted
        # authority check after it wins and immediately before crossing the
        # provider boundary.  If this check fails, retain the marker and force
        # read-only recovery; never release ownership and retry blindly.
        try:
            self._last_moment_authority(intent, request)
        except C4StageExecutionError:
            raise
        except Exception as exc:
            raise C4StageExecutionError("last-moment authority check failed") from exc
        try:
            result = self._dispatch(request)
        except Exception as exc:
            # A transport exception is inherently post-dispatch ambiguous: a
            # request may have reached the provider before the exception.
            return self._persist_ambiguous(intent, exc)

        result = cast(StageMutationResult, _canonical_model(result))
        try:
            self._verify_result(result, request, intent)
            receipt = self._receipt_from_result(intent, result)
            self._verify_receipt_authority(receipt, intent)
        except Exception as exc:
            # A result rejected by controller verification is evidence that
            # cannot be trusted, not evidence that no write occurred.
            return self._persist_ambiguous(intent, exc)
        self.journal.record_mutation_receipt(receipt)
        if receipt.outcome in {"ambiguous", "reconciliation_required"}:
            self._open_fence(intent, receipt)
        return receipt

    def _persist_ambiguous(
        self, intent: MainMutationIntent, error: Exception
    ) -> MainMutationReceipt:
        receipt = self._receipt_from_exception(intent, error)
        self._verify_receipt_authority(receipt, intent)
        self.journal.record_mutation_receipt(receipt)
        self._open_fence(intent, receipt)
        return receipt

    def recover(
        self,
        intent: MainMutationIntent | Sha256Digest,
        observation_request: StageObservationRequest,
        *,
        original_request: StageRequest,
    ) -> MainMutationReceipt:
        """Recover an uncertain stage with exactly one read-only observation.

        The original mutation request is mandatory because the durable intent
        stores its canonical digest, not every stage-specific request field.
        This prevents a recovery caller from choosing an unrelated provider
        object that happens to share the operation and stage.
        """

        expected = intent if isinstance(intent, str) else intent.intent_digest
        with _operation_lock(expected):
            return self._recover_locked(intent, observation_request, original_request)

    def recover_effective(
        self,
        intent: MainMutationIntent | Sha256Digest,
        observation_request: StageObservationRequest,
        *,
        original_request: StageRequest,
    ) -> C4StageExecutionResult:
        """Recover once and expose an authoritative successor-stage proof.

        Recovery remains read-only with respect to the provider.  The only
        writes possible here are the existing append-only ambiguous receipt,
        fence, and fence-resolution records needed to complete a recovery.
        """

        receipt = self.recover(
            intent, observation_request, original_request=original_request
        )
        return self.effective_result(intent, receipt)

    def effective_result(
        self,
        intent: MainMutationIntent | Sha256Digest,
        receipt: MainMutationReceipt | None = None,
    ) -> C4StageExecutionResult:
        """Read and classify a durable stage result without provider access.

        A resolved fence is an additional authoritative fact, not an update to
        its source receipt.  The source receipt is re-read and verified before
        the resolution is interpreted, so a caller cannot manufacture a
        successor-stage proof from an unrelated receipt.
        """

        expected = intent if isinstance(intent, str) else intent.intent_digest
        prior_intent = self.journal.read_mutation_intent(expected)
        if prior_intent is None:
            raise C4StageExecutionError("mutation intent is missing")
        durable_intent = prior_intent[0]
        if isinstance(intent, MainMutationIntent):
            intent = cast(MainMutationIntent, _canonical_model(intent))
            if durable_intent != intent:
                raise C4StageExecutionError("durable mutation intent differs")

        durable_receipt = self._read_receipt_for_intent(durable_intent.intent_digest)
        if durable_receipt is None:
            raise C4StageExecutionError("mutation receipt is missing")
        source_receipt = durable_receipt
        if receipt is not None:
            receipt = cast(MainMutationReceipt, _canonical_model(receipt))
            if receipt != source_receipt:
                raise C4StageExecutionError("supplied mutation receipt differs")
        self._check_receipt_binding(source_receipt, durable_intent)
        self._verify_receipt_authority(source_receipt, durable_intent)

        resolution = self._read_resolution_for_intent(durable_intent.intent_digest)
        if resolution is None:
            return C4StageExecutionResult(
                receipt=source_receipt,
                effective_outcome=source_receipt.outcome,
            )

        self._check_resolution_binding(resolution, durable_intent)
        self._check_resolution_provider(resolution)
        self._check_resolution_source(resolution, source_receipt)
        if resolution.outcome == "observed":
            observed_outcome = resolution.observed_outcome
            if observed_outcome is None:
                raise C4StageExecutionError("observed fence resolution lacks terminal outcome")
            return C4StageExecutionResult(
                receipt=source_receipt,
                effective_outcome=observed_outcome,
                authoritative_resolution=resolution,
                parent_resolution_digest=resolution.resolution_digest,
            )
        return C4StageExecutionResult(
            receipt=source_receipt,
            effective_outcome="not_applied",
            authoritative_resolution=resolution,
        )

    def _recover_locked(
        self,
        intent: MainMutationIntent | Sha256Digest,
        observation_request: StageObservationRequest,
        original_request: StageRequest,
    ) -> MainMutationReceipt:
        expected = intent if isinstance(intent, str) else intent.intent_digest
        prior_intent = self.journal.read_mutation_intent(expected)
        if prior_intent is None:
            raise C4StageExecutionError("mutation intent is missing")
        durable_intent = prior_intent[0]
        if isinstance(intent, MainMutationIntent) and durable_intent != intent:
            raise C4StageExecutionError("durable mutation intent differs")
        original_request = cast(StageRequest, _canonical_model(original_request))
        self._check_request(durable_intent, original_request)
        observation_request = cast(StageObservationRequest, _canonical_model(observation_request))
        self._check_observation_request(durable_intent, observation_request, original_request)

        # A resolved fence is closed and removed from the active target slot.
        # Discover its verified resolution before materializing a missing
        # receipt or attempting to create/reopen another fence.
        resolution = self._read_resolution_for_intent(durable_intent.intent_digest)
        if resolution is not None:
            self._check_resolution_binding(resolution, durable_intent)
            self._check_resolution_provider(resolution)
            resolved = self.journal.read_mutation_receipt(resolution.resolved_receipt_digest)
            if resolved is None:
                raise C4StageExecutionError("resolved mutation receipt is missing")
            receipt = resolved[0]
            self._check_receipt_binding(receipt, durable_intent)
            self._verify_receipt_authority(receipt, durable_intent)
            self._check_resolution_source(resolution, receipt)
            return receipt

        receipt = self._read_receipt_for_intent(durable_intent.intent_digest)
        if receipt is None:
            # A crash between provider dispatch and receipt publication leaves
            # only the intent reservation.  Materialize an ambiguous source
            # receipt; this is not a provider result and never permits retry.
            receipt = self._receipt_from_missing_dispatch(durable_intent)
            self._verify_receipt_authority(receipt, durable_intent)
            self.journal.record_mutation_receipt(receipt)
        self._check_receipt_binding(receipt, durable_intent)
        if receipt.outcome in {"applied", "already_applied", "rejected"}:
            return receipt

        fence = self._read_active_fence(durable_intent)
        if fence is not None:
            self._check_fence_binding(fence, durable_intent)
        if fence is None:
            fence = self._fence_from_receipt(durable_intent, receipt)
            self.journal.record_unresolved_mutation_fence(fence)
        resolution = self._read_resolution(fence.fence_digest)
        if resolution is not None:
            self._check_resolution_binding(resolution, durable_intent)
            self._check_resolution_provider(resolution)
            self._check_resolution_source(resolution, receipt)
            return receipt

        observed = self._observe(observation_request)
        self._verify_observation(observed, observation_request, durable_intent)
        if observed.outcome not in {"observed", "not_found"}:
            # Ambiguous/invalid observation leaves the target fence open.
            return receipt
        resolution = self._resolution_from_observation(fence, receipt, observed)
        self.journal.record_mutation_fence_resolution(resolution)
        return receipt

    # Public aliases are useful to coordinators that name the operation by
    # protocol rather than by implementation detail.
    execute_stage = execute
    recover_stage = recover

    def _check_request(self, intent: MainMutationIntent, request: StageRequest) -> None:
        expected = _MUTATION_REQUESTS.get(intent.stage)
        if expected is None or not isinstance(request, expected[0]):
            raise C4StageExecutionError("stage request type does not match stage")
        _same_binding(intent, request)
        method = expected[1]
        if not callable(getattr(self.capability, method, None)):
            raise C4StageExecutionError("capability does not implement the exact stage operation")

    def _check_observation_request(
        self,
        intent: MainMutationIntent,
        request: StageObservationRequest,
        original: StageRequest,
    ) -> None:
        expected = _OBSERVATION_REQUESTS.get(intent.stage)
        if expected is None or not isinstance(request, expected):
            raise C4StageExecutionError("observation request type does not match stage")
        _same_observation_binding(intent, request)
        _check_observation_object_binding(original, request, self.provider_repository)
        if self.observation_capability is None:
            raise C4StageExecutionError("read-only observation capability is missing")

    def _check_prerequisites(self, intent: MainMutationIntent) -> None:
        if intent.parent_resolution_digest is not None:
            resolution = self.journal.read_mutation_fence_resolution(
                intent.parent_resolution_digest
            )
            if resolution is None or resolution[0].intent_digest != intent.parent_intent_digest:
                raise C4StageExecutionError("parent fence resolution is missing or mismatched")
        elif intent.parent_intent_digest is not None and intent.parent_receipt is not None:
            parent = self.journal.read_mutation_intent(intent.parent_intent_digest)
            if parent is None or parent[0].operation_id != intent.operation_id:
                raise C4StageExecutionError("parent mutation intent is missing")
            if parent[0].stage != intent.parent_stage:
                raise C4StageExecutionError("parent mutation stage differs")

    def _last_moment_authority(self, intent: MainMutationIntent, request: StageRequest) -> None:
        expiry = getattr(request, "authorization_expires_at", None)
        if isinstance(expiry, datetime) and self.clock.now() >= expiry:
            raise C4StageExecutionError("stage authorization has expired")
        if intent.stage == "release_transition":
            if intent.release_claim_digest is None:
                raise C4StageExecutionError("release claim is missing")
            claim = self.journal.read_release_claim(intent.release_claim_digest)
            if claim is None or claim[0].operation_id != intent.operation_id:
                raise C4StageExecutionError("release claim is missing or mismatched")
            if self.clock.now() >= claim[0].authorization_expires_at:
                raise C4StageExecutionError("release authorization has expired")
        # This call is intentionally the final operation before dispatch.
        self.lease_fence.assert_current(
            operation_id=intent.operation_id, lease_epoch_digest=intent.lease_epoch_digest
        )

    def _dispatch(self, request: StageRequest) -> StageMutationResult:
        method = _MUTATION_REQUESTS[request.stage][1]
        return cast(StageMutationResult, getattr(self.capability, method)(request))

    def _claim_dispatch_owner(self, intent: MainMutationIntent, request: StageRequest) -> bool:
        claimer = getattr(self.journal, "claim_mutation_dispatch", None)
        if not callable(claimer):
            raise C4StageExecutionError("journal dispatch-owner CAS is missing")
        try:
            return bool(
                claimer(
                    operation_id=intent.operation_id,
                    intent_digest=intent.intent_digest,
                    request_digest=request.request_digest,
                    stage=intent.stage,
                    repository_digest=intent.repository_digest,
                    target_ref=intent.target_ref,
                    external_identity_digest=intent.external_identity.identity_digest,
                    lease_identity=intent.lease_identity,
                    lease_digest=intent.lease_digest,
                    lease_epoch_digest=intent.lease_epoch_digest,
                    recorded_at=self.clock.now(),
                )
            )
        except C4StageExecutionError:
            raise
        except Exception as exc:
            raise C4StageExecutionError("mutation dispatch owner was not durably claimed") from exc

    def _verify_result(
        self, result: StageMutationResult, request: StageRequest, intent: MainMutationIntent
    ) -> None:
        if result.stage != intent.stage or result.request_digest != request.request_digest:
            raise C4StageExecutionError("provider result identity differs from request")
        if result.external_identity != intent.external_identity.identity_digest:
            raise C4StageExecutionError("provider result external identity differs")
        verifier = self.authority_verifier
        fn = getattr(verifier, "verify_stage_result", None) or getattr(
            verifier, "verify_mutation_result", None
        )
        if not callable(fn):
            raise C4StageExecutionError("controller stage-result verifier is missing")
        fn(result, request, intent)

    def _verify_receipt_authority(
        self, receipt: MainMutationReceipt, intent: MainMutationIntent
    ) -> None:
        """Run the journal's mandatory controller verifier before publication."""

        fn = getattr(self.journal, "_verify_mutation_receipt", None)
        if not callable(fn):
            raise C4StageExecutionError("journal receipt authority verifier is missing")
        try:
            fn(receipt, intent)
        except Exception as exc:
            raise C4StageExecutionError("controller rejected mutation receipt") from exc

    def _verify_observation(
        self,
        result: StageObservationResult,
        request: StageObservationRequest,
        intent: MainMutationIntent,
    ) -> None:
        if result.stage != intent.stage or result.request_digest != request.request_digest:
            raise C4StageExecutionError("provider observation identity differs from request")
        if result.external_identity != request.external_identity:
            raise C4StageExecutionError("provider observation identity differs from request")
        verifier = self.authority_verifier
        fn = getattr(verifier, "verify_stage_observation", None) or getattr(
            verifier, "verify_observation", None
        )
        if not callable(fn):
            raise C4StageExecutionError("controller observation verifier is missing")
        fn(result, request, intent)

    def _receipt_values(self, intent: MainMutationIntent) -> dict[str, Any]:
        return {
            "repository_digest": intent.repository_digest,
            "target_ref": intent.target_ref,
            "operation_id": intent.operation_id,
            "stage": intent.stage,
            "intent_digest": intent.intent_digest,
            "parent_intent_digest": intent.parent_intent_digest,
            "lease_identity": intent.lease_identity,
            "lease_digest": intent.lease_digest,
            "lease_epoch_digest": intent.lease_epoch_digest,
            "policy_epoch_digest": intent.policy_epoch_digest,
            "controller_config_digest": intent.controller_config_digest,
            "preparation_authorization_digest": intent.preparation_authorization_digest,
            "release_authorization_digest": intent.release_authorization_digest,
            "release_claim_digest": intent.release_claim_digest,
            "external_identity": intent.external_identity,
        }

    def _receipt_from_result(
        self, intent: MainMutationIntent, result: StageMutationResult
    ) -> MainMutationReceipt:
        values = self._receipt_values(intent)
        values.update(
            outcome=result.outcome,
            dispatch_started=result.dispatch_started,
            response_digest=result.response_digest,
            observed_at=result.observed_at,
        )
        return cast(
            MainMutationReceipt, _digest_record(MainMutationReceipt, values, "receipt_digest")
        )

    def _receipt_from_exception(
        self, intent: MainMutationIntent, error: Exception
    ) -> MainMutationReceipt:
        values = self._receipt_values(intent)
        values.update(
            outcome="ambiguous",
            dispatch_started=True,
            response_digest=canonical_digest(
                {"exception": type(error).__name__, "message": str(error)}
            ),
            observed_at=self.clock.now(),
        )
        return cast(
            MainMutationReceipt, _digest_record(MainMutationReceipt, values, "receipt_digest")
        )

    def _receipt_from_missing_dispatch(self, intent: MainMutationIntent) -> MainMutationReceipt:
        values = self._receipt_values(intent)
        values.update(
            outcome="ambiguous",
            dispatch_started=True,
            response_digest=canonical_digest({"recovery": "receipt-missing-after-reservation"}),
            observed_at=self.clock.now(),
        )
        return cast(
            MainMutationReceipt, _digest_record(MainMutationReceipt, values, "receipt_digest")
        )

    def _fence_from_receipt(
        self, intent: MainMutationIntent, receipt: MainMutationReceipt
    ) -> MainUnresolvedMutationFence:
        values: dict[str, Any] = {
            "repository_digest": intent.repository_digest,
            "target_ref": intent.target_ref,
            "operation_id": intent.operation_id,
            "stage": intent.stage,
            "intent_digest": intent.intent_digest,
            "source_receipt_digest": receipt.receipt_digest,
            "external_identity_digest": intent.external_identity.identity_digest,
            "lease_identity": intent.lease_identity,
            "lease_digest": intent.lease_digest,
            "target_scope_digest": main_target_scope_digest(
                intent.repository_digest, intent.target_ref
            ),
            "opened_at": self.clock.now(),
        }
        return cast(
            MainUnresolvedMutationFence,
            _digest_record(MainUnresolvedMutationFence, values, "fence_digest"),
        )

    def _resolution_from_observation(
        self,
        fence: MainUnresolvedMutationFence,
        receipt: MainMutationReceipt,
        observation: StageObservationResult,
    ) -> MainMutationFenceResolution:
        if not self.provider_identity or not self.provider_api_version:
            raise C4StageExecutionError("provider identity/version is not controller configured")
        values: dict[str, Any] = {
            "repository_digest": fence.repository_digest,
            "target_ref": fence.target_ref,
            "fence_digest": fence.fence_digest,
            "operation_id": fence.operation_id,
            "intent_digest": fence.intent_digest,
            "external_identity_digest": fence.external_identity_digest,
            "lease_identity": fence.lease_identity,
            "lease_digest": fence.lease_digest,
            "target_scope_digest": fence.target_scope_digest,
            "resolved_receipt_digest": receipt.receipt_digest,
            "authoritative_observation_digest": observation.evidence_digest,
            "provider_identity": cast(NonEmptyString, self.provider_identity),
            "provider_api_version": cast(NonEmptyString, self.provider_api_version),
            "outcome": "observed" if observation.outcome == "observed" else "not_applied",
            "observed_outcome": "already_applied" if observation.outcome == "observed" else None,
            "resolved_at": self.clock.now(),
        }
        return cast(
            MainMutationFenceResolution,
            _digest_record(MainMutationFenceResolution, values, "resolution_digest"),
        )

    def _open_fence(self, intent: MainMutationIntent, receipt: MainMutationReceipt) -> None:
        fence = self._read_active_fence(intent)
        if fence is None:
            self.journal.record_unresolved_mutation_fence(self._fence_from_receipt(intent, receipt))

    def _read_receipt_for_intent(self, digest: str) -> MainMutationReceipt | None:
        reader = getattr(self.journal, "_read_receipt_for_intent", None)
        if not callable(reader):
            return None
        prior = reader(digest)
        return None if prior is None else cast(MainMutationReceipt, prior[0])

    def _read_active_fence(self, intent: MainMutationIntent) -> MainUnresolvedMutationFence | None:
        path_fn = getattr(self.journal, "_target_fence_path", None)
        envelope_fn = getattr(self.journal, "_read_target_fence_envelope", None)
        if not callable(path_fn) or not callable(envelope_fn):
            return None
        path = cast(Path, path_fn(intent))
        if not (path / "record.json").is_file():
            return None
        envelope = envelope_fn(
            path,
            MainBound(repository_digest=intent.repository_digest, target_ref=intent.target_ref),
        )
        prior = self.journal.read_unresolved_mutation_fence(envelope.fence_digest)
        return None if prior is None else prior[0]

    def _read_resolution(self, fence_digest: str) -> MainMutationFenceResolution | None:
        reader = getattr(self.journal, "read_mutation_fence_resolution_by_fence", None)
        if not callable(reader):
            raise C4StageExecutionError("journal verified fence-resolution reader is missing")
        prior = reader(fence_digest)
        return None if prior is None else cast(MainMutationFenceResolution, prior[0])

    def _read_resolution_for_intent(
        self, intent_digest: Sha256Digest
    ) -> MainMutationFenceResolution | None:
        reader = getattr(self.journal, "read_mutation_fence_resolution_by_intent", None)
        if not callable(reader):
            raise C4StageExecutionError("journal verified fence-resolution reader is missing")
        prior = reader(intent_digest)
        return None if prior is None else cast(MainMutationFenceResolution, prior[0])

    def _observe(self, request: StageObservationRequest) -> StageObservationResult:
        capability = self.observation_capability
        if capability is None:
            raise C4StageExecutionError("read-only observation capability is missing")
        method_name = {
            "candidate_publication": "observe_candidate",
            "pull_request_open": "observe_pull_request",
            "admission_check": "observe_admission",
            "queue_enqueue": "observe_queue",
            "merge_group_hold": "observe_group_hold",
            "release_transition": "observe_release",
        }[request.stage]
        method = getattr(capability, method_name, None)
        if not callable(method):
            raise C4StageExecutionError(
                "observation capability does not implement exact stage read"
            )
        return cast(StageObservationResult, method(request))

    def _check_receipt_binding(
        self, receipt: MainMutationReceipt, intent: MainMutationIntent
    ) -> None:
        if (
            receipt.intent_digest != intent.intent_digest
            or receipt.operation_id != intent.operation_id
            or receipt.stage != intent.stage
            or receipt.external_identity != intent.external_identity
        ):
            raise C4StageExecutionError("durable mutation receipt differs from intent")

    def _check_fence_binding(
        self, fence: MainUnresolvedMutationFence, intent: MainMutationIntent
    ) -> None:
        if (
            fence.intent_digest != intent.intent_digest
            or fence.operation_id != intent.operation_id
            or fence.stage != intent.stage
            or fence.repository_digest != intent.repository_digest
            or fence.target_ref != intent.target_ref
            or fence.external_identity_digest != intent.external_identity.identity_digest
            or fence.lease_digest != intent.lease_digest
            or fence.lease_identity != intent.lease_identity
        ):
            raise C4StageExecutionError("durable mutation fence differs from intent")

    def _check_resolution_binding(
        self, resolution: MainMutationFenceResolution, intent: MainMutationIntent
    ) -> None:
        if (
            resolution.intent_digest != intent.intent_digest
            or resolution.operation_id != intent.operation_id
            or resolution.repository_digest != intent.repository_digest
            or resolution.target_ref != intent.target_ref
            or resolution.external_identity_digest
            != intent.external_identity.identity_digest
            or resolution.lease_digest != intent.lease_digest
            or resolution.lease_identity != intent.lease_identity
        ):
            raise C4StageExecutionError("durable fence resolution differs from intent")

    def _check_resolution_provider(self, resolution: MainMutationFenceResolution) -> None:
        if not self.provider_identity or not self.provider_api_version:
            raise C4StageExecutionError(
                "provider identity/version is not controller configured"
            )
        if (
            resolution.provider_identity != self.provider_identity
            or resolution.provider_api_version != self.provider_api_version
        ):
            raise C4StageExecutionError("durable fence resolution provider differs")

    @staticmethod
    def _check_resolution_source(
        resolution: MainMutationFenceResolution, receipt: MainMutationReceipt
    ) -> None:
        if resolution.resolved_receipt_digest != receipt.receipt_digest:
            raise C4StageExecutionError("fence resolution source receipt differs")
        if receipt.outcome not in {"ambiguous", "reconciliation_required"}:
            raise C4StageExecutionError("fence resolution source receipt is terminal")
        if resolution.outcome == "observed" and resolution.observed_outcome is None:
            raise C4StageExecutionError("observed fence resolution lacks terminal outcome")


__all__ = [
    "C4StageExecutionError",
    "C4StageExecutionResult",
    "C4StageExecutor",
    "EffectiveStageOutcome",
    "StageAuthorityVerifier",
    "StageLeaseFence",
]
