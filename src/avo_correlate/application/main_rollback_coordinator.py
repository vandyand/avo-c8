"""Restart-safe aggregate coordinator for protected-main rollback.

Rollback is a sibling lifecycle to graduation.  This module intentionally does
not call the graduation coordinators: it starts from the durable successful
graduation package, obtains rollback authority from :class:`MainRollbackAuthority`,
and then runs the same capability-separated C4 stages in the rollback namespace.

The provider DTOs used to construct terminal rollback records are observations,
never authority.  A controller-owned ``result_builder`` and ``authority_verifier``
must authenticate the result before it is journaled.
"""
# Capability implementations are intentionally injected at this boundary;
# their concrete provider types live in adapter modules.  Runtime checks below
# keep the boundary fail-closed while these diagnostics remain adapter-agnostic.
# pyright: reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportArgumentType=false

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal, cast

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.adapters.hosted_git.protected_main import MainPullRequestObservation
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
    ReleaseIssueRequest,
    ReleaseObservationRequest,
    StageMutationResult,
    StageRequest,
)
from avo_correlate.application.c4_stage_executor import (
    C4StageExecutionError,
    C4StageExecutionResult,
    C4StageExecutor,
    StageAuthorityVerifier,
    StageLeaseFence,
)
from avo_correlate.application.main_rollback_authority import (
    MainRollbackAuthority,
    MainRollbackAuthorityError,
    MainRollbackAuthorityResult,
)
from avo_correlate.contracts.base import ArtifactRef, Sha256Digest, StrictModel
from avo_correlate.contracts.main_graduation import (
    MainAttestationManifest,
    MainCheckObservation,
    MainCompletionPackage,
    MainMergeGroupChecks,
    MainMergeGroupWebhookReceipt,
    MainMutationIntent,
    MainMutationReceipt,
    MainProtectionManifest,
    MainQueueAdmissionObservation,
    MainQueueConfigurationObservation,
    MainQueueObservation,
    MainReleaseAuthorization,
    MainReleaseHoldObservation,
    MainReleaseTransitionReceipt,
    MainRollbackCleanupIntent,
    MainRollbackCleanupObservation,
    MainRollbackCleanupReceipt,
    MainRollbackCleanupTerminalEvidence,
    MainRollbackCompletionPackage,
    MainRollbackPostStateObservation,
    MainRollbackResultReceipt,
    main_release_claim_key,
    main_target_scope_digest,
    rollback_cleanup_authority_digest,
)
from avo_correlate.contracts.main_graduation_phase_a import (
    MainClaimedReleaseTransitionReceipt,
    MainLeaseEvidenceRecord,
    MainReleaseClaim,
    main_stage_nonce,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

_ZERO = "sha256:" + "0" * 64


class _CaptureCapability:
    """Expose one exact mutation method while retaining its typed DTO."""

    def __init__(self, capability: object, method_name: str) -> None:
        self._capability = capability
        self._method_name = method_name
        self.result: StageMutationResult | None = None

    def __getattr__(self, name: str) -> Any:
        if name != self._method_name:
            raise AttributeError(name)
        method = getattr(self._capability, name)

        def call(request: StageRequest) -> StageMutationResult:
            value = method(request)
            self.result = value
            return cast(StageMutationResult, value)

        return call


class MainRollbackCoordinatorError(RuntimeError):
    """Rollback cannot safely advance or recover."""


@dataclass(frozen=True, slots=True)
class RollbackResult:
    operation_id: Sha256Digest
    state: Literal["completed", "reconciliation_required", "quarantined"]
    package: MainRollbackCompletionPackage | None = None
    stage: str | None = None
    reason: str | None = None
    artifacts: Mapping[str, Sha256Digest] = field(default_factory=dict)


def _digest_record(model: type[Any], values: Mapping[str, object], field_name: str) -> Any:
    payload = dict(values)
    probe = model.model_construct(**payload, **{field_name: _ZERO})
    payload[field_name] = canonical_digest(probe.model_dump(exclude={field_name}, mode="json"))
    return model.model_validate(payload)


def _canonical(value: object, expected: type[Any]) -> Any:
    if not isinstance(value, expected):
        raise MainRollbackCoordinatorError(f"provider returned an untyped {expected.__name__}")
    try:
        return expected.model_validate_json(value.model_dump_json())
    except Exception as exc:
        raise MainRollbackCoordinatorError(
            f"provider returned invalid {expected.__name__}"
        ) from exc


class MainRollbackCoordinator:
    """Compose, execute, recover, and close one rollback operation.

    Constructor arguments are deliberately capability-shaped.  ``provider`` is
    read-only evidence access; mutation capabilities are separate objects and
    are each checked for their one exact method.  The coordinator never owns a
    generic provider mutation callable or a direct ref-update capability.
    """

    def __init__(
        self,
        *,
        journal: MainGraduationJournal,
        clock: Any,
        lease_fence: StageLeaseFence,
        rollback_authority: MainRollbackAuthority,
        provider: object,
        publication_capability: object,
        pull_request_capability: object,
        admission_capability: object,
        enqueue_capability: object,
        hold_capability: object,
        release_capability: object,
        observation_capability: object | None = None,
        cleanup_capability: object | None = None,
        authority_verifier: StageAuthorityVerifier,
        result_builder: object | None = None,
        release_authorizer: object | None = None,
        attester: object | None = None,
        authorization_ttl: timedelta = timedelta(minutes=5),
        provider_identity: str | None = None,
        provider_api_version: str | None = None,
    ) -> None:
        if authorization_ttl <= timedelta(0):
            raise ValueError("authorization_ttl must be positive")
        capabilities = {
            "candidate_publication": publication_capability,
            "pull_request_open": pull_request_capability,
            "admission_check": admission_capability,
            "queue_enqueue": enqueue_capability,
            "merge_group_hold": hold_capability,
            "release_transition": release_capability,
        }
        methods = {
            "candidate_publication": "publish_candidate",
            "pull_request_open": "create_pull_request",
            "admission_check": "issue_admission",
            "queue_enqueue": "enqueue",
            "merge_group_hold": "issue_group_hold",
            "release_transition": "issue_release",
        }
        for stage, capability in capabilities.items():
            if not callable(getattr(capability, methods[stage], None)):
                raise ValueError(f"{stage} capability does not expose its exact operation")
        if hold_capability is release_capability:
            raise ValueError("hold and release capabilities must be separate")
        if callable(getattr(hold_capability, "issue_release", None)):
            raise ValueError("hold capability must not expose release")
        if callable(getattr(release_capability, "issue_group_hold", None)):
            raise ValueError("release capability must not expose group hold")
        if cleanup_capability is not None and not callable(
            getattr(cleanup_capability, "cleanup_rollback", None)
        ):
            raise ValueError("cleanup capability does not expose cleanup_rollback")
        self.journal = journal
        self.clock = clock
        self.lease_fence = lease_fence
        self.rollback_authority = rollback_authority
        self.provider = provider
        self.observation_capability = observation_capability or provider
        self.capabilities = capabilities
        self.cleanup_capability = cleanup_capability
        self.authority_verifier = authority_verifier
        self.result_builder = result_builder
        if release_authorizer is None or not callable(
            getattr(release_authorizer, "authorize_release", None)
        ):
            raise ValueError("controller-owned release authorizer is required")
        self.release_authorizer = release_authorizer
        if (
            attester is None
            or not callable(getattr(attester, "attest_admission", None))
            or not callable(getattr(attester, "attest_hold", None))
        ):
            raise ValueError("controller-owned admission/hold attester is required")
        self.attester = attester
        self.authorization_ttl = authorization_ttl
        self.provider_identity = provider_identity or cast(
            str | None, getattr(provider, "provider_identity", None)
        )
        self.provider_api_version = provider_api_version or cast(
            str | None, getattr(provider, "provider_api_version", None)
        )
        if not self.provider_identity or not self.provider_api_version:
            raise ValueError("provider identity and API version are required")
        self._stage_results: dict[str, StageMutationResult] = {}

    def execute(
        self,
        source_operation_id: Sha256Digest,
        *,
        attempt_nonce: str,
        composition: Any,
        lease: MainLeaseEvidenceRecord | None = None,
        group_sha: str | None = None,
        webhook_body: bytes | None = None,
        webhook_headers: Mapping[str, str] | None = None,
        pull_request_number: int | None = None,
    ) -> RollbackResult:
        """Run or recover the complete rollback chronology."""
        try:
            authority = self.rollback_authority.prepare(
                source_operation_id=source_operation_id,
                attempt_nonce=attempt_nonce,
                composition=composition,
                lease=lease,
            )
            existing = self.journal.read_rollback_completion(authority.operation_id)
            if existing is not None:
                package = existing[0]
                return RollbackResult(package.operation_id, "completed", package=package)
            return self._execute_authority(
                authority,
                group_sha=group_sha,
                webhook_body=webhook_body,
                webhook_headers=webhook_headers,
                pull_request_number=pull_request_number,
            )
        except (
            MainRollbackCoordinatorError,
            MainRollbackAuthorityError,
            C4StageExecutionError,
            MainGraduationJournalError,
            ValueError,
            TypeError,
        ) as exc:
            return RollbackResult(source_operation_id, "quarantined", reason=str(exc))

    run = execute
    resume = execute

    def recover_cleanup(
        self,
        *,
        authority: MainRollbackAuthorityResult,
        result: MainRollbackResultReceipt,
        cleanup_intent: MainRollbackCleanupIntent,
    ) -> tuple[
        MainRollbackCleanupReceipt,
        MainRollbackCleanupObservation | None,
        MainRollbackCleanupTerminalEvidence | None,
    ]:
        """Recover cleanup from a durable owner without running lifecycle stages.

        Every supplied record is compared with its journal-backed counterpart
        before recovery.  The owner marker is mandatory: this seam cannot
        reserve a cleanup dispatch, and the delegated path only reconciles
        read-only after the owner boundary.
        """
        operation_id = authority.operation_id
        if (
            result.operation_id != operation_id
            or cleanup_intent.operation_id != operation_id
            or cleanup_intent.result_receipt_digest != result.receipt_digest
        ):
            raise MainRollbackCoordinatorError("cleanup recovery operation binding differs")

        durable_intent = self.journal.read_rollback_cleanup_intent(operation_id)
        if durable_intent is None or canonical_bytes(durable_intent[0]) != canonical_bytes(
            cleanup_intent
        ):
            raise MainRollbackCoordinatorError("durable cleanup intent differs")
        durable_result = self.journal.read_rollback_result(operation_id)
        if durable_result is None or canonical_bytes(durable_result[0]) != canonical_bytes(result):
            raise MainRollbackCoordinatorError("durable rollback result differs")

        ancestry: tuple[tuple[str, object | None, object], ...] = (
            ("lease", self.journal.read_lease_evidence_record(operation_id), authority.lease),
            (
                "composition",
                self.journal.read_rollback_composition(authority.composition.composition_id),
                authority.composition,
            ),
            (
                "rollback authorization",
                self.journal.read_rollback_authorization(operation_id),
                authority.authorization,
            ),
            (
                "rollback intent",
                self.journal.read_rollback_intent(operation_id),
                authority.intent,
            ),
            (
                "attempt authority",
                self.journal.read_rollback_attempt_authority(operation_id),
                authority.attempt_authority,
            ),
            (
                "preparation authorization",
                self.journal.read_rollback_preparation_authorization(operation_id),
                authority.preparation_authorization,
            ),
        )
        for name, loaded, expected in ancestry:
            if loaded is None or canonical_bytes(loaded[0]) != canonical_bytes(expected):
                raise MainRollbackCoordinatorError(f"durable {name} ancestry differs")

        owner_reader = getattr(self.journal, "read_rollback_cleanup_dispatch_owner", None)
        if not callable(owner_reader):
            raise MainRollbackCoordinatorError("journal cleanup dispatch-owner reader is missing")
        owner = owner_reader(cleanup_intent.intent_digest)
        if owner is None:
            raise MainRollbackCoordinatorError("durable cleanup dispatch owner is missing")
        return self._cleanup(authority, result, cleanup_intent)

    def _execute_authority(
        self,
        authority: MainRollbackAuthorityResult,
        *,
        group_sha: str | None = None,
        webhook_body: bytes | None = None,
        webhook_headers: Mapping[str, str] | None = None,
        pull_request_number: int | None = None,
    ) -> RollbackResult:
        op = authority.operation_id
        source = self._source(op, authority.intent.source_operation_id)
        evidence = self._evidence(authority, source)
        prep = authority.preparation_authorization
        lease = authority.lease
        receipts: dict[str, MainMutationReceipt] = {}
        parent: tuple[MainMutationIntent, C4StageExecutionResult] | None = None

        candidate = CandidatePublicationRequest.build(
            operation_id=op,
            operation_kind="rollback",
            repository_digest=authority.intent.repository_digest,
            lease_epoch_digest=lease.lease_epoch_digest,
            candidate_ref=authority.intent.candidate_ref,
            candidate_commit=authority.composition.candidate_commit,
            preparation_authorization_digest=prep.authorization_digest,
        )
        parent = self._stage(candidate, authority, None)
        receipts[candidate.stage] = parent[1].receipt
        if not self._terminal(parent[1]):
            return self._reconcile(op, candidate.stage, receipts[candidate.stage])

        pr = PullRequestCreateRequest.build(
            operation_id=op,
            operation_kind="rollback",
            repository_digest=authority.intent.repository_digest,
            lease_epoch_digest=lease.lease_epoch_digest,
            candidate_ref=authority.intent.candidate_ref,
            candidate_commit=authority.composition.candidate_commit,
            candidate_tree=authority.composition.candidate_tree,
            base_commit=authority.composition.current_main_commit,
            base_tree=authority.composition.current_main_tree,
            preparation_authorization_digest=prep.authorization_digest,
        )
        parent = self._stage(pr, authority, parent)
        receipts[pr.stage] = parent[1].receipt
        if not self._terminal(parent[1]):
            return self._reconcile(op, pr.stage, receipts[pr.stage])
        pull_request = self._pull_request(authority, pr)

        protection = evidence["protection"]
        config = evidence["queue_configuration"]
        admission_seed = canonical_digest(
            {
                "operation_id": op,
                "stage": "admission_check",
                "pull_request_number": pull_request.number,
                "pull_request_url": pull_request.url,
                "head_commit": pull_request.head_commit,
            }
        )
        admission_request = AdmissionIssueRequest.build(
            operation_id=op,
            operation_kind="rollback",
            repository_digest=authority.intent.repository_digest,
            lease_epoch_digest=lease.lease_epoch_digest,
            queue_configuration_digest=config.queue_configuration_digest,
            pull_request_number=pull_request.number,
            pull_request_head=authority.composition.candidate_commit,
            pull_request_tree=authority.composition.candidate_tree,
            base_commit=authority.composition.current_main_commit,
            base_tree=authority.composition.current_main_tree,
            preparation_authorization_digest=prep.authorization_digest,
            admission_run_id="avo-main-admission-" + admission_seed.removeprefix("sha256:"),
            admission_nonce=main_stage_nonce(admission_seed),
            issuer_identity=protection.isolated_release_issuer,
            issuer_app_id=protection.release_issuer_app_id,
            issuer_isolation_digest=protection.issuer_isolation_digest,
        )
        parent = self._stage(admission_request, authority, parent)
        receipts[admission_request.stage] = parent[1].receipt
        if not self._terminal(parent[1]):
            return self._reconcile(op, admission_request.stage, receipts[admission_request.stage])
        admission = self._admission(authority, config, protection, pull_request, admission_request)
        self._record("queue-admission", admission, self.journal.record_queue_admission)

        queue_request = QueueEnqueueRequest.build(
            operation_id=op,
            operation_kind="rollback",
            repository_digest=authority.intent.repository_digest,
            lease_epoch_digest=lease.lease_epoch_digest,
            queue_configuration_digest=config.queue_configuration_digest,
            pull_request_number=pull_request.number,
            pull_request_url=pull_request.url,
            pull_request_identity=canonical_digest(
                {
                    "operation_id": op,
                    "repository_digest": authority.intent.repository_digest,
                    "pull_request_number": pull_request.number,
                    "pull_request_url": pull_request.url,
                }
            ),
            pull_request_head=authority.composition.candidate_commit,
            pull_request_tree=authority.composition.candidate_tree,
            base_commit=authority.composition.current_main_commit,
            base_tree=authority.composition.current_main_tree,
            preparation_authorization_digest=prep.authorization_digest,
            admission_observation_digest=canonical_digest(admission),
        )
        parent = self._stage(queue_request, authority, parent)
        receipts[queue_request.stage] = parent[1].receipt
        if not self._terminal(parent[1]):
            return self._reconcile(op, queue_request.stage, receipts[queue_request.stage])
        queue = self._queue(authority, config, admission, queue_request)
        evidence["queue"] = queue
        self._record("queue", queue, self.journal.record_queue_observation)

        if pull_request_number is not None and pull_request_number != admission.pull_request_number:
            raise MainRollbackCoordinatorError(
                "caller pull-request identity differs from provider evidence"
            )
        group = self._group(
            authority,
            queue,
            admission,
            group_sha=group_sha,
            webhook_body=webhook_body,
            webhook_headers=webhook_headers,
            pull_request_number=admission.pull_request_number,
        )
        hold_request = self._hold_request(authority, prep, lease, queue, admission, group)
        parent = self._stage(hold_request, authority, parent)
        receipts[hold_request.stage] = parent[1].receipt
        if not self._terminal(parent[1]):
            return self._reconcile(op, hold_request.stage, receipts[hold_request.stage])
        hold = self._hold(authority, prep, queue, admission, group, evidence, hold_request)
        evidence["merge_group_checks"] = hold.other_required_checks
        self._record("release-hold", hold, self.journal.record_release_hold)

        release_auth = self._release_authorization(authority, lease, hold)
        self._record(
            "release-authorization", release_auth, self.journal.record_release_authorization
        )
        claim = self._release_claim(authority, lease, hold, release_auth)
        self._record("release-claim", claim, self.journal.record_release_claim)
        release_request = self._release_request(authority, lease, hold, release_auth, claim)
        parent = self._stage(release_request, authority, parent, release_auth, claim)
        receipts[release_request.stage] = parent[1].receipt
        transition, claimed = self._transition_records(authority, hold, release_auth, claim, parent)
        if claimed is None or claimed.outcome not in {"transitioned", "already_transitioned"}:
            return RollbackResult(
                op,
                "reconciliation_required",
                stage="release_transition",
                reason="release remains unresolved",
            )

        result = self._rollback_result(authority, claimed, parent[1].receipt)
        post = self._post_state(authority, result)
        cleanup_intent = self._cleanup_intent(authority, result, pull_request)
        self._record(
            "rollback-cleanup-intent", cleanup_intent, self.journal.record_rollback_cleanup_intent
        )
        cleanup_receipt, cleanup_observation, terminal = self._cleanup(
            authority, result, cleanup_intent
        )
        if terminal is None:
            return RollbackResult(
                op, "reconciliation_required", stage="cleanup", reason="cleanup remains unresolved"
            )
        refs = self._record_terminal(
            authority,
            source,
            evidence,
            admission,
            hold,
            release_auth,
            claim,
            transition,
            claimed,
            parent[0],
            parent[1].receipt,
            result,
            post,
            cleanup_intent,
            cleanup_receipt,
            cleanup_observation,
            terminal,
        )
        package = self._package(
            authority,
            source,
            evidence,
            admission,
            hold,
            release_auth,
            claim,
            transition,
            claimed,
            parent[0],
            parent[1].receipt,
            result,
            post,
            cleanup_intent,
            cleanup_receipt,
            cleanup_observation,
            terminal,
            refs,
        )
        self._record("rollback-completion", package, self.journal.record_rollback_completion)
        return RollbackResult(
            op, "completed", package=package, artifacts={k: v.digest for k, v in refs.items()}
        )

    @staticmethod
    def _terminal(execution: C4StageExecutionResult) -> bool:
        return execution.effective_outcome in {"applied", "already_applied"}

    def _stage(
        self,
        request: StageRequest,
        authority: MainRollbackAuthorityResult,
        parent: tuple[MainMutationIntent, C4StageExecutionResult] | None,
        release_auth: MainReleaseAuthorization | None = None,
        claim: MainReleaseClaim | None = None,
    ) -> tuple[MainMutationIntent, C4StageExecutionResult]:
        prior = self.journal.read_mutation_intent_by_operation_stage(
            request.operation_id, request.stage
        )
        recorded_at = self.clock.now() if prior is None else prior[0].recorded_at
        parent_intent = parent[0] if parent else None
        parent_exec = parent[1] if parent else None
        if parent_exec is not None and not self._terminal(parent_exec):
            raise MainRollbackCoordinatorError("parent stage is not terminally applied")
        from avo_correlate.contracts.main_graduation import MainExternalIdentity

        ext = MainExternalIdentity.model_validate(
            {
                "operation_id": request.operation_id,
                "repository_digest": request.repository_digest,
                "target_ref": request.target_ref,
                "stage": request.stage,
                "external_key": request.external_key,
                "queue_generation_digest": request.queue_generation_digest,
                "identity_digest": request.external_identity,
            }
        )
        values = {
            "operation_id": request.operation_id,
            "repository_digest": request.repository_digest,
            "target_ref": request.target_ref,
            "stage": request.stage,
            "parent_stage": parent_intent.stage if parent_intent else None,
            "parent_intent_digest": parent_intent.intent_digest if parent_intent else None,
            "parent_receipt": None
            if parent_exec is None or parent_exec.parent_resolution_digest
            else (parent_exec.receipt if parent_exec else None),
            "parent_resolution_digest": parent_exec.parent_resolution_digest
            if parent_exec
            else None,
            "lease_identity": authority.lease.owner,
            "lease_digest": authority.lease.lease_digest,
            "lease_epoch_digest": authority.lease.lease_epoch_digest,
            "policy_epoch_digest": authority.authorization.policy_epoch,
            "controller_config_digest": authority.authorization.controller_config_digest,
            "preparation_authorization_digest": (
                authority.preparation_authorization.authorization_digest
            ),
            "release_authorization_digest": release_auth.authorization_digest
            if release_auth
            else None,
            "release_claim_digest": claim.claim_digest if claim else None,
            "external_identity": ext,
            "request_digest": request.request_digest,
            "recorded_at": recorded_at,
        }
        intent = _digest_record(MainMutationIntent, values, "intent_digest")
        if prior is not None and canonical_bytes(prior[0]) != canonical_bytes(intent):
            raise MainRollbackCoordinatorError(f"durable {request.stage} intent differs")
        capture = _CaptureCapability(
            self.capabilities[request.stage],
            {
                "candidate_publication": "publish_candidate",
                "pull_request_open": "create_pull_request",
                "admission_check": "issue_admission",
                "queue_enqueue": "enqueue",
                "merge_group_hold": "issue_group_hold",
                "release_transition": "issue_release",
            }[request.stage],
        )
        executor = C4StageExecutor(
            journal=self.journal,
            clock=self.clock,
            lease_fence=self.lease_fence,
            capability=capture,
            observation_capability=self.observation_capability,
            authority_verifier=self.authority_verifier,
            provider_identity=self.provider_identity,
            provider_api_version=self.provider_api_version,
            provider_repository=self._provider_repository(),
        )
        owner = self.journal.read_mutation_dispatch_owner(intent.intent_digest)
        receipt = self.journal.read_mutation_receipt_for_intent(intent.intent_digest)
        if owner is not None and receipt is None:
            # The provider boundary was already reserved.  Recover directly
            # from an exact read-only observation; execute_effective would
            # intentionally reject this state after attempting its execute
            # path, which obscures the no-redispatch rule at this aggregate
            # boundary.
            effective = executor.recover_effective(
                intent, self._observation_request(request), original_request=request
            )
        else:
            effective = executor.execute_effective(intent, request)
        if effective.effective_outcome in {"ambiguous", "reconciliation_required"}:
            effective = executor.recover_effective(
                intent, self._observation_request(request), original_request=request
            )
        if capture.result is not None and effective.authoritative_resolution is None:
            self._stage_results[request.stage] = capture.result
        return intent, effective

    def _provider_repository(self) -> str | None:
        repository = getattr(self.provider, "repository_name", None)
        if isinstance(repository, str) and repository:
            return repository
        owner = getattr(self.provider, "owner", None)
        repo = getattr(self.provider, "repo", None)
        if isinstance(owner, str) and isinstance(repo, str) and owner and repo:
            return f"{owner}/{repo}"
        return None

    def _observation_request(self, request: StageRequest) -> Any:
        values = request.model_dump(mode="json")
        values.pop("request_digest", None)
        if request.stage == "candidate_publication":
            cls, object_id = CandidateObservationRequest, request.candidate_ref
        elif request.stage == "pull_request_open":
            cls, object_id = PullRequestObservationRequest, None
            number = getattr(self._stage_results.get(request.stage), "pull_request_number", None)
            if not isinstance(number, int):
                lookup = getattr(self.provider, "lookup_pull_request", None)
                if not callable(lookup):
                    raise MainRollbackCoordinatorError(
                        "exact pull-request lookup is required for recovery"
                    )
                observed = lookup(
                    request.operation_id,
                    expected_head_commit=request.candidate_commit,
                    expected_base_commit=request.base_commit,
                    operation_kind="rollback",
                )
                number = getattr(observed, "number", None)
                if not isinstance(number, int):
                    raise MainRollbackCoordinatorError(
                        "exact pull-request lookup did not return a PR number"
                    )
            values.update(
                {
                    "pull_request_number": number,
                    "head_commit": request.candidate_commit,
                    "head_tree": request.candidate_tree,
                }
            )
            values.pop("candidate_commit", None)
            values.pop("candidate_tree", None)
            repository = self._provider_repository()
            if repository is None:
                raise MainRollbackCoordinatorError("provider repository identity is missing")
            object_id = f"{repository}:pull/{number}"
        elif request.stage == "admission_check":
            cls, object_id = AdmissionObservationRequest, request.admission_run_id
        elif request.stage == "queue_enqueue":
            cls, object_id = QueueObservationRequest, request.pull_request_url
            queue_values = dict(values)
            queue_values["object_id"] = object_id
            observed = self._call_observer(
                "observe_queue", QueueObservationRequest.build(**queue_values)
            )
            values["queue_generation_digest"] = observed.queue_generation_digest
        elif request.stage == "merge_group_hold":
            cls, object_id = GroupHoldObservationRequest, request.hold_run_id
        else:
            cls, object_id = ReleaseObservationRequest, request.hold_run_id
        if not isinstance(object_id, str):
            raise MainRollbackCoordinatorError("exact observation object identity is missing")
        values["object_id"] = object_id
        return cls.build(**values)

    def _call_observer(self, method_name: str, *args: object, **kwargs: object) -> Any:
        method = getattr(self.observation_capability, method_name, None)
        if not callable(method):
            raise MainRollbackCoordinatorError(f"read-only observer lacks {method_name}")
        try:
            return method(*args, **kwargs)
        except Exception as exc:
            raise MainRollbackCoordinatorError(f"read-only observer {method_name} failed") from exc

    def _source(self, operation_id: str, source_operation_id: str) -> MainCompletionPackage:
        loaded = self.journal.read_completion(source_operation_id)
        if loaded is None or loaded[0].operation_id != source_operation_id:
            raise MainRollbackCoordinatorError("durable source completion is missing")
        return cast(MainCompletionPackage, loaded[0])

    def _evidence(
        self, authority: MainRollbackAuthorityResult, source: MainCompletionPackage
    ) -> dict[str, Any]:
        op = authority.operation_id
        config = self._observe_evidence(
            "observe_queue_configuration", MainQueueConfigurationObservation, op
        )
        protection = self._observe_evidence("observe_protection", MainProtectionManifest, op)
        # Attestation is an upstream source fact.  Keep it immutable and do not
        # manufacture a second attestation under the rollback operation.
        attestation = _canonical(source.attestation_manifest, MainAttestationManifest)
        if attestation.package_digest != source.source_package.package_digest:
            raise MainRollbackCoordinatorError("source attestation package binding differs")
        return {"queue_configuration": config, "protection": protection, "attestation": attestation}

    def _observe_evidence(self, method_name: str, expected: type[Any], operation_id: str) -> Any:
        method = getattr(self.provider, method_name, None)
        if not callable(method):
            raise MainRollbackCoordinatorError(f"fresh provider {method_name} is missing")
        value = (
            method(operation_id=operation_id)
            if expected is MainQueueConfigurationObservation
            else method()
        )
        value = _canonical(value, expected)
        if expected is not MainProtectionManifest and value.operation_id != operation_id:
            raise MainRollbackCoordinatorError(f"provider {method_name} operation identity differs")
        self._verify_evidence(value)
        self._record(
            "evidence",
            value,
            getattr(
                self.journal,
                "record_queue_configuration"
                if expected is MainQueueConfigurationObservation
                else "record_protection_manifest",
            ),
        )
        return value

    def _verify_evidence(self, value: Any) -> None:
        names = {
            MainQueueConfigurationObservation: (
                "verify_queue_configuration_observation",
                "verify_queue_configuration",
            ),
            MainProtectionManifest: (
                "verify_protection_observation",
                "verify_protection_manifest",
                "verify_protection",
            ),
        }[type(value)]
        fn = next((getattr(self.authority_verifier, n, None) for n in names), None)
        if not callable(fn):
            raise MainRollbackCoordinatorError("controller-owned evidence verifier is missing")
        fn(value)

    def _pull_request(
        self, authority: MainRollbackAuthorityResult, request: PullRequestCreateRequest
    ) -> MainPullRequestObservation:
        result = self._stage_results.get("pull_request_open")
        number = getattr(result, "pull_request_number", None)
        if not isinstance(number, int):
            lookup = getattr(self.provider, "lookup_pull_request", None)
            if not callable(lookup):
                raise MainRollbackCoordinatorError("exact pull-request lookup is missing")
            observed = lookup(
                request.operation_id,
                expected_head_commit=request.candidate_commit,
                expected_base_commit=request.base_commit,
                operation_kind="rollback",
            )
            number = getattr(observed, "number", None)
        if not isinstance(number, int):
            raise MainRollbackCoordinatorError("authenticated pull request identity is missing")
        observe = getattr(self.provider, "observe_pull_request", None)
        if not callable(observe):
            raise MainRollbackCoordinatorError("typed pull-request observer is missing")
        value = observe(
            number,
            expected_base_commit=request.base_commit,
            expected_head_ref=request.candidate_ref,
            expected_head_commit=request.candidate_commit,
            operation_kind="rollback",
        )
        if not isinstance(value, MainPullRequestObservation):
            raise MainRollbackCoordinatorError("pull-request observer returned untrusted identity")
        if (
            value.repository_digest != request.repository_digest
            or value.number != number
            or value.base_commit != request.base_commit
            or value.base_tree != request.base_tree
            or value.head_commit != request.candidate_commit
            or value.head_tree != request.candidate_tree
            or value.base_ref != request.target_ref
            or value.state != "open"
            or value.draft
        ):
            raise MainRollbackCoordinatorError(
                "pull-request observation differs from rollback intent"
            )
        return value

    def _admission(
        self,
        authority: MainRollbackAuthorityResult,
        config: Any,
        protection: Any,
        pr: MainPullRequestObservation,
        request: AdmissionIssueRequest,
    ) -> MainQueueAdmissionObservation:
        values = {
            "operation_id": authority.operation_id,
            "repository_digest": authority.intent.repository_digest,
            "target_ref": authority.intent.target_ref,
            "preparation_authorization_digest": (
                authority.preparation_authorization.authorization_digest
            ),
            "package_digest": authority.intent.completion_package_digest,
            "composition_digest": authority.preparation_authorization.composition_digest,
            "pull_request_number": pr.number,
            "pull_request_url": pr.url,
            "base_commit": pr.base_commit,
            "base_tree": pr.base_tree,
            "head_commit": pr.head_commit,
            "head_tree": pr.head_tree,
            "admission_sha": pr.head_commit,
            "admission_run_id": request.admission_run_id,
            "admission_nonce": request.admission_nonce,
            "queue_configuration_digest": config.queue_configuration_digest,
            "protection_manifest_digest": protection.manifest_digest,
            "issuer_identity": request.issuer_identity,
            "release_issuer_app_id": request.issuer_app_id,
            "issuer_isolation_digest": request.issuer_isolation_digest,
            "observed_at": self.clock.now(),
            "validation_app_id": 15368,
        }
        check_observer = getattr(self.provider, "observe_pr_head_admission_check", None)
        if not callable(check_observer):
            raise MainRollbackCoordinatorError("provider admission-check observation is missing")
        check = _canonical(
            check_observer(pr.head_commit, freshness_cutoff=self.clock.now()),
            MainCheckObservation,
        )
        if (
            check.sha != pr.head_commit
            or check.run_id != request.admission_run_id
            or check.nonce != request.admission_nonce
            or check.status != "completed"
            or check.conclusion != "success"
            or check.app_id == 15368
        ):
            raise MainRollbackCoordinatorError("admission check is not exact provider proof")
        values["observed_at"] = check.observed_at
        value = MainQueueAdmissionObservation.model_validate(values)
        checked = self.attester.attest_admission(
            value,
            pr,
            config,
            preparation_authorization_digest=authority.preparation_authorization.authorization_digest,
            admission_check=check,
            freshness_cutoff=self.clock.now(),
        )
        return _canonical(checked, MainQueueAdmissionObservation)

    def _queue(
        self,
        authority: MainRollbackAuthorityResult,
        config: Any,
        admission: Any,
        request: QueueEnqueueRequest,
    ) -> MainQueueObservation:
        observe = getattr(self.provider, "observe_queue", None)
        if not callable(observe):
            raise MainRollbackCoordinatorError("typed queue observer is missing")
        value = observe(
            operation_id=authority.operation_id,
            queue_configuration_digest=config.queue_configuration_digest,
            admission_observation_digest=canonical_digest(admission),
        )
        value = _canonical(value, MainQueueObservation)
        if (
            value.operation_id != authority.operation_id
            or value.queue_configuration_digest != config.queue_configuration_digest
        ):
            raise MainRollbackCoordinatorError("queue observation differs from rollback authority")
        self._verify_named("verify_queue_observation", value)
        return value

    def _group(
        self,
        authority: MainRollbackAuthorityResult,
        queue: Any,
        admission: Any,
        *,
        group_sha: str | None,
        webhook_body: bytes | None,
        webhook_headers: Mapping[str, str] | None,
        pull_request_number: int,
    ) -> Any:
        if (
            not isinstance(group_sha, str)
            or not isinstance(webhook_body, bytes)
            or webhook_headers is None
        ):
            raise MainRollbackCoordinatorError(
                "authenticated merge-group webhook inputs are required"
            )
        observe = getattr(self.provider, "observe_merge_group", None)
        if not callable(observe):
            raise MainRollbackCoordinatorError("typed merge-group observer is missing")
        value = observe(
            "observe_merge_group",
            group_sha,
            webhook_body=webhook_body,
            webhook_headers=webhook_headers,
            queue=queue,
            pull_request_number=pull_request_number,
        )
        if value is None:
            raise MainRollbackCoordinatorError("authenticated merge-group observation is missing")
        return value

    def _hold_request(
        self,
        authority: MainRollbackAuthorityResult,
        prep: Any,
        lease: Any,
        queue: Any,
        admission: Any,
        group: Any,
    ) -> GroupHoldIssueRequest:
        seed = canonical_digest(
            {
                "operation_id": authority.operation_id,
                "group_sha": group.group_sha,
                "queue_generation_digest": queue.queue_generation_digest,
            }
        )
        return GroupHoldIssueRequest.build(
            operation_id=authority.operation_id,
            operation_kind="rollback",
            repository_digest=authority.intent.repository_digest,
            lease_epoch_digest=lease.lease_epoch_digest,
            queue_generation_digest=queue.queue_generation_digest,
            pull_request_number=admission.pull_request_number,
            pull_request_head=admission.head_commit,
            pull_request_tree=admission.head_tree,
            group_sha=group.group_sha,
            group_tree=group.group_tree,
            expected_group_tree=authority.composition.candidate_tree,
            group_parents=list(group.group_parents),
            expected_group_parents=list(queue.expected_group_parents),
            group_topology_digest=queue.group_topology_digest,
            base_commit=authority.composition.current_main_commit,
            base_tree=authority.composition.current_main_tree,
            queue_members=[admission.pull_request_number],
            hold_run_id="avo-main-hold-" + seed.removeprefix("sha256:")[:48],
            hold_nonce=main_stage_nonce(seed),
            issuer_identity=admission.issuer_identity,
            issuer_app_id=admission.release_issuer_app_id,
            issuer_isolation_digest=admission.issuer_isolation_digest,
            admission_observation_digest=canonical_digest(admission),
        )

    def _hold(
        self,
        authority: Any,
        prep: Any,
        queue: Any,
        admission: Any,
        group: Any,
        evidence: Mapping[str, Any],
        request: Any,
    ) -> MainReleaseHoldObservation:
        receipt = getattr(group, "webhook_receipt", None)
        if not isinstance(receipt, MainMergeGroupWebhookReceipt):
            raise MainRollbackCoordinatorError("authenticated merge-group receipt is missing")
        self._record(
            "merge-group-webhook-receipt", receipt, self.journal.record_merge_group_webhook_receipt
        )
        observe_checks = getattr(self.provider, "observe_merge_group_checks", None)
        if not callable(observe_checks):
            raise MainRollbackCoordinatorError("typed merge-group check observer is missing")
        checks_raw = observe_checks(
            group.group_sha,
            operation_id=authority.operation_id,
            package_digest=authority.intent.completion_package_digest,
            composition_digest=authority.preparation_authorization.composition_digest,
            config_digest=queue.queue_configuration_digest,
            freshness_cutoff=self.clock.now(),
        )
        if not isinstance(checks_raw, MainMergeGroupChecks):
            raise MainRollbackCoordinatorError(
                "provider merge-group checks must be typed and authenticated"
            )
        checks = _canonical(checks_raw, MainMergeGroupChecks)
        self._record("merge-group-checks", checks, self.journal.record_merge_group_checks)
        value = MainReleaseHoldObservation.model_validate(
            {
                "operation_id": authority.operation_id,
                "repository_digest": authority.intent.repository_digest,
                "target_ref": authority.intent.target_ref,
                "preparation_authorization_digest": prep.authorization_digest,
                "admission_observation_digest": canonical_digest(admission),
                "package_digest": authority.intent.completion_package_digest,
                "composition_digest": authority.preparation_authorization.composition_digest,
                "pull_request_number": admission.pull_request_number,
                "group_sha": group.group_sha,
                "group_tree": group.group_tree,
                "group_parents": list(group.group_parents),
                "expected_group_parents": list(queue.expected_group_parents),
                "group_topology_digest": queue.group_topology_digest,
                "base_commit": authority.composition.current_main_commit,
                "base_tree": authority.composition.current_main_tree,
                "composition_tree": authority.composition.candidate_tree,
                "queue_generation_digest": queue.queue_generation_digest,
                "queue_members": [admission.pull_request_number],
                "hold_run_id": request.hold_run_id,
                "hold_nonce": request.hold_nonce,
                "issuer_identity": admission.issuer_identity,
                "release_issuer_app_id": admission.release_issuer_app_id,
                "issuer_isolation_digest": admission.issuer_isolation_digest,
                "other_required_checks": checks,
                "merge_group_receipt": receipt,
                "protection_manifest_digest": evidence["protection"].manifest_digest,
                "attestation_manifest_digest": canonical_digest(evidence["attestation"]),
                "observed_at": self.clock.now(),
            }
        )
        checked = self.attester.attest_hold(
            value,
            admission,
            group,
            queue,
            hold_check=None,
            freshness_cutoff=self.clock.now(),
        )
        return _canonical(checked, MainReleaseHoldObservation)

    def _release_authorization(
        self, authority: Any, lease: Any, hold: Any
    ) -> MainReleaseAuthorization:
        value = self.release_authorizer.authorize_release(
            authority=authority,
            lease=lease,
            hold=hold,
            authorization_ttl=self.authorization_ttl,
        )
        return _canonical(value, MainReleaseAuthorization)

    def _release_claim(self, authority: Any, lease: Any, hold: Any, auth: Any) -> MainReleaseClaim:
        prior = self.journal.read_release_claim_for_authorization(authority.operation_id, auth)
        if prior is not None:
            return _canonical(prior[0], MainReleaseClaim)
        now = self.clock.now()
        values = {
            "operation_id": authority.operation_id,
            "repository_digest": authority.intent.repository_digest,
            "target_ref": authority.intent.target_ref,
            "authorization_digest": auth.authorization_digest,
            "hold_observation_digest": canonical_digest(hold),
            "group_sha": hold.group_sha,
            "hold_run_id": hold.hold_run_id,
            "hold_nonce": hold.hold_nonce,
            "queue_generation_digest": hold.queue_generation_digest,
            "lease_identity": lease.owner,
            "lease_digest": lease.lease_digest,
            "lease_epoch_digest": lease.lease_epoch_digest,
            "release_issuer_identity": auth.release_issuer_identity,
            "release_issuer_app_id": auth.release_issuer_app_id,
            "issuer_isolation_digest": auth.issuer_isolation_digest,
            "target_scope_digest": main_target_scope_digest(
                authority.intent.repository_digest, authority.intent.target_ref
            ),
            "authorization_expires_at": auth.expires_at,
            "lease_expires_at": lease.expires_at,
            "claimed_at": now,
        }
        values["claim_key"] = main_release_claim_key(
            **{
                k: values[k]
                for k in (
                    "repository_digest",
                    "target_ref",
                    "operation_id",
                    "authorization_digest",
                    "hold_observation_digest",
                    "group_sha",
                    "hold_run_id",
                    "hold_nonce",
                    "queue_generation_digest",
                    "lease_epoch_digest",
                    "lease_digest",
                    "release_issuer_identity",
                    "issuer_isolation_digest",
                    "authorization_expires_at",
                    "lease_expires_at",
                    "release_issuer_app_id",
                    "target_scope_digest",
                )
            }
        )
        return _digest_record(MainReleaseClaim, values, "claim_digest")

    def _release_request(
        self, authority: Any, lease: Any, hold: Any, auth: Any, claim: Any
    ) -> ReleaseIssueRequest:
        return ReleaseIssueRequest.build(
            operation_id=authority.operation_id,
            operation_kind="rollback",
            repository_digest=authority.intent.repository_digest,
            lease_epoch_digest=lease.lease_epoch_digest,
            queue_generation_digest=hold.queue_generation_digest,
            pull_request_number=hold.pull_request_number,
            pull_request_head=authority.composition.candidate_commit,
            pull_request_tree=authority.composition.candidate_tree,
            group_sha=hold.group_sha,
            group_tree=hold.group_tree,
            expected_group_tree=authority.composition.candidate_tree,
            group_parents=hold.group_parents,
            expected_group_parents=hold.expected_group_parents,
            group_topology_digest=hold.group_topology_digest,
            base_commit=hold.base_commit,
            base_tree=hold.base_tree,
            queue_members=hold.queue_members,
            hold_run_id=hold.hold_run_id,
            hold_nonce=hold.hold_nonce,
            issuer_identity=hold.issuer_identity,
            issuer_app_id=hold.release_issuer_app_id,
            issuer_isolation_digest=hold.issuer_isolation_digest,
            hold_observation_digest=canonical_digest(hold),
            admission_observation_digest=hold.admission_observation_digest,
            release_authorization_digest=auth.authorization_digest,
            release_claim_digest=claim.claim_digest,
            authorization_expires_at=auth.expires_at,
        )

    def _transition_records(
        self, authority: Any, hold: Any, auth: Any, claim: Any, stage: Any
    ) -> tuple[MainReleaseTransitionReceipt, MainClaimedReleaseTransitionReceipt | None]:
        effective = stage[1]
        mutation = effective.receipt
        resolution = effective.authoritative_resolution
        terminal = mutation.outcome in {"applied", "already_applied"} or (
            resolution is not None and resolution.outcome == "observed"
        )
        outcome = (
            "transitioned"
            if mutation.outcome == "applied"
            or (resolution is not None and resolution.observed_outcome == "applied")
            else "already_transitioned"
            if terminal
            else "reconciliation_required"
        )
        transition = MainReleaseTransitionReceipt(
            operation_id=authority.operation_id,
            repository_digest=authority.intent.repository_digest,
            target_ref=authority.intent.target_ref,
            release_authorization_digest=auth.authorization_digest,
            group_sha=hold.group_sha,
            hold_run_id=hold.hold_run_id,
            hold_nonce=hold.hold_nonce,
            issuer_identity=hold.issuer_identity,
            release_issuer_app_id=hold.release_issuer_app_id,
            issuer_isolation_digest=hold.issuer_isolation_digest,
            outcome=outcome,
            response_digest=mutation.response_digest,
            observed_at=mutation.observed_at,
        )
        self._record("release-transition", transition, self.journal.record_release_transition)
        claimed = None
        if terminal:
            claimed = _digest_record(
                MainClaimedReleaseTransitionReceipt,
                {
                    "operation_id": authority.operation_id,
                    "repository_digest": authority.intent.repository_digest,
                    "target_ref": authority.intent.target_ref,
                    "release_authorization_digest": auth.authorization_digest,
                    "claim_digest": claim.claim_digest,
                    "group_sha": hold.group_sha,
                    "hold_run_id": hold.hold_run_id,
                    "hold_nonce": hold.hold_nonce,
                    "issuer_identity": hold.issuer_identity,
                    "release_issuer_app_id": hold.release_issuer_app_id,
                    "issuer_isolation_digest": hold.issuer_isolation_digest,
                    "outcome": outcome,
                    "response_digest": mutation.response_digest,
                    "observed_at": mutation.observed_at,
                    "mutation_receipt_digest": mutation.receipt_digest,
                    "mutation_resolution_digest": None
                    if resolution is None
                    else resolution.resolution_digest,
                },
                "receipt_digest",
            )
            self._record(
                "claimed-release-transition",
                claimed,
                self.journal.record_claimed_release_transition,
            )
        return transition, claimed

    def _rollback_result(
        self, authority: Any, claimed: Any, mutation: Any
    ) -> MainRollbackResultReceipt:
        builder = self.result_builder
        if builder is None:
            raise MainRollbackCoordinatorError(
                "controller-owned rollback result builder is required"
            )
        fn = next(
            (getattr(builder, name, None) for name in ("build_rollback_result", "build_result")),
            None,
        )
        if not callable(fn):
            raise MainRollbackCoordinatorError("result builder seam is missing")
        value = fn(
            attempt=authority.attempt_authority,
            intent=authority.intent,
            mutation_receipt=mutation,
            provider=self.observation_capability,
        )
        value = _canonical(value, MainRollbackResultReceipt)
        self._verify_named(
            "verify_rollback_result", value, authority.intent, authority.authorization
        )
        self._record("rollback-result", value, self.journal.record_rollback_result)
        return value

    def _post_state(self, authority: Any, result: Any) -> MainRollbackPostStateObservation:
        fn = getattr(self.observation_capability, "observe_rollback_post_state", None)
        if not callable(fn):
            raise MainRollbackCoordinatorError("rollback post-state observer is missing")
        value = _canonical(
            fn(result, authority.attempt_authority), MainRollbackPostStateObservation
        )
        self._verify_named("verify_rollback_post_state", value, result, authority.attempt_authority)
        self._record(
            "rollback-post-state-observation",
            value,
            self.journal.record_rollback_post_state_observation,
        )
        return value

    def _cleanup_intent(
        self, authority: Any, result: Any, pr: MainPullRequestObservation
    ) -> MainRollbackCleanupIntent:
        cap = self.cleanup_capability
        if cap is None:
            raise MainRollbackCoordinatorError("rollback cleanup capability is required")
        cleanup = getattr(cap, "cleanup_principal", None) or getattr(cap, "cleanup_identity", None)
        observer = getattr(cap, "observer_principal", None) or getattr(
            self.observation_capability, "observer_principal", None
        )
        if cleanup is None or observer is None:
            raise MainRollbackCoordinatorError(
                "cleanup and observer principal bindings are required"
            )
        required = ("identity", "app_id", "isolation_digest")
        if any(not hasattr(cleanup, name) for name in required) or any(
            not hasattr(observer, name) for name in required
        ):
            raise MainRollbackCoordinatorError("cleanup principal bindings are incomplete")
        existing = self.journal.read_rollback_cleanup_intent(authority.operation_id)
        recorded_at = self.clock.now() if existing is None else existing[0].recorded_at
        candidate = _digest_record(
            MainRollbackCleanupIntent,
            {
                "operation_id": authority.operation_id,
                "source_operation_id": authority.intent.source_operation_id,
                "repository_digest": authority.intent.repository_digest,
                "target_ref": authority.intent.target_ref,
                "completion_package_digest": result.completion_package_digest,
                "result_receipt_digest": result.receipt_digest,
                "authorization_digest": authority.authorization.authorization_digest,
                "candidate_ref": authority.intent.candidate_ref,
                "candidate_commit": authority.intent.candidate_commit,
                "pull_request_number": pr.number,
                "pull_request_url": pr.url,
                "provider_identity": self.provider_identity,
                "provider_api_version": self.provider_api_version,
                "cleanup_principal_identity": cleanup.identity,
                "cleanup_principal_app_id": cleanup.app_id,
                "cleanup_principal_isolation_digest": cleanup.isolation_digest,
                "observer_identity": observer.identity,
                "observer_app_id": observer.app_id,
                "observer_isolation_digest": observer.isolation_digest,
                "observer_provider_identity": self.provider_identity,
                "observer_provider_api_version": self.provider_api_version,
                "cleanup_authority_digest": rollback_cleanup_authority_digest(
                    authority.intent.repository_digest, authority.intent.target_ref
                ),
                "recorded_at": recorded_at,
            },
            "intent_digest",
        )
        if existing is not None:
            durable = _canonical(existing[0], MainRollbackCleanupIntent)
            if canonical_bytes(durable) != canonical_bytes(candidate):
                raise MainRollbackCoordinatorError(
                    "durable rollback cleanup intent differs from exact binding"
                )
            return durable
        return candidate

    def _cleanup(self, authority: Any, result: Any, intent: Any) -> tuple[Any, Any, Any]:
        cap = cast(Any, self.cleanup_capability)
        receipt = self.journal.read_rollback_cleanup_receipt(authority.operation_id)
        if receipt is None:
            owner_reader = getattr(self.journal, "read_rollback_cleanup_dispatch_owner", None)
            owner = owner_reader(intent.intent_digest) if callable(owner_reader) else None
            claimed = False
            if owner is None:
                claimer = getattr(self.journal, "claim_rollback_cleanup_dispatch", None)
                if not callable(claimer):
                    raise MainRollbackCoordinatorError(
                        "journal cleanup dispatch-owner CAS is missing"
                    )
                claimed = bool(
                    claimer(
                        operation_id=authority.operation_id,
                        intent_digest=intent.intent_digest,
                        candidate_ref=intent.candidate_ref,
                        recorded_at=self.clock.now(),
                    )
                )
            if claimed:
                # This is the sole path permitted to cross the cleanup
                # provider boundary.  A lost race or a restart reconciles
                # read-only below.
                receipt_model = _canonical(cap.cleanup_rollback(intent), MainRollbackCleanupReceipt)
                self._record(
                    "cleanup-receipt", receipt_model, self.journal.record_rollback_cleanup_receipt
                )
                receipt = receipt_model
            else:
                reconcile = getattr(cap, "reconcile_rollback_cleanup", None)
                if not callable(reconcile):
                    raise MainRollbackCoordinatorError(
                        "read-only cleanup reconciliation is missing"
                    )
                receipt_prior = self.journal.read_rollback_cleanup_receipt(authority.operation_id)
                if receipt_prior is not None:
                    receipt = _canonical(receipt_prior[0], MainRollbackCleanupReceipt)
                else:
                    receipt_value = {
                        "operation_id": intent.operation_id,
                        "repository_digest": intent.repository_digest,
                        "target_ref": intent.target_ref,
                        "intent_digest": intent.intent_digest,
                        "authorization_digest": intent.authorization_digest,
                        "candidate_ref": intent.candidate_ref,
                        "candidate_commit": intent.candidate_commit,
                        "pull_request_number": intent.pull_request_number,
                        "pull_request_url": intent.pull_request_url,
                        "outcome": "reconciliation_required",
                        "dispatch_started": True,
                        "response_digest": canonical_digest(
                            {"recovery": "cleanup-owner-without-receipt"}
                        ),
                        "observed_at": self.clock.now(),
                        "provider_identity": intent.provider_identity,
                        "provider_api_version": intent.provider_api_version,
                        "cleanup_principal_identity": intent.cleanup_principal_identity,
                        "cleanup_principal_app_id": intent.cleanup_principal_app_id,
                        "cleanup_principal_isolation_digest": (
                            intent.cleanup_principal_isolation_digest
                        ),
                        "observer_identity": intent.observer_identity,
                        "observer_app_id": intent.observer_app_id,
                        "observer_isolation_digest": intent.observer_isolation_digest,
                        "observer_provider_identity": intent.observer_provider_identity,
                        "observer_provider_api_version": intent.observer_provider_api_version,
                        "cleanup_authority_digest": intent.cleanup_authority_digest,
                    }
                    receipt = _digest_record(
                        MainRollbackCleanupReceipt, receipt_value, "receipt_digest"
                    )
                    self._record(
                        "cleanup-receipt",
                        receipt,
                        self.journal.record_rollback_cleanup_receipt,
                    )
                observed = _canonical(
                    reconcile(intent, receipt), MainRollbackCleanupObservation
                )
                self._record(
                    "cleanup-observation",
                    observed,
                    self.journal.record_rollback_cleanup_observation,
                )
        else:
            receipt = receipt[0]
        self._verify_named("verify_rollback_cleanup_receipt", receipt, intent, result)
        observation = self.journal.read_rollback_cleanup_observation(authority.operation_id)
        if receipt.outcome in {"ambiguous", "reconciliation_required"} and observation is None:
            fn = getattr(cap, "reconcile_rollback_cleanup", None)
            if not callable(fn):
                raise MainRollbackCoordinatorError("read-only cleanup reconciliation is missing")
            observation = self._record(
                "cleanup-observation",
                fn(intent, receipt),
                self.journal.record_rollback_cleanup_observation,
            )
        observation_value = None if observation is None else observation[0]
        if observation_value is not None:
            self._verify_named(
                "verify_rollback_cleanup_observation", observation_value, intent, receipt
            )
        if (
            receipt.outcome in {"ambiguous", "reconciliation_required"}
            and observation_value is not None
            and observation_value.outcome not in {"absent", "already_absent"}
        ):
            return receipt, observation_value, None
        if (
            receipt.outcome in {"ambiguous", "reconciliation_required"}
            and observation_value is None
        ):
            return receipt, observation_value, None
        terminal = _digest_record(
            MainRollbackCleanupTerminalEvidence,
            {
                "operation_id": authority.operation_id,
                "repository_digest": intent.repository_digest,
                "target_ref": intent.target_ref,
                "cleanup_intent_digest": intent.intent_digest,
                "cleanup_receipt_digest": receipt.receipt_digest,
                "candidate_ref": intent.candidate_ref,
                "candidate_commit": intent.candidate_commit,
                "pull_request_number": intent.pull_request_number,
                "pull_request_url": intent.pull_request_url,
                "outcome": "absent" if observation_value is not None else "already_absent",
                "candidate_ref_absent": True,
                "pull_request_state": "closed",
                "pull_request_merged": True,
                "cleanup_observation_digest": None
                if observation_value is None
                else observation_value.observation_digest,
                "provider_identity": intent.provider_identity,
                "provider_api_version": intent.provider_api_version,
                "cleanup_principal_identity": intent.cleanup_principal_identity,
                "cleanup_principal_app_id": intent.cleanup_principal_app_id,
                "cleanup_principal_isolation_digest": intent.cleanup_principal_isolation_digest,
                "observer_identity": intent.observer_identity,
                "observer_app_id": intent.observer_app_id,
                "observer_isolation_digest": intent.observer_isolation_digest,
                "observer_provider_identity": intent.observer_provider_identity,
                "observer_provider_api_version": intent.observer_provider_api_version,
                "cleanup_authority_digest": intent.cleanup_authority_digest,
                "observed_at": self.clock.now(),
            },
            "evidence_digest",
        )
        self._record("cleanup-terminal", terminal, self.journal.record_rollback_cleanup_terminal)
        return receipt, observation_value, terminal

    def _record_terminal(
        self,
        authority: Any,
        source: Any,
        evidence: Mapping[str, Any],
        admission: Any,
        hold: Any,
        release_auth: Any,
        claim: Any,
        transition: Any,
        claimed: Any,
        intent: Any,
        mutation: Any,
        result: Any,
        post: Any,
        cleanup_intent: Any,
        cleanup_receipt: Any,
        cleanup_observation: Any,
        terminal: Any,
    ) -> dict[str, ArtifactRef]:
        records = [
            ("source-completion", source, self.journal.record_completion),
            ("composition", authority.composition, self.journal.record_rollback_composition),
            (
                "rollback-preparation-authorization",
                authority.preparation_authorization,
                self.journal.record_rollback_preparation_authorization,
            ),
            ("lease-evidence-record", authority.lease, self.journal.record_lease_evidence_record),
            (
                "rollback-authorization",
                authority.authorization,
                self.journal.record_rollback_authorization,
            ),
            ("rollback-intent", authority.intent, self.journal.record_rollback_intent),
            (
                "rollback-attempt-authority",
                authority.attempt_authority,
                self.journal.record_rollback_attempt_authority,
            ),
            ("queue-admission", admission, self.journal.record_queue_admission),
            ("release-hold", hold, self.journal.record_release_hold),
            ("release-authorization", release_auth, self.journal.record_release_authorization),
            ("release-claim", claim, self.journal.record_release_claim),
            ("mutation-intent", intent, self.journal.record_mutation_intent),
            ("mutation-receipt", mutation, self.journal.record_mutation_receipt),
            ("rollback-result", result, self.journal.record_rollback_result),
            (
                "rollback-post-state-observation",
                post,
                self.journal.record_rollback_post_state_observation,
            ),
            (
                "rollback-cleanup-intent",
                cleanup_intent,
                self.journal.record_rollback_cleanup_intent,
            ),
            (
                "rollback-cleanup-receipt",
                cleanup_receipt,
                self.journal.record_rollback_cleanup_receipt,
            ),
            ("rollback-cleanup-terminal", terminal, self.journal.record_rollback_cleanup_terminal),
        ]
        if cleanup_observation is not None:
            records.append(
                (
                    "rollback-cleanup-observation",
                    cleanup_observation,
                    self.journal.record_rollback_cleanup_observation,
                )
            )
        if transition is not None:
            records.append(
                ("release-transition", transition, self.journal.record_release_transition)
            )
        if claimed is not None:
            records.append(
                (
                    "claimed-release-transition",
                    claimed,
                    self.journal.record_claimed_release_transition,
                )
            )
        records.extend(
            [
                (
                    "queue-configuration",
                    evidence["queue_configuration"],
                    self.journal.record_queue_configuration,
                ),
                ("queue", evidence["queue"], self.journal.record_queue_observation),
                ("protection", evidence["protection"], self.journal.record_protection_manifest),
                ("attestations", evidence["attestation"], self.journal.record_attestation_manifest),
                (
                    "merge-group-checks",
                    evidence["merge_group_checks"],
                    self.journal.record_merge_group_checks,
                ),
                (
                    "merge-group-webhook-receipt",
                    hold.merge_group_receipt,
                    self.journal.record_merge_group_webhook_receipt,
                ),
            ]
        )
        refs: dict[str, ArtifactRef] = {}
        for kind, value, writer in records:
            self._record(kind, value, writer)
            refs[kind] = self._rollback_ref(kind, value)
        return refs

    def _rollback_ref(self, kind: str, value: StrictModel) -> ArtifactRef:
        """Store an explicit rollback-closure child role.

        The ordinary journal records retain their historical ``main-graduation``
        roles.  The terminal rollback package uses a distinct role namespace so
        its closure cannot be confused with a graduation package.
        """
        suffix = {
            "source-completion": "source-completion",
            "composition": "composition",
            "rollback-preparation-authorization": "preparation-authorization",
            "lease-evidence-record": "lease-evidence-record",
            "queue-configuration": "queue-configuration",
            "queue": "queue-observation",
            "protection": "protection-manifest",
            "attestations": "attestation-manifest",
            "queue-admission": "queue-admission",
            "release-hold": "release-hold",
            "release-authorization": "release-authorization",
            "release-claim": "release-claim",
            "merge-group-checks": "merge-group-checks",
            "merge-group-webhook-receipt": "merge-group-webhook-receipt",
            "release-transition": "release-transition",
            "claimed-release-transition": "claimed-release-transition",
            "mutation-intent": "mutation-intent",
            "mutation-receipt": "mutation-receipt",
            "rollback-authorization": "authorization",
            "rollback-intent": "intent",
            "rollback-attempt-authority": "attempt-authority",
            "rollback-result": "result",
            "rollback-post-state-observation": "post-state-observation",
            "rollback-cleanup-intent": "cleanup-intent",
            "rollback-cleanup-receipt": "cleanup-receipt",
            "rollback-cleanup-observation": "cleanup-observation",
            "rollback-cleanup-terminal": "cleanup-terminal",
        }.get(kind, kind)
        role = "main-rollback-" + suffix
        store = getattr(self.journal, "_store", None)
        maximum = getattr(self.journal, "_max", None)
        if store is None or not isinstance(maximum, int):
            raise MainRollbackCoordinatorError("journal rollback artifact store is unavailable")
        return store.put_bytes(
            canonical_bytes(value),
            media_type=f"application/vnd.avo.{role}+json",
            role=role,
            max_bytes=maximum,
        )

    def _package(
        self,
        authority: Any,
        source: Any,
        evidence: Mapping[str, Any],
        admission: Any,
        hold: Any,
        release_auth: Any,
        claim: Any,
        transition: Any,
        claimed: Any,
        intent: Any,
        mutation: Any,
        result: Any,
        post: Any,
        cleanup_intent: Any,
        cleanup_receipt: Any,
        cleanup_observation: Any,
        terminal: Any,
        refs: Mapping[str, ArtifactRef],
    ) -> MainRollbackCompletionPackage:
        values = {
            "operation_id": authority.operation_id,
            "repository_digest": authority.intent.repository_digest,
            "target_ref": authority.intent.target_ref,
            "composition_id": authority.composition.composition_id,
            "composition_artifact_digest": canonical_digest(authority.composition),
            "attempt_authority": authority.attempt_authority,
            "source_completion": source,
            "rollback_preparation_authorization": authority.preparation_authorization,
            "lease_evidence_record": authority.lease,
            "queue_configuration": evidence["queue_configuration"],
            "queue_observation": evidence["queue"],
            "protection_manifest": evidence["protection"],
            "attestation_manifest": evidence["attestation"],
            "merge_group_checks": hold.other_required_checks,
            "merge_group_receipt": hold.merge_group_receipt,
            "admission_observation": admission,
            "hold_observation": hold,
            "release_authorization": release_auth,
            "release_claim": claim,
            "claimed_transition_receipt": claimed,
            "release_transition_receipt": transition,
            "release_transition_intent": intent,
            "release_transition_mutation_receipt": mutation,
            "release_transition_fence_resolution": None,
            "composition": authority.composition,
            "rollback_authorization": authority.authorization,
            "rollback_intent": authority.intent,
            "rollback_result": result,
            "post_state": post,
            "cleanup_intent": cleanup_intent,
            "cleanup_receipt": cleanup_receipt,
            "cleanup_observation": cleanup_observation,
            "cleanup_terminal": terminal,
            "artifacts": list(refs.values()),
        }
        values["completion_digest"] = canonical_digest(
            cast(Any, MainRollbackCompletionPackage)
            .model_construct(**values, completion_digest=_ZERO)
            .model_dump(exclude={"completion_digest"}, mode="json")
        )
        return MainRollbackCompletionPackage.model_validate(values)

    def _reconcile(self, operation_id: str, stage: str, receipt: Any) -> RollbackResult:
        return RollbackResult(
            operation_id, "reconciliation_required", stage=stage, reason=receipt.outcome
        )

    def _verify_named(self, name: str, *values: Any) -> None:
        fn = getattr(self.authority_verifier, name, None)
        if not callable(fn):
            raise MainRollbackCoordinatorError(f"controller verifier {name} is missing")
        fn(*values)

    @staticmethod
    def _record(kind: str, value: Any, writer: Any) -> Any:
        return writer(value)


__all__ = ["MainRollbackCoordinator", "MainRollbackCoordinatorError", "RollbackResult"]
