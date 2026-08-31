# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportIndexIssue=false, reportUnnecessaryCast=false, reportUnusedClass=false

"""Restart-safe reversible C4 preparation coordinator.

The coordinator is intentionally a small orchestration layer.  All external
writes go through :class:`C4StageExecutor`; the journal remains the authority
for the plan, lease, preparation authorization, and phase-A records.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, cast

from avo_correlate.adapters.artifacts.main_graduation_journal import MainGraduationJournal
from avo_correlate.application.c4_capabilities import (
    AdmissionIssueRequest,
    AdmissionObservationRequest,
    AdmissionObservationResult,
    CandidateObservationRequest,
    CandidatePublicationRequest,
    PullRequestCreateRequest,
    PullRequestCreateResult,
    PullRequestObservationRequest,
    PullRequestObservationResult,
    QueueEnqueueRequest,
    QueueObservationRequest,
    StageMutationResult,
    StageObservationResult,
    StageRequest,
    TrustedClock,
)
from avo_correlate.application.c4_stage_executor import (
    C4StageExecutionError,
    C4StageExecutor,
    StageAuthorityVerifier,
    StageLeaseFence,
)
from avo_correlate.contracts.base import Sha256Digest
from avo_correlate.contracts.main_graduation import (
    MainCheckObservation,
    MainGraduationPlan,
    MainPreparationAuthorization,
    MainProtectionManifest,
    MainQueueAdmissionObservation,
    MainQueueObservation,
)
from avo_correlate.contracts.main_graduation_phase_a import (
    MainLeaseEvidenceReadRequest,
    MainLeaseEvidenceRecord,
    MainMutationIntent,
    MainMutationReceipt,
    main_stage_nonce,
)
from avo_correlate.domain.canonical import canonical_digest


class MainGraduationPreparationError(RuntimeError):
    """The durable C4 preparation state cannot safely advance."""


@dataclass(frozen=True, slots=True)
class PreparationResult:
    """Non-persisted summary of the durable C4 preparation state."""

    operation_id: Sha256Digest
    state: str
    stage: str | None = None
    stage_receipts: Mapping[str, Sha256Digest] = field(default_factory=dict)
    stage_intents: Mapping[str, Sha256Digest] = field(default_factory=dict)
    candidate_ref: str | None = None
    pull_request_number: int | None = None
    pull_request_url: str | None = None
    admission_observation_digest: Sha256Digest | None = None
    queue_generation_digest: Sha256Digest | None = None
    reason: str | None = None

    @property
    def terminal(self) -> bool:
        return self.state in {"queued", "reconciliation_required", "quarantined"}


@dataclass(frozen=True, slots=True)
class _PR:
    number: int
    url: str
    head_commit: str
    head_tree: str
    base_commit: str
    base_tree: str


class _CaptureCapability:
    """Expose one exact capability method while retaining its result."""

    def __init__(self, provider: object, method_name: str) -> None:
        self._provider = provider
        self._method_name = method_name
        self.result: StageMutationResult | None = None
        self.provider_identity = cast(str | None, getattr(provider, "provider_identity", None))
        self.provider_api_version = cast(
            str | None, getattr(provider, "provider_api_version", None)
        )
        self.repository_name = cast(str | None, getattr(provider, "repository_name", None))

    def __getattr__(self, name: str) -> Any:
        if name != self._method_name:
            raise AttributeError(name)

        def invoke(request: StageRequest) -> StageMutationResult:
            method = getattr(self._provider, self._method_name, None)
            if not callable(method):
                raise MainGraduationPreparationError(
                    f"provider does not implement {self._method_name}"
                )
            value = cast(StageMutationResult, method(request))
            self.result = value
            return value

        return invoke


def _digest_intent(values: dict[str, Any]) -> MainMutationIntent:
    probe = MainMutationIntent.model_construct(**values, intent_digest="sha256:" + "0" * 64)
    values = dict(values)
    values["intent_digest"] = canonical_digest(
        probe.model_dump(exclude={"intent_digest"}, mode="json")
    )
    return MainMutationIntent.model_validate(values)


def _external_identity(request: StageRequest) -> Any:
    from avo_correlate.contracts.main_graduation import MainExternalIdentity

    return MainExternalIdentity(
        operation_id=request.operation_id,
        repository_digest=request.repository_digest,
        target_ref=request.target_ref,
        stage=request.stage,
        external_key=request.external_key,
        queue_generation_digest=request.queue_generation_digest,
        identity_digest=request.external_identity,
    )


class MainGraduationPreparationCoordinator:
    """Run candidate publication, PR preparation, admission, and enqueue.

    ``provider`` may be a combined C4 adapter or a test double.  Only the four
    exact methods used by this class are ever exposed to ``C4StageExecutor``;
    there is no release, hold, or direct-main method on this coordinator.
    """

    _STAGES = ("candidate_publication", "pull_request_open", "admission_check", "queue_enqueue")

    def __init__(
        self,
        *,
        journal: MainGraduationJournal,
        clock: TrustedClock,
        lease_fence: StageLeaseFence,
        provider: object | None = None,
        protected_main_provider: object | None = None,
        candidate_capability: object | None = None,
        pull_request_capability: object | None = None,
        admission_capability: object | None = None,
        queue_capability: object | None = None,
        observation_capability: object | None = None,
        authority_verifier: StageAuthorityVerifier,
        attester: object | None = None,
        provider_identity: str | None = None,
        provider_api_version: str | None = None,
    ) -> None:
        self.journal = journal
        self.clock = clock
        self.lease_fence = lease_fence
        self.provider = provider or candidate_capability or pull_request_capability
        if self.provider is None:
            raise ValueError("a C4 provider or exact capabilities are required")
        self._capabilities: dict[str, object] = {
            "candidate_publication": candidate_capability or self.provider,
            "pull_request_open": pull_request_capability or self.provider,
            "admission_check": admission_capability or self.provider,
            "queue_enqueue": queue_capability or self.provider,
        }
        self.observation_capability = observation_capability or self.provider
        self.read_provider = protected_main_provider or self.provider
        if not callable(getattr(authority_verifier, "verify_stage_result", None)) or not callable(
            getattr(authority_verifier, "verify_stage_observation", None)
        ):
            raise ValueError("controller-owned stage authority verifier is required")
        if attester is None or not callable(getattr(attester, "attest_admission", None)):
            raise ValueError("controller-owned main graduation attester is required")
        self.authority_verifier = authority_verifier
        self.attester = attester
        self._last_stage_results: dict[str, StageMutationResult] = {}
        self.provider_identity = provider_identity or cast(
            str | None, getattr(self.read_provider, "provider_identity", None)
        )
        self.provider_api_version = provider_api_version or cast(
            str | None, getattr(self.read_provider, "provider_api_version", None)
        )
        if not self.provider_identity or not self.provider_api_version:
            raise ValueError("provider identity and API version are required")

    def prepare(self, operation_id: Sha256Digest) -> PreparationResult:
        """Resume or execute from one durable operation/state root."""
        try:
            plan, prep, lease = self._load(operation_id)
            self._preflight(plan, prep, lease)
            receipts: dict[str, Sha256Digest] = {}
            intents: dict[str, Sha256Digest] = {}

            candidate_request = CandidatePublicationRequest.build(
                operation_id=operation_id,
                repository_digest=plan.repository_digest,
                lease_epoch_digest=lease.lease_epoch_digest,
                candidate_ref=prep_candidate_ref(plan),
                candidate_commit=plan.composition.candidate_commit,
                preparation_authorization_digest=prep.authorization_digest,
            )
            self._preflight(plan, prep, lease)
            candidate_intent, receipt = self._run_stage(
                plan, prep, lease, candidate_request, None, "candidate_publication"
            )
            intents["candidate_publication"] = candidate_intent.intent_digest
            receipts["candidate_publication"] = receipt.receipt_digest
            if receipt.outcome not in {"applied", "already_applied"}:
                return self._result(
                    operation_id,
                    "reconciliation_required",
                    "candidate_publication",
                    receipts,
                    intents,
                    reason=receipt.outcome,
                )

            pr_request = PullRequestCreateRequest.build(
                operation_id=operation_id,
                repository_digest=plan.repository_digest,
                lease_epoch_digest=lease.lease_epoch_digest,
                candidate_ref=pr_candidate_ref(plan),
                candidate_commit=plan.composition.candidate_commit,
                candidate_tree=plan.composition.candidate_tree,
                base_commit=plan.composition.base_commit,
                base_tree=plan.composition.base_tree,
                preparation_authorization_digest=prep.authorization_digest,
            )
            self._preflight(plan, prep, lease)
            pr_intent, receipt = self._run_stage(
                plan, prep, lease, pr_request, candidate_intent, "pull_request_open"
            )
            intents["pull_request_open"] = pr_intent.intent_digest
            receipts["pull_request_open"] = receipt.receipt_digest
            if receipt.outcome not in {"applied", "already_applied"}:
                return self._result(
                    operation_id,
                    "reconciliation_required",
                    "pull_request_open",
                    receipts,
                    intents,
                    reason=receipt.outcome,
                )
            pr = self._resolve_pr(pr_request, receipt)
            self._verify_pr(plan, pr)

            queue = self._read_queue(operation_id)
            protection = self._read_protection(operation_id)
            admission_seed = canonical_digest(
                {
                    "operation_id": operation_id,
                    "stage": "admission_check",
                    "repository_digest": plan.repository_digest,
                    "queue_generation_digest": queue.queue_generation_digest,
                    "pull_request_number": pr.number,
                    "pull_request_head": pr.head_commit,
                    "pull_request_tree": pr.head_tree,
                    "base_commit": pr.base_commit,
                    "base_tree": pr.base_tree,
                    "preparation_authorization_digest": prep.authorization_digest,
                    "issuer_identity": protection.isolated_release_issuer,
                    "issuer_app_id": protection.release_issuer_app_id,
                    "issuer_isolation_digest": protection.issuer_isolation_digest,
                }
            )
            admission_request = AdmissionIssueRequest.build(
                operation_id=operation_id,
                repository_digest=plan.repository_digest,
                lease_epoch_digest=lease.lease_epoch_digest,
                queue_generation_digest=queue.queue_generation_digest,
                pull_request_number=pr.number,
                pull_request_head=pr.head_commit,
                pull_request_tree=pr.head_tree,
                base_commit=pr.base_commit,
                base_tree=pr.base_tree,
                preparation_authorization_digest=canonical_digest(prep),
                admission_run_id="avo-main-admission-" + admission_seed.removeprefix("sha256:"),
                admission_nonce=main_stage_nonce(admission_seed),
                issuer_identity=protection.isolated_release_issuer,
                issuer_app_id=protection.release_issuer_app_id,
                issuer_isolation_digest=protection.issuer_isolation_digest,
            )
            self._preflight(plan, prep, lease)
            admission_intent, receipt = self._run_stage(
                plan, prep, lease, admission_request, pr_intent, "admission_check"
            )
            intents["admission_check"] = admission_intent.intent_digest
            receipts["admission_check"] = receipt.receipt_digest
            if receipt.outcome not in {"applied", "already_applied"}:
                return self._result(
                    operation_id,
                    "reconciliation_required",
                    "admission_check",
                    receipts,
                    intents,
                    pr=pr,
                    reason=receipt.outcome,
                )
            admission = self._admit(plan, prep, queue, protection, pr, admission_request)
            admission_ref_digest = canonical_digest(admission)

            queue_request = QueueEnqueueRequest.build(
                operation_id=operation_id,
                repository_digest=plan.repository_digest,
                lease_epoch_digest=lease.lease_epoch_digest,
                queue_generation_digest=queue.queue_generation_digest,
                pull_request_number=pr.number,
                pull_request_url=pr.url,
                pull_request_identity=canonical_digest(
                    {
                        "operation_id": operation_id,
                        "repository_digest": plan.repository_digest,
                        "pull_request_number": pr.number,
                        "pull_request_url": pr.url,
                    }
                ),
                pull_request_head=pr.head_commit,
                pull_request_tree=pr.head_tree,
                base_commit=pr.base_commit,
                base_tree=pr.base_tree,
                preparation_authorization_digest=canonical_digest(prep),
                admission_observation_digest=admission_ref_digest,
            )
            self._preflight(plan, prep, lease)
            queue_intent, receipt = self._run_stage(
                plan, prep, lease, queue_request, admission_intent, "queue_enqueue"
            )
            intents["queue_enqueue"] = queue_intent.intent_digest
            receipts["queue_enqueue"] = receipt.receipt_digest
            state = (
                "queued"
                if receipt.outcome in {"applied", "already_applied"}
                else "reconciliation_required"
            )
            if state == "queued":
                self._observe_queued(queue_request, plan, queue, pr)
            return self._result(
                operation_id,
                state,
                "queue_enqueue",
                receipts,
                intents,
                pr=pr,
                admission=admission,
                queue=queue,
                reason=None if state == "queued" else receipt.outcome,
            )
        except (MainGraduationPreparationError, C4StageExecutionError) as exc:
            return PreparationResult(
                operation_id=operation_id, state="quarantined", reason=str(exc)
            )

    resume = prepare
    run = prepare
    execute = prepare

    def _load(
        self, operation_id: str
    ) -> tuple[MainGraduationPlan, MainPreparationAuthorization, MainLeaseEvidenceRecord]:
        plan_prior = self.journal.read_plan(operation_id)
        prep_prior = self.journal.read_preparation_authorization(operation_id)
        lease_prior = self.journal.read_lease_evidence_record(operation_id)
        if plan_prior is None or prep_prior is None or lease_prior is None:
            raise MainGraduationPreparationError(
                "plan, preparation authorization, and lease are required"
            )
        return (
            cast(MainGraduationPlan, plan_prior[0]),
            cast(MainPreparationAuthorization, prep_prior[0]),
            cast(MainLeaseEvidenceRecord, lease_prior[0]),
        )

    def _preflight(
        self,
        plan: MainGraduationPlan,
        prep: MainPreparationAuthorization,
        lease: MainLeaseEvidenceRecord,
    ) -> None:
        if (
            prep.scope != "candidate_publication_pr_preparation_queue_admission"
            or not prep.authorized
        ):
            raise MainGraduationPreparationError(
                "preparation authorization scope is not reversible C4"
            )
        if plan.repository_digest != prep.repository_digest or plan.target_ref != prep.target_ref:
            raise MainGraduationPreparationError("plan and authorization target differ")
        request = MainLeaseEvidenceReadRequest(
            operation_id=plan.operation_id,
            repository_digest=plan.repository_digest,
            target_ref=plan.target_ref,
            lease_digest=lease.lease_digest,
            requested_at=self.clock.now(),
        )
        self.journal.assert_lease_evidence(request)
        if lease.expires_at <= self.clock.now():
            raise MainGraduationPreparationError("main lease has expired")
        observe_main = getattr(self.read_provider, "observe_main", None)
        if not callable(observe_main):
            raise MainGraduationPreparationError("authoritative main observation is missing")
        main = observe_main()
        if (
            getattr(main, "repository_digest", None) != plan.repository_digest
            or getattr(main, "ref", None) != plan.target_ref
            or getattr(main, "commit", None) != plan.composition.base_commit
            or getattr(main, "tree", None) != plan.composition.base_tree
        ):
            raise MainGraduationPreparationError("protected main base is stale or changed")
        queue = self._read_queue(plan.operation_id)
        protection = self._read_protection(plan.operation_id)
        fresh_protection = getattr(self.read_provider, "observe_protection", None)
        if not callable(fresh_protection):
            raise MainGraduationPreparationError("authoritative protection observation is missing")
        observed_protection = fresh_protection()
        if (
            observed_protection.manifest_digest != protection.manifest_digest
            or observed_protection.protection_epoch != protection.protection_epoch
        ):
            raise MainGraduationPreparationError("protected-main policy is stale")
        fresh_queue = getattr(self.read_provider, "observe_queue", None)
        if not callable(fresh_queue):
            raise MainGraduationPreparationError("authoritative queue observation is missing")
        observed_queue = fresh_queue()
        if (
            observed_queue.queue_generation_digest != queue.queue_generation_digest
            or observed_queue.queue_manifest_digest != queue.queue_manifest_digest
            or observed_queue.protection_manifest_digest != queue.protection_manifest_digest
        ):
            raise MainGraduationPreparationError("merge queue generation is stale")

    def _read_queue(self, operation_id: str) -> MainQueueObservation:
        prior = self.journal.read_queue_observation(operation_id)
        if prior is None:
            raise MainGraduationPreparationError("durable queue observation is missing")
        queue = cast(MainQueueObservation, prior[0])
        if (
            not queue.queue_enabled
            or queue.max_entries_per_group != 1
            or queue.bypass_allowed
            or queue.direct_merge_allowed
            or queue.merge_method != "squash"
        ):
            raise MainGraduationPreparationError("queue policy is not exact C4 policy")
        return queue

    def _read_protection(self, operation_id: str) -> MainProtectionManifest:
        prior = self.journal.read_protection_manifest(operation_id)
        if prior is None:
            raise MainGraduationPreparationError("durable protection manifest is missing")
        protection = cast(MainProtectionManifest, prior[0])
        if (
            protection.release_issuer_app_id == 15368
            or not protection.queue_required
            or protection.bypass_allowed
            or protection.direct_merge_allowed
        ):
            raise MainGraduationPreparationError("protection manifest is not exact C4 policy")
        if (
            protection.provider_identity != self.provider_identity
            or protection.provider_api_version != self.provider_api_version
        ):
            raise MainGraduationPreparationError(
                "provider identity/version differs from durable protection"
            )
        return protection

    def _run_stage(
        self,
        plan: MainGraduationPlan,
        prep: MainPreparationAuthorization,
        lease: MainLeaseEvidenceRecord,
        request: StageRequest,
        parent: MainMutationIntent | None,
        stage: str,
    ) -> tuple[MainMutationIntent, MainMutationReceipt]:
        parent_receipt: MainMutationReceipt | None = None
        parent_resolution: Sha256Digest | None = None
        if parent is not None:
            parent_receipt = self._receipt_for_intent(parent.intent_digest)
            if parent_receipt is None:
                raise MainGraduationPreparationError("parent mutation receipt is missing")
            if parent_receipt.outcome not in {"applied", "already_applied"}:
                resolution = self.journal.read_mutation_fence_resolution_by_intent(
                    parent.intent_digest
                )
                if resolution is None or resolution[0].outcome != "observed":
                    raise MainGraduationPreparationError(
                        "parent mutation requires authoritative recovery"
                    )
                parent_resolution = resolution[0].resolution_digest
                parent_receipt = None
        values: dict[str, Any] = {
            "repository_digest": request.repository_digest,
            "target_ref": request.target_ref,
            "operation_id": request.operation_id,
            "stage": stage,
            "parent_stage": parent.stage if parent is not None else None,
            "parent_intent_digest": parent.intent_digest if parent is not None else None,
            "parent_receipt": parent_receipt,
            "parent_resolution_digest": parent_resolution,
            "lease_identity": prep.lease_identity,
            "lease_digest": prep.lease_digest,
            "lease_epoch_digest": lease.lease_epoch_digest,
            "policy_epoch_digest": prep.policy_epoch,
            "controller_config_digest": plan.controller_config_digest,
            "preparation_authorization_digest": prep.authorization_digest,
            "external_identity": _external_identity(request),
            "request_digest": request.request_digest,
            "recorded_at": self.clock.now(),
        }
        intent = _digest_intent(values)
        capture = _CaptureCapability(
            self._capabilities[stage],
            {
                "candidate_publication": "publish_candidate",
                "pull_request_open": "create_pull_request",
                "admission_check": "issue_admission",
                "queue_enqueue": "enqueue",
            }[stage],
        )
        executor = C4StageExecutor(
            journal=self.journal,
            clock=self.clock,
            lease_fence=self.lease_fence,
            capability=capture,
            observation_capability=cast(Any, self.observation_capability),
            authority_verifier=self.authority_verifier,
            provider_identity=self.provider_identity,
            provider_api_version=self.provider_api_version,
            provider_repository=cast(str | None, getattr(self.provider, "repository_name", None)),
        )
        durable = self.journal.read_mutation_intent(intent.intent_digest)
        if durable is None:
            receipt = executor.execute(intent, request)
        else:
            receipt = self._receipt_for_intent(intent.intent_digest)
            if receipt is None or receipt.outcome not in {"applied", "already_applied", "rejected"}:
                observation = self._observation_request(intent, request)
                receipt = executor.recover(intent, observation, original_request=request)
            else:
                receipt = executor.execute(intent, request)
        if receipt.outcome in {"ambiguous", "reconciliation_required"}:
            observation = self._observation_request(intent, request)
            receipt = executor.recover(intent, observation, original_request=request)
        if capture.result is not None:
            self._last_stage_results[stage] = capture.result
        return intent, receipt

    def _receipt_for_intent(self, intent_digest: str) -> MainMutationReceipt | None:
        reader = getattr(self.journal, "_read_receipt_for_intent", None)
        if not callable(reader):
            return None
        value = reader(intent_digest)
        return None if value is None else cast(MainMutationReceipt, value[0])

    def _observation_request(self, intent: MainMutationIntent, request: StageRequest) -> Any:
        values = request.model_dump(mode="json")
        values.pop("request_digest", None)
        object_ids: dict[str, str] = {}
        if request.stage == "candidate_publication":
            object_ids[request.stage] = request.candidate_ref
        elif request.stage == "admission_check":
            object_ids[request.stage] = request.admission_run_id
        elif request.stage == "queue_enqueue":
            object_ids[request.stage] = request.pull_request_url
        values["object_id"] = object_ids.get(request.stage, "unknown")
        if request.stage == "pull_request_open":
            pr = self._resolve_pr(request, None)
            values = {
                **{
                    k: v
                    for k, v in values.items()
                    if k
                    not in {
                        "candidate_commit",
                        "candidate_tree",
                        "external_key",
                        "external_identity",
                        "preparation_authorization_digest",
                    }
                },
                "pull_request_number": pr.number,
                "candidate_ref": request.candidate_ref,
                "head_commit": pr.head_commit,
                "head_tree": pr.head_tree,
                "base_commit": pr.base_commit,
                "base_tree": pr.base_tree,
                "object_id": self._repository_name() + ":pull/" + str(pr.number),
            }
        return {
            "candidate_publication": CandidateObservationRequest,
            "pull_request_open": PullRequestObservationRequest,
            "admission_check": AdmissionObservationRequest,
            "queue_enqueue": QueueObservationRequest,
        }[request.stage].build(**values)

    def _resolve_pr(
        self,
        request: StageRequest,
        receipt: MainMutationReceipt | None,
        *,
        prior: _PR | None = None,
    ) -> _PR:
        if prior is not None:
            return prior
        captured = self._last_stage_results.get("pull_request_open")
        if captured is not None:
            if not isinstance(captured, PullRequestCreateResult):
                raise MainGraduationPreparationError("PR result is not typed")
            if bool(getattr(captured, "draft", False)) or str(
                getattr(captured, "state", "open")
            ).casefold() not in {"open", "opened"}:
                raise MainGraduationPreparationError("pull request is draft or not open")
            return _PR(
                int(captured.pull_request_number),
                str(captured.pull_request_url),
                str(captured.candidate_commit),
                str(captured.candidate_tree),
                str(captured.base_commit),
                str(captured.base_tree),
            )
        durable_admission = self.journal.read_queue_admission(request.operation_id)
        if durable_admission is not None:
            evidence = cast(MainQueueAdmissionObservation, durable_admission[0])
            return self._observe_pr(request, evidence.pull_request_number)
        observe = getattr(self.provider, "observe_pull_request_by_candidate", None)
        if not callable(observe):
            raise MainGraduationPreparationError("typed PR recovery protocol is missing")
        observed = observe(request)
        if not isinstance(observed, PullRequestObservationResult):
            raise MainGraduationPreparationError("PR recovery result is not typed")
        return self._pr_from_observation(observed)

    def _observe_pr(self, request: StageRequest, number: int) -> _PR:
        observe = getattr(self.observation_capability, "observe_pull_request", None)
        if not callable(observe):
            raise MainGraduationPreparationError("read-only PR observation is missing")
        observed = observe(self._pr_observation_request(request, number))
        if not isinstance(observed, PullRequestObservationResult):
            raise MainGraduationPreparationError("PR observation result is not typed")
        return self._pr_from_observation(observed)

    def _pr_observation_request(
        self, request: StageRequest, number: int
    ) -> PullRequestObservationRequest:
        return PullRequestObservationRequest.build(
            operation_id=request.operation_id,
            repository_digest=request.repository_digest,
            lease_epoch_digest=request.lease_epoch_digest,
            pull_request_number=number,
            candidate_ref=request.candidate_ref,
            head_commit=request.candidate_commit,
            head_tree=request.candidate_tree,
            base_commit=request.base_commit,
            base_tree=request.base_tree,
            object_id=self._repository_name() + ":pull/" + str(number),
        )

    def _pr_from_observation(self, observed: PullRequestObservationResult) -> _PR:
        if observed.outcome != "observed":
            raise MainGraduationPreparationError("PR was not authoritatively observed")
        repository_url = getattr(self.read_provider, "repository_url", None)
        if not isinstance(repository_url, str) or not repository_url.startswith("https://"):
            raise MainGraduationPreparationError("provider PR URL authority is missing")
        return _PR(
            observed.pull_request_number,
            repository_url.rstrip("/") + "/pull/" + str(observed.pull_request_number),
            observed.head_commit,
            observed.head_tree,
            observed.base_commit,
            observed.base_tree,
        )

    def _verify_pr(self, plan: MainGraduationPlan, pr: _PR) -> None:
        if (
            not pr.url.startswith("https://")
            or pr.head_commit != plan.composition.candidate_commit
            or pr.head_tree != plan.composition.candidate_tree
            or pr.base_commit != plan.composition.base_commit
            or pr.base_tree != plan.composition.base_tree
        ):
            raise MainGraduationPreparationError(
                "pull request is not exact candidate/base identity"
            )

    def _admit(
        self,
        plan: MainGraduationPlan,
        prep: MainPreparationAuthorization,
        queue: MainQueueObservation,
        protection: MainProtectionManifest,
        pr: _PR,
        request: AdmissionIssueRequest,
    ) -> MainQueueAdmissionObservation:
        values: dict[str, Any] = {
            "operation_id": plan.operation_id,
            "repository_digest": plan.repository_digest,
            "target_ref": plan.target_ref,
            "preparation_authorization_digest": canonical_digest(prep),
            "package_digest": plan.package.package_digest,
            "composition_digest": plan.composition.composition_digest,
            "pull_request_number": pr.number,
            "pull_request_url": pr.url,
            "base_commit": pr.base_commit,
            "base_tree": pr.base_tree,
            "head_commit": pr.head_commit,
            "head_tree": pr.head_tree,
            "admission_sha": pr.head_commit,
            "admission_run_id": request.admission_run_id,
            "admission_nonce": request.admission_nonce,
            "queue_generation_digest": queue.queue_generation_digest,
            "protection_manifest_digest": protection.manifest_digest,
            "issuer_identity": request.issuer_identity,
            "release_issuer_app_id": request.issuer_app_id,
            "issuer_isolation_digest": request.issuer_isolation_digest,
            "observed_at": self.clock.now(),
        }
        observed = self._observe_admission(request)
        check = self._observe_admission_check(pr.head_commit)
        if (
            check.sha != request.pull_request_head
            or check.run_id != request.admission_run_id
            or check.nonce != request.admission_nonce
            or check.app_id != request.issuer_app_id
            or check.status != "completed"
            or check.conclusion != "success"
        ):
            raise MainGraduationPreparationError("admission check is not exact provider proof")
        if check.app_id == 15368:
            raise MainGraduationPreparationError("validation App 15368 cannot issue admission")
        values["observed_at"] = check.observed_at
        admission = MainQueueAdmissionObservation.model_validate(values)
        prior = self.journal.read_queue_admission(plan.operation_id)
        if prior is not None:
            existing = cast(MainQueueAdmissionObservation, prior[0])
            expected = admission.model_dump(mode="json")
            actual = existing.model_dump(mode="json")
            expected.pop("observed_at", None)
            actual.pop("observed_at", None)
            if expected != actual:
                raise MainGraduationPreparationError(
                    "durable admission differs from exact PR-head proof"
                )
            return existing
        del observed
        validated = self.attester.attest_admission(
            admission,
            self._protected_pr(pr, plan),
            queue,
            preparation_authorization_digest=canonical_digest(prep),
            admission_check=check,
            freshness_cutoff=self.clock.now(),
        )
        if not isinstance(validated, MainQueueAdmissionObservation):
            raise MainGraduationPreparationError("attester did not return typed admission evidence")
        self.journal.record_queue_admission(validated)
        return validated

    def _observe_admission(self, request: AdmissionIssueRequest) -> StageObservationResult:
        observe = getattr(self.observation_capability, "observe_admission", None)
        if not callable(observe):
            raise MainGraduationPreparationError("read-only admission observation is missing")
        observation_request = AdmissionObservationRequest.build(
            **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
            object_id=request.admission_run_id,
        )
        observed = observe(observation_request)
        if not isinstance(observed, AdmissionObservationResult) or observed.outcome != "observed":
            raise MainGraduationPreparationError("admission was not authoritatively observed")
        observed_values = observed.model_dump(mode="json")
        observed_values.pop("outcome", None)
        observed_values.pop("evidence_digest", None)
        observed_values.pop("observed_at", None)
        expected_values = observation_request.model_dump(mode="json")
        if observed_values != expected_values:
            raise MainGraduationPreparationError(
                "admission observation target differs from request"
            )
        return observed

    def _observe_admission_check(self, head: str) -> MainCheckObservation:
        observe = getattr(self.read_provider, "observe_pr_head_admission_check", None)
        if not callable(observe):
            raise MainGraduationPreparationError("provider admission-check observation is missing")
        check = observe(head, freshness_cutoff=self.clock.now())
        if not isinstance(check, MainCheckObservation):
            raise MainGraduationPreparationError("admission-check observation is not typed")
        return check

    def _observe_queued(
        self,
        request: QueueEnqueueRequest,
        plan: MainGraduationPlan,
        durable_queue: MainQueueObservation,
        pr: _PR,
    ) -> MainQueueObservation:
        observe = getattr(self.read_provider, "observe_queue", None)
        if not callable(observe):
            raise MainGraduationPreparationError("authoritative queue observation is missing")
        observed = observe()
        if not isinstance(observed, MainQueueObservation):
            raise MainGraduationPreparationError("queue observation is not typed")
        if (
            observed.repository_digest != plan.repository_digest
            or observed.target_ref != plan.target_ref
            or observed.pull_request_number != pr.number
            or observed.expected_base_commit != pr.base_commit
            or observed.expected_base_tree != pr.base_tree
            or observed.expected_group_parents != [pr.base_commit, pr.head_commit]
            or observed.queue_generation_digest != request.queue_generation_digest
            or observed.protection_manifest_digest != durable_queue.protection_manifest_digest
            or observed.protection_epoch != durable_queue.protection_epoch
            or observed.max_entries_per_group != 1
            or observed.bypass_allowed
            or observed.direct_merge_allowed
            or observed.merge_method != "squash"
        ):
            raise MainGraduationPreparationError("queued PR is not exact singleton queue admission")
        return observed

    def _protected_pr(self, pr: _PR, plan: MainGraduationPlan) -> Any:
        from avo_correlate.adapters.hosted_git.protected_main import MainPullRequestObservation

        return MainPullRequestObservation(
            plan.repository_digest,
            pr.number,
            pr.url,
            "refs/heads/main",
            pr.base_commit,
            pr.base_tree,
            plan.composition.candidate_ref,
            pr.head_commit,
            pr.head_tree,
            "OPEN",
            False,
            self.clock.now(),
        )

    def _result(
        self,
        operation_id: str,
        state: str,
        stage: str,
        receipts: Mapping[str, Sha256Digest],
        intents: Mapping[str, Sha256Digest],
        *,
        pr: _PR | None = None,
        admission: MainQueueAdmissionObservation | None = None,
        queue: MainQueueObservation | None = None,
        reason: str | None = None,
    ) -> PreparationResult:
        return PreparationResult(
            operation_id=operation_id,
            state=state,
            stage=stage,
            stage_receipts=dict(receipts),
            stage_intents=dict(intents),
            candidate_ref=pr_candidate_ref_from_operation(operation_id),
            pull_request_number=None if pr is None else pr.number,
            pull_request_url=None if pr is None else pr.url,
            admission_observation_digest=None if admission is None else canonical_digest(admission),
            queue_generation_digest=None if queue is None else queue.queue_generation_digest,
            reason=reason,
        )

    def _repository_name(self) -> str:
        value = getattr(self.read_provider, "repository_name", None)
        if isinstance(value, str) and value:
            return value
        owner, repo = (
            getattr(self.read_provider, "owner", None),
            getattr(self.read_provider, "repo", None),
        )
        if isinstance(owner, str) and isinstance(repo, str):
            return owner + "/" + repo
        return "repository"


def pr_candidate_ref_from_operation(operation_id: str) -> str:
    return "refs/heads/avo/candidate/" + operation_id.removeprefix("sha256:")


def prep_candidate_ref(plan: MainGraduationPlan) -> str:
    return plan.composition.candidate_ref


def pr_candidate_ref(plan: MainGraduationPlan) -> str:
    return plan.composition.candidate_ref


MainGraduationCoordinator = MainGraduationPreparationCoordinator
MainGraduationPreparationResult = PreparationResult


__all__ = [
    "MainGraduationCoordinator",
    "MainGraduationPreparationCoordinator",
    "MainGraduationPreparationError",
    "MainGraduationPreparationResult",
    "PreparationResult",
]
