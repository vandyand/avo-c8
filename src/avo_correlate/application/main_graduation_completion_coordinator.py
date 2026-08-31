# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportArgumentType=false, reportAttributeAccessIssue=false, reportIndexIssue=false, reportUnnecessaryCast=false, reportInvalidTypeForm=false, reportGeneralTypeIssues=false, reportOptionalMemberAccess=false

"""Restart-safe C4 completion coordinator.

This module is deliberately separate from ``main_graduation_coordinator``.
The preparation coordinator can therefore never acquire a main-release
capability by accident.  Every external write in this module goes through the
stage executor; provider reads are used only to authenticate evidence and to
resolve an uncertain dispatch.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, cast

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.application.c4_capabilities import (
    GroupHoldIssueRequest,
    GroupHoldObservationRequest,
    ReleaseIssueRequest,
    ReleaseObservationRequest,
    StageRequest,
    TrustedClock,
)
from avo_correlate.application.c4_stage_executor import (
    C4StageExecutionError,
    C4StageExecutor,
    StageAuthorityVerifier,
    StageLeaseFence,
)
from avo_correlate.contracts.base import ArtifactRef, Sha256Digest
from avo_correlate.contracts.main_graduation import (
    MainAttestationManifest,
    MainCheckObservation,
    MainCompletionPackage,
    MainCompositionArtifact,
    MainDeltaManifest,
    MainGraduationIntent,
    MainGraduationPlan,
    MainMergeGroupChecks,
    MainMergeGroupWebhookReceipt,
    MainMutationFenceResolution,
    MainPreparationAuthorization,
    MainProviderPostStateObservation,
    MainProviderReceipt,
    MainQueueAdmissionObservation,
    MainQueueConfigurationObservation,
    MainQueueObservation,
    MainReconciliation,
    MainReleaseAuthorization,
    MainReleaseClaim,
    MainReleaseHoldObservation,
    MainReleaseIssuerBinding,
    MainReleaseTransitionReceipt,
    MainSourcePackageBinding,
    main_target_scope_digest,
)
from avo_correlate.contracts.main_graduation_phase_a import (
    MainClaimedReleaseTransitionReceipt,
    MainLeaseEvidenceReadRequest,
    MainLeaseEvidenceRecord,
    MainMutationIntent,
    MainMutationReceipt,
    main_stage_nonce,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

_ZERO = "sha256:" + "0" * 64


class MainGraduationCompletionError(RuntimeError):
    """The durable C4 chain cannot safely be completed."""


@dataclass(frozen=True, slots=True)
class CompletionResult:
    operation_id: Sha256Digest
    state: str
    package: MainCompletionPackage | None = None
    stage: str | None = None
    reason: str | None = None
    artifacts: Mapping[str, Sha256Digest] = field(default_factory=dict)

    @property
    def terminal(self) -> bool:
        return self.state in {"completed", "reconciliation_required", "quarantined"}


def _digest_record(model: Any, values: Mapping[str, object], field: str) -> Any:
    data = dict(values)
    probe = model.model_construct(**data, **{field: _ZERO})
    data[field] = canonical_digest(probe.model_dump(exclude={field}, mode="json"))
    return model.model_validate(data)


def _stage_intent(
    *,
    request: StageRequest,
    prep: MainPreparationAuthorization,
    plan: MainGraduationPlan,
    lease: MainLeaseEvidenceRecord,
    parent: tuple[MainMutationIntent, MainMutationReceipt | MainMutationFenceResolution],
    recorded_at: datetime,
    authorization: MainReleaseAuthorization,
    claim: MainReleaseClaim,
) -> MainMutationIntent:
    parent_intent, parent_proof = parent
    values: dict[str, object] = {
        "repository_digest": request.repository_digest,
        "target_ref": request.target_ref,
        "operation_id": request.operation_id,
        "stage": "release_transition",
        "parent_stage": "merge_group_hold",
        "parent_intent_digest": parent_intent.intent_digest,
        "parent_receipt": parent_proof if isinstance(parent_proof, MainMutationReceipt) else None,
        "parent_resolution_digest": (
            parent_proof.resolution_digest
            if isinstance(parent_proof, MainMutationFenceResolution)
            else None
        ),
        "lease_identity": lease.owner,
        "lease_digest": lease.lease_digest,
        "lease_epoch_digest": lease.lease_epoch_digest,
        "policy_epoch_digest": prep.policy_epoch,
        "controller_config_digest": plan.controller_config_digest,
        "preparation_authorization_digest": prep.authorization_digest,
        "release_authorization_digest": authorization.authorization_digest,
        "release_claim_digest": claim.claim_digest,
        "external_identity": {
            "repository_digest": request.repository_digest,
            "target_ref": request.target_ref,
            "operation_id": request.operation_id,
            "stage": "release_transition",
            "external_key": request.external_key,
            "queue_generation_digest": request.queue_generation_digest,
            "identity_digest": request.external_identity,
        },
        "request_digest": request.request_digest,
        "recorded_at": recorded_at,
    }
    # The nested identity is a strict contract, not an arbitrary dictionary.
    from avo_correlate.contracts.main_graduation import MainExternalIdentity

    values["external_identity"] = MainExternalIdentity.model_validate(values["external_identity"])
    return _digest_record(MainMutationIntent, values, "intent_digest")


class MainGraduationCompletionCoordinator:
    """Advance an exact queued preparation chain through C4 release.

    ``merge_group`` may be a ``MainMergeGroupObservation`` returned by the
    authenticated protected-main provider.  Alternatively, callers may pass
    ``group_sha`` and raw webhook inputs and this coordinator obtains that
    observation from the provider.  No caller-supplied group membership is
    trusted without the provider's authenticated receipt.
    """

    def __init__(
        self,
        *,
        journal: MainGraduationJournal,
        clock: TrustedClock,
        lease_fence: StageLeaseFence,
        provider: object | None = None,
        protected_main_provider: object | None = None,
        hold_capability: object | None = None,
        release_capability: object | None = None,
        release_issuer_capability: object | None = None,
        observation_capability: object | None = None,
        authority_verifier: StageAuthorityVerifier,
        attester: object | None = None,
        attestation_manifest: MainAttestationManifest | None = None,
        authorization_ttl: timedelta = timedelta(minutes=5),
        provider_identity: str | None = None,
        provider_api_version: str | None = None,
    ) -> None:
        self.journal = journal
        self.clock = clock
        self.lease_fence = lease_fence
        self.provider = protected_main_provider or provider
        if self.provider is None:
            raise ValueError("a protected-main provider is required")
        self.hold_capability = hold_capability or release_capability or provider or self.provider
        self.release_capability = (
            release_capability or release_issuer_capability or provider or self.provider
        )
        self.observation_capability = observation_capability or self.provider
        self.authority_verifier = authority_verifier
        self.attester = attester
        self.attestation_manifest = attestation_manifest
        if authorization_ttl <= timedelta(0):
            raise ValueError("authorization_ttl must be positive")
        self.authorization_ttl = authorization_ttl
        self.provider_identity = provider_identity or cast(
            str | None, getattr(self.provider, "provider_identity", None)
        )
        self.provider_api_version = provider_api_version or cast(
            str | None, getattr(self.provider, "provider_api_version", None)
        )
        if not self.provider_identity or not self.provider_api_version:
            raise ValueError("provider identity and API version are required")

    def complete(
        self,
        operation_id: Sha256Digest,
        *,
        merge_group: object | None = None,
        merge_group_observation: object | None = None,
        group_observation: object | None = None,
        group_sha: str | None = None,
        webhook_body: bytes | None = None,
        webhook_headers: Mapping[str, str] | None = None,
        pull_request_number: int | None = None,
    ) -> CompletionResult:
        try:
            existing = self.journal.read_completion(operation_id)
            if existing is not None:
                return CompletionResult(
                    operation_id, "completed", cast(MainCompletionPackage, existing[0])
                )
            return self._complete(
                operation_id,
                merge_group=merge_group or merge_group_observation or group_observation,
                group_sha=group_sha,
                webhook_body=webhook_body,
                webhook_headers=webhook_headers,
                pull_request_number=pull_request_number,
            )
        except (
            MainGraduationCompletionError,
            C4StageExecutionError,
            MainGraduationJournalError,
            ValueError,
            TypeError,
        ) as exc:
            return CompletionResult(operation_id, "quarantined", reason=str(exc))

    resume = complete
    run = complete
    execute = complete

    def _complete(self, operation_id: Sha256Digest, **kwargs: object) -> CompletionResult:
        plan, prep, lease, queue_config, queue, admission, protection = self._load(operation_id)
        attestation = self._attestation(operation_id)
        release_started = self._read_stage_intent(operation_id, "release_transition") is not None
        hold_started = self._read_stage_intent(operation_id, "merge_group_hold") is not None
        self._assert_queued_chain(
            plan,
            prep,
            lease,
            queue_config,
            queue,
            admission,
            protection,
            check_lease=not release_started and not hold_started,
            revalidate_provider=not release_started,
        )
        # Once release intent exists, the provider boundary may already have
        # been crossed.  Recovery after authority expiry is therefore allowed
        # to proceed read-only; a fresh attempt still requires a live lease.
        if self._read_stage_intent(operation_id, "release_transition") is None:
            self._assert_current_lease(plan, lease)

        hold = self._read(operation_id, "release-hold", MainReleaseHoldObservation)
        hold_intent = self._read_stage_intent(operation_id, "merge_group_hold")
        group = kwargs.get("merge_group")
        if hold is None:
            group = self._group_observation(
                group,
                group_sha=cast(str | None, kwargs.get("group_sha")),
                webhook_body=cast(bytes | None, kwargs.get("webhook_body")),
                webhook_headers=cast(Mapping[str, str] | None, kwargs.get("webhook_headers")),
                queue=queue,
                pull_request_number=cast(int | None, kwargs.get("pull_request_number"))
                or admission.pull_request_number,
            )
            hold, hold_intent = self._issue_hold(
                plan, prep, lease, queue_config, queue, admission, protection, attestation, group
            )
        if hold_intent is None:
            hold_intent = self._read_stage_intent(operation_id, "merge_group_hold")
        if hold_intent is None:
            raise MainGraduationCompletionError("durable merge-group hold intent is missing")

        authorization = self._read(operation_id, "release-authorization", MainReleaseAuthorization)
        if authorization is None:
            authorization = self._issue_authorization(plan, prep, lease, admission, hold)
        claim = self._read_claim_for_authorization(operation_id, authorization)
        if claim is None:
            claim = self._issue_claim(lease, hold, authorization)

        transition, claimed, mutation, resolution, release_intent = self._release(
            plan, prep, lease, hold, authorization, claim, hold_intent
        )
        if claimed.outcome not in {"transitioned", "already_transitioned"}:
            return CompletionResult(
                operation_id,
                "reconciliation_required",
                stage="release_transition",
                reason="release dispatch remains unresolved",
            )
        provider_receipt, reconciliation, post_state = self._post_state(
            plan, authorization, transition, claimed
        )
        artifacts = self._record_completion(
            plan,
            attestation,
            queue_config,
            queue,
            protection,
            admission,
            hold,
            authorization,
            transition,
            lease,
            claim,
            claimed,
            release_intent,
            mutation,
            resolution,
            provider_receipt,
            post_state,
            reconciliation,
        )
        package = self._build_package(
            operation_id,
            plan,
            attestation,
            queue_config,
            queue,
            protection,
            admission,
            hold,
            authorization,
            transition,
            lease,
            claim,
            claimed,
            release_intent,
            mutation,
            resolution,
            provider_receipt,
            post_state,
            reconciliation,
            artifacts,
        )
        self.journal.record_completion(package)
        return CompletionResult(
            operation_id, "completed", package, "release_transition", artifacts=artifacts
        )

    def _load(
        self, operation_id: str
    ) -> tuple[
        MainGraduationPlan,
        MainPreparationAuthorization,
        MainLeaseEvidenceRecord,
        MainQueueConfigurationObservation,
        MainQueueObservation,
        MainQueueAdmissionObservation,
        Any,
    ]:
        def required(kind: str, model: Any) -> Any:
            value = self._read(operation_id, kind, model)
            if value is None:
                raise MainGraduationCompletionError(f"durable {kind} is missing")
            return value

        return (
            required("plan", MainGraduationPlan),
            required("preparation-authorization", MainPreparationAuthorization),
            required("lease-evidence-record", MainLeaseEvidenceRecord),
            required("queue-configuration", MainQueueConfigurationObservation),
            required("queue", MainQueueObservation),
            required("queue-admission", MainQueueAdmissionObservation),
            required("protection", Any),
        )

    def _read(self, operation_id: str, kind: str, model: Any) -> Any | None:
        methods = {
            "plan": "read_plan",
            "preparation-authorization": "read_preparation_authorization",
            "lease-evidence-record": "read_lease_evidence_record",
            "queue-configuration": "read_queue_configuration",
            "queue": "read_queue_observation",
            "queue-admission": "read_queue_admission",
            "protection": "read_protection_manifest",
            "attestations": "read_attestation_manifest",
            "release-hold": "read_release_hold",
            "release-authorization": "read_release_authorization",
            "release-transition": "read_release_transition",
            "provider-receipt": "read_provider_receipt",
            "provider-post-state-observation": "read",
            "reconciliation": "read_reconciliation",
            "source-package": "read_source_package",
            "delta": "read_delta",
            "composition": "read_composition",
            "merge-group-checks": "read_merge_group_checks",
            "merge-group-webhook-receipt": "read_merge_group_webhook_receipt",
            "release-issuer-binding": "read_release_issuer_binding",
            "intent": "read_intent",
        }
        method = getattr(self.journal, methods.get(kind, f"read_{kind}"), None)
        if not callable(method):
            return None
        if kind == "provider-post-state-observation":
            value = method(kind, operation_id)
        else:
            value = method(operation_id)
        if value is None:
            return None
        return cast(model, value[0])

    def _attestation(self, operation_id: str) -> MainAttestationManifest:
        if self.attestation_manifest is not None:
            return self.attestation_manifest
        value = self._read(operation_id, "attestations", MainAttestationManifest)
        if value is None:
            raise MainGraduationCompletionError("durable attestation manifest is missing")
        return value

    def _assert_queued_chain(
        self,
        plan: MainGraduationPlan,
        prep: MainPreparationAuthorization,
        lease: MainLeaseEvidenceRecord,
        config: MainQueueConfigurationObservation,
        queue: MainQueueObservation,
        admission: MainQueueAdmissionObservation,
        protection: Any,
        *,
        check_lease: bool = True,
        revalidate_provider: bool = True,
    ) -> None:
        if (
            prep.scope != "candidate_publication_pr_preparation_queue_admission"
            or not prep.authorized
        ):
            raise MainGraduationCompletionError("preparation authorization is not reversible C4")
        if check_lease:
            self.journal.assert_lease_evidence(
                MainLeaseEvidenceReadRequest(
                    operation_id=plan.operation_id,
                    repository_digest=plan.repository_digest,
                    target_ref=plan.target_ref,
                    lease_digest=lease.lease_digest,
                    requested_at=self.clock.now(),
                )
            )
        if queue.operation_id != plan.operation_id or admission.operation_id != plan.operation_id:
            raise MainGraduationCompletionError("queued preparation operation identity differs")
        if queue.queue_configuration_digest != config.queue_configuration_digest:
            raise MainGraduationCompletionError("queued preparation configuration differs")
        if queue.admission_observation_digest != canonical_digest(admission):
            raise MainGraduationCompletionError("queue does not bind admission observation")
        if queue.pull_request_number != admission.pull_request_number:
            raise MainGraduationCompletionError("queue membership differs from admission")
        if (
            queue.provider_identity != self.provider_identity
            or queue.provider_api_version != self.provider_api_version
        ):
            raise MainGraduationCompletionError("queued provider identity differs")
        if (
            protection.provider_identity != self.provider_identity
            or protection.provider_api_version != self.provider_api_version
        ):
            raise MainGraduationCompletionError("protection provider identity differs")
        observe_queue = getattr(self.provider, "observe_queue", None)
        if revalidate_provider and callable(observe_queue):
            fresh_queue = observe_queue()
            if hasattr(fresh_queue, "model_dump"):
                expected = queue.model_dump(mode="json")
                actual = fresh_queue.model_dump(mode="json")
                expected.pop("observed_at", None)
                actual.pop("observed_at", None)
                if expected != actual:
                    raise MainGraduationCompletionError(
                        "queued preparation differs from provider state"
                    )
        observe_protection = getattr(self.provider, "observe_protection", None)
        if revalidate_provider and callable(observe_protection):
            fresh_protection = observe_protection()
            if (
                getattr(fresh_protection, "manifest_digest", None) != protection.manifest_digest
                or getattr(fresh_protection, "protection_epoch", None)
                != protection.protection_epoch
            ):
                raise MainGraduationCompletionError("protected-main policy is stale")
        observe_main = getattr(self.provider, "observe_main", None)
        if revalidate_provider and callable(observe_main):
            fresh_main = observe_main()
            if (
                getattr(fresh_main, "commit", None) != plan.composition.base_commit
                or getattr(fresh_main, "tree", None) != plan.composition.base_tree
            ):
                raise MainGraduationCompletionError("protected main base is stale")

    def _assert_current_lease(
        self, plan: MainGraduationPlan, lease: MainLeaseEvidenceRecord
    ) -> None:
        if self.clock.now() >= lease.expires_at:
            raise MainGraduationCompletionError("main lease has expired")
        self.lease_fence.assert_current(
            operation_id=plan.operation_id, lease_epoch_digest=lease.lease_epoch_digest
        )

    def _group_observation(
        self,
        supplied: object | None,
        *,
        group_sha: str | None,
        webhook_body: bytes | None,
        webhook_headers: Mapping[str, str] | None,
        queue: MainQueueObservation,
        pull_request_number: int,
    ) -> object:
        if supplied is not None:
            receipt = getattr(supplied, "webhook_receipt", None)
            if receipt is None or not isinstance(receipt, MainMergeGroupWebhookReceipt):
                raise MainGraduationCompletionError(
                    "authenticated merge-group webhook receipt is required"
                )
            return supplied
        if not group_sha:
            raise MainGraduationCompletionError("merge-group SHA is required")
        observe = getattr(self.provider, "observe_merge_group", None)
        if not callable(observe):
            raise MainGraduationCompletionError("protected-main merge-group observation is missing")
        return observe(
            group_sha,
            webhook_body=webhook_body,
            webhook_headers=webhook_headers,
            queue=queue,
            pull_request_number=pull_request_number,
        )

    def _issue_hold(
        self,
        plan: MainGraduationPlan,
        prep: MainPreparationAuthorization,
        lease: MainLeaseEvidenceRecord,
        config: MainQueueConfigurationObservation,
        queue: MainQueueObservation,
        admission: MainQueueAdmissionObservation,
        protection: Any,
        attestation: MainAttestationManifest,
        group: object,
    ) -> tuple[MainReleaseHoldObservation, MainMutationIntent]:
        group_sha = cast(str, group.group_sha)
        group_tree = cast(str, group.group_tree)
        parents = list(cast(tuple[str, ...], group.group_parents))
        receipt = cast(MainMergeGroupWebhookReceipt, group.webhook_receipt)
        if (
            receipt.operation_id != plan.operation_id
            or receipt.repository_digest != plan.repository_digest
            or receipt.target_ref != plan.target_ref
            or receipt.group_sha != group_sha
            or receipt.group_tree != group_tree
            or receipt.group_parents != parents
            or receipt.pull_request_number != admission.pull_request_number
            or receipt.queue_generation_digest != queue.queue_generation_digest
            or tuple(group.pull_request_numbers) != (admission.pull_request_number,)
            or parents != list(queue.expected_group_parents)
            or group.queue_generation_digest != queue.queue_generation_digest
        ):
            raise MainGraduationCompletionError(
                "authenticated merge-group observation differs from queued preparation"
            )
        topology = canonical_digest(
            {
                "base_commit": plan.composition.base_commit,
                "base_tree": plan.composition.base_tree,
                "pull_request_number": admission.pull_request_number,
                "pull_request_head": admission.head_commit,
                "pull_request_tree": admission.head_tree,
                "expected_group_parents": queue.expected_group_parents,
                "expected_group_tree": plan.composition.candidate_tree,
                "queue_generation_digest": queue.queue_generation_digest,
                "merge_method": "squash",
            }
        )
        seed = canonical_digest(
            {
                "operation_id": plan.operation_id,
                "group_sha": group_sha,
                "queue_generation_digest": queue.queue_generation_digest,
            }
        )
        request = GroupHoldIssueRequest.build(
            operation_id=plan.operation_id,
            repository_digest=plan.repository_digest,
            lease_epoch_digest=lease.lease_epoch_digest,
            queue_generation_digest=queue.queue_generation_digest,
            queue_configuration_digest=None,
            pull_request_number=admission.pull_request_number,
            pull_request_head=admission.head_commit,
            pull_request_tree=admission.head_tree,
            group_sha=group_sha,
            group_tree=group_tree,
            expected_group_tree=plan.composition.candidate_tree,
            group_parents=parents,
            expected_group_parents=list(queue.expected_group_parents),
            group_topology_digest=topology,
            base_commit=plan.composition.base_commit,
            base_tree=plan.composition.base_tree,
            queue_members=[admission.pull_request_number],
            hold_run_id="avo-main-hold-" + seed.removeprefix("sha256:")[:48],
            hold_nonce=main_stage_nonce(seed),
            issuer_identity=protection.isolated_release_issuer,
            issuer_app_id=protection.release_issuer_app_id,
            issuer_isolation_digest=protection.issuer_isolation_digest,
            admission_observation_digest=canonical_digest(admission),
        )
        intent = self._stage_intent_for_hold(request, prep, plan, lease)
        executor = C4StageExecutor(
            journal=self.journal,
            clock=self.clock,
            lease_fence=self.lease_fence,
            capability=self.hold_capability,
            observation_capability=self.observation_capability,
            authority_verifier=self.authority_verifier,
            provider_identity=self.provider_identity,
            provider_api_version=self.provider_api_version,
        )
        result = executor.execute_effective(intent, request)
        if result.effective_outcome in {"ambiguous", "reconciliation_required"}:
            observation = GroupHoldObservationRequest.build(
                **request.model_dump(
                    exclude={"request_digest", "external_key", "external_identity"}
                ),
                object_id=request.hold_run_id,
            )
            result = executor.recover_effective(intent, observation, original_request=request)
        if result.effective_outcome not in {"applied", "already_applied"}:
            raise MainGraduationCompletionError("merge-group hold is not terminally applied")
        self.journal.record_merge_group_webhook_receipt(receipt)
        checks = self._group_checks(group_sha, plan, attestation, queue)
        self.journal.record_merge_group_checks(checks)
        hold_values: dict[str, object] = {
            "operation_id": plan.operation_id,
            "repository_digest": plan.repository_digest,
            "target_ref": plan.target_ref,
            "preparation_authorization_digest": prep.authorization_digest,
            "admission_observation_digest": canonical_digest(admission),
            "package_digest": plan.package.package_digest,
            "composition_digest": plan.composition.composition_digest,
            "pull_request_number": admission.pull_request_number,
            "group_sha": group_sha,
            "group_tree": group_tree,
            "group_parents": parents,
            "expected_group_parents": list(queue.expected_group_parents),
            "group_topology_digest": topology,
            "base_commit": plan.composition.base_commit,
            "base_tree": plan.composition.base_tree,
            "composition_tree": plan.composition.candidate_tree,
            "queue_generation_digest": queue.queue_generation_digest,
            "queue_members": [admission.pull_request_number],
            "hold_run_id": request.hold_run_id,
            "hold_nonce": request.hold_nonce,
            "issuer_identity": protection.isolated_release_issuer,
            "release_issuer_app_id": protection.release_issuer_app_id,
            "issuer_isolation_digest": protection.issuer_isolation_digest,
            "other_required_checks": checks,
            "merge_group_receipt": receipt,
            "protection_manifest_digest": protection.manifest_digest,
            "attestation_manifest_digest": canonical_digest(attestation),
            "observed_at": (
                result.authoritative_resolution.resolved_at
                if result.authoritative_resolution is not None
                else result.receipt.observed_at
            ),
        }
        hold = MainReleaseHoldObservation.model_validate(hold_values)
        if callable(getattr(self.attester, "attest_hold", None)):
            checked = self.attester.attest_hold(
                hold, admission, group, queue, freshness_cutoff=self.clock.now()
            )
            hold = MainReleaseHoldObservation.model_validate(checked.model_dump(mode="json"))
        self.journal.record_release_hold(hold)
        return hold, intent

    def _stage_intent_for_hold(
        self,
        request: StageRequest,
        prep: MainPreparationAuthorization,
        plan: MainGraduationPlan,
        lease: MainLeaseEvidenceRecord,
    ) -> MainMutationIntent:
        prior = self._read_stage_intent(plan.operation_id, "merge_group_hold")
        if prior is not None:
            return prior
        parent = self._read_stage_intent(plan.operation_id, "queue_enqueue")
        if parent is None:
            raise MainGraduationCompletionError("durable queue enqueue intent is missing")
        receipt = self._mutation_receipt(parent.intent_digest)
        if receipt is None:
            raise MainGraduationCompletionError("queue enqueue is not terminally applied")
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
        return _digest_record(
            MainMutationIntent,
            {
                "operation_id": request.operation_id,
                "repository_digest": request.repository_digest,
                "target_ref": request.target_ref,
                "stage": request.stage,
                "parent_stage": "queue_enqueue",
                "parent_intent_digest": parent.intent_digest,
                "parent_receipt": receipt,
                "parent_resolution_digest": None,
                "lease_identity": lease.owner,
                "lease_digest": lease.lease_digest,
                "lease_epoch_digest": lease.lease_epoch_digest,
                "policy_epoch_digest": prep.policy_epoch,
                "controller_config_digest": plan.controller_config_digest,
                "preparation_authorization_digest": prep.authorization_digest,
                "release_authorization_digest": None,
                "release_claim_digest": None,
                "external_identity": ext,
                "request_digest": request.request_digest,
                "recorded_at": self.clock.now(),
            },
            "intent_digest",
        )

    def _parent_proof(
        self, intent: MainMutationIntent
    ) -> MainMutationReceipt | MainMutationFenceResolution:
        receipt = self._mutation_receipt(intent.intent_digest)
        if receipt is None:
            raise MainGraduationCompletionError("merge-group hold mutation receipt is missing")
        if receipt.outcome in {"applied", "already_applied"}:
            return receipt
        resolution_reader = getattr(self.journal, "read_mutation_fence_resolution_by_intent", None)
        if callable(resolution_reader):
            prior = resolution_reader(intent.intent_digest)
            if prior is not None and prior[0].outcome == "observed":
                return cast(MainMutationFenceResolution, prior[0])
        raise MainGraduationCompletionError("merge-group hold is not terminally applied")

    def _group_checks(
        self,
        group_sha: str,
        plan: MainGraduationPlan,
        attestation: MainAttestationManifest,
        queue: MainQueueObservation,
    ) -> MainMergeGroupChecks:
        observe = getattr(self.provider, "observe_merge_group_checks", None)
        if not callable(observe):
            raise MainGraduationCompletionError("merge-group check observation is missing")
        raw = observe(group_sha, freshness_cutoff=self.clock.now())
        if isinstance(raw, MainMergeGroupChecks):
            return MainMergeGroupChecks.model_validate(raw.model_dump(mode="json"))
        checks = tuple(cast(MainCheckObservation, item) for item in raw)
        contexts = tuple(sorted({item.context for item in checks}))
        if not contexts or "avo-main-release" in contexts:
            raise MainGraduationCompletionError("merge-group checks include release hold context")
        return MainMergeGroupChecks(
            operation_id=plan.operation_id,
            repository_digest=plan.repository_digest,
            target_ref=plan.target_ref,
            package_digest=plan.package.package_digest,
            composition_digest=plan.composition.composition_digest,
            group_sha=group_sha,
            checks=list(checks),
            allowlisted_contexts=list(contexts),
            config_digest=queue.queue_configuration_digest,
            validation_app_id=15368,
            freshness_cutoff=self.clock.now(),
            observed_at=self.clock.now(),
        )

    def _issue_authorization(
        self,
        plan: MainGraduationPlan,
        prep: MainPreparationAuthorization,
        lease: MainLeaseEvidenceRecord,
        admission: MainQueueAdmissionObservation,
        hold: MainReleaseHoldObservation,
    ) -> MainReleaseAuthorization:
        now = self.clock.now()
        expires = min(now + self.authorization_ttl, lease.expires_at)
        if expires <= now:
            raise MainGraduationCompletionError(
                "release authorization cannot be issued after lease expiry"
            )
        values = {
            "operation_id": plan.operation_id,
            "repository_digest": plan.repository_digest,
            "target_ref": plan.target_ref,
            "preparation_authorization_digest": prep.authorization_digest,
            "admission_observation_digest": canonical_digest(admission),
            "hold_observation_digest": canonical_digest(hold),
            "package_digest": plan.package.package_digest,
            "composition_digest": plan.composition.composition_digest,
            "group_sha": hold.group_sha,
            "hold_run_id": hold.hold_run_id,
            "hold_nonce": hold.hold_nonce,
            "queue_generation_digest": hold.queue_generation_digest,
            "lease_identity": lease.owner,
            "lease_digest": lease.lease_digest,
            "policy_epoch": prep.policy_epoch,
            "release_issuer_identity": hold.issuer_identity,
            "release_issuer_app_id": hold.release_issuer_app_id,
            "issuer_isolation_digest": hold.issuer_isolation_digest,
            "expires_at": expires,
            "authorized_at": now,
        }
        authorization = _digest_record(MainReleaseAuthorization, values, "authorization_digest")
        self.journal.record_release_authorization(authorization)
        return authorization

    def _read_claim_for_authorization(
        self, operation_id: str, authorization: MainReleaseAuthorization
    ) -> MainReleaseClaim | None:
        # Claim identity is derived from the immutable authorization/hold; the
        # journal has no operation-local claim index by design.
        directory = self.journal.root / "main-graduation-index" / "release-claim"
        for path in sorted(directory.glob("*.json")) if directory.is_dir() else ():
            digest = "sha256:" + path.stem
            value = self.journal.read_release_claim(digest)
            if (
                value is not None
                and value[0].operation_id == operation_id
                and value[0].authorization_digest == authorization.authorization_digest
            ):
                return value[0]
        return None

    def _issue_claim(
        self,
        lease: MainLeaseEvidenceRecord,
        hold: MainReleaseHoldObservation,
        authorization: MainReleaseAuthorization,
    ) -> MainReleaseClaim:
        now = self.clock.now()
        values: dict[str, object] = {
            "operation_id": authorization.operation_id,
            "repository_digest": authorization.repository_digest,
            "target_ref": authorization.target_ref,
            "authorization_digest": authorization.authorization_digest,
            "hold_observation_digest": canonical_digest(hold),
            "group_sha": hold.group_sha,
            "hold_run_id": hold.hold_run_id,
            "hold_nonce": hold.hold_nonce,
            "queue_generation_digest": hold.queue_generation_digest,
            "lease_identity": lease.owner,
            "lease_digest": lease.lease_digest,
            "lease_epoch_digest": lease.lease_epoch_digest,
            "release_issuer_identity": authorization.release_issuer_identity,
            "release_issuer_app_id": authorization.release_issuer_app_id,
            "issuer_isolation_digest": authorization.issuer_isolation_digest,
            "target_scope_digest": main_target_scope_digest(
                authorization.repository_digest, authorization.target_ref
            ),
            "authorization_expires_at": authorization.expires_at,
            "lease_expires_at": lease.expires_at,
            "claimed_at": now,
        }
        key_values = dict(values)
        key_values.pop("claimed_at", None)
        key_values["target_scope_digest"] = values["target_scope_digest"]
        key_values["release_issuer_app_id"] = authorization.release_issuer_app_id
        values["claim_key"] = canonical_digest(key_values)
        claim = _digest_record(MainReleaseClaim, values, "claim_digest")
        self.journal.record_release_claim(claim)
        return claim

    def _release(
        self,
        plan: MainGraduationPlan,
        prep: MainPreparationAuthorization,
        lease: MainLeaseEvidenceRecord,
        hold: MainReleaseHoldObservation,
        authorization: MainReleaseAuthorization,
        claim: MainReleaseClaim,
        hold_intent: MainMutationIntent,
    ) -> tuple[
        MainReleaseTransitionReceipt,
        MainClaimedReleaseTransitionReceipt,
        MainMutationReceipt,
        MainMutationFenceResolution | None,
        MainMutationIntent,
    ]:
        request = ReleaseIssueRequest.build(
            operation_id=plan.operation_id,
            repository_digest=plan.repository_digest,
            lease_epoch_digest=lease.lease_epoch_digest,
            queue_generation_digest=hold.queue_generation_digest,
            pull_request_number=hold.pull_request_number,
            pull_request_head=plan.composition.candidate_commit,
            pull_request_tree=plan.composition.candidate_tree,
            group_sha=hold.group_sha,
            group_tree=hold.group_tree,
            expected_group_tree=plan.composition.candidate_tree,
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
            release_authorization_digest=authorization.authorization_digest,
            release_claim_digest=claim.claim_digest,
            authorization_expires_at=authorization.expires_at,
        )
        prior = self._read_stage_intent(plan.operation_id, "release_transition")
        parent_proof = self._parent_proof(hold_intent)
        intent = prior or _stage_intent(
            request=request,
            prep=prep,
            plan=plan,
            lease=lease,
            parent=(hold_intent, parent_proof),
            recorded_at=self.clock.now(),
            authorization=authorization,
            claim=claim,
        )
        executor = C4StageExecutor(
            journal=self.journal,
            clock=self.clock,
            lease_fence=self.lease_fence,
            capability=self.release_capability,
            observation_capability=self.observation_capability,
            authority_verifier=self.authority_verifier,
            provider_identity=self.provider_identity,
            provider_api_version=self.provider_api_version,
        )
        mutation = self._mutation_receipt(intent.intent_digest)
        effective = (
            executor.effective_result(intent, mutation)
            if mutation is not None
            else executor.execute_effective(intent, request)
        )
        resolution = effective.authoritative_resolution
        if effective.effective_outcome in {"ambiguous", "reconciliation_required"}:
            observation = ReleaseObservationRequest.build(
                **request.model_dump(
                    exclude={"request_digest", "external_key", "external_identity"}
                ),
                object_id=hold.group_sha,
            )
            effective = executor.recover_effective(intent, observation, original_request=request)
            resolution = effective.authoritative_resolution
        mutation = effective.receipt
        if mutation.outcome in {"applied", "already_applied"}:
            outcome = "transitioned" if mutation.outcome == "applied" else "already_transitioned"
            observed_at, response = mutation.observed_at, mutation.response_digest
        elif resolution is not None and resolution.outcome == "observed":
            outcome = (
                "transitioned"
                if resolution.observed_outcome == "applied"
                else "already_transitioned"
            )
            observed_at, response = (
                resolution.resolved_at,
                resolution.authoritative_observation_digest,
            )
        else:
            outcome, observed_at, response = (
                "reconciliation_required",
                mutation.observed_at,
                mutation.response_digest,
            )
        transition = self._read(
            plan.operation_id, "release-transition", MainReleaseTransitionReceipt
        )
        if transition is None:
            transition = MainReleaseTransitionReceipt(
                operation_id=plan.operation_id,
                repository_digest=plan.repository_digest,
                target_ref=plan.target_ref,
                release_authorization_digest=authorization.authorization_digest,
                group_sha=hold.group_sha,
                hold_run_id=hold.hold_run_id,
                hold_nonce=hold.hold_nonce,
                issuer_identity=hold.issuer_identity,
                release_issuer_app_id=hold.release_issuer_app_id,
                issuer_isolation_digest=hold.issuer_isolation_digest,
                outcome=outcome,
                response_digest=response,
                observed_at=(
                    mutation.observed_at
                    if mutation.outcome not in {"applied", "already_applied"}
                    else observed_at
                ),
            )
            self.journal.record_release_transition(transition)
        claimed = self._read_claimed(claim)
        if claimed is None:
            claimed = _digest_record(
                MainClaimedReleaseTransitionReceipt,
                {
                    "operation_id": plan.operation_id,
                    "repository_digest": plan.repository_digest,
                    "target_ref": plan.target_ref,
                    "release_authorization_digest": authorization.authorization_digest,
                    "claim_digest": claim.claim_digest,
                    "group_sha": hold.group_sha,
                    "hold_run_id": hold.hold_run_id,
                    "hold_nonce": hold.hold_nonce,
                    "issuer_identity": hold.issuer_identity,
                    "release_issuer_app_id": hold.release_issuer_app_id,
                    "issuer_isolation_digest": hold.issuer_isolation_digest,
                    "outcome": outcome,
                    "response_digest": response,
                    "observed_at": observed_at,
                    "mutation_receipt_digest": mutation.receipt_digest,
                    "mutation_resolution_digest": None
                    if resolution is None
                    else resolution.resolution_digest,
                },
                "receipt_digest",
            )
            self.journal.record_claimed_release_transition(claimed)
        return transition, claimed, mutation, resolution, intent

    def _post_state(
        self,
        plan: MainGraduationPlan,
        authorization: MainReleaseAuthorization,
        transition: MainReleaseTransitionReceipt,
        claimed: MainClaimedReleaseTransitionReceipt,
    ) -> tuple[MainProviderReceipt, MainReconciliation, MainProviderPostStateObservation]:
        observe = getattr(self.provider, "observe_main", None)
        if not callable(observe):
            raise MainGraduationCompletionError(
                "authoritative post-release main observation is missing"
            )
        main = observe()
        commit, tree = getattr(main, "commit", None), getattr(main, "tree", None)
        parents = list(getattr(main, "parents", ()))
        if not isinstance(commit, str) or not isinstance(tree, str) or len(parents) != 1:
            raise MainGraduationCompletionError("provider post-state is incomplete")
        response = cast(str | None, getattr(main, "response_digest", None)) or canonical_digest(
            {"commit": commit, "tree": tree, "parents": parents}
        )
        observed_at = cast(datetime, getattr(main, "observed_at", self.clock.now()))
        provider_receipt = self._read(plan.operation_id, "provider-receipt", MainProviderReceipt)
        if provider_receipt is None:
            provider_receipt = MainProviderReceipt(
                operation_id=plan.operation_id,
                repository_digest=plan.repository_digest,
                target_ref=plan.target_ref,
                release_authorization_digest=authorization.authorization_digest,
                provider_identity=self.provider_identity,
                provider_api_version=self.provider_api_version,
                outcome="observed",
                result_commit=commit,
                result_tree=tree,
                result_parents=parents,
                response_digest=response,
                observed_at=observed_at,
            )
            self.journal.record_provider_receipt(provider_receipt)
        reconciliation = self._read(plan.operation_id, "reconciliation", MainReconciliation)
        if reconciliation is None:
            state = (
                "completed"
                if tree == plan.composition.candidate_tree
                and parents == [plan.composition.base_commit]
                else "reconciliation_required"
            )
            reconciliation = MainReconciliation(
                operation_id=plan.operation_id,
                repository_digest=plan.repository_digest,
                target_ref=plan.target_ref,
                state=state,
                main_commit=commit,
                main_tree=tree,
                main_parents=parents,
                expected_tree=plan.composition.candidate_tree,
                expected_base_commit=plan.composition.base_commit,
                queue_generation_digest=self._read(
                    plan.operation_id, "queue", MainQueueObservation
                ).queue_generation_digest,
                transition_receipt_digest=canonical_digest(transition),
                claimed_transition_receipt_digest=claimed.receipt_digest,
            )
            self.journal.record_reconciliation(reconciliation)
        post_state = self._read(
            plan.operation_id, "provider-post-state-observation", MainProviderPostStateObservation
        )
        if post_state is None:
            post_state = _digest_record(
                MainProviderPostStateObservation,
                {
                    "operation_id": plan.operation_id,
                    "repository_digest": plan.repository_digest,
                    "target_ref": plan.target_ref,
                    "release_authorization_digest": authorization.authorization_digest,
                    "provider_identity": self.provider_identity,
                    "provider_api_version": self.provider_api_version,
                    "result_commit": provider_receipt.result_commit,
                    "result_tree": provider_receipt.result_tree,
                    "result_parents": provider_receipt.result_parents,
                    "response_digest": provider_receipt.response_digest,
                    "observed_at": provider_receipt.observed_at,
                },
                "observation_digest",
            )
            self.journal.record("provider-post-state-observation", post_state)
        return provider_receipt, reconciliation, post_state

    def _mutation_receipt(self, digest: str) -> MainMutationReceipt | None:
        value = self.journal.read_mutation_receipt(digest)
        return None if value is None else value[0]

    def _read_stage_intent(self, operation_id: str, stage: str) -> MainMutationIntent | None:
        value = self.journal.read_mutation_intent_by_operation_stage(operation_id, cast(Any, stage))
        return None if value is None else value[0]

    def _read_claimed(self, claim: MainReleaseClaim) -> MainClaimedReleaseTransitionReceipt | None:
        value = self.journal.read_claimed_release_transition(claim.claim_digest)
        return None if value is None else value[0]

    def _record_completion(self, *records: Any) -> dict[str, Sha256Digest]:
        result: dict[str, Sha256Digest] = {}
        kinds = (
            "plan",
            "attestations",
            "queue-configuration",
            "queue",
            "protection",
            "queue-admission",
            "release-hold",
            "release-authorization",
            "release-transition",
            "lease-evidence-record",
            "release-claim",
            "claimed-release-transition",
            "mutation-intent",
            "mutation-receipt",
            "mutation-fence-resolution",
            "provider-receipt",
            "provider-post-state-observation",
            "reconciliation",
        )
        for kind, record in zip(kinds, records, strict=False):
            if record is None:
                continue
            method = getattr(self.journal, "record_" + kind.replace("-", "_"), None)
            if not callable(method):
                method = self.journal.record
                ref = method(kind, record)
            else:
                ref = method(record)
            result[kind] = ref.digest
        return result

    def _build_package(
        self,
        operation_id: str,
        plan: MainGraduationPlan,
        attestation: MainAttestationManifest,
        config: MainQueueConfigurationObservation,
        queue: MainQueueObservation,
        protection: Any,
        admission: MainQueueAdmissionObservation,
        hold: MainReleaseHoldObservation,
        authorization: MainReleaseAuthorization,
        transition: MainReleaseTransitionReceipt,
        lease: MainLeaseEvidenceRecord,
        claim: MainReleaseClaim,
        claimed: MainClaimedReleaseTransitionReceipt,
        release_intent: MainMutationIntent,
        mutation: MainMutationReceipt,
        resolution: MainMutationFenceResolution | None,
        provider_receipt: MainProviderReceipt,
        post_state: MainProviderPostStateObservation,
        reconciliation: MainReconciliation,
        recorded: Mapping[str, Sha256Digest],
    ) -> MainCompletionPackage:
        def read(kind: str, digest: str | None = None) -> tuple[Any, ArtifactRef]:
            if kind in {
                "lease-evidence-record",
                "release-claim",
                "claimed-release-transition",
                "mutation-intent",
                "mutation-receipt",
                "mutation-fence-resolution",
            }:
                key = digest or (
                    release_intent.intent_digest
                    if kind == "mutation-intent"
                    else mutation.receipt_digest
                    if kind == "mutation-receipt"
                    else claim.claim_digest
                    if kind == "release-claim"
                    else claimed.claim_digest
                    if kind == "claimed-release-transition"
                    else resolution.resolution_digest
                    if resolution
                    else _ZERO
                )
                value = self.journal.read(kind, key)
            else:
                value = self.journal.read(kind, operation_id)
            if value is None:
                raise MainGraduationCompletionError(f"durable completion child is missing: {kind}")
            return value

        children = [
            ("main-graduation-source-package", read("source-package")[0]),
            ("main-graduation-delta", read("delta")[0]),
            ("main-graduation-composition", read("composition")[0]),
            ("main-graduation-queue-configuration", config),
            ("main-graduation-queue-observation", queue),
            ("main-graduation-protection-manifest", protection),
            ("main-graduation-attestation-manifest", attestation),
            ("main-graduation-merge-group-checks", read("merge-group-checks")[0]),
            ("main-graduation-merge-group-webhook-receipt", hold.merge_group_receipt),
            ("main-graduation-release-issuer-binding", read("release-issuer-binding")[0]),
            ("main-graduation-plan", plan),
            ("main-graduation-intent", read("intent")[0]),
            ("main-graduation-preparation-authorization", read("preparation-authorization")[0]),
            ("main-graduation-queue-admission", admission),
            ("main-graduation-release-hold", hold),
            ("main-graduation-release-authorization", authorization),
            ("main-graduation-release-transition", transition),
            ("main-graduation-provider-receipt", provider_receipt),
            ("main-graduation-provider-post-state-observation", post_state),
            ("main-graduation-reconciliation", reconciliation),
            ("main-graduation-lease-evidence-record", lease),
            ("main-graduation-release-claim", claim),
            ("main-graduation-claimed-release-transition", claimed),
            ("main-graduation-mutation-intent", release_intent),
            ("main-graduation-mutation-receipt", mutation),
        ]
        if resolution is not None:
            children.append(("main-graduation-mutation-fence-resolution", resolution))
        refs: list[ArtifactRef] = []
        for role, value in children:
            refs.append(
                ArtifactRef(
                    digest=canonical_digest(value),
                    size_bytes=len(canonical_bytes(value)),
                    media_type=f"application/vnd.avo.{role}+json",
                    role=role,
                    created_at=cast(datetime, getattr(value, "observed_at", self.clock.now())),
                )
            )
        source = cast(MainSourcePackageBinding, children[0][1])
        delta = cast(MainDeltaManifest, children[1][1])
        comp = cast(MainCompositionArtifact, children[2][1])
        intent = cast(MainGraduationIntent, children[11][1])
        binding = cast(MainReleaseIssuerBinding, children[9][1])
        prep = cast(MainPreparationAuthorization, children[12][1])
        checks = cast(MainMergeGroupChecks, children[7][1])
        return MainCompletionPackage.model_validate(
            {
                "operation_id": operation_id,
                "repository_digest": plan.repository_digest,
                "plan": plan,
                "source_package": source,
                "delta": delta,
                "composition": comp,
                "queue_configuration": config,
                "queue_observation": queue,
                "protection_manifest": protection,
                "attestation_manifest": attestation,
                "merge_group_checks": checks,
                "intent": intent,
                "release_issuer_binding": binding,
                "preparation_authorization": prep,
                "admission_observation": admission,
                "hold_observation": hold,
                "release_authorization": authorization,
                "transition_receipt": transition,
                "lease_evidence_record": lease,
                "release_claim": claim,
                "claimed_transition_receipt": claimed,
                "release_transition_intent": release_intent,
                "release_transition_mutation_receipt": mutation,
                "release_transition_fence_resolution": resolution,
                "provider_receipt": provider_receipt,
                "provider_post_state_observation": post_state,
                "reconciliation": reconciliation,
                "artifacts": refs,
            }
        )


__all__ = [
    "CompletionResult",
    "MainGraduationCompletionCoordinator",
    "MainGraduationCompletionError",
]
