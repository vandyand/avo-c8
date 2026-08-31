"""Filesystem-backed C4 preparation coordinator coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from avo_correlate.adapters.artifacts.main_graduation_journal import MainGraduationJournal
from avo_correlate.adapters.git.main_composition import MainBaseSnapshot, MainCompositionAdapter
from avo_correlate.application.c4_capabilities import (
    AdmissionIssueResult,
    AdmissionObservationResult,
    CandidateObservationResult,
    CandidatePublicationRequest,
    CandidatePublicationResult,
    PullRequestCreateRequest,
    PullRequestCreateResult,
    PullRequestObservationResult,
    QueueEnqueueResult,
)
from avo_correlate.application.main_graduation_coordinator import (
    MainGraduationPreparationCoordinator,
)
from avo_correlate.contracts.main_graduation import (
    MainCheckObservation,
    MainGraduationPlan,
    MainPreparationAuthorization,
    MainProtectionManifest,
    MainQueueObservation,
    MainReleaseIssuerBinding,
)
from avo_correlate.contracts.main_graduation_phase_a import MainLeaseEvidenceRecord
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.phase_a_test_support import TEST_PHASE_A_AUTHORITY
from tests.unit.test_main_graduation_c4_validated_fixture import (
    MAIN_OPERATION,
    REPOSITORY,
    _git,
    _source,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)
CONFIG = "sha256:" + "3" * 64
POLICY = canonical_digest({"controller_config_digest": CONFIG, "main_policy": "ordinary"})
LEASE_EPOCH = "sha256:" + "4" * 64
ISOLATION = "sha256:" + "5" * 64


class Clock:
    def now(self) -> datetime:
        return NOW


class Fence:
    def assert_current(self, **_: object) -> None:
        return None


class Authority:
    provider_identity = "fixture-provider"
    provider_api_version = "v1"

    def verify_lease_evidence(self, record: Any) -> None:
        TEST_PHASE_A_AUTHORITY.verify_lease_evidence(record)

    def verify_mutation_receipt(self, receipt: Any, intent: Any) -> None:
        TEST_PHASE_A_AUTHORITY.verify_mutation_receipt(receipt, intent)

    def verify_fence_resolution(self, resolution: Any, receipt: Any) -> None:
        TEST_PHASE_A_AUTHORITY.verify_fence_resolution(resolution, receipt)

    def verify_stage_result(self, result: Any, request: Any, intent: Any) -> None:
        assert result.request_digest == request.request_digest
        assert result.external_identity == intent.external_identity.identity_digest

    def verify_stage_observation(self, result: Any, request: Any, intent: Any) -> None:
        assert result.request_digest == request.request_digest
        assert result.external_identity == request.external_identity


class Attester:
    def attest_admission(self, observation: Any, *_: Any, **__: Any) -> Any:
        return observation


class Provider:
    provider_identity = "fixture-provider"
    provider_api_version = "v1"
    repository_name = "avo/example"
    repository_url = "https://github.com/avo/example"

    def __init__(self, base: str, tree: str, candidate: str, candidate_tree: str) -> None:
        self.base, self.tree = base, tree
        self.candidate, self.candidate_tree = candidate, candidate_tree
        self.calls: list[str] = []
        self.queue_reads = 0
        self.pr_number = 41
        self.pr_url = self.repository_url + "/pull/41"

    def observe_main(self) -> Any:
        return type(
            "Main",
            (),
            {
                "repository_digest": REPOSITORY,
                "ref": "refs/heads/main",
                "commit": self.base,
                "tree": self.tree,
            },
        )()

    def observe_protection(self) -> MainProtectionManifest:
        return self.protection

    def observe_queue(self) -> MainQueueObservation:
        self.queue_reads += 1
        if self.queue_reads < 6:
            return self.queue
        parents = [self.base, self.candidate]
        topology = canonical_digest(
            {
                "expected_group_parents": parents,
                "pull_request_number": self.pr_number,
                "merge_method": "squash",
                "provider_identity": self.provider_identity,
                "provider_api_version": self.provider_api_version,
                "queue_manifest_digest": self.queue.queue_manifest_digest,
            }
        )
        return MainQueueObservation.model_validate(
            self.queue.model_dump(mode="json")
            | {
                "pull_request_number": self.pr_number,
                "expected_group_parents": parents,
                "group_topology_digest": topology,
            }
        )

    def observe_pr_head_admission_check(
        self, _: str, *, freshness_cutoff: datetime
    ) -> MainCheckObservation:
        del freshness_cutoff
        return MainCheckObservation(
            name="admission",
            context="avo-main-release",
            app_id=9001,
            sha=self.candidate,
            status="completed",
            conclusion="success",
            run_id=self.admission_run_id,
            nonce=self.admission_nonce,
            observed_at=NOW,
        )

    def publish_candidate(self, request: CandidatePublicationRequest) -> CandidatePublicationResult:
        self.calls.append("candidate")
        return CandidatePublicationResult.build(
            **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
            outcome="applied",
            response_digest=CONFIG,
            observed_at=NOW,
            dispatch_started=True,
        )

    def create_pull_request(self, request: PullRequestCreateRequest) -> PullRequestCreateResult:
        self.calls.append("pr")
        result = PullRequestCreateResult.build(
            **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
            pull_request_number=self.pr_number,
            pull_request_url=self.pr_url,
            pull_request_identity=canonical_digest(
                {
                    "operation_id": request.operation_id,
                    "repository_digest": request.repository_digest,
                    "pull_request_number": self.pr_number,
                    "pull_request_url": self.pr_url,
                }
            ),
            outcome="applied",
            response_digest=CONFIG,
            observed_at=NOW,
            dispatch_started=True,
        )
        return result.model_copy(update={"request_digest": request.request_digest})

    def issue_admission(self, request: Any) -> Any:
        self.calls.append("admission")
        self.admission_run_id, self.admission_nonce = (
            request.admission_run_id,
            request.admission_nonce,
        )
        return AdmissionIssueResult.build(
            **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
            outcome="applied",
            response_digest=CONFIG,
            observed_at=NOW,
            dispatch_started=True,
        )

    def enqueue(self, request: Any) -> QueueEnqueueResult:
        self.calls.append("enqueue")
        return QueueEnqueueResult.build(
            **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
            outcome="applied",
            response_digest=CONFIG,
            observed_at=NOW,
            dispatch_started=True,
        )

    def observe_candidate(self, request: Any) -> CandidateObservationResult:
        return CandidateObservationResult.build(
            **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
            outcome="observed",
            evidence_digest=CONFIG,
            observed_at=NOW,
        )

    def observe_pull_request_by_candidate(self, request: Any) -> PullRequestObservationResult:
        values = request.model_dump(
            exclude={
                "request_digest",
                "external_key",
                "external_identity",
                "candidate_commit",
                "candidate_tree",
                "preparation_authorization_digest",
            }
        )
        values.update(
            pull_request_number=self.pr_number,
            head_commit=self.candidate,
            head_tree=self.candidate_tree,
            base_commit=self.base,
            base_tree=self.tree,
            object_id=self.repository_name + ":pull/" + str(self.pr_number),
            outcome="observed",
            evidence_digest=CONFIG,
            observed_at=NOW,
        )
        return PullRequestObservationResult.build(**values)

    def observe_pull_request(self, request: Any) -> PullRequestObservationResult:
        return self.observe_pull_request_by_candidate(request)

    def observe_admission(self, request: Any) -> AdmissionObservationResult:
        return AdmissionObservationResult.build(
            **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
            outcome="observed",
            evidence_digest=CONFIG,
            observed_at=NOW,
        )


def _fixture(root: Path) -> tuple[MainGraduationJournal, Provider]:
    source = _source(root)
    checkout = root / "checkout"
    base = _git(checkout, "rev-parse", "HEAD~1")
    base_tree = _git(checkout, "rev-parse", "HEAD~1^{tree}")
    result = _git(checkout, "rev-parse", "HEAD")
    result_tree = _git(checkout, "rev-parse", "HEAD^{tree}")
    issuer_values = {
        "operation_id": MAIN_OPERATION,
        "repository_digest": REPOSITORY,
        "target_ref": "refs/heads/main",
        "controller_config_digest": CONFIG,
        "issuer_id": "isolated-release",
        "app_id": 9001,
        "isolation_digest": ISOLATION,
        "issuer_domain": "isolated-release-check",
        "trusted_source_issuer": source.source_issuer,
        "trusted_source_domain": source.source_domain,
    }
    issuer = MainReleaseIssuerBinding.model_validate(
        issuer_values | {"binding_digest": canonical_digest(issuer_values | {"schema_version": 1})}
    )

    class Reader:
        def fresh_main_base(self) -> MainBaseSnapshot:
            return MainBaseSnapshot(REPOSITORY, base, base_tree)

    class FixtureJournal(MainGraduationJournal):
        def _require_preparation_chain(self, _: Any) -> None:
            return None

    journal = FixtureJournal(
        root,
        release_issuer_binding=issuer,
        composition_root=checkout,
        repository_digest=REPOSITORY,
        base_reader=Reader(),
        phase_a_authority_verifier=Authority(),
    )
    journal.record_release_issuer_binding(issuer)
    journal.record_source_package(source)
    composition = MainCompositionAdapter(
        checkout,
        journal,
        repository_digest=REPOSITORY,
        base_reader=Reader(),
        controller_config_digest=CONFIG,
        policy_epoch=POLICY,
    ).compose(source)
    plan = MainGraduationPlan.model_validate(
        {
            "operation_id": MAIN_OPERATION,
            "repository_digest": REPOSITORY,
            "target_ref": "refs/heads/main",
            "package": source,
            "delta": composition.delta,
            "composition": composition.composition,
            "composition_proof": composition.proof,
            "composition_proof_artifact": composition.proof_artifact,
            "policy_epoch": POLICY,
            "controller_config_digest": CONFIG,
            "release_issuer_binding": issuer,
            "evidence_artifacts": [source.package_artifact, *source.child_artifacts],
        }
    )
    journal.record_plan(plan)
    lease_values = {
        "operation_id": MAIN_OPERATION,
        "repository_digest": REPOSITORY,
        "target_ref": "refs/heads/main",
        "owner": "lease",
        "policy_epoch": POLICY,
        "lease_epoch_digest": LEASE_EPOCH,
        "acquired_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(hours=1),
    }
    lease_probe = MainLeaseEvidenceRecord.model_construct(
        **lease_values, lease_digest=CONFIG, evidence_digest=CONFIG
    )
    lease_values["lease_digest"] = canonical_digest(
        lease_probe.model_dump(exclude={"lease_digest", "evidence_digest"}, mode="json")
    )
    lease_probe = MainLeaseEvidenceRecord.model_construct(**lease_values, evidence_digest=CONFIG)
    lease = MainLeaseEvidenceRecord.model_validate(
        lease_values
        | {
            "evidence_digest": canonical_digest(
                lease_probe.model_dump(exclude={"evidence_digest"}, mode="json")
            )
        }
    )
    journal.record_lease_evidence_record(lease)
    auth_values = {
        "operation_id": MAIN_OPERATION,
        "repository_digest": REPOSITORY,
        "target_ref": "refs/heads/main",
        "plan_digest": canonical_digest(plan),
        "intent_digest": CONFIG,
        "package_digest": source.package_digest,
        "composition_digest": composition.composition.composition_digest,
        "base_commit": base,
        "base_tree": base_tree,
        "candidate_commit": result,
        "candidate_tree": result_tree,
        "lease_identity": "lease",
        "lease_digest": lease.lease_digest,
        "policy_epoch": POLICY,
        "authorized_at": NOW,
    }
    auth_probe = MainPreparationAuthorization.model_construct(
        **auth_values, authorization_digest=CONFIG
    )
    journal.record_preparation_authorization(
        MainPreparationAuthorization.model_validate(
            auth_values
            | {
                "authorization_digest": canonical_digest(
                    auth_probe.model_dump(exclude={"authorization_digest"}, mode="json")
                )
            }
        )
    )
    protection = MainProtectionManifest(
        operation_id=MAIN_OPERATION,
        repository_digest=REPOSITORY,
        provider_identity=Provider.provider_identity,
        provider_api_version=Provider.provider_api_version,
        isolated_release_issuer=issuer.issuer_id,
        release_issuer_app_id=issuer.app_id,
        issuer_isolation_digest=issuer.isolation_digest,
        protection_epoch=CONFIG,
        manifest_digest=CONFIG,
        observed_at=NOW,
    )
    journal.record_protection_manifest(protection)
    parents = [base]
    topology = canonical_digest(
        {
            "expected_group_parents": parents,
            "pull_request_number": 0,
            "merge_method": "squash",
            "provider_identity": Provider.provider_identity,
            "provider_api_version": Provider.provider_api_version,
            "queue_manifest_digest": CONFIG,
        }
    )
    queue = MainQueueObservation(
        operation_id=MAIN_OPERATION,
        repository_digest=REPOSITORY,
        queue_generation_digest=CONFIG,
        queue_manifest_digest=CONFIG,
        expected_base_commit=base,
        expected_base_tree=base_tree,
        protection_manifest_digest=CONFIG,
        protection_epoch=CONFIG,
        provider_identity=Provider.provider_identity,
        provider_api_version=Provider.provider_api_version,
        expected_group_parents=parents,
        group_topology_digest=topology,
        merge_method="squash",
        isolated_release_issuer=issuer.issuer_id,
        release_issuer_app_id=issuer.app_id,
        issuer_isolation_digest=issuer.isolation_digest,
        observed_at=NOW,
    )
    journal.record_queue_observation(queue)
    provider = Provider(base, base_tree, result, result_tree)
    provider.candidate = plan.composition.candidate_commit
    provider.candidate_tree = plan.composition.candidate_tree
    provider.queue, provider.protection = queue, protection
    return journal, provider


def test_happy_path_is_exact_four_stage_and_replay_is_read_only(tmp_path: Path) -> None:
    journal, provider = _fixture(tmp_path)
    coordinator = MainGraduationPreparationCoordinator(
        journal=journal,
        clock=Clock(),
        lease_fence=Fence(),
        provider=provider,
        observation_capability=provider,
        authority_verifier=Authority(),
        attester=Attester(),
    )
    result = coordinator.prepare(MAIN_OPERATION)
    assert result.state == "queued", result
    assert provider.calls == ["candidate", "pr", "admission", "enqueue"]
    assert journal.read_queue_admission(MAIN_OPERATION) is not None
    before = list(provider.calls)
    replay = coordinator.resume(MAIN_OPERATION)
    assert replay.state == "queued"
    assert provider.calls == before
