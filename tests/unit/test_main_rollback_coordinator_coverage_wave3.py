"""Third adversarial coverage wave for the rollback aggregate coordinator."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportUnknownMemberType=false, reportArgumentType=false, reportCallIssue=false, reportUnknownLambdaType=false, reportMissingImports=false, reportOptionalMemberAccess=false, reportAttributeAccessIssue=false, reportUnusedImport=false, reportUntypedBaseClass=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict

import avo_correlate.application.main_rollback_coordinator as rollback_module
from avo_correlate.adapters.hosted_git.protected_main import MainPullRequestObservation
from avo_correlate.application.c4_capabilities import (
    PullRequestCreateRequest,
)
from avo_correlate.application.main_rollback_coordinator import (
    MainRollbackCoordinator,
    MainRollbackCoordinatorError,
)
from avo_correlate.contracts.main_graduation import (
    MainAttestationManifest,
    MainCheckObservation,
    MainMergeGroupChecks,
    MainMergeGroupWebhookReceipt,
    MainProtectionManifest,
    MainQueueAdmissionObservation,
    MainQueueObservation,
    MainRollbackCleanupIntent,
    MainRollbackCleanupReceipt,
    rollback_cleanup_authority_digest,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_main_graduation_github import (
    DIGEST,
    OBJECT,
    candidate_request,
    rollback_candidate_request,
)


class _Capability:
    def __init__(self, method: str) -> None:
        self.method = method

    def __getattr__(self, name: str) -> Any:
        if name != self.method:
            raise AttributeError(name)
        return lambda *_args, **_kwargs: SimpleNamespace(outcome="applied")


class _Authorizer:
    def authorize_release(self, **_kwargs: Any) -> Any:
        return SimpleNamespace()


class _Attester:
    def attest_admission(self, value: Any, *_args: Any, **_kwargs: Any) -> Any:
        return value

    def attest_hold(self, value: Any, *_args: Any, **_kwargs: Any) -> Any:
        return value


def _kwargs() -> dict[str, Any]:
    return {
        "journal": SimpleNamespace(),
        "clock": SimpleNamespace(now=lambda: datetime(2026, 9, 2, tzinfo=UTC)),
        "lease_fence": object(),
        "rollback_authority": object(),
        "provider": SimpleNamespace(provider_identity="github", provider_api_version="v1"),
        "publication_capability": _Capability("publish_candidate"),
        "pull_request_capability": _Capability("create_pull_request"),
        "admission_capability": _Capability("issue_admission"),
        "enqueue_capability": _Capability("enqueue"),
        "hold_capability": _Capability("issue_group_hold"),
        "release_capability": _Capability("issue_release"),
        "authority_verifier": SimpleNamespace(),
        "release_authorizer": _Authorizer(),
        "attester": _Attester(),
    }


def _bare(**values: Any) -> MainRollbackCoordinator:
    coordinator = object.__new__(MainRollbackCoordinator)
    coordinator.provider = SimpleNamespace(**values)
    coordinator.observation_capability = coordinator.provider
    coordinator._stage_results = {}
    coordinator.clock = SimpleNamespace(now=lambda: datetime(2026, 9, 2, tzinfo=UTC))
    coordinator.authorization_ttl = timedelta(minutes=5)
    coordinator.authority_verifier = SimpleNamespace()
    coordinator.journal = SimpleNamespace()
    return coordinator


def _authority() -> Any:
    return SimpleNamespace(
        operation_id=DIGEST,
        intent=SimpleNamespace(
            source_operation_id=DIGEST,
            repository_digest=DIGEST,
            target_ref="refs/heads/main",
            completion_package_digest=DIGEST,
            candidate_ref="refs/heads/avo/main-rollback/" + "a" * 64,
            candidate_commit=OBJECT,
        ),
        preparation_authorization=SimpleNamespace(
            authorization_digest=DIGEST, composition_digest=DIGEST
        ),
        authorization=SimpleNamespace(
            authorization_digest=DIGEST,
            policy_epoch=DIGEST,
            controller_config_digest=DIGEST,
        ),
        lease=SimpleNamespace(
            owner="owner",
            lease_digest=DIGEST,
            lease_epoch_digest=DIGEST,
            expires_at=datetime(2026, 9, 3, tzinfo=UTC),
        ),
        composition=SimpleNamespace(
            composition_id=DIGEST,
            candidate_commit=OBJECT,
            candidate_tree="d" * 40,
            current_main_commit="b" * 40,
            current_main_tree="c" * 40,
        ),
    )


def _signed(model: type[Any], values: dict[str, Any], field: str) -> Any:
    probe = model.model_construct(**values, **{field: "sha256:" + "0" * 64})
    values[field] = __import__(
        "avo_correlate.domain.canonical", fromlist=["canonical_digest"]
    ).canonical_digest(probe.model_dump(exclude={field}, mode="json"))
    return model.model_validate(values)


class _Record(BaseModel):
    model_config = ConfigDict(extra="allow")


class _WriterJournal:
    def __getattr__(self, name: str) -> Any:
        if name.startswith("record_"):
            return lambda value: value
        raise AttributeError(name)


def test_constructor_rejects_invalid_capability_wiring_and_identity_defaults() -> None:
    ready = MainRollbackCoordinator(**_kwargs())
    assert ready._stage_results == {}  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError, match="authorization_ttl"):
        MainRollbackCoordinator(**_kwargs(), authorization_ttl=timedelta(0))
    bad = _kwargs()
    bad["enqueue_capability"] = _Capability("wrong")
    with pytest.raises(ValueError, match="queue_enqueue"):
        MainRollbackCoordinator(**bad)
    bad = _kwargs()

    class _Both:
        def issue_group_hold(self, *_args: Any, **_kwargs: Any) -> Any:
            return None

        def issue_release(self, *_args: Any, **_kwargs: Any) -> Any:
            return None

    both = _Both()
    bad["hold_capability"] = both
    bad["release_capability"] = both
    with pytest.raises(ValueError, match="separate"):
        MainRollbackCoordinator(**bad)
    bad = _kwargs()

    class _HoldWithRelease(_Capability):
        def __init__(self) -> None:
            super().__init__("issue_group_hold")

        def issue_release(self, *_args: Any, **_kwargs: Any) -> Any:
            return None

    bad["hold_capability"] = _HoldWithRelease()
    with pytest.raises(ValueError, match="must not expose release"):
        MainRollbackCoordinator(**bad)
    bad = _kwargs()

    class _ReleaseWithHold(_Capability):
        def __init__(self) -> None:
            super().__init__("issue_release")

        def issue_group_hold(self, *_args: Any, **_kwargs: Any) -> Any:
            return None

    bad["release_capability"] = _ReleaseWithHold()
    with pytest.raises(ValueError, match="must not expose group hold"):
        MainRollbackCoordinator(**bad)
    bad = _kwargs()
    bad["cleanup_capability"] = object()
    with pytest.raises(ValueError, match="cleanup_rollback"):
        MainRollbackCoordinator(**bad)
    bad = _kwargs()
    bad["release_authorizer"] = object()
    with pytest.raises(ValueError, match="release authorizer"):
        MainRollbackCoordinator(**bad)
    bad = _kwargs()
    bad["attester"] = object()
    with pytest.raises(ValueError, match="attester"):
        MainRollbackCoordinator(**bad)
    bad = _kwargs()
    bad["provider"] = SimpleNamespace()
    with pytest.raises(ValueError, match="identity"):
        MainRollbackCoordinator(**bad)


def test_execute_and_scoped_execution_quarantine_missing_and_existing_completion() -> None:
    coordinator = _bare()
    coordinator.attester = _Attester()
    coordinator.journal = SimpleNamespace()
    result = coordinator.execute(DIGEST, attempt_nonce="nonce", composition=object())
    assert result.state == "quarantined"
    assert "recovery context" in (result.reason or "")

    class Recovery:
        def __call__(self, _operation: str) -> Any:
            class Context:
                def __enter__(self) -> None:
                    return None

                def __exit__(self, *_args: Any) -> None:
                    return None

            return Context()

    coordinator.journal = SimpleNamespace(
        rollback_authority_recovery=Recovery(),
        read_rollback_completion=lambda _operation: (
            SimpleNamespace(operation_id=DIGEST),
            None,
        ),
    )
    coordinator.rollback_authority = SimpleNamespace(
        prepare=lambda **_kwargs: SimpleNamespace(operation_id=DIGEST)
    )
    result = coordinator.execute(DIGEST, attempt_nonce="nonce", composition=object())
    assert result.state == "completed"

    coordinator.journal.read_rollback_completion = lambda _operation: None
    coordinator._execute_authority = lambda *_args, **_kwargs: (_ for _ in ()).throw(  # pyright: ignore[reportPrivateUsage]
        ValueError("invalid authority")
    )
    result = coordinator.execute(DIGEST, attempt_nonce="nonce", composition=object())
    assert result.state == "quarantined"


def test_provider_and_observation_request_recovery_edges() -> None:
    coordinator = _bare(repository_name="owner/repo")
    assert coordinator._provider_repository() == "owner/repo"  # pyright: ignore[reportPrivateUsage]
    coordinator.provider = SimpleNamespace(owner="owner", repo="repo")
    assert coordinator._provider_repository() == "owner/repo"  # pyright: ignore[reportPrivateUsage]
    coordinator.provider = SimpleNamespace(owner="", repo="repo")
    assert coordinator._provider_repository() is None  # pyright: ignore[reportPrivateUsage]

    candidate = candidate_request()
    candidate_observation = coordinator._observation_request(candidate)  # pyright: ignore[reportPrivateUsage]
    assert candidate_observation.object_id == candidate.candidate_ref

    pr_values = {
        "operation_id": DIGEST,
        "operation_kind": "rollback",
        "repository_digest": __import__(
            "avo_correlate.adapters.hosted_git.github", fromlist=["github_repository_digest"]
        ).github_repository_digest("owner", "repo"),
        "lease_epoch_digest": DIGEST,
        "candidate_ref": "refs/heads/avo/main-rollback/" + "a" * 64,
        "candidate_commit": OBJECT,
        "candidate_tree": "d" * 40,
        "base_commit": "b" * 40,
        "base_tree": "c" * 40,
    }
    pr = SimpleNamespace(
        **pr_values,
        stage="pull_request_open",
        model_dump=lambda mode: dict(pr_values),
    )
    coordinator._stage_results["pull_request_open"] = SimpleNamespace(pull_request_number=4)
    coordinator.provider = SimpleNamespace(owner="owner", repo="repo")
    assert coordinator._observation_request(pr).pull_request_number == 4  # pyright: ignore[reportPrivateUsage]
    coordinator._stage_results.clear()
    coordinator.provider = SimpleNamespace()
    with pytest.raises(MainRollbackCoordinatorError, match="lookup"):
        coordinator._observation_request(pr)  # pyright: ignore[reportPrivateUsage]

    coordinator.observation_capability = SimpleNamespace()
    with pytest.raises(MainRollbackCoordinatorError, match="lacks"):
        coordinator._call_observer("observe_candidate", object())  # pyright: ignore[reportPrivateUsage]
    coordinator.observation_capability = SimpleNamespace(
        observe_candidate=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline"))
    )
    with pytest.raises(MainRollbackCoordinatorError, match="failed"):
        coordinator._call_observer("observe_candidate", object())  # pyright: ignore[reportPrivateUsage]


def test_source_evidence_and_verifier_boundaries_fail_closed() -> None:
    coordinator = _bare()
    coordinator.journal = SimpleNamespace(read_completion=lambda _operation: None)
    with pytest.raises(MainRollbackCoordinatorError, match="source completion"):
        coordinator._source(DIGEST, DIGEST)  # pyright: ignore[reportPrivateUsage]

    coordinator.provider = SimpleNamespace()
    with pytest.raises(MainRollbackCoordinatorError, match="fresh provider"):
        coordinator._observe_evidence("observe_protection", MainProtectionManifest, DIGEST)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(MainRollbackCoordinatorError, match="verifier"):
        coordinator._verify_evidence(MainProtectionManifest.model_construct())  # pyright: ignore[reportPrivateUsage]

    coordinator.authority_verifier = SimpleNamespace(verify_queue_observation=lambda _value: None)
    with pytest.raises(MainRollbackCoordinatorError, match="missing"):
        coordinator._verify_named("missing", object())  # pyright: ignore[reportPrivateUsage]
    assert coordinator._verify_named("verify_queue_observation", object()) is None  # pyright: ignore[reportPrivateUsage]


def test_pull_request_admission_queue_and_group_require_typed_authority() -> None:
    coordinator = _bare()
    authority = SimpleNamespace(
        operation_id=DIGEST,
        intent=SimpleNamespace(
            repository_digest=DIGEST, target_ref="refs/heads/main", completion_package_digest=DIGEST
        ),
        preparation_authorization=SimpleNamespace(
            authorization_digest=DIGEST, composition_digest=DIGEST
        ),
        lease=SimpleNamespace(lease_epoch_digest=DIGEST),
    )
    request = PullRequestCreateRequest.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        candidate_ref="refs/heads/avo/main-rollback/" + "a" * 64,
        candidate_commit=OBJECT,
        candidate_tree="d" * 40,
        base_commit="b" * 40,
        base_tree="c" * 40,
    )
    with pytest.raises(MainRollbackCoordinatorError, match="lookup"):
        coordinator._pull_request(authority, request)  # pyright: ignore[reportPrivateUsage]
    coordinator.provider = SimpleNamespace(
        lookup_pull_request=lambda *_args, **_kwargs: SimpleNamespace(number=1)
    )
    with pytest.raises(MainRollbackCoordinatorError, match="observer"):
        coordinator._pull_request(authority, request)  # pyright: ignore[reportPrivateUsage]

    config = SimpleNamespace(queue_configuration_digest=DIGEST)
    protection = SimpleNamespace(
        manifest_digest=DIGEST,
        isolated_release_issuer="issuer",
        release_issuer_app_id=99,
        issuer_isolation_digest=DIGEST,
    )
    pr = SimpleNamespace(
        number=1,
        url="https://github.com/owner/repo/pull/1",
        base_commit="b" * 40,
        base_tree="c" * 40,
        head_commit=OBJECT,
        head_tree="d" * 40,
    )
    admission_request = SimpleNamespace(
        admission_run_id="run",
        admission_nonce="nonce",
        issuer_identity="issuer",
        issuer_app_id=99,
        issuer_isolation_digest=DIGEST,
    )
    with pytest.raises(MainRollbackCoordinatorError, match="admission-check"):
        coordinator._admission(authority, config, protection, pr, admission_request)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(MainRollbackCoordinatorError, match="queue"):
        coordinator._queue(authority, config, object(), SimpleNamespace())  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(MainRollbackCoordinatorError, match="webhook"):
        coordinator._group(
            authority,
            object(),
            object(),
            group_sha=None,
            webhook_body=None,
            webhook_headers=None,
            pull_request_number=1,
        )  # pyright: ignore[reportPrivateUsage]


def test_hold_and_cleanup_prerequisites_reject_missing_typed_inputs() -> None:
    coordinator = _bare()
    authority = SimpleNamespace(
        operation_id=DIGEST,
        intent=SimpleNamespace(
            repository_digest=DIGEST, target_ref="refs/heads/main", completion_package_digest=DIGEST
        ),
        preparation_authorization=SimpleNamespace(
            authorization_digest=DIGEST, composition_digest=DIGEST
        ),
        lease=SimpleNamespace(lease_epoch_digest=DIGEST),
        composition=SimpleNamespace(
            current_main_commit="b" * 40, current_main_tree="c" * 40, candidate_tree="d" * 40
        ),
    )
    with pytest.raises(MainRollbackCoordinatorError, match="receipt"):
        coordinator._hold(
            authority,
            authority.preparation_authorization,
            SimpleNamespace(
                queue_configuration_digest=DIGEST,
                expected_group_parents=["b" * 40, OBJECT],
                queue_generation_digest=DIGEST,
                group_topology_digest=DIGEST,
            ),
            SimpleNamespace(
                pull_request_number=1,
                issuer_identity="i",
                release_issuer_app_id=99,
                issuer_isolation_digest=DIGEST,
            ),
            SimpleNamespace(
                group_sha="e" * 40, group_tree="d" * 40, group_parents=["b" * 40, OBJECT]
            ),
            {},
            SimpleNamespace(),
        )  # pyright: ignore[reportPrivateUsage]

    coordinator.cleanup_capability = None
    with pytest.raises(MainRollbackCoordinatorError, match="cleanup capability"):
        coordinator._cleanup_intent(
            authority,
            SimpleNamespace(completion_package_digest=DIGEST, receipt_digest=DIGEST),
            SimpleNamespace(number=1, url="url"),
        )  # pyright: ignore[reportPrivateUsage]


def test_reconcile_and_terminal_helpers_are_explicit_about_ambiguous_outcomes() -> None:
    coordinator = _bare()
    result = coordinator._reconcile(
        DIGEST, "release_transition", SimpleNamespace(outcome="ambiguous")
    )  # pyright: ignore[reportPrivateUsage]
    assert result.state == "reconciliation_required"
    assert result.stage == "release_transition"
    with pytest.raises(MainRollbackCoordinatorError, match="missing"):
        coordinator._verify_named("verify_missing", object())  # pyright: ignore[reportPrivateUsage]


def test_typed_admission_and_queue_observations_bind_provider_proof() -> None:
    authority = _authority()
    pr = MainPullRequestObservation(
        repository_digest=DIGEST,
        number=1,
        url="https://github.example/owner/repo/pull/1",
        base_ref="refs/heads/main",
        base_commit="b" * 40,
        base_tree="c" * 40,
        head_ref=authority.intent.candidate_ref,
        head_commit=OBJECT,
        head_tree="d" * 40,
        state="open",
        draft=False,
        observed_at=datetime(2026, 9, 2, tzinfo=UTC),
    )
    request = SimpleNamespace(
        admission_run_id="admission-run",
        admission_nonce="admission-nonce",
        issuer_identity="release",
        issuer_app_id=42,
        issuer_isolation_digest=DIGEST,
    )
    config = SimpleNamespace(queue_configuration_digest=DIGEST)
    protection = SimpleNamespace(manifest_digest=DIGEST)
    check = MainCheckObservation(
        name="avo-main",
        context="other-check",
        app_id=42,
        sha=OBJECT,
        status="completed",
        conclusion="success",
        run_id=request.admission_run_id,
        nonce=request.admission_nonce,
        observed_at=datetime(2026, 9, 2, tzinfo=UTC),
    )
    admission_coordinator = _bare(
        observe_pr_head_admission_check=lambda *_args, **_kwargs: check,
    )
    admission_coordinator.attester = _Attester()
    admission = admission_coordinator._admission(  # pyright: ignore[reportPrivateUsage]
        authority, config, protection, pr, request
    )
    assert admission.pull_request_number == 1

    queue = MainQueueObservation.model_construct(
        repository_digest=DIGEST,
        operation_id=DIGEST,
        queue_generation_digest=DIGEST,
        queue_manifest_digest=DIGEST,
        queue_configuration_digest=DIGEST,
        admission_observation_digest=canonical_digest(admission),
        expected_base_commit="b" * 40,
        expected_base_tree="c" * 40,
        protection_manifest_digest=DIGEST,
        protection_epoch=DIGEST,
        provider_identity="github",
        provider_api_version="v1",
        expected_group_parents=["b" * 40, OBJECT],
        group_topology_digest=canonical_digest(
            {
                "expected_group_parents": ["b" * 40, OBJECT],
                "pull_request_number": 1,
                "merge_method": "squash",
                "provider_identity": "github",
                "provider_api_version": "v1",
                "queue_manifest_digest": DIGEST,
            }
        ),
        merge_method="squash",
        isolated_release_issuer="release",
        release_issuer_app_id=42,
        issuer_isolation_digest=DIGEST,
        observed_at=datetime(2026, 9, 2, tzinfo=UTC),
        pull_request_number=1,
    )
    queue_coordinator = _bare(observe_queue=lambda **_kwargs: queue)
    queue_coordinator.authority_verifier = SimpleNamespace(
        verify_queue_observation=lambda value: value,
    )
    observed = queue_coordinator._queue(  # pyright: ignore[reportPrivateUsage]
        authority, config, admission, object()
    )
    assert observed.operation_id == DIGEST


def test_pull_request_observer_accepts_only_exact_open_provider_identity() -> None:
    authority = _authority()
    request = PullRequestCreateRequest.build(
        operation_id=DIGEST,
        operation_kind="rollback",
        repository_digest=DIGEST,
        lease_epoch_digest=DIGEST,
        candidate_ref=authority.intent.candidate_ref,
        candidate_commit=OBJECT,
        candidate_tree="d" * 40,
        base_commit="b" * 40,
        base_tree="c" * 40,
        preparation_authorization_digest=DIGEST,
    )
    observed = MainPullRequestObservation(
        repository_digest=DIGEST,
        number=2,
        url="https://github.example/owner/repo/pull/2",
        base_ref="refs/heads/main",
        base_commit="b" * 40,
        base_tree="c" * 40,
        head_ref=authority.intent.candidate_ref,
        head_commit=OBJECT,
        head_tree="d" * 40,
        state="open",
        draft=False,
        observed_at=datetime(2026, 9, 2, tzinfo=UTC),
    )
    coordinator = _bare(
        lookup_pull_request=lambda *_args, **_kwargs: SimpleNamespace(number=2),
        observe_pull_request=lambda *_args, **_kwargs: observed,
    )
    value = coordinator._pull_request(authority, request)  # pyright: ignore[reportPrivateUsage]
    assert value == observed

    coordinator.provider.observe_pull_request = lambda *_args, **_kwargs: SimpleNamespace(number=2)
    with pytest.raises(MainRollbackCoordinatorError, match="untrusted"):
        coordinator._pull_request(authority, request)  # pyright: ignore[reportPrivateUsage]


def test_cleanup_intent_binds_distinct_mutator_and_observer_principals() -> None:
    authority = _authority()
    authority.intent.source_operation_id = "sha256:" + "b" * 64
    coordinator = _bare()
    coordinator.provider_identity = "github"
    coordinator.provider_api_version = "v1"
    coordinator.cleanup_capability = SimpleNamespace(
        cleanup_principal=SimpleNamespace(
            identity="cleanup", app_id=7, isolation_digest="sha256:" + "c" * 64
        ),
        observer_principal=SimpleNamespace(
            identity="observer", app_id=8, isolation_digest="sha256:" + "d" * 64
        ),
    )
    coordinator.journal = SimpleNamespace(read_rollback_cleanup_intent=lambda _op: None)
    result = SimpleNamespace(completion_package_digest=DIGEST, receipt_digest=DIGEST)
    pr = SimpleNamespace(number=1, url="https://github.example/owner/repo/pull/1")
    intent = coordinator._cleanup_intent(authority, result, pr)  # pyright: ignore[reportPrivateUsage]
    assert intent.cleanup_principal_identity == "cleanup"
    coordinator.journal.read_rollback_cleanup_intent = lambda _op: (intent, None)
    assert coordinator._cleanup_intent(authority, result, pr) == intent  # pyright: ignore[reportPrivateUsage]
    coordinator.cleanup_capability.cleanup_principal = SimpleNamespace(identity="incomplete")
    with pytest.raises(MainRollbackCoordinatorError, match="principal bindings are incomplete"):
        coordinator._cleanup_intent(authority, result, pr)  # pyright: ignore[reportPrivateUsage]


def test_hold_request_and_group_hold_validate_authenticated_webhook_and_checks() -> None:
    authority = _authority()
    coordinator = _bare()
    coordinator.attester = _Attester()
    queue = SimpleNamespace(
        queue_generation_digest=DIGEST,
        expected_group_parents=["b" * 40, OBJECT],
        group_topology_digest=DIGEST,
        queue_configuration_digest=DIGEST,
    )
    admission = MainQueueAdmissionObservation.model_construct(
        operation_id=DIGEST,
        preparation_authorization_digest=DIGEST,
        package_digest=DIGEST,
        composition_digest=DIGEST,
        pull_request_number=1,
        pull_request_url="https://github.example/owner/repo/pull/1",
        base_commit="b" * 40,
        base_tree="c" * 40,
        head_commit=OBJECT,
        head_tree="d" * 40,
        admission_sha=OBJECT,
        admission_run_id="admission-run",
        admission_nonce="admission-nonce",
        queue_configuration_digest=DIGEST,
        protection_manifest_digest=DIGEST,
        issuer_identity="release",
        release_issuer_app_id=42,
        issuer_isolation_digest=DIGEST,
        observed_at=datetime(2026, 9, 2, tzinfo=UTC),
    )
    group_sha = "e" * 40
    group = SimpleNamespace(
        group_sha=group_sha,
        group_tree="d" * 40,
        group_parents=["b" * 40, OBJECT],
        webhook_receipt=_signed(
            MainMergeGroupWebhookReceipt,
            {
                "operation_id": DIGEST,
                "repository_digest": DIGEST,
                "target_ref": "refs/heads/main",
                "group_sha": group_sha,
                "group_tree": "d" * 40,
                "group_parents": ["b" * 40, OBJECT],
                "pull_request_number": 1,
                "queue_generation_digest": DIGEST,
                "delivery_id": "delivery-1",
                "body_digest": DIGEST,
                "observed_at": datetime(2026, 9, 2, tzinfo=UTC),
            },
            "receipt_digest",
        ),
    )
    hold_request = coordinator._hold_request(  # pyright: ignore[reportPrivateUsage]
        authority,
        authority.preparation_authorization,
        authority.lease,
        queue,
        admission,
        group,
    )
    assert hold_request.group_sha == group_sha
    check = MainCheckObservation(
        name="required",
        context="required-check",
        app_id=15368,
        sha=group_sha,
        status="completed",
        conclusion="success",
        run_id="run",
        nonce="nonce",
        observed_at=datetime(2026, 9, 2, tzinfo=UTC),
    )
    checks = MainMergeGroupChecks(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        package_digest=DIGEST,
        composition_digest=DIGEST,
        group_sha=group_sha,
        checks=[check],
        allowlisted_contexts=["required-check"],
        config_digest=DIGEST,
        freshness_cutoff=datetime(2026, 9, 1, tzinfo=UTC),
        observed_at=datetime(2026, 9, 2, tzinfo=UTC),
    )
    coordinator.provider = SimpleNamespace(
        observe_merge_group_checks=lambda *_args, **_kwargs: checks,
    )
    coordinator.journal = SimpleNamespace(
        record_merge_group_webhook_receipt=lambda value: value,
        record_merge_group_checks=lambda value: value,
        record_release_hold=lambda value: value,
    )
    evidence = {
        "protection": SimpleNamespace(manifest_digest=DIGEST),
        "attestation": MainAttestationManifest.model_construct(
            operation_id=DIGEST, package_digest=DIGEST, reviewer_identity="reviewer"
        ),
    }
    hold = coordinator._hold(  # pyright: ignore[reportPrivateUsage]
        authority,
        authority.preparation_authorization,
        queue,
        admission,
        group,
        evidence,
        hold_request,
    )
    assert hold.group_sha == group_sha


def test_cleanup_recovery_revalidates_durable_ancestry_and_adopts_owner() -> None:
    lease = _Record(lease_digest=DIGEST)
    composition = _Record(composition_id=DIGEST)
    authorization = _Record(authorization_digest=DIGEST)
    intent = _Record(source_operation_id=DIGEST, intent_digest=DIGEST)
    attempt = _Record(attempt_digest=DIGEST)
    preparation = _Record(authorization_digest=DIGEST)
    authority = _Record(
        operation_id=DIGEST,
        intent=intent,
        lease=lease,
        composition=composition,
        authorization=authorization,
        attempt_authority=attempt,
        preparation_authorization=preparation,
    )
    result = _Record(operation_id=DIGEST, receipt_digest=DIGEST)
    cleanup_intent = _Record(
        operation_id=DIGEST,
        result_receipt_digest=DIGEST,
        intent_digest=DIGEST,
    )
    values = {
        "read_rollback_cleanup_intent": lambda _op: (cleanup_intent, None),
        "read_rollback_result": lambda _op: (result, None),
        "read_lease_evidence_record": lambda _op: (lease, None),
        "read_rollback_composition": lambda _op: (composition, None),
        "read_rollback_authorization": lambda _op: (authorization, None),
        "read_rollback_intent": lambda _op: (intent, None),
        "read_rollback_attempt_authority": lambda _op: (attempt, None),
        "read_rollback_preparation_authorization": lambda _op: (preparation, None),
        "read_rollback_cleanup_dispatch_owner": lambda _digest: _Record(owner_digest=DIGEST),
    }
    coordinator = _bare()
    coordinator.journal = SimpleNamespace(**values)
    coordinator._cleanup = lambda *_args, **_kwargs: ("receipt", "observation", "terminal")
    recovered = coordinator._recover_cleanup_scoped(  # pyright: ignore[reportPrivateUsage]
        authority=authority,
        result=result,
        cleanup_intent=cleanup_intent,
    )
    assert recovered == ("receipt", "observation", "terminal")
    for reader_name, message in (
        ("read_rollback_cleanup_intent", "durable cleanup intent"),
        ("read_rollback_result", "durable rollback result"),
        ("read_lease_evidence_record", "durable lease ancestry"),
        ("read_rollback_composition", "durable composition ancestry"),
        ("read_rollback_authorization", "durable rollback authorization ancestry"),
        ("read_rollback_intent", "durable rollback intent ancestry"),
        ("read_rollback_attempt_authority", "durable attempt authority ancestry"),
        ("read_rollback_preparation_authorization", "durable preparation authorization ancestry"),
    ):
        broken = dict(values)
        broken[reader_name] = lambda *_args: None
        coordinator.journal = SimpleNamespace(**broken)
        with pytest.raises(MainRollbackCoordinatorError, match=message):
            coordinator._recover_cleanup_scoped(  # pyright: ignore[reportPrivateUsage]
                authority=authority,
                result=result,
                cleanup_intent=cleanup_intent,
            )
    broken = dict(values)
    del broken["read_rollback_cleanup_dispatch_owner"]
    coordinator.journal = SimpleNamespace(**broken)
    with pytest.raises(MainRollbackCoordinatorError, match="owner reader"):
        coordinator._recover_cleanup_scoped(  # pyright: ignore[reportPrivateUsage]
            authority=authority,
            result=result,
            cleanup_intent=cleanup_intent,
        )
    broken = dict(values)
    broken["read_rollback_cleanup_dispatch_owner"] = lambda _digest: None
    coordinator.journal = SimpleNamespace(**broken)
    with pytest.raises(MainRollbackCoordinatorError, match="owner is missing"):
        coordinator._recover_cleanup_scoped(  # pyright: ignore[reportPrivateUsage]
            authority=authority,
            result=result,
            cleanup_intent=cleanup_intent,
        )


def test_cleanup_claimed_dispatch_records_receipt_and_terminal_evidence() -> None:
    coordinator = _bare()
    candidate_ref = "refs/heads/avo/main-rollback/" + "a" * 64
    intent = MainRollbackCleanupIntent.model_construct(
        operation_id=DIGEST,
        source_operation_id="sha256:" + "b" * 64,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        completion_package_digest=DIGEST,
        result_receipt_digest=DIGEST,
        authorization_digest=DIGEST,
        candidate_ref=candidate_ref,
        candidate_commit=OBJECT,
        pull_request_number=1,
        pull_request_url="https://github.example/owner/repo/pull/1",
        provider_identity="github",
        provider_api_version="v1",
        cleanup_principal_identity="cleanup",
        cleanup_principal_app_id=7,
        cleanup_principal_isolation_digest="sha256:" + "c" * 64,
        observer_identity="observer",
        observer_app_id=8,
        observer_isolation_digest="sha256:" + "d" * 64,
        observer_provider_identity="github",
        observer_provider_api_version="v1",
        cleanup_authority_digest=rollback_cleanup_authority_digest(DIGEST, "refs/heads/main"),
        recorded_at=datetime(2026, 9, 2, tzinfo=UTC),
        intent_digest=DIGEST,
    )
    result = _Record(
        completion_package_digest=DIGEST,
        receipt_digest=DIGEST,
    )
    receipt_values = {
        "operation_id": DIGEST,
        "repository_digest": DIGEST,
        "target_ref": "refs/heads/main",
        "intent_digest": DIGEST,
        "authorization_digest": DIGEST,
        "candidate_ref": candidate_ref,
        "candidate_commit": OBJECT,
        "pull_request_number": 1,
        "pull_request_url": "https://github.example/owner/repo/pull/1",
        "outcome": "applied",
        "dispatch_started": True,
        "response_digest": DIGEST,
        "observed_at": datetime(2026, 9, 2, tzinfo=UTC),
        "provider_identity": "github",
        "provider_api_version": "v1",
        "cleanup_principal_identity": "cleanup",
        "cleanup_principal_app_id": 7,
        "cleanup_principal_isolation_digest": "sha256:" + "c" * 64,
        "observer_identity": "observer",
        "observer_app_id": 8,
        "observer_isolation_digest": "sha256:" + "d" * 64,
        "observer_provider_identity": "github",
        "observer_provider_api_version": "v1",
        "cleanup_authority_digest": intent.cleanup_authority_digest,
    }
    receipt = _signed(MainRollbackCleanupReceipt, receipt_values, "receipt_digest")
    coordinator.cleanup_capability = SimpleNamespace(
        cleanup_rollback=lambda _intent: receipt,
    )
    coordinator.authority_verifier = SimpleNamespace(
        verify_rollback_cleanup_receipt=lambda *_args: None,
    )
    coordinator.journal = SimpleNamespace(
        read_rollback_cleanup_receipt=lambda _op: None,
        read_rollback_cleanup_dispatch_owner=lambda _digest: None,
        claim_rollback_cleanup_dispatch=lambda **_kwargs: True,
        record_rollback_cleanup_receipt=lambda value: value,
        read_rollback_cleanup_observation=lambda _op: None,
        read_rollback_cleanup_terminal=lambda _op: None,
        record_rollback_cleanup_terminal=lambda value: value,
    )
    actual_receipt, observation, terminal = coordinator._cleanup(  # pyright: ignore[reportPrivateUsage]
        SimpleNamespace(operation_id=DIGEST), result, intent
    )
    assert actual_receipt == receipt
    assert observation is None
    assert terminal is not None


def test_execute_authority_composes_every_typed_stage_and_closes_terminal_package() -> None:
    coordinator = _bare(repository_name="owner/repo")
    coordinator.journal = _WriterJournal()
    authority = _authority()
    source = _Record(
        operation_id=DIGEST,
        source_package=_Record(package_digest=DIGEST),
        attestation_manifest=_Record(package_digest=DIGEST),
    )
    config = _Record(queue_configuration_digest=DIGEST)
    protection = _Record(
        manifest_digest=DIGEST,
        isolated_release_issuer="release",
        release_issuer_app_id=42,
        issuer_isolation_digest=DIGEST,
    )
    evidence = {"queue_configuration": config, "protection": protection, "attestation": _Record()}
    pull_request = MainPullRequestObservation(
        repository_digest=DIGEST,
        number=1,
        url="https://github.example/owner/repo/pull/1",
        base_ref="refs/heads/main",
        base_commit="b" * 40,
        base_tree="c" * 40,
        head_ref=authority.intent.candidate_ref,
        head_commit=OBJECT,
        head_tree="d" * 40,
        state="open",
        draft=False,
        observed_at=datetime(2026, 9, 2, tzinfo=UTC),
    )
    admission = _Record(
        pull_request_number=1,
        pull_request_url=pull_request.url,
        head_commit=OBJECT,
        head_tree="d" * 40,
        issuer_identity="release",
        release_issuer_app_id=42,
        issuer_isolation_digest=DIGEST,
    )
    queue = _Record(queue_generation_digest=DIGEST)
    group = _Record(group_sha="e" * 40)
    hold = _Record(other_required_checks=_Record(), merge_group_receipt=_Record())
    release_auth = _Record(authorization_digest=DIGEST)
    claim = _Record(claim_digest=DIGEST)
    mutation = _Record(outcome="applied")
    result = _Record(completion_package_digest=DIGEST, receipt_digest=DIGEST)
    terminal = _Record()

    coordinator._source = lambda *_args: source
    coordinator._evidence = lambda *_args: dict(evidence)
    coordinator._pull_request = lambda *_args: pull_request
    coordinator._admission = lambda *_args: admission
    coordinator._queue = lambda *_args: queue
    coordinator._group = lambda *_args, **_kwargs: group
    coordinator._hold_request = lambda *_args: SimpleNamespace(stage="merge_group_hold")
    coordinator._hold = lambda *_args: hold
    coordinator._release_authorization = lambda *_args: release_auth
    coordinator._release_claim = lambda *_args: claim
    coordinator._release_request = lambda *_args: SimpleNamespace(stage="release_transition")
    coordinator._transition_records = lambda *_args: (_Record(), _Record(outcome="transitioned"))
    coordinator._rollback_result = lambda *_args: result
    coordinator._post_state = lambda *_args: _Record()
    coordinator._cleanup_intent = lambda *_args: _Record()
    coordinator._cleanup = lambda *_args: (_Record(), _Record(), terminal)
    coordinator._record_terminal = lambda *_args: {}
    coordinator._package = lambda *_args: _Record(operation_id=DIGEST)

    def stage(request: Any, *_args: Any, **_kwargs: Any) -> Any:
        return (
            _Record(stage=request.stage),
            SimpleNamespace(
                effective_outcome="applied",
                receipt=mutation,
                authoritative_resolution=None,
            ),
        )

    coordinator._stage = stage
    completed = coordinator._execute_authority(  # pyright: ignore[reportPrivateUsage]
        authority,
        group_sha=group.group_sha,
        webhook_body=b"webhook",
        webhook_headers={"x-signature": "signed"},
        pull_request_number=1,
    )
    assert completed.state == "completed"
    assert completed.package is not None

    for stop_stage in (
        "candidate_publication",
        "pull_request_open",
        "admission_check",
        "queue_enqueue",
        "merge_group_hold",
    ):

        def staged_until_stop(
            request: Any, *_args: Any, stop: str = stop_stage, **_kwargs: Any
        ) -> Any:
            outcome = "reconciliation_required" if request.stage == stop else "applied"
            return (
                _Record(stage=request.stage),
                SimpleNamespace(
                    effective_outcome=outcome,
                    receipt=mutation,
                    authoritative_resolution=None,
                ),
            )

        coordinator._stage = staged_until_stop
        stopped = coordinator._execute_authority(  # pyright: ignore[reportPrivateUsage]
            authority,
            group_sha=group.group_sha,
            webhook_body=b"webhook",
            webhook_headers={"x-signature": "signed"},
            pull_request_number=1,
        )
        assert stopped.state == "reconciliation_required"

    coordinator._stage = stage
    coordinator._transition_records = lambda *_args: (_Record(), None)
    unresolved = coordinator._execute_authority(  # pyright: ignore[reportPrivateUsage]
        authority,
        group_sha=group.group_sha,
        webhook_body=b"webhook",
        webhook_headers={"x-signature": "signed"},
        pull_request_number=1,
    )
    assert unresolved.state == "reconciliation_required"


def test_stage_replays_owner_and_ambiguous_mutation_without_redispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = rollback_candidate_request()
    authority = _authority()
    authority.intent.repository_digest = request.repository_digest
    coordinator = _bare(owner="owner", repo="repo")
    coordinator.capabilities = {
        "candidate_publication": _Capability("publish_candidate"),
        "pull_request_open": _Capability("create_pull_request"),
        "admission_check": _Capability("issue_admission"),
        "queue_enqueue": _Capability("enqueue"),
        "merge_group_hold": _Capability("issue_group_hold"),
        "release_transition": _Capability("issue_release"),
    }
    coordinator.provider_identity = "github"
    coordinator.provider_api_version = "v1"
    coordinator.lease_fence = object()
    coordinator.journal = SimpleNamespace(
        read_mutation_intent_by_operation_stage=lambda *_args: None,
        read_mutation_dispatch_owner=lambda _digest: None,
        read_mutation_receipt_for_intent=lambda _digest: None,
    )

    class _Executor:
        outcome = "applied"

        def __init__(self, **_kwargs: Any) -> None:
            return None

        def execute_effective(self, _intent: Any, _request: Any) -> Any:
            return SimpleNamespace(
                effective_outcome=self.outcome,
                receipt=SimpleNamespace(outcome="applied"),
                authoritative_resolution=None,
            )

        def recover_effective(self, _intent: Any, _request: Any, **_kwargs: Any) -> Any:
            return SimpleNamespace(
                effective_outcome="applied",
                receipt=SimpleNamespace(outcome="already_applied"),
                authoritative_resolution=None,
            )

    monkeypatch.setattr(rollback_module, "C4StageExecutor", _Executor)
    _, effective = coordinator._stage(  # pyright: ignore[reportPrivateUsage]
        request, authority, None
    )
    assert effective.effective_outcome == "applied"

    _Executor.outcome = "ambiguous"
    _, effective = coordinator._stage(  # pyright: ignore[reportPrivateUsage]
        request, authority, None
    )
    assert effective.receipt.outcome == "already_applied"

    coordinator.journal.read_mutation_dispatch_owner = lambda _digest: _Record(owner_digest=DIGEST)
    _, effective = coordinator._stage(  # pyright: ignore[reportPrivateUsage]
        request, authority, None
    )
    assert effective.receipt.outcome == "already_applied"


def test_terminal_recording_writes_complete_rollback_closure_roles() -> None:
    coordinator = _bare()
    coordinator.journal = _WriterJournal()
    coordinator._rollback_ref = lambda *_args: _Record(digest=DIGEST)
    authority = _authority()
    authority.attempt_authority = _Record()
    source = _Record()
    evidence = {
        "queue_configuration": _Record(),
        "queue": _Record(),
        "protection": _Record(),
        "attestation": _Record(),
        "merge_group_checks": _Record(),
    }
    admission = _Record()
    hold = _Record(merge_group_receipt=_Record())
    values = [_Record() for _ in range(9)]
    refs = coordinator._record_terminal(  # pyright: ignore[reportPrivateUsage]
        authority,
        source,
        evidence,
        admission,
        hold,
        values[0],
        values[1],
        None,
        None,
        values[2],
        values[3],
        values[4],
        values[5],
        values[6],
        values[7],
        None,
        values[8],
    )
    assert len(refs) == 24
    refs_with_transition = coordinator._record_terminal(  # pyright: ignore[reportPrivateUsage]
        authority,
        source,
        evidence,
        admission,
        hold,
        values[0],
        values[1],
        values[2],
        values[3],
        values[4],
        values[5],
        values[6],
        values[7],
        values[8],
        values[0],
        values[1],
        values[2],
    )
    assert len(refs_with_transition) == 27


def test_rollback_ref_uses_content_addressed_store_with_dedicated_role() -> None:
    coordinator = _bare()
    coordinator.journal = SimpleNamespace(
        _max=4096,
        _store=SimpleNamespace(put_bytes=lambda *_args, **kwargs: _Record(digest=DIGEST, **kwargs)),
    )
    reference = coordinator._rollback_ref("result", _Record(value="terminal"))  # pyright: ignore[reportPrivateUsage]
    assert reference.digest == DIGEST
    assert reference.role == "main-rollback-result"


def test_package_builder_binds_all_terminal_evidence_and_artifact_refs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Package:
        @classmethod
        def model_construct(cls, **values: Any) -> Any:
            return _Record(**values)

        @classmethod
        def model_validate(cls, values: Any) -> Any:
            return _Record(**values)

    monkeypatch.setattr(rollback_module, "MainRollbackCompletionPackage", _Package)
    coordinator = _bare()
    authority = _authority()
    authority.attempt_authority = _Record()
    authority.intent = _Record(**vars(authority.intent))
    authority.authorization = _Record(**vars(authority.authorization))
    authority.lease = _Record(**vars(authority.lease))
    authority.composition = _Record(**vars(authority.composition))
    authority.preparation_authorization = _Record(**vars(authority.preparation_authorization))
    source = _Record()
    evidence = {
        "queue_configuration": _Record(),
        "queue": _Record(),
        "protection": _Record(),
        "attestation": _Record(),
    }
    hold = _Record(other_required_checks=_Record(), merge_group_receipt=_Record())
    package = coordinator._package(  # pyright: ignore[reportPrivateUsage]
        authority,
        source,
        evidence,
        _Record(),
        hold,
        _Record(),
        _Record(),
        _Record(),
        _Record(),
        _Record(),
        _Record(),
        _Record(),
        _Record(),
        _Record(),
        _Record(),
        _Record(),
        _Record(),
        {"result": _Record(digest=DIGEST)},
    )
    assert package.operation_id == DIGEST
    assert package.completion_digest.startswith("sha256:")
