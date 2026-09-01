"""Filesystem-backed restart recovery for the C5 rollback aggregate."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.adapters.git.main_rollback_composition import MainRollbackCompositionResult
from avo_correlate.application.c4_capabilities import (
    CandidateObservationRequest,
    CandidateObservationResult,
    CandidatePublicationRequest,
)
from avo_correlate.application.main_rollback_authority import (
    MainRollbackAuthority,
    MainRollbackCurrentAuthority,
)
from avo_correlate.application.main_rollback_coordinator import MainRollbackCoordinator
from avo_correlate.contracts.main_graduation import (
    MainExternalIdentity,
    MainRollbackCleanupIntent,
    MainRollbackCleanupObservation,
    MainRollbackCleanupReceipt,
    MainRollbackResultReceipt,
)
from avo_correlate.contracts.main_graduation_phase_a import MainMutationIntent
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_main_rollback_authority import _durable_lease
from tests.unit.test_main_rollback_composition import _adapter, _Reader, _ready

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false

NOW = datetime(2026, 1, 1, 0, 20, tzinfo=UTC)


class _Clock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class _Fence:
    def assert_current(self, **_: object) -> None:
        return None


class _Principal:
    identity = "cleanup"
    app_id = 5
    isolation_digest = "sha256:" + "1" * 64


class _RollbackVerifier:
    def verify_rollback_result(self, *_: object) -> None:
        return None

    def verify_rollback_cleanup_intent(self, *_: object) -> None:
        return None

    def verify_rollback_cleanup_receipt(self, *_: object) -> None:
        return None

    def verify_rollback_cleanup_observation(self, *_: object) -> None:
        return None

    def verify_rollback_cleanup_terminal(self, *_: object) -> None:
        return None


class _CoordinatorVerifier(_RollbackVerifier):
    def verify_stage_observation(
        self, result: CandidateObservationResult, request: CandidateObservationRequest, _: object
    ) -> None:
        if result.request_digest != request.request_digest:
            raise AssertionError("observation request changed during recovery")


class _Provider:
    provider_identity = "fixture-provider"
    provider_api_version = "v1"
    repository_name = "avo/example"


class _StageCapability:
    provider_identity = _Provider.provider_identity
    provider_api_version = _Provider.provider_api_version

    def publish_candidate(self, _: CandidatePublicationRequest) -> object:
        raise AssertionError("recovery must not dispatch a second candidate mutation")


class _PrCapability:
    def create_pull_request(self, _: object) -> object:
        raise AssertionError("unused capability")


class _AdmissionCapability:
    def issue_admission(self, _: object) -> object:
        raise AssertionError("unused capability")


class _EnqueueCapability:
    def enqueue(self, _: object) -> object:
        raise AssertionError("unused capability")


class _HoldCapability:
    def issue_group_hold(self, _: object) -> object:
        raise AssertionError("unused capability")


class _ReleaseCapability:
    def issue_release(self, _: object) -> object:
        raise AssertionError("unused capability")


class _ReleaseAuthorizer:
    def authorize_release(self, *_: object, **__: object) -> object:
        raise AssertionError("unused capability")


class _Attester:
    def attest_admission(self, *_: object, **__: object) -> object:
        raise AssertionError("unused capability")

    def attest_hold(self, *_: object, **__: object) -> object:
        raise AssertionError("unused capability")


class _CleanupCapability:
    cleanup_principal = _Principal()
    observer_principal = SimpleNamespace(
        identity="observer", app_id=4, isolation_digest="sha256:" + "2" * 64
    )

    def __init__(self, provider_identity: str = _Provider.provider_identity) -> None:
        self.calls = 0
        self.provider_identity = provider_identity

    def cleanup_rollback(self, intent: MainRollbackCleanupIntent) -> MainRollbackCleanupReceipt:
        self.calls += 1
        return _cleanup_receipt(intent, intent.recorded_at + timedelta(minutes=1), "applied")

    def reconcile_rollback_cleanup(
        self, intent: MainRollbackCleanupIntent, receipt: MainRollbackCleanupReceipt
    ) -> MainRollbackCleanupObservation:
        return _cleanup_observation(intent, receipt, receipt.observed_at + timedelta(minutes=1))


class _ObservationCapability:
    def __init__(self, observation: CandidateObservationResult) -> None:
        self.observation = observation
        self.calls = 0

    def observe_candidate(self, _: CandidateObservationRequest) -> CandidateObservationResult:
        self.calls += 1
        return self.observation


def _digest(model: type[Any], values: dict[str, Any], field: str) -> Any:
    probe = model.model_construct(**values, **{field: "sha256:" + "0" * 64})
    return model.model_validate(
        values | {field: canonical_digest(probe.model_dump(exclude={field}, mode="json"))}
    )


def _rollback_journal(base: MainGraduationJournal) -> MainGraduationJournal:
    return MainGraduationJournal(
        base.root,
        release_issuer_binding=base._release_issuer_binding,
        policy_epoch=base._policy_epoch,
        composition_root=base._composition_root,
        repository_digest=base._composition_repository_digest,
        base_reader=base._composition_base_reader,
        phase_a_authority_verifier=base._phase_a_authority_verifier,
        rollback_authority_verifier=_RollbackVerifier(),
    )


def _prepared_rollback(
    tmp_path: Path,
) -> tuple[MainGraduationJournal, Any, MainRollbackResultReceipt, MainRollbackCompositionResult]:
    base, checkout, provider, package = _ready(tmp_path)
    composition = _adapter(
        tmp_path,
        base,
        _Reader(checkout, provider.main_commit, provider.main_tree),
    ).compose(
        source_operation_id=package.operation_id,
        completion_package_digest=canonical_digest(package),
    )
    source_lease = base.read_lease_evidence_record(package.operation_id)
    assert source_lease is not None
    assert base.release_target_lease(
        package.repository_digest,
        package.target_ref,
        package.operation_id,
        source_lease[0].lease_digest,
    )
    journal = _rollback_journal(base)
    clock = _Clock()

    def acquire(operation_id: str, repository_digest: str, target_ref: str) -> Any:
        assert repository_digest == package.repository_digest
        assert target_ref == package.target_ref
        return _durable_lease(journal, operation_id, package.plan.policy_epoch, clock.now())

    authority = MainRollbackAuthority(
        journal=journal,
        clock=clock,
        policy_epoch=package.plan.policy_epoch,
        controller_config_digest=package.release_issuer_binding.controller_config_digest,
        release_issuer_binding=package.release_issuer_binding,
        current_authority_reader=lambda: MainRollbackCurrentAuthority(
            current_main_commit=provider.main_commit,
            current_main_tree=provider.main_tree,
            current_main_parent_commit=package.reconciliation.main_parents[0],
            policy_epoch=package.plan.policy_epoch,
            controller_config_digest=package.release_issuer_binding.controller_config_digest,
            release_issuer_binding=package.release_issuer_binding,
        ),
        lease_acquirer=acquire,
    )
    prepared = authority.prepare(
        source_operation_id=package.operation_id,
        attempt_nonce="recovery-tests",
        composition=composition,
    )
    values = {
        "operation_id": prepared.operation_id,
        "source_operation_id": prepared.intent.source_operation_id,
        "composition_id": prepared.intent.composition_id,
        "composition_artifact_digest": prepared.intent.composition_artifact_digest,
        "repository_digest": prepared.intent.repository_digest,
        "target_ref": prepared.intent.target_ref,
        "completion_package_digest": prepared.intent.completion_package_digest,
        "intent_digest": prepared.intent.intent_digest,
        "authorization_digest": prepared.authorization.authorization_digest,
        "inverse_delta_digest": prepared.composition.inverse_delta_digest,
        "inverse_delta_artifact_digest": canonical_digest(prepared.composition),
        "current_main_commit": prepared.authorization.current_main_commit,
        "inverse_tree": prepared.composition.inverse_tree,
        "provider_identity": _Provider.provider_identity,
        "provider_api_version": _Provider.provider_api_version,
        "result_commit": prepared.composition.candidate_commit,
        "result_tree": prepared.composition.inverse_tree,
        "result_parent_commit": prepared.authorization.current_main_commit,
        "result_parents": [prepared.authorization.current_main_commit],
        "outcome": "applied",
        "response_digest": "sha256:" + "3" * 64,
        "observed_at": clock.now() + timedelta(minutes=1),
    }
    result = _digest(MainRollbackResultReceipt, values, "receipt_digest")
    with journal.rollback_authority_recovery(package.operation_id):
        journal.record_rollback_result(result)
    return journal, prepared, result, composition


def _coordinator(
    journal: MainGraduationJournal,
    clock: _Clock,
    *,
    cleanup: _CleanupCapability | None = None,
    observation: object | None = None,
    publication: object | None = None,
    verifier: object | None = None,
) -> MainRollbackCoordinator:
    return MainRollbackCoordinator(
        journal=journal,
        clock=clock,
        lease_fence=_Fence(),
        rollback_authority=object(),
        provider=_Provider(),
        publication_capability=publication or _StageCapability(),
        pull_request_capability=_PrCapability(),
        admission_capability=_AdmissionCapability(),
        enqueue_capability=_EnqueueCapability(),
        hold_capability=_HoldCapability(),
        release_capability=_ReleaseCapability(),
        observation_capability=observation,
        cleanup_capability=cleanup,
        authority_verifier=verifier or _CoordinatorVerifier(),
        release_authorizer=_ReleaseAuthorizer(),
        attester=_Attester(),
    )


def _cleanup_intent(
    coordinator: MainRollbackCoordinator, authority: Any, result: MainRollbackResultReceipt
) -> MainRollbackCleanupIntent:
    return coordinator._cleanup_intent(
        authority,
        result,
        SimpleNamespace(number=17, url="https://github.example/pull/17"),
    )


def _cleanup_receipt(
    intent: MainRollbackCleanupIntent, observed_at: datetime, outcome: str
) -> MainRollbackCleanupReceipt:
    values = {
        "operation_id": intent.operation_id,
        "repository_digest": intent.repository_digest,
        "target_ref": intent.target_ref,
        "intent_digest": intent.intent_digest,
        "authorization_digest": intent.authorization_digest,
        "candidate_ref": intent.candidate_ref,
        "candidate_commit": intent.candidate_commit,
        "pull_request_number": intent.pull_request_number,
        "pull_request_url": intent.pull_request_url,
        "outcome": outcome,
        "dispatch_started": outcome not in {"already_absent", "invalid"},
        "response_digest": "sha256:" + "4" * 64,
        "observed_at": observed_at,
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
    }
    return _digest(MainRollbackCleanupReceipt, values, "receipt_digest")


def _cleanup_observation(
    intent: MainRollbackCleanupIntent,
    receipt: MainRollbackCleanupReceipt,
    observed_at: datetime,
) -> MainRollbackCleanupObservation:
    values = {
        "operation_id": intent.operation_id,
        "repository_digest": intent.repository_digest,
        "target_ref": intent.target_ref,
        "intent_digest": intent.intent_digest,
        "receipt_digest": receipt.receipt_digest,
        "candidate_ref": intent.candidate_ref,
        "candidate_commit": intent.candidate_commit,
        "pull_request_number": intent.pull_request_number,
        "pull_request_url": intent.pull_request_url,
        "outcome": "absent",
        "provider_identity": intent.provider_identity,
        "provider_api_version": intent.provider_api_version,
        "observer_identity": intent.observer_identity,
        "observer_api_version": intent.observer_provider_api_version,
        "cleanup_principal_identity": intent.cleanup_principal_identity,
        "cleanup_principal_app_id": intent.cleanup_principal_app_id,
        "cleanup_principal_isolation_digest": intent.cleanup_principal_isolation_digest,
        "observer_app_id": intent.observer_app_id,
        "observer_isolation_digest": intent.observer_isolation_digest,
        "observer_provider_identity": intent.observer_provider_identity,
        "observer_provider_api_version": intent.observer_provider_api_version,
        "cleanup_authority_digest": intent.cleanup_authority_digest,
        "candidate_ref_absent": True,
        "pull_request_state": "closed",
        "pull_request_merged": True,
        "observed_at": observed_at,
    }
    return _digest(MainRollbackCleanupObservation, values, "observation_digest")


def test_cleanup_intent_restart_adopts_exact_timestamp_and_dispatches_once(tmp_path: Path) -> None:
    journal, authority, result, _ = _prepared_rollback(tmp_path)
    first = _coordinator(journal, _Clock(NOW + timedelta(minutes=5)), cleanup=_CleanupCapability())
    intent = _cleanup_intent(first, authority, result)
    with journal.rollback_authority_recovery(authority.intent.source_operation_id):
        journal.record_rollback_cleanup_intent(intent)

    cleanup = _CleanupCapability()
    restarted = _rollback_journal(journal)
    second = _coordinator(restarted, _Clock(NOW + timedelta(minutes=10)), cleanup=cleanup)
    with restarted.rollback_authority_recovery(authority.intent.source_operation_id):
        adopted = _cleanup_intent(second, authority, result)
    assert adopted.recorded_at == intent.recorded_at
    assert adopted.intent_digest == intent.intent_digest

    with restarted.rollback_authority_recovery(authority.intent.source_operation_id):
        receipt, observation, terminal = second._cleanup(authority, result, adopted)
    assert cleanup.calls == 1
    assert receipt.outcome == "applied"
    assert observation is None
    assert terminal is not None
    persisted = _rollback_journal(restarted)
    with persisted.rollback_authority_recovery(authority.intent.source_operation_id):
        assert persisted.read_rollback_cleanup_intent(adopted.operation_id)[0] == adopted
        assert persisted.read_rollback_cleanup_receipt(adopted.operation_id)[0] == receipt
        assert persisted.read_rollback_cleanup_terminal(adopted.operation_id)[0] == terminal


def test_source_recovery_context_does_not_bypass_foreign_lease_slot(tmp_path: Path) -> None:
    journal, authority, _result, _ = _prepared_rollback(tmp_path)
    assert journal.release_target_lease(
        authority.lease.repository_digest,
        authority.lease.target_ref,
        authority.operation_id,
        authority.lease.lease_digest,
    )

    recovery = journal.rollback_authority_recovery(authority.intent.source_operation_id)
    with pytest.raises(MainGraduationJournalError, match="target lease"), recovery:
        journal.read_lease_evidence_record(authority.operation_id)


def test_cleanup_owner_without_receipt_reconciles_absence_without_second_delete(
    tmp_path: Path,
) -> None:
    journal, authority, result, _ = _prepared_rollback(tmp_path)
    seed = _coordinator(journal, _Clock(NOW + timedelta(minutes=5)), cleanup=_CleanupCapability())
    intent = _cleanup_intent(seed, authority, result)
    with journal.rollback_authority_recovery(authority.intent.source_operation_id):
        journal.record_rollback_cleanup_intent(intent)
    with journal.rollback_authority_recovery(authority.intent.source_operation_id):
        assert journal.claim_rollback_cleanup_dispatch(
            operation_id=intent.operation_id,
            intent_digest=intent.intent_digest,
            candidate_ref=intent.candidate_ref,
            recorded_at=NOW + timedelta(minutes=6),
        )

    cleanup = _CleanupCapability()
    restarted = _rollback_journal(journal)
    recovery = _coordinator(
        restarted,
        _Clock(NOW + timedelta(minutes=10)),
        cleanup=cleanup,
    )
    receipt, observation, terminal = recovery.recover_cleanup(
        authority=authority,
        result=result,
        cleanup_intent=intent,
    )
    assert cleanup.calls == 0
    assert receipt.outcome == "reconciliation_required"
    assert receipt.dispatch_started is True
    assert observation is not None and observation.outcome == "absent"
    assert observation.candidate_ref_absent is True
    assert terminal is not None and terminal.outcome == "absent"

    persisted = _rollback_journal(restarted)
    with persisted.rollback_authority_recovery(authority.intent.source_operation_id):
        assert persisted.read_rollback_cleanup_dispatch_owner(intent.intent_digest) is not None
        assert persisted.read_rollback_cleanup_receipt(intent.operation_id)[0] == receipt
        assert persisted.read_rollback_cleanup_observation(intent.operation_id)[0] == observation
        assert persisted.read_rollback_cleanup_terminal(intent.operation_id)[0] == terminal


def test_c4_owner_without_receipt_coordinator_recovers_read_only_with_resolution(
    tmp_path: Path,
) -> None:
    journal, authority, _result, _ = _prepared_rollback(tmp_path)
    request = CandidatePublicationRequest.build(
        operation_id=authority.operation_id,
        operation_kind="rollback",
        repository_digest=authority.intent.repository_digest,
        lease_epoch_digest=authority.lease.lease_epoch_digest,
        candidate_ref=authority.intent.candidate_ref,
        candidate_commit=authority.composition.candidate_commit,
        preparation_authorization_digest=authority.preparation_authorization.authorization_digest,
    )
    external = MainExternalIdentity.model_validate(
        {
            "operation_id": request.operation_id,
            "repository_digest": request.repository_digest,
            "target_ref": request.target_ref,
            "stage": request.stage,
            "external_key": request.external_key,
            "identity_digest": request.external_identity,
        }
    )
    intent = _digest(
        MainMutationIntent,
        {
            "operation_id": request.operation_id,
            "repository_digest": request.repository_digest,
            "target_ref": request.target_ref,
            "stage": request.stage,
            "parent_stage": None,
            "parent_intent_digest": None,
            "parent_receipt": None,
            "parent_resolution_digest": None,
            "lease_identity": authority.lease.owner,
            "lease_digest": authority.lease.lease_digest,
            "lease_epoch_digest": authority.lease.lease_epoch_digest,
            "policy_epoch_digest": authority.authorization.policy_epoch,
            "controller_config_digest": authority.authorization.controller_config_digest,
            "preparation_authorization_digest": (
                authority.preparation_authorization.authorization_digest
            ),
            "release_authorization_digest": None,
            "release_claim_digest": None,
            "external_identity": external,
            "request_digest": request.request_digest,
            "recorded_at": NOW,
        },
        "intent_digest",
    )
    with journal.rollback_authority_recovery(authority.intent.source_operation_id):
        journal.record_mutation_intent(intent)
        assert journal.claim_mutation_dispatch(
            operation_id=intent.operation_id,
            intent_digest=intent.intent_digest,
            request_digest=request.request_digest,
            stage=request.stage,
            repository_digest=request.repository_digest,
            target_ref=request.target_ref,
            external_identity_digest=request.external_identity,
            lease_identity=authority.lease.owner,
            lease_digest=authority.lease.lease_digest,
            lease_epoch_digest=authority.lease.lease_epoch_digest,
            recorded_at=NOW + timedelta(minutes=1),
        )
    observation_request = CandidateObservationRequest.build(
        **request.model_dump(
            exclude={"request_digest", "external_key", "external_identity"}, mode="json"
        ),
        object_id=request.candidate_ref,
    )
    observed = CandidateObservationResult.build(
        **observation_request.model_dump(
            exclude={"request_digest", "external_key", "external_identity"}, mode="json"
        ),
        outcome="observed",
        evidence_digest="sha256:" + "5" * 64,
        observed_at=NOW + timedelta(minutes=2),
    )
    observer = _ObservationCapability(observed)
    restarted = _rollback_journal(journal)
    coordinator = _coordinator(
        restarted,
        _Clock(NOW + timedelta(minutes=10)),
        observation=observer,
        publication=_StageCapability(),
    )
    with restarted.rollback_authority_recovery(authority.intent.source_operation_id):
        recovered_intent, execution = coordinator._stage(request, authority, None)
    assert recovered_intent == intent
    assert execution.effective_outcome in {"applied", "already_applied"}
    assert observer.calls == 1
    with restarted.rollback_authority_recovery(authority.intent.source_operation_id):
        assert restarted.read_mutation_receipt_for_intent(intent.intent_digest) is not None
        assert restarted.read_mutation_fence_resolution_by_intent(intent.intent_digest) is not None
    persisted = _rollback_journal(restarted)
    with persisted.rollback_authority_recovery(authority.intent.source_operation_id):
        assert persisted.read_mutation_receipt_for_intent(intent.intent_digest) is not None
        assert persisted.read_mutation_fence_resolution_by_intent(intent.intent_digest) is not None
