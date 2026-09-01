"""Adversarial aggregate/C4 replay matrix for protected-main rollback.

These tests deliberately use the filesystem-backed fixtures and fresh journal
instances.  They model process loss at the intent, dispatch-owner, provider,
receipt, and cleanup boundaries; no persistence seam is replaced by a mock.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.application.c4_capabilities import (
    CandidateObservationRequest,
    CandidateObservationResult,
    CandidatePublicationRequest,
)
from avo_correlate.application.c4_stage_executor import C4StageExecutionError
from avo_correlate.application.main_rollback_coordinator import (
    MainRollbackCoordinator,
    MainRollbackCoordinatorError,
)
from tests.unit.test_c4_stage_executor import (
    Authority,
    CandidateProvider,
    Clock,
    Fence,
    Observation,
    _executor,
    _fixture,
)
from tests.unit.test_main_rollback_coordinator_recovery import (
    NOW,
    _AdmissionCapability,
    _Attester,
    _cleanup_intent,
    _CleanupCapability,
    _CoordinatorVerifier,
    _EnqueueCapability,
    _HoldCapability,
    _PrCapability,
    _prepared_rollback,
    _Provider,
    _ReleaseAuthorizer,
    _ReleaseCapability,
    _rollback_journal,
    _StageCapability,
)
from tests.unit.test_main_rollback_coordinator_recovery import _Clock as RollbackClock

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false


def _candidate_observation(
    request: CandidatePublicationRequest, outcome: str
) -> tuple[CandidateObservationRequest, CandidateObservationResult]:
    observation_request = CandidateObservationRequest.build(
        **request.model_dump(
            exclude={"request_digest", "external_key", "external_identity"}, mode="json"
        ),
        object_id=request.candidate_ref,
    )
    observation = CandidateObservationResult.build(
        **observation_request.model_dump(
            exclude={"request_digest", "external_key", "external_identity"}, mode="json"
        ),
        outcome=outcome,
        evidence_digest="sha256:" + "7" * 64,
        observed_at=NOW,
    )
    return observation_request, observation


def _fresh_c4_journal(journal: Any, tmp_path: Path, authority: Authority) -> Any:
    """Re-open the exact journal root so recovery crosses a process boundary."""

    return type(journal)(
        tmp_path,
        release_issuer_binding=journal._release_issuer_binding,
        phase_a_authority_verifier=authority,
    )


def _coordinator(journal: Any, clock: Any, **overrides: object) -> MainRollbackCoordinator:
    values: dict[str, object] = {
        "journal": journal,
        "clock": clock,
        "lease_fence": Fence(),
        "rollback_authority": object(),
        "provider": _Provider(),
        "publication_capability": _StageCapability(),
        "pull_request_capability": _PrCapability(),
        "admission_capability": _AdmissionCapability(),
        "enqueue_capability": _EnqueueCapability(),
        "hold_capability": _HoldCapability(),
        "release_capability": _ReleaseCapability(),
        "authority_verifier": _CoordinatorVerifier(),
        "release_authorizer": _ReleaseAuthorizer(),
        "attester": _Attester(),
    }
    values.update(overrides)
    return MainRollbackCoordinator(**values)  # type: ignore[arg-type]


class _CrashCleanup:
    cleanup_principal = _CleanupCapability.cleanup_principal
    observer_principal = _CleanupCapability.observer_principal

    def __init__(self) -> None:
        self.delete_calls = 0

    def cleanup_rollback(self, _: object) -> object:
        self.delete_calls += 1
        raise TimeoutError("crash after cleanup dispatch")

    def reconcile_rollback_cleanup(self, intent: Any, receipt: Any) -> Any:
        from tests.unit.test_main_rollback_coordinator_recovery import _cleanup_observation

        return _cleanup_observation(intent, receipt, receipt.observed_at + timedelta(minutes=1))


class _GenericDeployOnly:
    provider_identity = _Provider.provider_identity
    provider_api_version = _Provider.provider_api_version

    def deploy(self, _: object) -> object:
        raise AssertionError("generic deploy must never be accepted as a stage capability")


class _BothStageCapabilities:
    def issue_group_hold(self, _: object) -> object:
        raise AssertionError("cross-stage capability must never dispatch")

    def issue_release(self, _: object) -> object:
        raise AssertionError("cross-stage capability must never dispatch")


def test_capability_boundary_rejects_generic_deploy_and_cross_stage_wires(tmp_path: Path) -> None:
    journal, authority, _result, _composition = _prepared_rollback(tmp_path)

    with pytest.raises(ValueError, match="candidate_publication"):
        _coordinator(journal, Clock(), publication_capability=_GenericDeployOnly())

    hold = _BothStageCapabilities()
    with pytest.raises(ValueError, match="separate"):
        _coordinator(journal, Clock(), hold_capability=hold, release_capability=hold)

    with pytest.raises(ValueError, match="release capability must not expose group hold"):
        _coordinator(journal, Clock(), release_capability=hold)
    with pytest.raises(ValueError, match="release_transition"):
        _coordinator(journal, Clock(), release_capability=_HoldCapability())

    # The aggregate constructor has no deploy/ref-update argument or generic
    # mutation callback; only the six exact stage capabilities are accepted.
    assert not hasattr(MainRollbackCoordinator, "deploy")
    assert not hasattr(MainRollbackCoordinator, "update_main_ref")
    assert authority.operation_id != ""


def test_provider_crash_persists_ambiguous_once_and_fresh_recovery_is_read_only(
    tmp_path: Path,
) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    provider = CandidateProvider(error=True)
    first = _executor(journal, provider, Clock(), Fence(), authority)

    receipt = first.execute(intent, request)
    assert receipt.outcome == "ambiguous"
    assert provider.calls == 1

    observation_request, observed = _candidate_observation(request, "observed")
    observer = Observation(observed)
    restarted_journal = _fresh_c4_journal(journal, tmp_path, authority)
    restarted = _executor(
        restarted_journal, CandidateProvider(), Clock(), Fence(), authority, observer
    )
    recovered = restarted.recover_effective(
        intent, observation_request, original_request=request
    )
    assert recovered.effective_outcome == "already_applied"
    assert recovered.has_authoritative_resolution
    assert observer.calls == 1
    assert restarted_journal.read_mutation_receipt_for_intent(intent.intent_digest) is not None


@pytest.mark.parametrize(
    ("observed_outcome", "effective_outcome"),
    [("observed", "already_applied"), ("not_found", "not_applied"), ("ambiguous", "ambiguous")],
)
def test_owner_without_receipt_has_exactly_one_observation_and_no_redispatch(
    tmp_path: Path, observed_outcome: str, effective_outcome: str
) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    journal.record_mutation_intent(intent)
    provider = CandidateProvider()
    executor = _executor(journal, provider, Clock(), Fence(), authority)
    assert executor._claim_dispatch_owner(intent, request)

    observation_request, observed = _candidate_observation(request, observed_outcome)
    observer = Observation(observed)
    restarted_journal = _fresh_c4_journal(journal, tmp_path, authority)
    restarted = _executor(
        restarted_journal, CandidateProvider(), Clock(), Fence(), authority, observer
    )
    result = restarted.recover_effective(
        intent, observation_request, original_request=request
    )
    assert result.effective_outcome == effective_outcome
    assert provider.calls == 0
    assert observer.calls == 1
    assert restarted_journal.read_mutation_dispatch_owner(intent.intent_digest) is not None


def test_recovery_rejects_stale_identity_without_observing_or_dispatching(tmp_path: Path) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    provider = CandidateProvider(ambiguous=True)
    assert _executor(journal, provider, Clock(), Fence(), authority).execute(intent, request)
    _observation_request, observed = _candidate_observation(request, "observed")
    observer = Observation(observed)
    stale = CandidateObservationRequest.build(
        **request.model_dump(
            exclude={"request_digest", "external_key", "external_identity"}, mode="json"
        ),
        object_id=request.candidate_ref + "-stale",
    )
    restarted_journal = _fresh_c4_journal(journal, tmp_path, authority)
    restarted = _executor(
        restarted_journal, CandidateProvider(), Clock(), Fence(), authority, observer
    )
    with pytest.raises(C4StageExecutionError, match="object identity"):
        restarted.recover(intent, stale, original_request=request)
    assert observer.calls == 0


def test_cleanup_owner_crash_public_recovery_reconciles_once_without_second_delete(
    tmp_path: Path,
) -> None:
    journal, authority, result, _composition = _prepared_rollback(tmp_path)
    seed = _coordinator(
        journal,
        RollbackClock(NOW + timedelta(minutes=5)),
        cleanup_capability=_CrashCleanup(),
    )
    intent = _cleanup_intent(seed, authority, result)
    with journal.rollback_authority_recovery(authority.intent.source_operation_id):
        journal.record_rollback_cleanup_intent(intent)
        with pytest.raises(TimeoutError, match="cleanup dispatch"):
            seed._cleanup(authority, result, intent)
    with journal.rollback_authority_recovery(authority.intent.source_operation_id):
        assert journal.read_rollback_cleanup_dispatch_owner(intent.intent_digest) is not None

    restarted = _rollback_journal(journal)
    cleanup = _CleanupCapability()
    recovery = _coordinator(
        restarted, RollbackClock(NOW + timedelta(minutes=10)), cleanup_capability=cleanup
    )
    receipt, observation, terminal = recovery.recover_cleanup(
        authority=authority, result=result, cleanup_intent=intent
    )
    assert cleanup.calls == 0
    assert receipt.outcome == "reconciliation_required"
    assert observation is not None and observation.outcome == "absent"
    assert terminal is not None and terminal.outcome == "absent"

    durable = _rollback_journal(restarted)
    with durable.rollback_authority_recovery(authority.intent.source_operation_id):
        assert durable.read_rollback_cleanup_receipt(authority.operation_id)[0] == receipt
        assert durable.read_rollback_cleanup_observation(authority.operation_id)[0] == observation
        assert durable.read_rollback_cleanup_terminal(authority.operation_id)[0] == terminal


def test_cleanup_replay_and_mismatched_result_are_non_mutating(tmp_path: Path) -> None:
    journal, authority, result, _composition = _prepared_rollback(tmp_path)
    cleanup = _CleanupCapability()
    coordinator = _coordinator(
        journal, RollbackClock(NOW + timedelta(minutes=5)), cleanup_capability=cleanup
    )
    intent = _cleanup_intent(coordinator, authority, result)
    coordinator.clock.value = intent.recorded_at + timedelta(minutes=1)
    with journal.rollback_authority_recovery(authority.intent.source_operation_id):
        journal.record_rollback_cleanup_intent(intent)
        first_receipt, first_observation, first_terminal = coordinator._cleanup(
            authority, result, intent
        )
    assert cleanup.calls == 1
    assert first_receipt.outcome == "applied"
    assert first_observation is None
    assert first_terminal is not None

    restarted = _rollback_journal(journal)
    replay_cleanup = _CleanupCapability()
    replay = _coordinator(
        restarted, RollbackClock(NOW + timedelta(minutes=10)), cleanup_capability=replay_cleanup
    )
    replay_receipt, replay_observation, replay_terminal = replay.recover_cleanup(
        authority=authority, result=result, cleanup_intent=intent
    )
    assert replay_cleanup.calls == 0
    assert replay_receipt == first_receipt
    assert replay_observation is None
    assert replay_terminal == first_terminal

    forged_result = result.model_copy(update={"target_ref": "refs/heads/elsewhere"})
    with pytest.raises(MainRollbackCoordinatorError, match="durable rollback result"):
        replay.recover_cleanup(
            authority=authority, result=forged_result, cleanup_intent=intent
        )
    assert replay_cleanup.calls == 0


def test_cleanup_recovery_rejects_mismatched_intent_before_owner_or_delete(tmp_path: Path) -> None:
    journal, authority, result, _composition = _prepared_rollback(tmp_path)
    cleanup = _CleanupCapability()
    coordinator = _coordinator(
        journal, RollbackClock(NOW + timedelta(minutes=5)), cleanup_capability=cleanup
    )
    intent = _cleanup_intent(coordinator, authority, result)
    with journal.rollback_authority_recovery(authority.intent.source_operation_id):
        journal.record_rollback_cleanup_intent(intent)
        assert journal.claim_rollback_cleanup_dispatch(
            operation_id=intent.operation_id,
            intent_digest=intent.intent_digest,
            candidate_ref=intent.candidate_ref,
            recorded_at=NOW,
        )
    forged_intent = intent.model_copy(update={"candidate_ref": intent.candidate_ref + "-other"})
    with pytest.raises(MainRollbackCoordinatorError, match="durable cleanup intent"):
        coordinator.recover_cleanup(
            authority=authority, result=result, cleanup_intent=forged_intent
        )
    assert cleanup.calls == 0
