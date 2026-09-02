"""Focused negative-path coverage for the C4 stage execution kernel."""
# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportArgumentType=false, reportCallIssue=false, reportMissingImports=false, reportUnusedImport=false, reportUnusedVariable=false, reportUnnecessaryCast=false, reportAttributeAccessIssue=false, reportIndexIssue=false

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from avo_correlate.application.c4_capabilities import (
    CandidateObservationRequest,
    CandidateObservationResult,
)
from avo_correlate.application.c4_stage_executor import (
    C4StageExecutionError,
    C4StageExecutor,
)
from tests.unit.test_c4_stage_executor import (
    CANDIDATE,
    NOW,
    CandidateProvider,
    Clock,
    Fence,
    Observation,
    _executor,
    _fixture,
)


def test_expiry_and_release_claim_authority_fail_closed(tmp_path: Path) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    executor = _executor(journal, CandidateProvider(), Clock(), Fence(), authority)
    expired = SimpleNamespace(authorization_expires_at=NOW - timedelta(seconds=1))
    with pytest.raises(C4StageExecutionError, match="expired"):
        executor._last_moment_authority(intent, expired)  # pyright: ignore[reportPrivateUsage]

    release_intent = intent.model_copy(update={"stage": "release_transition"})
    with pytest.raises(C4StageExecutionError, match="release claim"):
        executor._last_moment_authority(release_intent, request)  # pyright: ignore[reportPrivateUsage]


def test_request_and_observation_capability_validation_is_exact(tmp_path: Path) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    executor = _executor(journal, CandidateProvider(), Clock(), Fence(), authority)
    with pytest.raises(C4StageExecutionError, match="request type"):
        executor._check_request(intent, object())  # pyright: ignore[reportPrivateUsage,arg-type]
    with pytest.raises(C4StageExecutionError, match="capability"):
        C4StageExecutor(
            journal=journal,
            clock=Clock(),
            lease_fence=Fence(),
            capability=object(),
            authority_verifier=authority,
        )._check_request(intent, request)  # pyright: ignore[reportPrivateUsage]

    observation_request = CandidateObservationRequest.build(
        **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
        object_id=request.candidate_ref,
    )
    with pytest.raises(C4StageExecutionError, match="missing"):
        C4StageExecutor(
            journal=journal,
            clock=Clock(),
            lease_fence=Fence(),
            capability=CandidateProvider(),
            authority_verifier=authority,
        )._check_observation_request(  # pyright: ignore[reportPrivateUsage]
            intent, observation_request, request
        )


def test_result_and_observation_validation_rejects_identity_and_missing_verifiers(
    tmp_path: Path,
) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    provider = CandidateProvider()
    executor = _executor(journal, provider, Clock(), Fence(), authority)
    result = provider.publish_candidate(request)
    with pytest.raises(C4StageExecutionError, match="identity"):
        executor._verify_result(  # pyright: ignore[reportPrivateUsage]
            result.model_copy(update={"request_digest": CANDIDATE}), request, intent
        )
    with pytest.raises(C4StageExecutionError, match="external identity"):
        executor._verify_result(  # pyright: ignore[reportPrivateUsage]
            result.model_copy(update={"external_identity": CANDIDATE}), request, intent
        )

    observation_request = CandidateObservationRequest.build(
        **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
        object_id=request.candidate_ref,
    )
    observation = executor.authority_verifier  # retain valid fixture authority
    del observation
    no_verifier = C4StageExecutor(
        journal=journal,
        clock=Clock(),
        lease_fence=Fence(),
        capability=provider,
        observation_capability=SimpleNamespace(),
        authority_verifier=SimpleNamespace(),
    )
    with pytest.raises(C4StageExecutionError, match="missing"):
        no_verifier._verify_result(result, request, intent)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(C4StageExecutionError, match="missing"):
        no_verifier._verify_observation(  # pyright: ignore[reportPrivateUsage]
            SimpleNamespace(stage=intent.stage, request_digest=observation_request.request_digest,
                            external_identity=observation_request.external_identity),
            observation_request,
            intent,
        )


def test_missing_dispatch_and_recovery_observation_paths_are_durable(tmp_path: Path) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    journal.record_mutation_intent(intent)
    executor = _executor(journal, CandidateProvider(), Clock(), Fence(), authority)
    observation_request = CandidateObservationRequest.build(
        **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
        object_id=request.candidate_ref,
    )
    with pytest.raises(C4StageExecutionError, match="missing"):
        executor.recover(intent, observation_request, original_request=request)
    journal.claim_mutation_dispatch(
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
        recorded_at=NOW,
    )
    observation_result = CandidateObservationResult.build(
        **observation_request.model_dump(
            exclude={"request_digest", "external_key", "external_identity"}
        ),
        outcome="not_found",
        evidence_digest="sha256:" + "4" * 64,
        observed_at=NOW,
    )
    observer = _executor(
        journal,
        CandidateProvider(),
        Clock(),
        Fence(),
        authority,
        Observation(observation_result),
    )
    result = observer.recover_effective(intent, observation_request, original_request=request)
    assert result.receipt.outcome == "ambiguous"


def test_parent_prerequisites_and_binding_checks_reject_wrong_durable_records(
    tmp_path: Path,
) -> None:
    journal, intent, _request, authority = _fixture(tmp_path)
    executor = _executor(journal, CandidateProvider(), Clock(), Fence(), authority)
    with pytest.raises(C4StageExecutionError, match="parent"):
        executor._check_prerequisites(  # pyright: ignore[reportPrivateUsage]
            intent.model_copy(update={"parent_intent_digest": intent.intent_digest,
                                       "parent_receipt": intent.intent_digest})
        )
    receipt = executor._receipt_from_exception(intent, RuntimeError("uncertain"))  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(C4StageExecutionError, match="receipt"):
        executor._check_receipt_binding(  # pyright: ignore[reportPrivateUsage]
            receipt.model_copy(update={"stage": "release_transition"}), intent
        )
    fence = executor._fence_from_receipt(intent, receipt)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(C4StageExecutionError, match="fence"):
        executor._check_fence_binding(  # pyright: ignore[reportPrivateUsage]
            fence.model_copy(update={"lease_identity": "other"}), intent
        )


def test_effective_result_rejects_missing_and_mismatched_durable_receipts(tmp_path: Path) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    executor = _executor(journal, CandidateProvider(), Clock(), Fence(), authority)
    journal.record_mutation_intent(intent)
    with pytest.raises(C4StageExecutionError, match="receipt"):
        executor.effective_result(intent)
    _ = executor.execute(intent, request)
    other_journal, other_intent, other_request, other_authority = _fixture(tmp_path / "other")
    other_receipt = _executor(
        other_journal,
        CandidateProvider(),
        Clock(),
        Fence(),
        other_authority,
    ).execute(other_intent, other_request)
    with pytest.raises(C4StageExecutionError, match="supplied"):
        executor.effective_result(intent, other_receipt)


def test_missing_journal_and_provider_interfaces_fail_closed(tmp_path: Path) -> None:
    _journal, intent, request, authority = _fixture(tmp_path)
    bare = C4StageExecutor(
        journal=SimpleNamespace(),
        clock=Clock(),
        lease_fence=Fence(),
        capability=CandidateProvider(),
        authority_verifier=authority,
    )
    with pytest.raises(C4StageExecutionError, match="reader"):
        bare._read_resolution(intent.intent_digest)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(C4StageExecutionError, match="CAS"):
        bare._claim_dispatch_owner(intent, request)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(C4StageExecutionError, match="observation"):
        bare._observe(  # pyright: ignore[reportPrivateUsage]
            CandidateObservationRequest.model_construct(stage="candidate_publication")
        )
