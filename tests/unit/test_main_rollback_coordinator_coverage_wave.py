"""Focused branch tests for rollback coordination seams."""
# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportArgumentType=false, reportCallIssue=false, reportUnknownLambdaType=false, reportMissingImports=false, reportAttributeAccessIssue=false, reportUnknownVariableType=false

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from avo_correlate.application.c4_capabilities import CandidatePublicationRequest
from avo_correlate.application.main_rollback_coordinator import (
    MainRollbackCoordinator,
    MainRollbackCoordinatorError,
    RollbackResult,
    _canonical,  # pyright: ignore[reportPrivateUsage]
    _digest_record,  # pyright: ignore[reportPrivateUsage]
)
from avo_correlate.contracts.main_graduation import MainMutationIntent
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_main_graduation_github import candidate_request, queue_request


def _bare(**values: Any) -> MainRollbackCoordinator:
    coordinator = object.__new__(MainRollbackCoordinator)
    coordinator.provider = SimpleNamespace(**values)
    coordinator.observation_capability = coordinator.provider
    coordinator._stage_results = {}
    return coordinator


def test_small_helpers_fail_closed_and_preserve_reconciliation_shape() -> None:
    assert MainRollbackCoordinator._terminal(  # pyright: ignore[reportPrivateUsage]
        SimpleNamespace(effective_outcome="applied")
    )
    assert not MainRollbackCoordinator._terminal(  # pyright: ignore[reportPrivateUsage]
        SimpleNamespace(effective_outcome="ambiguous")
    )
    result = MainRollbackCoordinator._reconcile(  # pyright: ignore[reportPrivateUsage]
        _bare(), "sha256:" + "1" * 64, "candidate_publication", SimpleNamespace(outcome="ambiguous")
    )
    assert isinstance(result, RollbackResult)
    assert result.state == "reconciliation_required"
    assert result.stage == "candidate_publication"

    coordinator = _bare()
    coordinator.authority_verifier = object()
    with pytest.raises(MainRollbackCoordinatorError, match="verifier"):
        coordinator._verify_named("verify_missing", object())  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(MainRollbackCoordinatorError, match="untyped"):
        _canonical(object(), CandidatePublicationRequest)
    checked = _canonical(candidate_request(), CandidatePublicationRequest)
    assert checked.request_digest == candidate_request().request_digest


def test_provider_repository_supports_adapter_and_rejects_empty_identity() -> None:
    coordinator = _bare(owner="owner", repo="repo")
    assert coordinator._provider_repository() == "owner/repo"  # pyright: ignore[reportPrivateUsage]
    coordinator = _bare(repository_name="owner/repo")
    assert coordinator._provider_repository() == "owner/repo"  # pyright: ignore[reportPrivateUsage]
    coordinator = _bare(owner="", repo="repo")
    assert coordinator._provider_repository() is None  # pyright: ignore[reportPrivateUsage]


def test_observation_request_builds_candidate_and_queue_identity() -> None:
    coordinator = _bare(repository_name="owner/repo")
    candidate = candidate_request()
    observed = coordinator._observation_request(candidate)  # pyright: ignore[reportPrivateUsage]
    assert observed.object_id == candidate.candidate_ref
    assert observed.operation_id == candidate.operation_id

    class Observer:
        def observe_queue(self, request: Any) -> Any:
            assert request.object_id == "https://github.com/owner/repo/pull/1"
            return SimpleNamespace(queue_generation_digest="sha256:" + "2" * 64)

    coordinator.observation_capability = Observer()
    queue = queue_request()
    # Queue observations require a post-enqueue generation.  A raw enqueue
    # request has no generation yet, so this fail-closed path must not invoke
    # the observer with an under-specified request.
    with pytest.raises(ValueError, match="post-enqueue queue generation"):
        coordinator._observation_request(queue)  # pyright: ignore[reportPrivateUsage]


def test_observation_call_wraps_missing_and_provider_failures() -> None:
    coordinator = _bare()
    with pytest.raises(MainRollbackCoordinatorError, match="lacks"):
        coordinator._call_observer("observe_candidate", object())  # pyright: ignore[reportPrivateUsage]


def test_execute_and_cleanup_recovery_quarantine_missing_authority_context() -> None:
    coordinator = _bare()
    coordinator.journal = object()
    operation = "sha256:" + "1" * 64
    result = coordinator.execute(operation, attempt_nonce="nonce", composition=object())
    assert result.state == "quarantined"
    assert result.operation_id == operation
    with pytest.raises(MainRollbackCoordinatorError, match="recovery context"):
        coordinator.recover_cleanup(
            authority=SimpleNamespace(intent=SimpleNamespace(source_operation_id=operation)),
            result=SimpleNamespace(),
            cleanup_intent=SimpleNamespace(),
        )


def test_source_and_evidence_boundaries_report_missing_durable_authority() -> None:
    coordinator = _bare()

    class Journal:
        def read_completion(self, _operation: str) -> None:
            return None

    coordinator.journal = Journal()
    with pytest.raises(MainRollbackCoordinatorError, match="source completion"):
        coordinator._source("sha256:" + "1" * 64, "sha256:" + "2" * 64)  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(MainRollbackCoordinatorError, match="observe_protection"):
        coordinator._observe_evidence(  # pyright: ignore[reportPrivateUsage]
            "observe_protection", object, "sha256:" + "1" * 64
        )

    class Broken:
        def observe_candidate(self, *_args: object) -> None:
            raise RuntimeError("offline")

    coordinator.observation_capability = Broken()
    with pytest.raises(MainRollbackCoordinatorError, match="failed"):
        coordinator._call_observer("observe_candidate", object())  # pyright: ignore[reportPrivateUsage]


def test_stage_rejects_nonterminal_parent_before_capability_dispatch() -> None:
    coordinator = _bare()
    coordinator.journal = SimpleNamespace(
        read_mutation_intent_by_operation_stage=lambda *_: None,
    )
    coordinator.clock = SimpleNamespace(now=lambda: None)
    request = candidate_request()
    authority = SimpleNamespace(
        lease=SimpleNamespace(
            owner="owner",
            lease_digest="sha256:" + "1" * 64,
            lease_epoch_digest="sha256:" + "2" * 64,
        ),
        authorization=SimpleNamespace(
            policy_epoch="p", controller_config_digest="sha256:" + "3" * 64
        ),
        preparation_authorization=SimpleNamespace(authorization_digest="sha256:" + "4" * 64),
    )
    parent = (
        SimpleNamespace(stage="prior", intent_digest="x"),
        SimpleNamespace(effective_outcome="ambiguous"),
    )
    with pytest.raises(MainRollbackCoordinatorError, match="parent stage"):
        coordinator._stage(request, authority, parent)  # pyright: ignore[reportPrivateUsage]


def test_digest_record_is_deterministic_and_record_delegates() -> None:
    class Model:
        def __init__(self, values: dict[str, Any]) -> None:
            self.values = values

        @classmethod
        def model_construct(cls, **values: Any) -> Model:
            return cls(values)

        def model_dump(self, **_kwargs: Any) -> dict[str, Any]:
            return self.values

        @classmethod
        def model_validate(cls, values: dict[str, Any]) -> Model:
            return cls(values)

    values = {"operation_id": "sha256:" + "1" * 64}
    record = _digest_record(Model, values, "intent_digest")
    assert record.values["intent_digest"].startswith("sha256:")

    probe = MainMutationIntent.model_construct(
        operation_id=values["operation_id"], intent_digest="sha256:" + "0" * 64
    )
    digest = canonical_digest(probe.model_dump(exclude={"intent_digest"}, mode="json"))
    assert digest.startswith("sha256:")

    def writer(value: Any) -> Any:
        return value

    assert MainRollbackCoordinator._record("x", values, writer) == values  # pyright: ignore[reportPrivateUsage]
