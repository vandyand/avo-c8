# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportIndexIssue=false, reportUnnecessaryCast=false, reportPrivateUsage=false, reportMissingImports=false

"""High-yield fail-closed coverage for the C4 preparation coordinator.

These tests intentionally exercise the controller's boundary decisions with
the existing durable fixture.  They do not loosen policy or manufacture
authority records with ``model_construct``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from avo_correlate.application.c4_capabilities import CandidatePublicationResult
from avo_correlate.application.main_graduation_coordinator import (
    MainGraduationPreparationError,
    PreparationResult,
    _CaptureCapability,
    pr_candidate_ref_from_operation,
)
from avo_correlate.contracts.main_graduation import MainQueueConfigurationObservation
from tests.unit.test_main_graduation_coordinator_preparation import (
    MAIN_OPERATION,
    Provider,
    _coordinator,
    _fixture,
)


def test_result_terminal_and_deterministic_refs() -> None:
    operation = "sha256:" + "a" * 64
    for state in ("queued", "reconciliation_required", "quarantined"):
        assert PreparationResult(operation, state).terminal
    assert not PreparationResult(operation, "running").terminal
    assert pr_candidate_ref_from_operation(operation).endswith("a" * 64)


def test_capture_capability_exposes_only_one_method() -> None:
    provider = Provider("base", "tree", "candidate", "candidate-tree")
    capture = _CaptureCapability(provider, "publish_candidate")
    assert not hasattr(capture, "create_pull_request")
    request = object()
    with pytest.raises(MainGraduationPreparationError, match="provider does not implement"):
        _CaptureCapability(provider, "missing").missing(request)  # type: ignore[operator]


def test_prepare_quarantines_when_durable_authority_is_missing(tmp_path: Path) -> None:
    journal, provider = _fixture(tmp_path)
    result = _coordinator(journal, provider).prepare("sha256:" + "f" * 64)
    assert result.state == "quarantined"
    assert result.reason == "plan, preparation authorization, and lease are required"


def test_preflight_rejects_stale_main_and_invalid_queue_policy(tmp_path: Path) -> None:
    journal, provider = _fixture(tmp_path)
    provider.base = "0" * 40
    result = _coordinator(journal, provider).prepare(MAIN_OPERATION)
    assert result.state == "quarantined"
    assert result.reason == "protected main base is stale or changed"

    journal2, provider2 = _fixture(tmp_path / "policy")
    provider2.queue = provider2.queue.model_copy(
        update={"queue_configuration_digest": "sha256:" + "f" * 64}
    )
    result2 = _coordinator(journal2, provider2).prepare(MAIN_OPERATION)
    assert result2.state == "quarantined"
    assert result2.reason == "merge queue configuration is stale"


class _RejectedCandidateProvider(Provider):
    def publish_candidate(self, request: Any) -> CandidatePublicationResult:
        result = super().publish_candidate(request)
        return result.model_copy(update={"outcome": "rejected", "dispatch_started": False})


def test_prepare_returns_nonterminal_reconciliation_for_rejected_stage(tmp_path: Path) -> None:
    journal, provider = _fixture(tmp_path, _RejectedCandidateProvider)
    result = _coordinator(journal, provider).prepare(MAIN_OPERATION)
    assert result.state == "reconciliation_required"
    assert result.stage == "candidate_publication"
    assert result.reason == "rejected"


def test_provider_revalidation_and_verifier_fail_closed(tmp_path: Path) -> None:
    journal, provider = _fixture(tmp_path)
    coordinator = _coordinator(journal, provider)
    provider.observe_main = cast(Any, lambda: object())
    result = coordinator.prepare(MAIN_OPERATION)
    assert result.state == "quarantined"
    assert result.reason == "controller rejected provider main observation"

    class GenericAuthority:
        provider_identity = "fixture-provider"
        provider_api_version = "v1"

        def verify_stage_result(self, result: Any, request: Any, intent: Any) -> None:
            assert result.request_digest == request.request_digest
            assert result.external_identity == intent.external_identity.identity_digest

        def verify_stage_observation(self, result: Any, request: Any, intent: Any) -> None:
            assert result.request_digest == request.request_digest
            assert result.external_identity == request.external_identity

        def verify_provider_dto(self, kind: str, value: object) -> None:
            assert kind == "main"
            assert value is not None

    journal2, provider2 = _fixture(tmp_path / "generic")
    generic = _coordinator(journal2, provider2)
    generic.authority_verifier = GenericAuthority()
    generic._verify_provider_dto("main", provider2.observe_main())


def test_provider_observation_and_pr_identity_helpers_fail_closed(tmp_path: Path) -> None:
    journal, provider = _fixture(tmp_path)
    coordinator = _coordinator(journal, provider)
    with pytest.raises(MainGraduationPreparationError, match="number is invalid"):
        coordinator._pr_from_fields(0, provider.pr_url, "h", "t", "b", "bt")
    with pytest.raises(MainGraduationPreparationError, match="canonical same-repository"):
        coordinator._pr_from_fields(41, "https://evil.example/pull/41", "h", "t", "b", "bt")
    provider.repository_url = "relative"
    with pytest.raises(MainGraduationPreparationError, match="authority is missing"):
        coordinator._canonical_pr_url(41)


def test_queue_configuration_signature_variants_and_invalid_dto(tmp_path: Path) -> None:
    journal, provider = _fixture(tmp_path)
    coordinator = _coordinator(journal, provider)
    calls: list[str] = []

    def no_argument() -> MainQueueConfigurationObservation:
        calls.append("none")
        return provider.queue

    def with_argument(*, operation_id: str) -> MainQueueConfigurationObservation:
        calls.append(operation_id)
        return provider.queue

    assert coordinator._invoke_queue_configuration(no_argument, "ignored") == provider.queue
    assert coordinator._invoke_queue_configuration(with_argument, "op") == provider.queue
    assert calls == ["none", "op"]
    with pytest.raises(MainGraduationPreparationError, match="untyped"):
        coordinator._canonical_dto(object(), MainQueueConfigurationObservation)
