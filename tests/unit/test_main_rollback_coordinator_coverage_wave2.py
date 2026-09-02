"""Second non-overlapping branch wave for the rollback aggregate coordinator."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportUnknownMemberType=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false, reportMissingImports=false, reportUntypedBaseClass=false, reportUntypedFunctionDecorator=false, reportUnusedImport=false, reportUnknownLambdaType=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import BaseModel, ConfigDict

from avo_correlate.application.main_rollback_coordinator import (
    MainRollbackCoordinator,
    MainRollbackCoordinatorError,
)
from avo_correlate.contracts.main_graduation import MainReleaseAuthorization
from avo_correlate.contracts.main_graduation_phase_a import MainReleaseClaim
from avo_correlate.domain.canonical import canonical_digest

NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportUnknownMemberType=false, reportArgumentType=false, reportCallIssue=false

D = "sha256:" + "a" * 64
BASE = "a" * 40
TREE = "b" * 40
GROUP = "c" * 40
MERGE_GROUP = "d" * 40


class _Hold(BaseModel):
    model_config = ConfigDict(extra="allow")
    group_sha: str = MERGE_GROUP
    group_tree: str = BASE
    group_parents: list[str] = [BASE]
    expected_group_parents: list[str] = [BASE]
    group_topology_digest: str = D
    hold_run_id: str = "hold-run"
    hold_nonce: str = "hold-nonce"
    queue_generation_digest: str = D
    pull_request_number: int = 7
    issuer_identity: str = "release"
    release_issuer_app_id: int = 9001
    issuer_isolation_digest: str = D
    admission_observation_digest: str = D
    base_commit: str = BASE
    base_tree: str = TREE
    queue_members: list[int] = [7]


def _coordinator(journal: Any) -> MainRollbackCoordinator:
    coordinator = object.__new__(MainRollbackCoordinator)
    coordinator.journal = journal
    coordinator.clock = SimpleNamespace(now=lambda: NOW)
    coordinator.authority_verifier = SimpleNamespace()
    coordinator.authorization_ttl = timedelta(minutes=5)
    return coordinator


def _authority_and_hold(tmp_path: Any) -> tuple[Any, Any, MainRollbackCoordinator]:
    del tmp_path
    intent = SimpleNamespace(
        source_operation_id=D,
        repository_digest=D,
        target_ref="refs/heads/main",
        completion_package_digest=D,
        candidate_commit=GROUP,
        candidate_tree=BASE,
    )
    authorization = SimpleNamespace(
        policy_epoch=D,
        authorization_digest=D,
    )
    lease = SimpleNamespace(
        owner="rollback-controller",
        lease_digest=D,
        lease_epoch_digest=D,
        expires_at=NOW + timedelta(minutes=10),
    )
    preparation = SimpleNamespace(
        authorization_digest=D,
        composition_digest=D,
    )
    authority = SimpleNamespace(
        operation_id=D,
        intent=intent,
        authorization=authorization,
        lease=lease,
        preparation_authorization=preparation,
        composition=SimpleNamespace(composition_id=D, candidate_commit=GROUP, candidate_tree=BASE),
    )
    return authority, _Hold(), _coordinator(SimpleNamespace())


def _release_auth(authority: Any, hold: Any) -> MainReleaseAuthorization:
    values: dict[str, Any] = {
        "operation_id": authority.operation_id,
        "repository_digest": authority.intent.repository_digest,
        "target_ref": authority.intent.target_ref,
        "preparation_authorization_digest": (
            authority.preparation_authorization.authorization_digest
        ),
        "admission_observation_digest": hold.admission_observation_digest,
        "hold_observation_digest": canonical_digest(hold),
        "package_digest": authority.intent.completion_package_digest,
        "composition_digest": authority.preparation_authorization.composition_digest,
        "group_sha": hold.group_sha,
        "hold_run_id": hold.hold_run_id,
        "hold_nonce": hold.hold_nonce,
        "queue_generation_digest": hold.queue_generation_digest,
        "lease_identity": authority.lease.owner,
        "lease_digest": authority.lease.lease_digest,
        "policy_epoch": authority.authorization.policy_epoch,
        "release_issuer_identity": hold.issuer_identity,
        "release_issuer_app_id": hold.release_issuer_app_id,
        "issuer_isolation_digest": hold.issuer_isolation_digest,
        "expires_at": NOW + timedelta(minutes=5),
        "authorized_at": NOW,
    }
    probe = MainReleaseAuthorization.model_construct(**values, authorization_digest=D)
    values["authorization_digest"] = canonical_digest(
        probe.model_dump(exclude={"authorization_digest"}, mode="json")
    )
    return MainReleaseAuthorization.model_validate(values)


def test_release_claim_is_created_once_then_adopted(tmp_path: Any) -> None:
    authority, hold, coordinator = _authority_and_hold(tmp_path)
    auth = _release_auth(authority, hold)
    journal = SimpleNamespace(read_release_claim_for_authorization=lambda *_: None)
    coordinator.journal = journal
    claim = coordinator._release_claim(authority, authority.lease, hold, auth)  # type: ignore[reportPrivateUsage]
    assert isinstance(claim, MainReleaseClaim)

    coordinator.journal = SimpleNamespace(
        read_release_claim_for_authorization=lambda *_: (claim, None)
    )
    assert coordinator._release_claim(authority, authority.lease, hold, auth) == claim  # type: ignore[reportPrivateUsage]


def test_release_authorizer_and_request_are_typed_and_bound(tmp_path: Any) -> None:
    authority, hold, coordinator = _authority_and_hold(tmp_path)
    auth = _release_auth(authority, hold)

    class Authorizer:
        def authorize_release(self, **_: Any) -> Any:
            return auth

    coordinator.release_authorizer = Authorizer()
    assert (
        coordinator._release_authorization(authority, authority.lease, hold).authorization_digest
        == auth.authorization_digest
    )  # type: ignore[reportPrivateUsage]
    coordinator.journal = SimpleNamespace(read_release_claim_for_authorization=lambda *_: None)
    claim = coordinator._release_claim(authority, authority.lease, hold, auth)  # type: ignore[reportPrivateUsage]
    request = coordinator._release_request(authority, authority.lease, hold, auth, claim)  # type: ignore[reportPrivateUsage]
    assert request.release_claim_digest == claim.claim_digest

    coordinator.release_authorizer = SimpleNamespace(authorize_release=lambda **_: object())
    with pytest.raises(MainRollbackCoordinatorError, match="untyped"):
        coordinator._release_authorization(authority, authority.lease, hold)  # type: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    ("mutation_outcome", "resolution", "expected", "has_claim"),
    [
        ("applied", None, "transitioned", True),
        ("already_applied", None, "already_transitioned", True),
        ("reconciliation_required", None, "reconciliation_required", False),
    ],
)
def test_transition_records_classifies_provider_outcomes(
    tmp_path: Any,
    mutation_outcome: str,
    resolution: Any,
    expected: str,
    has_claim: bool,
) -> None:
    authority, hold, coordinator = _authority_and_hold(tmp_path)
    auth = _release_auth(authority, hold)
    claim = SimpleNamespace(claim_digest=D)
    mutation = SimpleNamespace(
        outcome=mutation_outcome,
        response_digest=D,
        observed_at=NOW,
        receipt_digest=D,
    )
    coordinator.journal = SimpleNamespace(
        record_release_transition=lambda value: value,
        record_claimed_release_transition=lambda value: value,
    )
    if resolution is not None:
        resolution = SimpleNamespace(
            outcome="observed", observed_outcome="applied", resolution_digest=D
        )
    effective = SimpleNamespace(receipt=mutation, authoritative_resolution=resolution)
    transition, claimed = coordinator._transition_records(  # type: ignore[reportPrivateUsage]
        authority, hold, auth, claim, (None, effective)
    )
    assert transition.outcome == expected
    assert (claimed is not None) is has_claim


def test_transition_resolution_can_authoritatively_complete_reconciliation(tmp_path: Any) -> None:
    authority, hold, coordinator = _authority_and_hold(tmp_path)
    auth = _release_auth(authority, hold)
    claim = SimpleNamespace(claim_digest=D)
    mutation = SimpleNamespace(
        outcome="reconciliation_required", response_digest=D, observed_at=NOW, receipt_digest=D
    )
    resolution = SimpleNamespace(
        outcome="observed", observed_outcome="applied", resolution_digest=D
    )
    coordinator.journal = SimpleNamespace(
        record_release_transition=lambda value: value,
        record_claimed_release_transition=lambda value: value,
    )
    _transition, claimed = coordinator._transition_records(  # type: ignore[reportPrivateUsage]
        authority,
        hold,
        auth,
        claim,
        (None, SimpleNamespace(receipt=mutation, authoritative_resolution=resolution)),
    )
    assert claimed is not None


def test_small_result_poststate_and_artifact_boundaries_fail_closed(tmp_path: Any) -> None:
    authority, _hold, coordinator = _authority_and_hold(tmp_path)
    coordinator.result_builder = None
    with pytest.raises(MainRollbackCoordinatorError, match="result builder"):
        coordinator._rollback_result(authority, object(), object())  # type: ignore[reportPrivateUsage]
    coordinator.result_builder = SimpleNamespace()
    with pytest.raises(MainRollbackCoordinatorError, match="seam"):
        coordinator._rollback_result(authority, object(), object())  # type: ignore[reportPrivateUsage]

    coordinator.observation_capability = SimpleNamespace()
    with pytest.raises(MainRollbackCoordinatorError, match="post-state"):
        coordinator._post_state(authority, object())  # type: ignore[reportPrivateUsage]

    coordinator.journal = SimpleNamespace()
    with pytest.raises(MainRollbackCoordinatorError, match="artifact store"):
        coordinator._rollback_ref("x", cast(Any, object()))  # type: ignore[reportPrivateUsage]


def test_cleanup_intent_requires_distinct_bound_principals(tmp_path: Any) -> None:
    authority, _hold, coordinator = _authority_and_hold(tmp_path)
    result = SimpleNamespace(
        completion_package_digest=authority.intent.completion_package_digest,
        receipt_digest=D,
    )
    coordinator.cleanup_capability = None
    with pytest.raises(MainRollbackCoordinatorError, match="cleanup capability"):
        coordinator._cleanup_intent(authority, result, SimpleNamespace(number=7, url="url"))  # type: ignore[reportPrivateUsage]

    coordinator.cleanup_capability = SimpleNamespace()
    coordinator.observation_capability = SimpleNamespace()
    with pytest.raises(MainRollbackCoordinatorError, match="principal"):
        coordinator._cleanup_intent(authority, result, SimpleNamespace(number=7, url="url"))  # type: ignore[reportPrivateUsage]


def test_cleanup_terminal_and_named_verifier_edges_are_explicit(tmp_path: Any) -> None:
    _authority, _hold, coordinator = _authority_and_hold(tmp_path)
    with pytest.raises(MainRollbackCoordinatorError, match="missing"):
        coordinator._verify_named("verify_any", object())  # type: ignore[reportPrivateUsage]
    coordinator.authority_verifier = SimpleNamespace(verify_any=lambda value: value)
    assert coordinator._verify_named("verify_any", object()) is None  # type: ignore[reportPrivateUsage]
    assert (
        coordinator._reconcile(D, "release_transition", SimpleNamespace(outcome="ambiguous")).reason
        == "ambiguous"
    )  # type: ignore[reportPrivateUsage]
