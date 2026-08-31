"""Focused negative tests for the capability-separated C4 executor boundary."""

from datetime import UTC, datetime
from typing import cast

import pytest
from pydantic import ValidationError

from avo_correlate.application.c4_capabilities import (
    AdmissionIssuerCapability,
    AdmissionIssueRequest,
    CandidatePublicationCapability,
    CandidatePublicationRequest,
    CandidatePublicationResult,
    GroupHoldIssuerCapability,
    GroupHoldIssueRequest,
    LeaseFence,
    PullRequestCreateResult,
    PullRequestPreparationCapability,
    PullRequestReconcileRequest,
    QueueEnqueueCapability,
    QueueEnqueueRequest,
    ReadOnlyObservationCapability,
    ReleaseIssuerCapability,
    ReleaseIssueRequest,
    TrustedClock,
)
from avo_correlate.contracts.main_graduation import MainMutationStage, main_stage_identity_digest
from avo_correlate.domain.canonical import canonical_digest

DIGEST = "sha256:" + "a" * 64
OBJECT = "a" * 40


def stage_identity(stage: str, key: str, queue: str | None = None) -> str:
    return main_stage_identity_digest(
        DIGEST,
        cast(MainMutationStage, stage),
        key,
        queue_generation_digest=queue,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
    )


def test_capabilities_are_disjoint_and_have_no_merge_or_ref_surface() -> None:
    assert "publish_candidate" in CandidatePublicationCapability.__dict__
    assert "create_pull_request" in PullRequestPreparationCapability.__dict__
    assert "enqueue" in QueueEnqueueCapability.__dict__
    assert "issue_admission" in AdmissionIssuerCapability.__dict__
    assert "issue_group_hold" in GroupHoldIssuerCapability.__dict__
    assert "issue_release" in ReleaseIssuerCapability.__dict__
    assert "merge" not in ReadOnlyObservationCapability.__dict__
    assert "update_main_ref" not in ReadOnlyObservationCapability.__dict__
    assert "issue_release" not in AdmissionIssuerCapability.__dict__
    assert "enqueue" not in ReleaseIssuerCapability.__dict__


def test_candidate_ref_and_preparation_authorization_are_bound() -> None:
    values = dict(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        lease_epoch_digest=DIGEST,
        external_key="candidate-publication",
        candidate_ref="refs/heads/wrong",
        candidate_commit=OBJECT,
        preparation_authorization_digest=DIGEST,
    )
    with pytest.raises(ValidationError):
        CandidatePublicationRequest.build(**values)
    request = CandidatePublicationRequest.build(
        **{**values, "candidate_ref": f"refs/heads/avo/candidate/{'a' * 64}"}
    )
    assert request.preparation_authorization_digest == DIGEST


def test_request_digest_is_required_and_self_binding() -> None:
    values = dict(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        lease_epoch_digest=DIGEST,
        external_key="candidate-publication",
        candidate_ref=f"refs/heads/avo/candidate/{'a' * 64}",
        candidate_commit=OBJECT,
        preparation_authorization_digest=DIGEST,
    )
    request = CandidatePublicationRequest.build(**values)
    with pytest.raises(ValidationError):
        CandidatePublicationRequest.model_validate(
            {**request.model_dump(), "request_digest": DIGEST}
        )
    assert request.request_digest != DIGEST


def test_pr_create_and_reconcile_are_dedicated_exact_models() -> None:
    assert "pull_request_number" not in CandidatePublicationRequest.model_fields
    assert "pull_request_number" not in PullRequestPreparationCapability.__dict__
    with pytest.raises(ValidationError):
        PullRequestReconcileRequest.model_validate(
            dict(
                operation_id=DIGEST,
                repository_digest=DIGEST,
                lease_epoch_digest=DIGEST,
                request_digest=DIGEST,
                pull_request_number="9",
                candidate_ref="candidate",
                head_commit=OBJECT,
                base_commit="b" * 40,
                repository_name="org/repo",
            )
        )


def test_admission_rejects_validation_app_and_requires_queue_identity() -> None:
    values = dict(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        lease_epoch_digest=DIGEST,
        external_key="admission",
        preparation_authorization_digest=DIGEST,
        pull_request_number=9,
        pull_request_head=OBJECT,
        pull_request_tree="b" * 40,
        base_commit="c" * 40,
        base_tree="d" * 40,
        admission_run_id="run",
        admission_nonce="nonce",
        issuer_identity="validation",
        issuer_app_id=15368,
        issuer_isolation_digest=DIGEST,
        queue_generation_digest=DIGEST,
    )
    with pytest.raises(ValidationError):
        AdmissionIssueRequest.build(**values)


def test_mutation_result_rejects_wrong_external_identity() -> None:
    request = CandidatePublicationRequest.build(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        lease_epoch_digest=DIGEST,
        candidate_ref=f"refs/heads/avo/candidate/{'a' * 64}",
        candidate_commit=OBJECT,
        preparation_authorization_digest=DIGEST,
    )
    with pytest.raises(ValidationError):
        CandidatePublicationResult.model_validate(
            {
                **request.model_dump(),
                "external_identity": DIGEST,
                "outcome": "applied",
                "response_digest": DIGEST,
                "observed_at": datetime.now(UTC),
                "dispatch_started": True,
            }
        )


def _group_values() -> dict[str, object]:
    base = "b" * 40
    head = "c" * 40
    head_tree = "d" * 40
    group = "e" * 40
    group_tree = "f" * 40
    queue = DIGEST
    parents = [base, head]
    return dict(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        lease_epoch_digest=DIGEST,
        queue_generation_digest=queue,
        admission_observation_digest=DIGEST,
        pull_request_number=9,
        pull_request_head=head,
        pull_request_tree=head_tree,
        group_sha=group,
        group_tree=group_tree,
        expected_group_tree=group_tree,
        group_parents=parents,
        expected_group_parents=parents,
        group_topology_digest=canonical_digest(
            {
                "base_commit": base,
                "base_tree": "1" * 40,
                "pull_request_number": 9,
                "pull_request_head": head,
                "pull_request_tree": head_tree,
                "expected_group_parents": parents,
                "expected_group_tree": group_tree,
                "queue_generation_digest": queue,
                "merge_method": "squash",
            }
        ),
        base_commit=base,
        base_tree="1" * 40,
        queue_members=[9],
        hold_run_id="run",
        hold_nonce="nonce",
        issuer_identity="isolated",
        issuer_app_id=99,
        issuer_isolation_digest=DIGEST,
    )


def test_group_hold_binds_full_pending_topology_and_rejects_pr_head_reuse() -> None:
    values = _group_values()
    hold = GroupHoldIssueRequest.build(**values)
    assert hold.check_conclusion == "pending"
    with pytest.raises(ValidationError):
        GroupHoldIssueRequest.build(**{**values, "group_sha": values["pull_request_head"]})
    with pytest.raises(ValidationError):
        GroupHoldIssueRequest.build(**{**values, "queue_members": [10]})
    with pytest.raises(ValidationError):
        GroupHoldIssueRequest.build(**{**values, "group_tree": "0" * 40})


def test_release_binds_pending_hold_and_success_transition() -> None:
    values = _group_values()
    release = ReleaseIssueRequest.build(
        **{
            **values,
            "hold_observation_digest": DIGEST,
            "release_authorization_digest": DIGEST,
            "release_claim_digest": DIGEST,
            "authorization_expires_at": datetime.now(UTC),
        }
    )
    assert release.pending_check_conclusion == "pending"
    with pytest.raises(ValidationError):
        ReleaseIssueRequest.build(
            **{
                **release.model_dump(
                    exclude={"external_key", "external_identity", "request_digest"}
                ),
                "issuer_app_id": 15368,
            }
        )
    with pytest.raises(ValidationError):
        ReleaseIssueRequest.build(
            **{
                **release.model_dump(
                    exclude={"external_key", "external_identity", "request_digest"}
                ),
                "group_tree": "0" * 40,
            }
        )


def test_create_result_server_identity_binds_queue_request() -> None:
    pull_request_url = "https://example.test/org/repo/pull/9"
    pull_request_identity = canonical_digest(
        {
            "operation_id": DIGEST,
            "repository_digest": DIGEST,
            "pull_request_number": 9,
            "pull_request_url": pull_request_url,
        }
    )
    result_values = dict(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        lease_epoch_digest=DIGEST,
        stage="pull_request_open",
        queue_generation_digest=None,
        candidate_ref=f"refs/heads/avo/candidate/{'a' * 64}",
        candidate_commit=OBJECT,
        candidate_tree="b" * 40,
        base_commit="c" * 40,
        base_tree="d" * 40,
        preparation_authorization_digest=DIGEST,
        pull_request_number=9,
        pull_request_url=pull_request_url,
        pull_request_identity=pull_request_identity,
        outcome="applied",
        response_digest=DIGEST,
        observed_at=datetime.now(UTC),
        dispatch_started=True,
    )
    result = PullRequestCreateResult.build(**result_values)

    queue = QueueEnqueueRequest.build(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        lease_epoch_digest=DIGEST,
        queue_generation_digest=DIGEST,
        pull_request_number=result.pull_request_number,
        pull_request_url=result.pull_request_url,
        pull_request_identity=result.pull_request_identity,
        pull_request_head=result.candidate_commit,
        pull_request_tree=result.candidate_tree,
        base_commit=result.base_commit,
        base_tree=result.base_tree,
        preparation_authorization_digest=DIGEST,
        admission_observation_digest=DIGEST,
    )
    assert queue.pull_request_identity == result.pull_request_identity
    with pytest.raises(ValidationError):
        QueueEnqueueRequest.build(
            **{
                **queue.model_dump(exclude={"external_key", "external_identity", "request_digest"}),
                "pull_request_identity": DIGEST,
            }
        )


def test_trusted_clock_and_lease_fence_are_explicit_seams() -> None:
    assert "now" in TrustedClock.__dict__
    assert "assert_current" in LeaseFence.__dict__
