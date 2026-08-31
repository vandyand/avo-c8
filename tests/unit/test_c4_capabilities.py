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
    GroupHoldIssuerCapability,
    LeaseFence,
    MutationResult,
    PullRequestPreparationCapability,
    PullRequestReconcileRequest,
    QueueEnqueueCapability,
    ReadOnlyObservationCapability,
    ReleaseIssuerCapability,
    TrustedClock,
)
from avo_correlate.contracts.main_graduation import MainMutationStage, main_stage_identity_digest

DIGEST = "sha256:" + "a" * 64
OBJECT = "a" * 40


def stage_identity(stage: str, key: str, queue: str | None = None) -> str:
    return main_stage_identity_digest(
        DIGEST, cast(MainMutationStage, stage), key, queue_generation_digest=queue,
        repository_digest=DIGEST, target_ref="refs/heads/main",
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
        operation_id=DIGEST, repository_digest=DIGEST, lease_epoch_digest=DIGEST,
        external_key="candidate-publication", candidate_ref="refs/heads/wrong",
        candidate_commit=OBJECT, preparation_authorization_digest=DIGEST,
    )
    with pytest.raises(ValidationError):
        CandidatePublicationRequest.build(**values)
    request = CandidatePublicationRequest.build(
        **{**values, "candidate_ref": f"refs/heads/avo/candidate/{'a' * 64}"}
    )
    assert request.preparation_authorization_digest == DIGEST


def test_request_digest_is_required_and_self_binding() -> None:
    values = dict(
        operation_id=DIGEST, repository_digest=DIGEST, lease_epoch_digest=DIGEST,
        external_key="candidate-publication",
        candidate_ref=f"refs/heads/avo/candidate/{'a' * 64}",
        candidate_commit=OBJECT, preparation_authorization_digest=DIGEST,
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
                operation_id=DIGEST, repository_digest=DIGEST, lease_epoch_digest=DIGEST,
                request_digest=DIGEST, pull_request_number="9", candidate_ref="candidate",
                head_commit=OBJECT, base_commit="b" * 40, repository_name="org/repo",
            )
        )


def test_admission_rejects_validation_app_and_requires_queue_identity() -> None:
    values = dict(
        operation_id=DIGEST, repository_digest=DIGEST, lease_epoch_digest=DIGEST,
        external_key="admission", preparation_authorization_digest=DIGEST,
        pull_request_number=9, pull_request_head=OBJECT, admission_run_id="run",
        admission_nonce="nonce", issuer_identity="validation", issuer_app_id=15368,
        issuer_isolation_digest=DIGEST, queue_generation_digest=DIGEST,
    )
    with pytest.raises(ValidationError):
        AdmissionIssueRequest.build(**values)


def test_mutation_result_rejects_wrong_external_identity() -> None:
    common = dict(
        operation_id=DIGEST, repository_digest=DIGEST, stage="candidate_publication",
        request_digest=DIGEST, external_key="candidate-publication", external_identity=DIGEST,
        outcome="applied", response_digest=DIGEST, observed_at=datetime.now(UTC),
        dispatch_started=True,
    )
    with pytest.raises(ValidationError):
        MutationResult.model_validate(common)


def test_trusted_clock_and_lease_fence_are_explicit_seams() -> None:
    assert "now" in TrustedClock.__dict__
    assert "assert_current" in LeaseFence.__dict__
