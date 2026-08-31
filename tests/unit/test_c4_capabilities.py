"""Focused tests for the capability-separated C4 executor boundary."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from avo_correlate.application.c4_capabilities import (
    AdmissionIssuerCapability,
    CandidatePublicationCapability,
    CandidatePublicationRequest,
    GroupHoldIssuerCapability,
    LeaseFence,
    MutationResult,
    ObservationRequest,
    PullRequestPreparationCapability,
    QueueEnqueueCapability,
    ReadOnlyObservationCapability,
    ReleaseIssuerCapability,
    TrustedClock,
)

DIGEST = "sha256:" + "a" * 64
OBJECT = "a" * 40


def test_capabilities_have_one_distinct_mutation_surface() -> None:
    assert set(CandidatePublicationCapability.__dict__) >= {"publish_candidate"}
    assert set(PullRequestPreparationCapability.__dict__) >= {"prepare_pull_request"}
    assert set(QueueEnqueueCapability.__dict__) >= {"enqueue"}
    assert set(AdmissionIssuerCapability.__dict__) >= {"issue_admission"}
    assert set(GroupHoldIssuerCapability.__dict__) >= {"issue_group_hold"}
    assert set(ReleaseIssuerCapability.__dict__) >= {"issue_release"}
    assert "merge" not in ReadOnlyObservationCapability.__dict__
    assert "update_main_ref" not in ReadOnlyObservationCapability.__dict__
    assert "issue_release" not in AdmissionIssuerCapability.__dict__
    assert "enqueue" not in ReleaseIssuerCapability.__dict__


def test_requests_bind_to_protected_main_and_reject_coercion() -> None:
    request = CandidatePublicationRequest(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        lease_epoch_digest=DIGEST,
        request_digest=DIGEST,
        candidate_ref="refs/heads/avo/candidate/attempt",
        candidate_commit=OBJECT,
        publication_identity=DIGEST,
    )
    assert request.target_ref == "refs/heads/main"
    with pytest.raises(ValidationError):
        CandidatePublicationRequest.model_validate(
            {
                "operation_id": DIGEST,
                "repository_digest": DIGEST,
                "target_ref": "refs/heads/other",
                "lease_epoch_digest": DIGEST,
                "request_digest": DIGEST,
                "candidate_ref": "refs/heads/avo/candidate/attempt",
                "candidate_commit": OBJECT,
                "publication_identity": DIGEST,
            }
        )


def test_mutation_outcomes_enforce_dispatch_semantics_and_strict_identity() -> None:
    common: dict[str, object] = {
        "operation_id": DIGEST,
        "repository_digest": DIGEST,
        "external_identity": DIGEST,
        "response_digest": DIGEST,
        "observed_at": datetime.now(UTC),
    }
    result = MutationResult.model_validate(
        {**common, "outcome": "ambiguous", "dispatch_started": True}
    )
    assert result.outcome == "ambiguous"
    with pytest.raises(ValidationError):
        MutationResult.model_validate({**common, "outcome": "rejected", "dispatch_started": True})
    with pytest.raises(ValidationError):
        MutationResult.model_validate({**common, "outcome": "applied", "dispatch_started": "yes"})


def test_read_only_observation_requires_exact_kind_and_identity() -> None:
    observation = ObservationRequest(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        lease_epoch_digest=DIGEST,
        request_digest=DIGEST,
        external_identity=DIGEST,
        object_kind="group_hold",
        object_key="hold:one",
    )
    assert observation.object_kind == "group_hold"
    with pytest.raises(ValidationError):
        ObservationRequest(
            operation_id=DIGEST,
            repository_digest=DIGEST,
            lease_epoch_digest=DIGEST,
            request_digest=DIGEST,
            external_identity="not-a-digest",
            object_kind="group_hold",
            object_key="hold:one",
        )


def test_clock_and_fence_are_injected_protocol_seams() -> None:
    assert "assert_current" in LeaseFence.__dict__
    assert "now" in TrustedClock.__dict__
