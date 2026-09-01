from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar

import pytest
from pydantic import ValidationError

from avo_correlate.contracts.base import ArtifactRef, StrictModel
from avo_correlate.contracts.main_graduation_ledger import (
    MainLedgerAccumulatorState,
    MainLedgerAccumulatorTransition,
    MainLedgerActivation,
    MainLedgerBoundaryResetTransition,
    MainLedgerBoundaryViolationEvidence,
    MainLedgerC8CapabilityEvidence,
    MainLedgerClassificationEvidence,
    MainLedgerControllerAuthority,
    MainLedgerEvidencePackage,
    MainLedgerHostedRollbackProof,
    MainLedgerSubmissionEnvelope,
    MainLedgerTerminalOutcome,
    main_ledger_genesis_state,
)
from avo_correlate.domain.canonical import canonical_digest

DIGEST = "sha256:" + "1" * 64
NOW = datetime(2026, 9, 1, tzinfo=UTC)
ModelT = TypeVar("ModelT", bound=StrictModel)


def _artifact(role: str, media_type: str, digest: str = DIGEST) -> ArtifactRef:
    return ArtifactRef(
        digest=digest,
        size_bytes=1,
        media_type=media_type,
        role=role,
        created_at=NOW - timedelta(minutes=1),
    )


def _with_digest(model_type: type[ModelT], values: dict[str, Any], field: str) -> ModelT:  # noqa: UP047
    base_values = {key: value for key, value in values.items() if key != field}
    probe = model_type.model_construct(  # pyright: ignore[reportArgumentType]
        **base_values,  # pyright: ignore[reportArgumentType]
        **{field: DIGEST},  # pyright: ignore[reportArgumentType]
    )
    return model_type.model_validate(
        {**values, field: canonical_digest(probe.model_dump(exclude={field}, mode="json"))}
    )


def _activation() -> MainLedgerActivation:
    authority = _with_digest(
        MainLedgerControllerAuthority,
        {
            "repository_digest": DIGEST,
            "protocol_digest": DIGEST,
            "controller_config_digest": DIGEST,
            "policy_digest": DIGEST,
            "policy_epoch": DIGEST,
            "issuer_identity": "ledger-controller",
            "issuer_authority_digest": DIGEST,
            "authorized_at": NOW - timedelta(minutes=5),
            "expires_at": NOW + timedelta(hours=1),
        },
        "authority_digest",
    )
    proof = _with_digest(
        MainLedgerHostedRollbackProof,
        {
            "operation_id": DIGEST,
            "repository_digest": DIGEST,
            "proof_artifact_digest": DIGEST,
            "controller_authority_digest": authority.authority_digest,
            "rollback_authority_identity": "main-rollback-authority",
            "rollback_authority_digest": DIGEST,
            "result_evidence_digest": DIGEST,
            "completed_at": NOW - timedelta(minutes=1),
        },
        "proof_digest",
    )
    capability = _with_digest(
        MainLedgerC8CapabilityEvidence,
        {
            "repository_digest": DIGEST,
            "controller_authority_digest": authority.authority_digest,
            "hosting_authority_identity": "org-hosting",
            "queue_configuration_digest": DIGEST,
            "queue_generation_digest": DIGEST,
            "release_issuer_identity": "isolated-release",
            "release_issuer_app_id": 9001,
            "release_issuer_authority_digest": DIGEST,
            "observed_at": NOW,
        },
        "evidence_digest",
    )
    values = {
        "repository_digest": DIGEST,
        "protocol_digest": DIGEST,
        "controller_config_digest": DIGEST,
        "policy_digest": DIGEST,
        "policy_epoch": DIGEST,
        "controller_issuer_identity": "ledger-controller",
        "controller_issuer_authority_digest": DIGEST,
        "scheduler_sequence_watermark": 10,
        "controller_authority": authority,
        "freshness_cutoff": NOW - timedelta(minutes=2),
        "hosted_rollback_proof": proof,
        "c8_capability_evidence": capability,
        "hosted_rollback_proof_digest": proof.proof_digest,
        "hosted_rollback_artifact_digest": proof.proof_artifact_digest,
        "rollback_authority_identity": "main-rollback-authority",
        "rollback_authority_digest": DIGEST,
        "c8_capability_evidence_digest": capability.evidence_digest,
        "activated_at": NOW,
    }
    return _with_digest(MainLedgerActivation, values, "activation_digest")


def _submission(
    activation: MainLedgerActivation,
    sequence: int = 11,
    submission_identity: str | None = None,
) -> MainLedgerSubmissionEnvelope:
    identity = submission_identity or f"submission-{sequence}"
    values = {
        "activation_digest": activation.activation_digest,
        "repository_digest": activation.repository_digest,
        "scheduler_sequence": sequence,
        "source_identity": "scheduler",
        "submission_identity": identity,
        "submission_digest": DIGEST,
        "content_artifact": _artifact(
            "scheduler-submission-content", "application/vnd.avo.scheduler-submission+json"
        ),
        "operation_id": canonical_digest(
            {
                "domain": "avo.main.ledger.submission.v2",
                "activation_digest": activation.activation_digest,
                "scheduler_sequence": sequence,
                "source_identity": "scheduler",
                "submission_identity": identity,
                "submission_digest": DIGEST,
            }
        ),
        "recorded_at": NOW,
    }
    return _with_digest(MainLedgerSubmissionEnvelope, values, "envelope_digest")


def test_raw_legacy_or_missing_discriminator_fails_closed() -> None:
    with pytest.raises(ValidationError):
        MainLedgerTerminalOutcome.model_validate(
            {
                "schema_version": 1,
                "activation_digest": DIGEST,
                "submission_digest": DIGEST,
                "classification_digest": DIGEST,
                "operation_id": DIGEST,
                "attempt_id": DIGEST,
                "scheduler_sequence": 11,
                "outcome": "success",
                "terminal_evidence_digest": DIGEST,
                "terminal_at": NOW,
                "outcome_digest": DIGEST,
            }
        )


def test_activation_and_submission_forgery_is_rejected() -> None:
    activation = _activation()
    with pytest.raises(ValidationError, match="activation configuration"):
        MainLedgerActivation.model_validate(
            {**activation.model_dump(), "policy_epoch": DIGEST[:-1] + "2"}
        )


def test_activation_rejects_stale_hosted_prerequisites() -> None:
    activation = _activation()
    with pytest.raises(ValidationError, match="hosted rollback proof"):
        MainLedgerActivation.model_validate({**activation.model_dump(), "freshness_cutoff": NOW})
    stale_capability = _with_digest(
        MainLedgerC8CapabilityEvidence,
        {
            **activation.c8_capability_evidence.model_dump(),
            "observed_at": NOW - timedelta(minutes=3),
        },
        "evidence_digest",
    )
    with pytest.raises(ValidationError, match="C8 capability evidence"):
        MainLedgerActivation.model_validate(
            {
                **activation.model_dump(),
                "c8_capability_evidence": stale_capability,
                "c8_capability_evidence_digest": stale_capability.evidence_digest,
                "freshness_cutoff": NOW - timedelta(minutes=1),
            }
        )
    with pytest.raises(ValidationError, match="identity mismatch"):
        MainLedgerSubmissionEnvelope.model_validate(
            {**_submission(activation).model_dump(), "source_identity": "forged"}
        )


def test_classification_excludes_only_independently_proven_empty_or_nonordinary() -> None:
    activation = _activation()
    common: dict[str, Any] = {
        "activation_digest": activation.activation_digest,
        "submission_digest": DIGEST,
        "operation_id": DIGEST,
        "scheduler_sequence": 11,
        "empty": True,
        "ordinary": True,
        "paths": [],
        "path_manifest_digest": canonical_digest([]),
        "policy_digest": activation.policy_digest,
        "policy_epoch": activation.policy_epoch,
        "issuer_identity": "ledger-controller",
        "issuer_authority_digest": DIGEST,
        "classification": "excluded",
        "risk_class": "ordinary",
        "controller_authority": activation.controller_authority,
        "exclusion_reason": "empty",
        "independent_exclusion_evidence_digest": DIGEST,
        "independent_exclusion_evidence": _artifact(
            "ledger-classification-exclusion-evidence",
            "application/vnd.avo.ledger-exclusion-evidence+json",
        ),
    }
    good = _with_digest(MainLedgerClassificationEvidence, common, "classification_digest")
    assert good.classification == "excluded"
    with pytest.raises(ValidationError, match="empty flag"):
        _with_digest(
            MainLedgerClassificationEvidence,
            {**common, "empty": False, "ordinary": True},
            "classification_digest",
        )


def test_accumulator_is_exact_at_11_and_12_and_resets_non_success() -> None:
    activation = _activation()
    prior_values = {
        "activation_digest": activation.activation_digest,
        "last_scheduler_sequence": 10,
        "streak": 11,
        "successes": 11,
        "failures": 0,
        "boundary_violations": 0,
        "threshold_complete": False,
    }
    prior = _with_digest(MainLedgerAccumulatorState, prior_values, "state_digest")
    with pytest.raises(ValidationError, match="threshold completion"):
        MainLedgerAccumulatorState.model_validate(
            {**prior.model_dump(), "streak": 12, "threshold_complete": False}
        )


def test_accumulator_transition_rejects_gap_and_forged_outcome_binding() -> None:
    activation = _activation()
    prior = _with_digest(
        MainLedgerAccumulatorState,
        {
            "activation_digest": activation.activation_digest,
            "last_scheduler_sequence": 10,
            "streak": 0,
            "successes": 0,
            "failures": 0,
            "boundary_violations": 0,
            "threshold_complete": False,
        },
        "state_digest",
    )
    classification = _with_digest(
        MainLedgerClassificationEvidence,
        {
            "activation_digest": activation.activation_digest,
            "submission_digest": DIGEST,
            "operation_id": DIGEST,
            "scheduler_sequence": 12,
            "classification": "eligible",
            "empty": False,
            "ordinary": True,
            "risk_class": "ordinary",
            "paths": ["src/feature.py"],
            "path_manifest_digest": canonical_digest(["src/feature.py"]),
            "policy_digest": activation.policy_digest,
            "policy_epoch": activation.policy_epoch,
            "controller_authority": activation.controller_authority,
            "issuer_identity": "ledger-controller",
            "issuer_authority_digest": DIGEST,
        },
        "classification_digest",
    )
    attempt_id = canonical_digest(
        {
            "domain": "avo.main.ledger.attempt.v2",
            "activation_digest": activation.activation_digest,
            "scheduler_sequence": 12,
            "submission_digest": DIGEST,
        }
    )
    outcome = _with_digest(
        MainLedgerTerminalOutcome,
        {
            "activation_digest": activation.activation_digest,
            "submission_digest": DIGEST,
            "classification_digest": classification.classification_digest,
            "classification": classification,
            "operation_id": DIGEST,
            "attempt_id": attempt_id,
            "scheduler_sequence": 12,
            "outcome": "success",
            "evidence_kind": "success",
            "terminal_evidence_digest": DIGEST,
            "terminal_evidence": _artifact(
                "ledger-terminal-evidence", "application/vnd.avo.ledger-terminal-evidence+json"
            ),
            "package_digest": DIGEST,
            "package_artifact": _artifact(
                "integration-campaign-package", "application/vnd.avo.integration-campaign+json"
            ),
            "package_binding_digest": canonical_digest(
                {
                    "activation_digest": activation.activation_digest,
                    "classification_digest": classification.classification_digest,
                    "operation_id": DIGEST,
                    "package_digest": DIGEST,
                    "submission_digest": DIGEST,
                }
            ),
            "terminal_at": NOW,
        },
        "outcome_digest",
    )
    with pytest.raises(ValidationError, match="boundary_violation"):
        MainLedgerTerminalOutcome.model_validate(
            {**outcome.model_dump(), "boundary_violation": True}
        )
    with pytest.raises(ValidationError, match="sequence has a gap"):
        MainLedgerAccumulatorTransition.model_validate(
            {
                "activation_digest": activation.activation_digest,
                "prior_state": prior,
                "prior_state_digest": prior.state_digest,
                "outcome": outcome,
                "outcome_digest": outcome.outcome_digest,
                "reset_applied": False,
                "classification": classification,
                "resulting_state": prior,
                "resulting_state_digest": prior.state_digest,
                "transition_digest": DIGEST,
            }
        )


def test_excluded_submission_advances_cas_without_counting_or_resetting() -> None:
    activation = _activation()
    submission = _submission(activation, 11)
    prior = _with_digest(
        MainLedgerAccumulatorState,
        {
            "activation_digest": activation.activation_digest,
            "last_scheduler_sequence": 10,
            "streak": 0,
            "successes": 0,
            "failures": 0,
            "boundary_violations": 0,
            "threshold_complete": False,
        },
        "state_digest",
    )
    classification = _with_digest(
        MainLedgerClassificationEvidence,
        {
            "activation_digest": activation.activation_digest,
            "submission_digest": DIGEST,
            "operation_id": submission.operation_id,
            "scheduler_sequence": 11,
            "classification": "excluded",
            "empty": True,
            "ordinary": True,
            "risk_class": "ordinary",
            "paths": [],
            "path_manifest_digest": canonical_digest([]),
            "policy_digest": activation.policy_digest,
            "policy_epoch": activation.policy_epoch,
            "controller_authority": activation.controller_authority,
            "issuer_identity": "ledger-controller",
            "issuer_authority_digest": DIGEST,
            "exclusion_reason": "empty",
            "independent_exclusion_evidence_digest": DIGEST,
            "independent_exclusion_evidence": _artifact(
                "ledger-classification-exclusion-evidence",
                "application/vnd.avo.ledger-exclusion-evidence+json",
            ),
        },
        "classification_digest",
    )
    result = _with_digest(
        MainLedgerAccumulatorState,
        {
            "activation_digest": activation.activation_digest,
            "last_scheduler_sequence": 11,
            "streak": 0,
            "successes": 0,
            "failures": 0,
            "boundary_violations": 0,
            "threshold_complete": False,
        },
        "state_digest",
    )
    transition = _with_digest(
        MainLedgerAccumulatorTransition,
        {
            "activation_digest": activation.activation_digest,
            "classification": classification,
            "prior_state": prior,
            "prior_state_digest": prior.state_digest,
            "reset_applied": False,
            "resulting_state": result,
            "resulting_state_digest": result.state_digest,
        },
        "transition_digest",
    )
    assert transition.outcome is None
    assert transition.resulting_state.streak == 0
    forged_prior = _with_digest(
        MainLedgerAccumulatorState,
        {
            "activation_digest": activation.activation_digest,
            "last_scheduler_sequence": 10,
            "streak": 11,
            "successes": 11,
            "failures": 0,
            "boundary_violations": 0,
            "threshold_complete": False,
        },
        "state_digest",
    )
    forged_transition = transition.model_copy(
        update={"prior_state": forged_prior, "prior_state_digest": forged_prior.state_digest}
    )
    forged_package = MainLedgerEvidencePackage.model_construct(
        activation=activation,
        status="threshold_complete",
        submissions=[submission],
        classifications=[classification],
        outcomes=[],
        transitions=[forged_transition],
        final_state=result,
        package_digest=DIGEST,
    )
    with pytest.raises(ValidationError, match="canonical genesis"):
        MainLedgerEvidencePackage.model_validate(forged_package)


def test_genesis_and_duplicate_delivery_are_closed_by_aggregate() -> None:
    activation = _activation()
    genesis = main_ledger_genesis_state(
        activation.activation_digest, activation.scheduler_sequence_watermark
    )
    assert genesis.streak == 0
    assert genesis.successes == genesis.failures == genesis.boundary_violations == 0
    assert genesis.last_scheduler_sequence == activation.scheduler_sequence_watermark
    submission = _submission(activation, 11)
    duplicate = _submission(activation, 12, submission.submission_identity)
    fake_classification = MainLedgerClassificationEvidence.model_construct(
        activation_digest=activation.activation_digest,
        submission_digest=DIGEST,
        operation_id=DIGEST,
        scheduler_sequence=11,
        classification="excluded",
        empty=True,
        ordinary=True,
        risk_class="ordinary",
        paths=[],
        path_manifest_digest=canonical_digest([]),
        policy_digest=activation.policy_digest,
        policy_epoch=activation.policy_epoch,
        controller_authority=activation.controller_authority,
        issuer_identity="ledger-controller",
        issuer_authority_digest=DIGEST,
        exclusion_reason="empty",
        independent_exclusion_evidence_digest=DIGEST,
        independent_exclusion_evidence=_artifact(
            "ledger-classification-exclusion-evidence",
            "application/vnd.avo.ledger-exclusion-evidence+json",
        ),
        classification_digest=DIGEST,
    )
    forged_package = MainLedgerEvidencePackage.model_construct(
        activation=activation,
        status="threshold_complete",
        submissions=[submission, duplicate],
        classifications=[fake_classification, fake_classification],
        outcomes=[],
        transitions=[],
        final_state=genesis,
        package_digest=DIGEST,
    )
    with pytest.raises(ValidationError, match="duplicate scheduler"):
        MainLedgerEvidencePackage.model_validate(forged_package)

    distinct_identity = _submission(activation, 12, "distinct-identity")
    physical_duplicate_package = MainLedgerEvidencePackage.model_construct(
        activation=activation,
        status="threshold_complete",
        submissions=[submission, distinct_identity],
        classifications=[fake_classification, fake_classification],
        outcomes=[],
        transitions=[],
        final_state=genesis,
        package_digest=DIGEST,
    )
    with pytest.raises(ValidationError, match="physical submission content"):
        MainLedgerEvidencePackage.model_validate(physical_duplicate_package)

    forged_repository = submission.model_copy(
        update={"repository_digest": DIGEST[:-1] + "2"}
    )
    forged_repository_package = MainLedgerEvidencePackage.model_construct(
        activation=activation,
        status="threshold_complete",
        submissions=[forged_repository],
        classifications=[fake_classification],
        outcomes=[],
        transitions=[],
        final_state=genesis,
        package_digest=DIGEST,
    )
    with pytest.raises(ValidationError, match="repository target"):
        MainLedgerEvidencePackage.model_validate(forged_repository_package)


def test_boundary_reset_can_terminalize_before_first_submission() -> None:
    activation = _activation()
    genesis = main_ledger_genesis_state(
        activation.activation_digest, activation.scheduler_sequence_watermark
    )
    violation = _with_digest(
        MainLedgerBoundaryViolationEvidence,
        {
            "activation_digest": activation.activation_digest,
            "controller_authority": activation.controller_authority,
            "expected_scheduler_sequence": 11,
            "current_state_digest": genesis.state_digest,
            "violation_kind": "starvation",
            "evidence_artifact": _artifact(
                "ledger-boundary-violation-evidence",
                "application/vnd.avo.ledger-boundary-violation+json",
            ),
            "detected_at": NOW,
        },
        "violation_digest",
    )
    result = _with_digest(
        MainLedgerAccumulatorState,
        {
            "activation_digest": activation.activation_digest,
            "last_scheduler_sequence": activation.scheduler_sequence_watermark,
            "streak": 0,
            "successes": 0,
            "failures": 0,
            "boundary_violations": 1,
            "threshold_complete": False,
        },
        "state_digest",
    )
    reset = _with_digest(
        MainLedgerBoundaryResetTransition,
        {
            "activation_digest": activation.activation_digest,
            "prior_state": genesis,
            "prior_state_digest": genesis.state_digest,
            "violation": violation,
            "resulting_state": result,
            "resulting_state_digest": result.state_digest,
        },
        "transition_digest",
    )
    package_values: dict[str, Any] = {
        "status": "boundary_reset",
        "activation": activation,
        "submissions": [],
        "classifications": [],
        "outcomes": [],
        "transitions": [],
        "final_state": result,
        "boundary_evidence": violation,
        "terminal_boundary_reset": reset,
    }
    package_probe = MainLedgerEvidencePackage.model_construct(  # pyright: ignore[reportArgumentType]
        **package_values, package_digest=DIGEST
    )
    package = MainLedgerEvidencePackage.model_validate(
        {
            **package_values,
            "package_digest": canonical_digest(
                package_probe.model_dump(exclude={"package_digest"}, mode="json")
            ),
        }
    )
    assert package.status == "boundary_reset"

    stale_violation = _with_digest(
        MainLedgerBoundaryViolationEvidence,
        {
            **violation.model_dump(),
            "detected_at": NOW - timedelta(seconds=1),
        },
        "violation_digest",
    )
    stale_reset = _with_digest(
        MainLedgerBoundaryResetTransition,
        {
            **reset.model_dump(),
            "violation": stale_violation,
        },
        "transition_digest",
    )
    stale_values = {
        **package_values,
        "boundary_evidence": stale_violation,
        "terminal_boundary_reset": stale_reset,
    }
    stale_probe = MainLedgerEvidencePackage.model_construct(
        **stale_values, package_digest=DIGEST  # pyright: ignore[reportArgumentType]
    )
    with pytest.raises(ValidationError, match="active controller root"):
        MainLedgerEvidencePackage.model_validate(
            {
                **stale_values,
                "package_digest": canonical_digest(
                    stale_probe.model_dump(exclude={"package_digest"}, mode="json")
                ),
            }
        )
