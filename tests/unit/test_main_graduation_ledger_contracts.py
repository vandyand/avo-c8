from datetime import UTC, datetime
from typing import Any, TypeVar

import pytest
from pydantic import ValidationError

from avo_correlate.contracts.base import StrictModel
from avo_correlate.contracts.main_graduation_ledger import (
    MainLedgerAccumulatorState,
    MainLedgerAccumulatorTransition,
    MainLedgerActivation,
    MainLedgerClassificationEvidence,
    MainLedgerSubmissionEnvelope,
    MainLedgerTerminalOutcome,
)
from avo_correlate.domain.canonical import canonical_digest

DIGEST = "sha256:" + "1" * 64
NOW = datetime(2026, 9, 1, tzinfo=UTC)
ModelT = TypeVar("ModelT", bound=StrictModel)


def _with_digest(model_type: type[ModelT], values: dict[str, Any], field: str) -> ModelT:  # noqa: UP047
    probe = model_type.model_construct(**values, **{field: DIGEST})  # pyright: ignore[reportArgumentType]
    return model_type.model_validate(
        {**values, field: canonical_digest(probe.model_dump(exclude={field}, mode="json"))}
    )


def _activation() -> MainLedgerActivation:
    values = {
        "repository_digest": DIGEST,
        "protocol_digest": DIGEST,
        "controller_config_digest": DIGEST,
        "policy_digest": DIGEST,
        "policy_epoch": DIGEST,
        "controller_issuer_identity": "ledger-controller",
        "controller_issuer_authority_digest": DIGEST,
        "scheduler_sequence_watermark": 10,
        "hosted_rollback_proof_digest": DIGEST,
        "hosted_rollback_artifact_digest": DIGEST,
        "rollback_authority_identity": "main-rollback-authority",
        "c8_capability_evidence_digest": DIGEST,
        "activated_at": NOW,
    }
    return _with_digest(MainLedgerActivation, values, "activation_digest")


def _submission(
    activation: MainLedgerActivation, sequence: int = 11
) -> MainLedgerSubmissionEnvelope:
    values = {
        "activation_digest": activation.activation_digest,
        "repository_digest": activation.repository_digest,
        "scheduler_sequence": sequence,
        "source_identity": "scheduler",
        "submission_identity": f"submission-{sequence}",
        "submission_digest": DIGEST,
        "operation_id": canonical_digest(
            {
                "domain": "avo.main.ledger.submission.v2",
                "activation_digest": activation.activation_digest,
                "scheduler_sequence": sequence,
                "source_identity": "scheduler",
                "submission_identity": f"submission-{sequence}",
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
    with pytest.raises(ValidationError, match="activation digest"):
        MainLedgerActivation.model_validate(
            {**activation.model_dump(), "policy_epoch": DIGEST[:-1] + "2"}
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
        "exclusion_reason": "empty",
        "independent_exclusion_evidence_digest": DIGEST,
    }
    good = _with_digest(MainLedgerClassificationEvidence, common, "classification_digest")
    assert good.classification == "excluded"
    with pytest.raises(ValidationError, match="cannot be excluded"):
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
            "streak": 11,
            "successes": 11,
            "failures": 0,
            "boundary_violations": 0,
            "threshold_complete": False,
        },
        "state_digest",
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
            "classification_digest": DIGEST,
            "operation_id": DIGEST,
            "attempt_id": attempt_id,
            "scheduler_sequence": 12,
            "outcome": "success",
            "evidence_kind": "success",
            "terminal_evidence_digest": DIGEST,
            "package_digest": DIGEST,
            "package_binding_digest": DIGEST,
            "terminal_at": NOW,
        },
        "outcome_digest",
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
                "resulting_state": prior,
                "resulting_state_digest": prior.state_digest,
                "transition_digest": DIGEST,
            }
        )
