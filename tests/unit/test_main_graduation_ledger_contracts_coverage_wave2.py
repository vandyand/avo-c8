"""Adversarial contract coverage for C6 ledger invariants.

These tests exercise rejection branches which are intentionally difficult to
reach through the happy-path journal fixtures.  Every case starts from a
real, canonically digested contract and mutates one authority or accounting
binding at a time.
"""

# Dynamic model construction is intentional here: it exercises outer
# validators against malformed nested records without changing production.
# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportArgumentType=false, reportCallIssue=false

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation_ledger import (
    MainLedgerAccumulatorState,
    MainLedgerAccumulatorTransition,
    MainLedgerActivation,
    MainLedgerBoundaryResetTransition,
    MainLedgerBoundaryViolationEvidence,
    MainLedgerClassificationEvidence,
    MainLedgerControllerAuthority,
    MainLedgerHostedRollbackProof,
    MainLedgerSubmissionEnvelope,
    MainLedgerTerminalOutcome,
    MainLedgerUnresolvedTailEntry,
    main_ledger_genesis_state,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_main_graduation_ledger_contracts import (
    DIGEST,
    NOW,
    _activation,
    _artifact,
    _boundary_package_with_tail,
    _submission,
    _with_digest,
)


def _classification(
    activation: MainLedgerActivation,
    submission: MainLedgerSubmissionEnvelope,
    *,
    excluded: bool = False,
) -> MainLedgerClassificationEvidence:
    values: dict[str, Any] = {
        "activation_digest": activation.activation_digest,
        "submission_digest": submission.submission_digest,
        "operation_id": submission.operation_id,
        "scheduler_sequence": submission.scheduler_sequence,
        "classification": "excluded" if excluded else "eligible",
        "empty": excluded,
        "ordinary": True,
        "risk_class": "ordinary",
        "paths": [] if excluded else ["src/feature.py"],
        "path_manifest_digest": canonical_digest([] if excluded else ["src/feature.py"]),
        "policy_digest": activation.policy_digest,
        "policy_epoch": activation.policy_epoch,
        "controller_authority": activation.controller_authority,
        "issuer_identity": activation.controller_authority.issuer_identity,
        "issuer_authority_digest": activation.controller_authority.issuer_authority_digest,
    }
    if excluded:
        values.update(
            exclusion_reason="empty",
            independent_exclusion_evidence_digest=DIGEST,
            independent_exclusion_evidence=_artifact(
                "ledger-classification-exclusion-evidence",
                "application/vnd.avo.ledger-exclusion-evidence+json",
            ),
        )
    return _with_digest(MainLedgerClassificationEvidence, values, "classification_digest")


def _outcome(
    activation: MainLedgerActivation,
    submission: MainLedgerSubmissionEnvelope,
    classification: MainLedgerClassificationEvidence,
    *,
    outcome: str = "failure",
) -> MainLedgerTerminalOutcome:
    values: dict[str, Any] = {
        "activation_digest": activation.activation_digest,
        "submission_digest": submission.submission_digest,
        "classification_digest": classification.classification_digest,
        "classification": classification,
        "operation_id": submission.operation_id,
        "attempt_id": canonical_digest(
            {
                "domain": "avo.main.ledger.attempt.v2",
                "activation_digest": activation.activation_digest,
                "scheduler_sequence": submission.scheduler_sequence,
                "submission_digest": submission.submission_digest,
            }
        ),
        "scheduler_sequence": submission.scheduler_sequence,
        "outcome": outcome,
        "evidence_kind": outcome,
        "terminal_evidence_digest": DIGEST,
        "terminal_evidence": _artifact(
            "ledger-terminal-evidence", "application/vnd.avo.ledger-terminal-evidence+json"
        ),
        "reason": "bounded failure",
        "terminal_at": NOW,
    }
    return _with_digest(MainLedgerTerminalOutcome, values, "outcome_digest")


def _state(activation: MainLedgerActivation, sequence: int = 10) -> MainLedgerAccumulatorState:
    return _with_digest(
        MainLedgerAccumulatorState,
        {
            "activation_digest": activation.activation_digest,
            "last_scheduler_sequence": sequence,
            "streak": 0,
            "successes": 0,
            "failures": 0,
            "boundary_violations": 0,
            "threshold_complete": False,
        },
        "state_digest",
    )


def _forged(model: Any, **updates: Any) -> Any:
    """Keep nested model objects intact while testing an outer validator."""

    values = dict(model.__dict__)
    values.update(updates)
    return type(model).model_construct(**values)


def test_authority_proof_capability_and_activation_rejection_matrix() -> None:
    activation = _activation()
    authority = activation.controller_authority
    authority_values = authority.model_dump(mode="json")
    authority_values["expires_at"] = authority_values["authorized_at"]
    with pytest.raises(ValidationError, match="expiry"):
        MainLedgerControllerAuthority.model_validate(authority_values)

    proof_values = activation.hosted_rollback_proof.model_dump(mode="json")
    proof_values["proof_digest"] = DIGEST[:-1] + "2"
    with pytest.raises(ValidationError, match="proof digest"):
        MainLedgerHostedRollbackProof.model_validate(proof_values)

    capability_values = activation.c8_capability_evidence.model_dump(mode="json")
    capability_values["release_issuer_app_id"] = 15368
    capability_values["evidence_digest"] = canonical_digest(
        {key: value for key, value in capability_values.items() if key != "evidence_digest"}
    )
    with pytest.raises(ValidationError, match="release issuer"):
        type(activation.c8_capability_evidence).model_validate(capability_values)

    mutations = [
        ("repository_digest", DIGEST[:-1] + "2", "target differs"),
        ("activated_at", NOW + timedelta(days=2), "outside controller"),
        ("freshness_cutoff", NOW + timedelta(days=2), "freshness"),
        ("hosted_rollback_raw_artifact_digest", activation.hosted_rollback_artifact_digest, "raw"),
        ("activation_digest", DIGEST[:-1] + "2", "activation digest"),
        ("threshold", 11, "threshold"),
        ("initial_streak", 1, "streak"),
    ]
    for field, value, message in mutations:
        values = activation.model_dump(mode="json")
        values[field] = value
        if field in {"threshold", "initial_streak"}:
            values["activation_digest"] = canonical_digest(
                {key: item for key, item in values.items() if key != "activation_digest"}
            )
        with pytest.raises(ValidationError, match=message):
            MainLedgerActivation.model_validate(values)


def test_submission_envelope_rejects_each_content_and_identity_binding() -> None:
    activation = _activation()
    submission = _submission(activation)
    cases = [
        ({"submission_digest": DIGEST[:-1] + "2"}, "submission digest"),
        (
            {
                "content_artifact": _artifact(
                    "wrong", "application/vnd.avo.scheduler-submission+json"
                )
            },
            "wrong role",
        ),
        (
            {"content_artifact": _artifact("scheduler-submission-content", "application/json")},
            "wrong media",
        ),
        (
            {
                "content_artifact": _artifact(
                    "scheduler-submission-content",
                    "application/vnd.avo.scheduler-submission+json",
                    digest=DIGEST,
                ).model_copy(update={"size_bytes": 0})
            },
            "cannot be empty",
        ),
        ({"recorded_at": NOW - timedelta(days=1)}, "postdates"),
        ({"operation_id": DIGEST[:-1] + "2"}, "operation identity"),
        ({"envelope_digest": DIGEST[:-1] + "2"}, "envelope digest"),
    ]
    for updates, message in cases:
        values = submission.model_dump(mode="json")
        values.update(
            {
                key: (
                    value.model_dump(mode="json")
                    if isinstance(value, ArtifactRef)
                    else value.isoformat()
                    if isinstance(value, datetime)
                    else value
                )
                for key, value in updates.items()
            }
        )
        if "envelope_digest" not in updates:
            values["envelope_digest"] = canonical_digest(
                {key: item for key, item in values.items() if key != "envelope_digest"}
            )
        with pytest.raises(ValidationError, match=message):
            MainLedgerSubmissionEnvelope.model_validate(values)


def test_classification_policy_path_and_exclusion_matrix() -> None:
    activation = _activation()
    submission = _submission(activation)
    valid = _classification(activation, submission)
    cases: list[tuple[dict[str, Any], str]] = [
        ({"issuer_identity": "forged"}, "issuer or policy"),
        ({"path_manifest_digest": DIGEST}, "path manifest"),
        ({"empty": True}, "empty flag"),
        ({"ordinary": False}, "risk does not"),
        ({"risk_class": "nonordinary"}, "risk does not"),
        (
            {
                "empty": True,
                "paths": [],
                "path_manifest_digest": canonical_digest([]),
            },
            "only ordinary",
        ),
        ({"classification": "excluded", "empty": False}, "cannot be excluded"),
        (
            {
                "classification": "excluded",
                "empty": True,
                "paths": [],
                "path_manifest_digest": canonical_digest([]),
                "exclusion_reason": None,
            },
            "independent controller evidence",
        ),
        (
            {
                "classification": "excluded",
                "empty": True,
                "paths": [],
                "path_manifest_digest": canonical_digest([]),
                "exclusion_reason": "empty",
                "independent_exclusion_evidence_digest": DIGEST,
                "independent_exclusion_evidence": _artifact("wrong", "application/json"),
            },
            "artifact binding",
        ),
        ({"classification": "eligible", "exclusion_reason": "empty"}, "eligible classification"),
        ({"classification_digest": DIGEST[:-1] + "2"}, "classification evidence digest"),
    ]
    for updates, message in cases:
        values = valid.model_dump(mode="json")
        values.update(
            {
                key: value.model_dump(mode="json") if isinstance(value, ArtifactRef) else value
                for key, value in updates.items()
            }
        )
        if updates.get("classification") == "excluded" and "exclusion_reason" not in updates:
            values.update(
                exclusion_reason="empty",
                independent_exclusion_evidence_digest=DIGEST,
                independent_exclusion_evidence=_artifact(
                    "ledger-classification-exclusion-evidence",
                    "application/vnd.avo.ledger-exclusion-evidence+json",
                ).model_dump(mode="json"),
            )
        if "classification_digest" not in updates:
            values["classification_digest"] = canonical_digest(
                {key: item for key, item in values.items() if key != "classification_digest"}
            )
        with pytest.raises(ValidationError, match=message):
            MainLedgerClassificationEvidence.model_validate(values)


def test_terminal_outcome_and_package_binding_rejection_matrix() -> None:
    activation = _activation()
    submission = _submission(activation)
    classification = _classification(activation, submission)
    outcome = _outcome(activation, submission, classification)
    cases: list[tuple[dict[str, Any], str]] = [
        ({"evidence_kind": "success"}, "discriminator"),
        ({"classification": _classification(activation, submission, excluded=True)}, "eligible"),
        ({"activation_digest": DIGEST[:-1] + "2"}, "activation differs"),
        ({"terminal_evidence_digest": DIGEST[:-1] + "2"}, "evidence digest"),
        ({"terminal_evidence": _artifact("wrong", "application/json")}, "artifact binding"),
        ({"classification_digest": DIGEST[:-1] + "2"}, "classification digest"),
        ({"operation_id": DIGEST[:-1] + "2"}, "exact classification"),
        ({"attempt_id": DIGEST[:-1] + "2"}, "attempt identity"),
        ({"outcome": "success", "evidence_kind": "success"}, "successful outcome"),
        ({"package_digest": DIGEST}, "package digest and package binding"),
        (
            {"package_digest": DIGEST, "package_binding_digest": DIGEST},
            "package digest and package artifact",
        ),
        ({"outcome_digest": DIGEST[:-1] + "2"}, "outcome digest"),
    ]
    for updates, message in cases:
        values = outcome.model_dump(mode="json")
        values.update(
            {
                key: value.model_dump(mode="json") if hasattr(value, "model_dump") else value
                for key, value in updates.items()
            }
        )
        if "outcome_digest" not in updates:
            values["outcome_digest"] = canonical_digest(
                {key: item for key, item in values.items() if key != "outcome_digest"}
            )
        with pytest.raises(ValidationError, match=message):
            MainLedgerTerminalOutcome.model_validate(values)


def test_tail_boundary_reset_and_transition_reject_each_cross_field_binding() -> None:
    activation = _activation()
    submission = _submission(activation)
    prior = _state(activation)
    tail = _with_digest(
        MainLedgerUnresolvedTailEntry,
        {"scheduler_sequence": 11},
        "entry_digest",
    )
    tail_cases = [
        ({"submission_digest": DIGEST}, "incomplete"),
        (
            {
                "submission_digest": DIGEST,
                "operation_id": DIGEST,
                "envelope_digest": DIGEST,
                "content_artifact": _artifact(
                    "wrong", "application/json", digest="sha256:" + "2" * 64
                ),
            },
            "differs from submission",
        ),
        ({"entry_digest": DIGEST[:-1] + "2"}, "tail entry digest"),
    ]
    for updates, message in tail_cases:
        values = tail.model_dump(mode="json")
        values.update(
            {
                key: value.model_dump(mode="json") if isinstance(value, ArtifactRef) else value
                for key, value in updates.items()
            }
        )
        if "entry_digest" not in updates:
            values["entry_digest"] = canonical_digest(
                {key: item for key, item in values.items() if key != "entry_digest"}
            )
        with pytest.raises(ValidationError, match=message):
            MainLedgerUnresolvedTailEntry.model_validate(values)
    assert not tail.has_envelope_identity

    evidence_values: dict[str, Any] = {
        "activation_digest": activation.activation_digest,
        "controller_authority": activation.controller_authority,
        "expected_scheduler_sequence": 11,
        "current_state_digest": prior.state_digest,
        "violation_kind": "starvation",
        "evidence_artifact": _artifact(
            "ledger-boundary-violation-evidence",
            "application/vnd.avo.ledger-boundary-violation+json",
        ),
        "detected_at": NOW,
    }
    evidence = _with_digest(
        MainLedgerBoundaryViolationEvidence, evidence_values, "violation_digest"
    )
    for updates, message in [
        ({"detected_at": NOW + timedelta(days=2)}, "outside"),
        ({"submission_digest": DIGEST}, "incomplete"),
        ({"evidence_artifact": _artifact("wrong", "application/json")}, "artifact binding"),
        ({"violation_digest": DIGEST[:-1] + "2"}, "violation digest"),
    ]:
        values = evidence.model_dump(mode="json")
        values.update(
            {
                key: (
                    value.model_dump(mode="json")
                    if isinstance(value, ArtifactRef)
                    else value.isoformat()
                    if isinstance(value, datetime)
                    else value
                )
                for key, value in updates.items()
            }
        )
        if "violation_digest" not in updates:
            values["violation_digest"] = canonical_digest(
                {key: item for key, item in values.items() if key != "violation_digest"}
            )
        with pytest.raises(ValidationError, match=message):
            MainLedgerBoundaryViolationEvidence.model_validate(values)

    result_values = {
        **prior.model_dump(exclude={"state_digest"}),
        "boundary_violations": 1,
    }
    result = _with_digest(MainLedgerAccumulatorState, result_values, "state_digest")
    reset_values: dict[str, Any] = {
        "activation_digest": activation.activation_digest,
        "prior_state": prior,
        "prior_state_digest": prior.state_digest,
        "violation": evidence,
        "resulting_state": result,
        "resulting_state_digest": result.state_digest,
    }
    reset = _with_digest(MainLedgerBoundaryResetTransition, reset_values, "transition_digest")
    for updates, message in [
        ({"prior_state_digest": DIGEST}, "prior state digest"),
        ({"activation_digest": DIGEST}, "activation differs"),
        (
            {"violation": _forged(evidence, activation_digest=DIGEST)},
            "violation activation",
        ),
        ({"resulting_state_digest": DIGEST}, "resulting state digest"),
        ({"transition_digest": DIGEST}, "transition digest"),
    ]:
        with pytest.raises((ValidationError, ValueError), match=message):
            _forged(reset, **updates).validate_reset()

    excluded = _classification(activation, submission, excluded=True)
    excluded_result = _with_digest(
        MainLedgerAccumulatorState,
        {**prior.model_dump(exclude={"state_digest"}), "last_scheduler_sequence": 11},
        "state_digest",
    )
    transition_values: dict[str, Any] = {
        "activation_digest": activation.activation_digest,
        "classification": excluded,
        "prior_state": prior,
        "prior_state_digest": prior.state_digest,
        "reset_applied": False,
        "resulting_state": excluded_result,
        "resulting_state_digest": excluded_result.state_digest,
    }
    for updates, message in [
        ({"prior_state_digest": DIGEST}, "prior state"),
        ({"activation_digest": DIGEST}, "activation binding"),
        (
            {"classification": _forged(excluded, activation_digest=DIGEST)},
            "classification activation",
        ),
        ({"resulting_state_digest": DIGEST}, "resulting state digest"),
        (
            {"resulting_state": _forged(excluded_result, activation_digest=DIGEST)},
            "resulting state activation",
        ),
        ({"reset_applied": True}, "outcome or reset"),
        (
            {"resulting_state": _forged(excluded_result, successes=1)},
            "counters",
        ),
    ]:
        values = {**transition_values, **updates}
        with pytest.raises((ValidationError, ValueError), match=message):
            MainLedgerAccumulatorTransition.model_construct(**values).validate_transition()


def test_eligible_transition_delta_and_genesis_edges_are_fail_closed() -> None:
    activation = _activation()
    submission = _submission(activation)
    classification = _classification(activation, submission)
    outcome = _outcome(activation, submission, classification)
    prior = _state(activation)
    result = _with_digest(
        MainLedgerAccumulatorState,
        {
            **prior.model_dump(exclude={"state_digest"}),
            "last_scheduler_sequence": 11,
            "failures": 1,
        },
        "state_digest",
    )
    values: dict[str, Any] = {
        "activation_digest": activation.activation_digest,
        "classification": classification,
        "prior_state": prior,
        "prior_state_digest": prior.state_digest,
        "outcome": outcome,
        "outcome_digest": outcome.outcome_digest,
        "reset_applied": True,
        "resulting_state": result,
        "resulting_state_digest": result.state_digest,
    }
    for updates, message in [
        (
            {"outcome": outcome.model_copy(update={"activation_digest": DIGEST})},
            "outcome activation",
        ),
        (
            {"outcome": outcome.model_copy(update={"classification_digest": DIGEST})},
            "outcome classification",
        ),
        (
            {
                "outcome": MainLedgerTerminalOutcome.model_construct(
                    **{**outcome.model_dump(), "scheduler_sequence": 12}
                )
            },
            "outcome sequence",
        ),
        (
            {"resulting_state": result.model_copy(update={"last_scheduler_sequence": 12})},
            "resulting state sequence",
        ),
        ({"transition_digest": DIGEST}, "transition digest"),
        ({"reset_applied": False}, "reset"),
        ({"resulting_state": result.model_copy(update={"failures": 2})}, "failure counter"),
        ({"resulting_state": result.model_copy(update={"successes": 1})}, "unrelated counters"),
    ]:
        candidate = {**values, **updates}
        with pytest.raises((ValidationError, ValueError), match=message):
            MainLedgerAccumulatorTransition.model_construct(**candidate).validate_transition()
    genesis = main_ledger_genesis_state(activation.activation_digest, 10)
    assert genesis == _state(activation)


def test_boundary_package_inventory_and_cas_closure_rejects_adversarial_forms() -> None:
    activation = _activation()
    submission = _submission(activation)
    package = _boundary_package_with_tail(activation, submissions=[], tail=[])
    mutations: list[tuple[dict[str, Any], str]] = [
        (
            {
                "status": "threshold_complete",
                "boundary_evidence": package.boundary_evidence,
                "terminal_boundary_reset": package.terminal_boundary_reset,
            },
            "unresolved boundary",
        ),
        ({"boundary_evidence": None, "terminal_boundary_reset": None}, "requires boundary"),
        (
            {"final_state": _forged(package.final_state, activation_digest=DIGEST)},
            "final state activation",
        ),
        ({"submissions": [submission, submission]}, "duplicate"),
        ({"package_digest": DIGEST}, "package digest"),
    ]
    for updates, message in mutations:
        candidate = package.model_copy(update=updates)
        with pytest.raises((ValidationError, ValueError), match=message):
            candidate.validate_package()


def test_leaf_digest_and_path_guards_cover_canonical_rejection_edges() -> None:
    activation = _activation()
    submission = _submission(activation)
    valid_classification = _classification(activation, submission)

    for paths, message in [
        (["src/z.py", "src/a.py"], "sorted"),
        (["SRC/A.PY", "src/a.py"], "unique"),
        (["../outside.py"], "normalized"),
    ]:
        values = valid_classification.model_dump(mode="json")
        values["paths"] = paths
        with pytest.raises(ValidationError, match=message):
            MainLedgerClassificationEvidence.model_validate(values)

    proof = _forged(activation.hosted_rollback_proof, proof_digest=DIGEST)
    with pytest.raises(ValueError, match="proof digest"):
        proof.validate_digest()
    state = _forged(_state(activation), state_digest=DIGEST)
    with pytest.raises(ValueError, match="state digest"):
        state.validate_state()
    activation_bad_probe = _forged(activation, threshold=11)
    activation_bad = _forged(
        activation_bad_probe,
        activation_digest=canonical_digest(
            activation_bad_probe.model_dump(exclude={"activation_digest"}, mode="json")
        ),
    )
    with pytest.raises(ValueError, match="threshold"):
        activation_bad.validate_activation()


def test_tail_and_boundary_reset_deep_guards_are_independently_checked() -> None:
    activation = _activation()
    prior = _state(activation)
    submission = _submission(activation)
    envelope = _forged(
        submission,
        submission_digest=DIGEST,
        content_artifact=_forged(submission.content_artifact, digest="sha256:" + "2" * 64),
    )
    tail = _forged(
        MainLedgerUnresolvedTailEntry.model_construct(
            scheduler_sequence=11,
            envelope=envelope,
            entry_digest=DIGEST,
        ),
        submission_digest=DIGEST[:-1] + "2",
        operation_id=envelope.operation_id,
        envelope_digest=envelope.envelope_digest,
        content_artifact=envelope.content_artifact,
    )
    with pytest.raises(ValueError, match="differs from envelope"):
        tail.validate_tail_entry()

    evidence = _with_digest(
        MainLedgerBoundaryViolationEvidence,
        {
            "activation_digest": activation.activation_digest,
            "controller_authority": activation.controller_authority,
            "expected_scheduler_sequence": 11,
            "current_state_digest": prior.state_digest,
            "violation_kind": "starvation",
            "evidence_artifact": _artifact(
                "ledger-boundary-violation-evidence",
                "application/vnd.avo.ledger-boundary-violation+json",
            ),
            "detected_at": NOW,
        },
        "violation_digest",
    )
    invalid_expected = _forged(evidence, expected_scheduler_sequence=0)
    with pytest.raises(ValueError, match="expected sequence"):
        invalid_expected.validate_violation()
    bad_current = _forged(evidence, current_state_digest=DIGEST)
    reset = _forged(
        MainLedgerBoundaryResetTransition.model_construct(
            activation_digest=activation.activation_digest,
            prior_state=prior,
            prior_state_digest=prior.state_digest,
            violation=bad_current,
            resulting_state=prior,
            resulting_state_digest=prior.state_digest,
            transition_digest=DIGEST,
        )
    )
    with pytest.raises(ValueError, match="current state"):
        reset.validate_reset()
    late = _forged(
        evidence, current_state_digest=prior.state_digest, expected_scheduler_sequence=10
    )
    reset = _forged(reset, violation=late)
    with pytest.raises(ValueError, match="not after"):
        reset.validate_reset()


def test_success_transition_delta_guards_reject_counter_drift() -> None:
    activation = _activation()
    submission = _submission(activation)
    classification = _classification(activation, submission)
    failure = _outcome(activation, submission, classification)
    success = _forged(failure, outcome="success", evidence_kind="success")
    prior = _state(activation)
    result = _with_digest(
        MainLedgerAccumulatorState,
        {
            **prior.model_dump(exclude={"state_digest"}),
            "last_scheduler_sequence": 11,
            "streak": 1,
            "successes": 1,
        },
        "state_digest",
    )
    values = {
        "activation_digest": activation.activation_digest,
        "classification": classification,
        "prior_state": prior,
        "prior_state_digest": prior.state_digest,
        "outcome": success,
        "outcome_digest": success.outcome_digest,
        "reset_applied": False,
        "resulting_state": result,
        "resulting_state_digest": result.state_digest,
    }
    for updates, message in [
        ({"reset_applied": True}, "increment"),
        ({"resulting_state": _forged(result, streak=2)}, "streak/counter"),
        ({"resulting_state": _forged(result, failures=1)}, "unrelated counters"),
    ]:
        with pytest.raises(ValueError, match=message):
            MainLedgerAccumulatorTransition.model_construct(
                **{**values, **updates}
            ).validate_transition()


def test_remaining_leaf_digest_and_reset_delta_guards() -> None:
    activation = _activation()
    capability = _forged(activation.c8_capability_evidence, evidence_digest=DIGEST)
    with pytest.raises(ValueError, match="evidence digest"):
        capability.validate_capability()

    submission = _submission(activation)
    classification = _classification(activation, submission)
    outcome = _outcome(activation, submission, classification)
    bad_package_ref = _artifact("wrong", "application/json")
    packaged = _forged(
        outcome,
        outcome="success",
        evidence_kind="success",
        package_digest=DIGEST,
        package_binding_digest=DIGEST,
        package_artifact=bad_package_ref,
    )
    with pytest.raises(ValueError, match="package artifact"):
        packaged.validate_outcome()
    good_package_ref = _artifact(
        "integration-campaign-package", "application/vnd.avo.integration-campaign+json"
    )
    wrong_binding = _forged(
        packaged,
        package_artifact=good_package_ref,
        package_binding_digest=DIGEST,
    )
    with pytest.raises(ValueError, match="package binding"):
        wrong_binding.validate_outcome()

    prior = _state(activation)
    result = _forged(prior, boundary_violations=1, successes=1, state_digest=prior.state_digest)
    reset_probe = MainLedgerBoundaryResetTransition.model_construct(
        activation_digest=activation.activation_digest,
        prior_state=prior,
        prior_state_digest=prior.state_digest,
        violation=_with_digest(
            MainLedgerBoundaryViolationEvidence,
            {
                "activation_digest": activation.activation_digest,
                "controller_authority": activation.controller_authority,
                "expected_scheduler_sequence": 11,
                "current_state_digest": prior.state_digest,
                "violation_kind": "starvation",
                "evidence_artifact": _artifact(
                    "ledger-boundary-violation-evidence",
                    "application/vnd.avo.ledger-boundary-violation+json",
                ),
                "detected_at": NOW,
            },
            "violation_digest",
        ),
        resulting_state=result,
        resulting_state_digest=result.state_digest,
        transition_digest=DIGEST,
    )
    reset = _forged(
        reset_probe,
        transition_digest=canonical_digest(
            reset_probe.model_dump(exclude={"transition_digest"}, mode="json")
        ),
    )
    with pytest.raises(ValueError, match="state delta"):
        reset.validate_reset()


def test_package_inventory_and_prefix_closure_rejection_edges() -> None:
    activation = _activation()
    submission = _submission(activation)
    base = _boundary_package_with_tail(activation, submissions=[], tail=[])
    cases: list[tuple[dict[str, Any], str]] = [
        (
            {"submissions": [_submission(activation, 12), submission]},
            "scheduler order",
        ),
        (
            {
                "submissions": [
                    submission,
                    _forged(
                        submission,
                        submission_identity="second",
                        submission_digest="sha256:" + "2" * 64,
                    ),
                ]
            },
            "physical submission artifact",
        ),
        (
            {
                "submissions": [
                    submission,
                    _forged(
                        submission,
                        submission_identity="second",
                        submission_digest="sha256:" + "3" * 64,
                        content_artifact=_forged(
                            submission.content_artifact, digest="sha256:" + "3" * 64
                        ),
                    ),
                ]
            },
            "duplicate scheduler",
        ),
        (
            {"submissions": [_forged(submission, activation_digest=DIGEST)]},
            "submission activation",
        ),
        ({"submissions": [_submission(activation, 12)]}, "scheduler sequence has a gap"),
        (
            {"classifications": [_classification(activation, submission)]},
            "every processed submission",
        ),
    ]
    for updates, message in cases:
        with pytest.raises(ValueError, match=message):
            _forged(base, **updates).validate_package()

    outcome = _outcome(activation, submission, _classification(activation, submission))
    with pytest.raises(ValueError, match="terminal outcomes"):
        _forged(base, outcomes=[outcome, outcome]).validate_package()

    early_boundary = _forged(base.boundary_evidence, expected_scheduler_sequence=10)
    with pytest.raises(ValueError, match="precedes activation"):
        _forged(base, boundary_evidence=early_boundary).validate_package()
    normal_gap = _forged(
        base,
        status="threshold_complete",
        boundary_evidence=None,
        terminal_boundary_reset=None,
        submissions=[_submission(activation, 12)],
    )
    with pytest.raises(ValueError, match="scheduler sequence has a gap"):
        normal_gap.validate_package()
    boundary_prefix = _forged(
        base,
        boundary_evidence=_forged(base.boundary_evidence, expected_scheduler_sequence=12),
    )
    with pytest.raises(ValueError, match="contiguous prefix"):
        boundary_prefix.validate_package()
    threshold_classification = _forged(
        base,
        status="threshold_complete",
        boundary_evidence=None,
        terminal_boundary_reset=None,
        classifications=[_classification(activation, submission)],
    )
    with pytest.raises(ValueError, match="every submission"):
        threshold_classification.validate_package()
