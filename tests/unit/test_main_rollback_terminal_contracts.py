"""Focused C5 terminal post-state, cleanup, and closure tests."""

# pyright: reportPrivateUsage=false, reportArgumentType=false, reportUnknownArgumentType=false

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournalError,
)
from avo_correlate.contracts.main_graduation import (
    MainRollbackAttemptAuthority,
    MainRollbackCleanupTerminalEvidence,
    MainRollbackCompletionPackage,
    MainRollbackPostStateObservation,
    main_rollback_operation_id,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_main_rollback_lifecycle_contracts import (
    NOW,
    RB,
    D,
    R,
    _cleanup_intent,
    _cleanup_observation,
    _cleanup_receipt,
    _journal_with_records,
    _rollback_fixture,
    _signed,
)


def _attempt(source: Any, inverse: Any, intent: Any, auth: Any) -> MainRollbackAttemptAuthority:
    values: dict[str, Any] = {
        "attempt_nonce": "rollback-attempt-1",
        "source_operation_id": source.operation_id,
        "completion_package_digest": canonical_digest(source),
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "current_main_commit": auth.current_main_commit,
        "current_main_tree": auth.current_main_tree,
        "current_main_parent_commit": auth.current_main_parent_commit,
        "original_delta_digest": inverse.original_delta_digest,
        "inverse_delta_digest": inverse.inverse_delta_digest,
        "inverse_delta_artifact_digest": canonical_digest(inverse),
        "inverse_tree": inverse.inverse_tree,
        "candidate_commit": intent.candidate_commit,
        "candidate_tree": intent.candidate_tree,
        "candidate_parent_commit": intent.candidate_parent_commit,
        "policy_epoch": auth.policy_epoch,
        "controller_config_digest": auth.controller_config_digest,
        "release_issuer_identity": auth.release_issuer_identity,
        "release_issuer_app_id": auth.release_issuer_app_id,
        "issuer_isolation_digest": auth.issuer_isolation_digest,
    }
    probe = MainRollbackAttemptAuthority.model_construct(
        **values,
        operation_id=D,
        candidate_ref="refs/heads/avo/main-rollback/" + "0" * 64,
        manifest_digest=D,
    )
    operation_id = main_rollback_operation_id(
        **probe.model_dump(exclude={"operation_id", "manifest_digest"}, mode="json")
    )
    values.update(
        operation_id=operation_id,
        candidate_ref="refs/heads/avo/main-rollback/" + operation_id[7:],
    )
    probe = MainRollbackAttemptAuthority.model_construct(**values, manifest_digest=D)
    values["manifest_digest"] = canonical_digest(
        probe.model_dump(exclude={"manifest_digest"}, mode="json")
    )
    return MainRollbackAttemptAuthority.model_validate(values)


class _Authority:
    def __init__(self, *, reject_post_state: bool = False) -> None:
        self.calls: list[str] = []
        self.reject_post_state = reject_post_state

    def verify_rollback_result(self, *_args: Any) -> None:
        self.calls.append("result")

    def verify_rollback_cleanup_intent(self, *_args: Any) -> None:
        self.calls.append("cleanup-intent")

    def verify_rollback_cleanup_receipt(self, *_args: Any) -> None:
        self.calls.append("cleanup-receipt")

    def verify_rollback_cleanup_observation(self, *_args: Any) -> None:
        self.calls.append("cleanup-observation")

    def verify_rollback_post_state(self, *_args: Any) -> None:
        self.calls.append("post-state")
        if self.reject_post_state:
            raise ValueError("forged read observation")

    def verify_rollback_cleanup_terminal(self, *_args: Any) -> None:
        self.calls.append("cleanup-terminal")


def _post_state(
    result: Any, attempt: MainRollbackAttemptAuthority
) -> MainRollbackPostStateObservation:
    values = {
        "operation_id": RB,
        "source_operation_id": attempt.source_operation_id,
        "attempt_manifest_digest": attempt.manifest_digest,
        "result_receipt_digest": result.receipt_digest,
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "inverse_tree": attempt.inverse_tree,
        "current_main_commit": attempt.current_main_commit,
        "result_commit": result.result_commit,
        "result_tree": result.result_tree,
        "result_parents": result.result_parents,
        "observer_identity": "read-only-observer",
        "observer_api_version": "v2",
        "response_digest": "sha256:" + "9" * 64,
        "observed_at": NOW + timedelta(minutes=4),
    }
    return _signed(MainRollbackPostStateObservation, values, "observation_digest")


def test_post_state_allows_distinct_authenticated_read_observer() -> None:
    source, inverse, intent, auth, _lease, result = _rollback_fixture()
    attempt = _attempt(source, inverse, intent, auth)
    observation = _post_state(result, attempt)
    journal = _journal_with_records(
        Path("."),
        {"rollback-attempt-authority": attempt, "rollback-result": result},
        authority := _Authority(),
    )
    journal._require_rollback_post_state(observation)  # type: ignore[attr-defined]
    assert authority.calls == ["post-state"]


def test_post_state_forgery_is_rejected_by_injected_authority() -> None:
    source, inverse, intent, auth, _lease, result = _rollback_fixture()
    attempt = _attempt(source, inverse, intent, auth)
    observation = _post_state(result, attempt)
    journal = _journal_with_records(
        Path("."),
        {"rollback-attempt-authority": attempt, "rollback-result": result},
        _Authority(reject_post_state=True),
    )
    with pytest.raises(MainGraduationJournalError, match="authority verification"):
        journal._require_rollback_post_state(observation)  # type: ignore[attr-defined]


def test_ambiguous_cleanup_closes_only_with_absence_observation() -> None:
    _source, _inverse, intent, auth, _lease, result = _rollback_fixture()
    cleanup = _cleanup_intent(intent, auth, result)
    ambiguous = _cleanup_receipt(cleanup).model_dump(mode="json")
    ambiguous.update({"outcome": "ambiguous", "receipt_digest": D})
    receipt = _signed(type(_cleanup_receipt(cleanup)), ambiguous, "receipt_digest")
    observation = _cleanup_observation(cleanup, receipt)
    observation_values = observation.model_dump(mode="json")
    observation_values.update(
        {"provider_identity": "read-only-cleanup-observer", "observation_digest": D}
    )
    observation = _signed(type(observation), observation_values, "observation_digest")
    terminal_values = {
        "operation_id": RB,
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "cleanup_intent_digest": cleanup.intent_digest,
        "cleanup_receipt_digest": receipt.receipt_digest,
        "candidate_ref": cleanup.candidate_ref,
        "candidate_commit": cleanup.candidate_commit,
        "pull_request_number": cleanup.pull_request_number,
        "pull_request_url": cleanup.pull_request_url,
        "outcome": "absent",
        "candidate_ref_absent": True,
        "pull_request_state": "closed",
        "cleanup_observation_digest": observation.observation_digest,
        "provider_identity": observation.provider_identity,
        "provider_api_version": observation.provider_api_version,
        "observed_at": NOW + timedelta(minutes=7),
    }
    terminal = _signed(MainRollbackCleanupTerminalEvidence, terminal_values, "evidence_digest")
    records = {
        "rollback-cleanup-intent": cleanup,
        "rollback-cleanup-receipt": receipt,
        "rollback-cleanup-observation": observation,
    }
    authority = _Authority()
    journal = _journal_with_records(Path("."), records, authority)
    journal._require_rollback_cleanup_terminal(terminal)  # type: ignore[attr-defined]
    assert "cleanup-terminal" in authority.calls

    missing_records = {
        key: value for key, value in records.items() if key != "rollback-cleanup-observation"
    }
    missing = _journal_with_records(Path("."), missing_records, authority)
    with pytest.raises(MainGraduationJournalError, match="terminal cleanup observation"):
        missing._require_rollback_cleanup_terminal(terminal)  # type: ignore[attr-defined]


def test_rollback_completion_requires_full_authority_closure() -> None:
    required = {
        "rollback_preparation_authorization",
        "lease_evidence_record",
        "admission_observation",
        "hold_observation",
        "release_authorization",
        "release_claim",
        "claimed_transition_receipt",
        "release_transition_intent",
        "release_transition_mutation_receipt",
    }
    assert required.issubset(MainRollbackCompletionPackage.model_fields)
    for name in required:
        assert MainRollbackCompletionPackage.model_fields[name].is_required()
