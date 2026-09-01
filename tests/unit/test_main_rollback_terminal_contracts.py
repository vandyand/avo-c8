"""Focused C5 terminal post-state, cleanup, and closure tests."""

# pyright: reportPrivateUsage=false, reportArgumentType=false, reportUnknownArgumentType=false

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.contracts.main_graduation import (
    MainRollbackAttemptAuthority,
    MainRollbackCleanupTerminalEvidence,
    MainRollbackCompletionPackage,
    MainRollbackPostStateObservation,
    main_rollback_operation_id,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_main_rollback_lifecycle_contracts import (
    NOW,
    RB,
    D,
    R,
    _cleanup_intent,
    _cleanup_observation,
    _cleanup_receipt,
    _journal_with_records,
    _ref,
    _rollback_fixture,
    _signed,
)


def _attempt(source: Any, inverse: Any, intent: Any, auth: Any) -> MainRollbackAttemptAuthority:
    values: dict[str, Any] = {
        "attempt_nonce": "rollback-attempt-1",
            "source_operation_id": source.operation_id,
            "composition_id": intent.composition_id,
            "composition_artifact_digest": intent.composition_artifact_digest,
        "completion_package_digest": canonical_digest(source),
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "current_main_commit": auth.current_main_commit,
        "current_main_tree": auth.current_main_tree,
        "current_main_parent_commit": auth.current_main_parent_commit,
        "original_delta_digest": inverse.original_delta_digest,
        "inverse_delta_digest": inverse.inverse_delta_digest,
            "inverse_delta_artifact_digest": intent.composition_artifact_digest,
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
    observation_values.update({"observation_digest": D})
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
        "provider_identity": cleanup.provider_identity,
        "provider_api_version": cleanup.provider_api_version,
        "cleanup_principal_identity": cleanup.cleanup_principal_identity,
        "cleanup_principal_app_id": cleanup.cleanup_principal_app_id,
        "cleanup_principal_isolation_digest": cleanup.cleanup_principal_isolation_digest,
        "observer_identity": cleanup.observer_identity,
        "observer_app_id": cleanup.observer_app_id,
        "observer_isolation_digest": cleanup.observer_isolation_digest,
        "observer_provider_identity": cleanup.observer_provider_identity,
        "observer_provider_api_version": cleanup.observer_provider_api_version,
        "cleanup_authority_digest": cleanup.cleanup_authority_digest,
        "pull_request_merged": True,
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


def test_terminal_contracts_reject_abandoned_v1_wires_and_round_trip_v2() -> None:
    source, inverse, intent, auth, _lease, result = _rollback_fixture()
    attempt = _attempt(source, inverse, intent, auth)
    post = _post_state(result, attempt)
    post_wire = post.model_dump(mode="json")
    assert post_wire["schema_version"] == 2
    with pytest.raises(ValidationError, match="schema_version"):
        MainRollbackPostStateObservation.model_validate(
            {**post_wire, "schema_version": 1}
        )
    assert canonical_bytes(
        MainRollbackPostStateObservation.model_validate_json(canonical_bytes(post))
    ) == canonical_bytes(post)

    cleanup = _cleanup_intent(intent, auth, result)
    receipt = _cleanup_receipt(cleanup)
    terminal = _signed(
        MainRollbackCleanupTerminalEvidence,
        {
            "operation_id": RB,
            "repository_digest": R,
            "target_ref": "refs/heads/main",
            "cleanup_intent_digest": cleanup.intent_digest,
            "cleanup_receipt_digest": receipt.receipt_digest,
            "candidate_ref": cleanup.candidate_ref,
            "candidate_commit": cleanup.candidate_commit,
            "pull_request_number": cleanup.pull_request_number,
            "pull_request_url": cleanup.pull_request_url,
            "outcome": "already_absent",
            "candidate_ref_absent": True,
            "pull_request_state": "closed",
            "pull_request_merged": True,
            "cleanup_observation_digest": None,
            "provider_identity": cleanup.provider_identity,
            "provider_api_version": cleanup.provider_api_version,
            "cleanup_principal_identity": cleanup.cleanup_principal_identity,
            "cleanup_principal_app_id": cleanup.cleanup_principal_app_id,
            "cleanup_principal_isolation_digest": cleanup.cleanup_principal_isolation_digest,
            "observer_identity": cleanup.observer_identity,
            "observer_app_id": cleanup.observer_app_id,
            "observer_isolation_digest": cleanup.observer_isolation_digest,
            "observer_provider_identity": cleanup.observer_provider_identity,
            "observer_provider_api_version": cleanup.observer_provider_api_version,
            "cleanup_authority_digest": cleanup.cleanup_authority_digest,
            "observed_at": NOW + timedelta(minutes=3),
        },
        "evidence_digest",
    )
    terminal_wire = terminal.model_dump(mode="json")
    assert terminal_wire["schema_version"] == 3
    with pytest.raises(ValidationError, match="schema_version"):
        MainRollbackCleanupTerminalEvidence.model_validate(
            {**terminal_wire, "schema_version": 1}
        )
    assert canonical_bytes(
        MainRollbackCleanupTerminalEvidence.model_validate_json(canonical_bytes(terminal))
    ) == canonical_bytes(terminal)

    assert MainRollbackCompletionPackage.model_fields["schema_version"].default == 6
    with pytest.raises(ValidationError, match="schema_version"):
        MainRollbackCompletionPackage.model_validate({"schema_version": 1})


def test_post_state_filesystem_record_restart_and_cas_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, inverse, intent, auth, _lease, result = _rollback_fixture()
    attempt = _attempt(source, inverse, intent, auth)
    observation = _post_state(result, attempt)
    authority = _Authority()
    dependencies = {
        "rollback-attempt-authority": attempt,
        "rollback-result": result,
    }
    journal = MainGraduationJournal(
        tmp_path, policy_epoch=D, rollback_authority_verifier=authority
    )
    journal._read = lambda kind, key: (  # type: ignore[method-assign]
        dependencies[kind], _ref()
    ) if kind in dependencies else journal._read_impl(kind, key)
    reference = journal.record_rollback_post_state_observation(observation)
    replay = journal.record_rollback_post_state_observation(observation)
    assert replay == reference

    restarted = MainGraduationJournal(
        tmp_path, policy_epoch=D, rollback_authority_verifier=authority
    )
    original = restarted._read_impl

    def read(kind: str, key: str) -> Any:
        if kind == "rollback-post-state-observation":
            return original(kind, key)
        if kind in dependencies:
            return dependencies[kind], _ref()
        return original(kind, key)

    monkeypatch.setattr(restarted, "_read", read)
    loaded = restarted.read_rollback_post_state_observation(RB)
    assert loaded is not None and loaded[0] == observation and loaded[1] == reference
    assert authority.calls.count("post-state") == 3

    restarted.delete_artifact(reference.digest)
    with pytest.raises(MainGraduationJournalError):
        restarted.read_rollback_post_state_observation(RB)


def test_ambiguous_cleanup_terminal_filesystem_restart_and_observer_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _source, _inverse, intent, auth, _lease, result = _rollback_fixture()
    cleanup = _cleanup_intent(intent, auth, result)
    receipt_values = _cleanup_receipt(cleanup).model_dump(mode="json")
    receipt_values.update({"outcome": "ambiguous", "receipt_digest": D})
    receipt = _signed(type(_cleanup_receipt(cleanup)), receipt_values, "receipt_digest")
    observation_values = _cleanup_observation(cleanup, receipt).model_dump(mode="json")
    observation_values.update({"observation_digest": D})
    observation = _signed(
        type(_cleanup_observation(cleanup, receipt)),
        observation_values,
        "observation_digest",
    )
    terminal = _signed(
        MainRollbackCleanupTerminalEvidence,
        {
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
            "provider_identity": cleanup.provider_identity,
            "provider_api_version": cleanup.provider_api_version,
            "cleanup_principal_identity": cleanup.cleanup_principal_identity,
            "cleanup_principal_app_id": cleanup.cleanup_principal_app_id,
            "cleanup_principal_isolation_digest": cleanup.cleanup_principal_isolation_digest,
            "observer_identity": cleanup.observer_identity,
            "observer_app_id": cleanup.observer_app_id,
            "observer_isolation_digest": cleanup.observer_isolation_digest,
            "observer_provider_identity": cleanup.observer_provider_identity,
            "observer_provider_api_version": cleanup.observer_provider_api_version,
            "cleanup_authority_digest": cleanup.cleanup_authority_digest,
            "pull_request_merged": True,
            "observed_at": NOW + timedelta(minutes=7),
        },
        "evidence_digest",
    )
    dependencies = {
        "rollback-cleanup-intent": cleanup,
        "rollback-cleanup-receipt": receipt,
        "rollback-cleanup-observation": observation,
    }
    authority = _Authority()
    journal = MainGraduationJournal(
        tmp_path, policy_epoch=D, rollback_authority_verifier=authority
    )
    journal._read = lambda kind, key: (  # type: ignore[method-assign]
        dependencies[kind], _ref()
    ) if kind in dependencies else journal._read_impl(kind, key)
    observation_ref = journal.record_rollback_cleanup_observation(observation)
    terminal_ref = journal.record_rollback_cleanup_terminal(terminal)
    assert journal.record_rollback_cleanup_terminal(terminal) == terminal_ref

    restarted = MainGraduationJournal(
        tmp_path, policy_epoch=D, rollback_authority_verifier=authority
    )
    original = restarted._read_impl

    def read(kind: str, key: str) -> Any:
        if kind in {"rollback-cleanup-terminal", "rollback-cleanup-observation"}:
            return original(kind, key)
        if kind in dependencies:
            return dependencies[kind], _ref()
        return original(kind, key)

    monkeypatch.setattr(restarted, "_read", read)
    loaded = restarted.read_rollback_cleanup_terminal(RB)
    assert loaded is not None and loaded[0] == terminal and loaded[1] == terminal_ref
    assert observation_ref.digest != terminal_ref.digest
    assert "cleanup-observation" in authority.calls
    assert authority.calls.count("cleanup-terminal") == 3

    missing_observation = MainGraduationJournal(
        tmp_path, policy_epoch=D, rollback_authority_verifier=authority
    )
    missing_original = missing_observation._read_impl

    def read_missing(kind: str, key: str) -> Any:
        if kind == "rollback-cleanup-terminal":
            return missing_original(kind, key)
        if kind == "rollback-cleanup-observation":
            return None
        if kind in dependencies:
            return dependencies[kind], _ref()
        return missing_original(kind, key)

    monkeypatch.setattr(missing_observation, "_read", read_missing)
    with pytest.raises(MainGraduationJournalError):
        missing_observation.read_rollback_cleanup_terminal(RB)

    mismatched = terminal.model_copy(
        update={"cleanup_observation_digest": "sha256:" + "8" * 64}
    )
    mismatched = _signed(
        MainRollbackCleanupTerminalEvidence,
        mismatched.model_dump(mode="json"),
        "evidence_digest",
    )
    with pytest.raises(MainGraduationJournalError, match="observation binding"):
        restarted._require_rollback_cleanup_terminal(mismatched)  # type: ignore[attr-defined]

    present = terminal.model_copy(update={"pull_request_state": "open"})
    with pytest.raises(ValidationError, match="pull_request_state"):
        MainRollbackCleanupTerminalEvidence.model_validate(
            present.model_dump(mode="json")
        )

    restarted.delete_artifact(observation_ref.digest)
    with pytest.raises(MainGraduationJournalError):
        restarted.read_rollback_cleanup_terminal(RB)
