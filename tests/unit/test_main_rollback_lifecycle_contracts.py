"""Bounded C5 rollback lifecycle contract and journal tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.application.c4_capabilities import CandidatePublicationRequest
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation import (
    MainInverseDeltaArtifact,
    MainPreparationAuthorization,
    MainRollbackAuthorization,
    MainRollbackCleanupIntent,
    MainRollbackCleanupObservation,
    MainRollbackCleanupReceipt,
    MainRollbackIntent,
    MainRollbackResultReceipt,
)
from avo_correlate.contracts.main_graduation_phase_a import MainLeaseEvidenceRecord
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_main_graduation_journal_coverage import completion

# These tests intentionally exercise private journal seams with small durable
# dependency maps.  They do not alter production contracts or schemas.
# pyright: reportPrivateUsage=false, reportArgumentType=false, reportUnknownArgumentType=false

D = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
R = "sha256:" + "3" * 64
RB = "sha256:" + "4" * 64
LEASE_EPOCH = "sha256:" + "5" * 64
BASE = "a" * 40
HEAD = "b" * 40
TREE = "c" * 40
RESULT = "d" * 40
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _ref(digest: str = D) -> ArtifactRef:
    return ArtifactRef(
        digest=digest,
        size_bytes=1,
        media_type="application/json",
        role="evidence",
        created_at=NOW,
    )


def _signed(model: Any, values: dict[str, Any], field: str) -> Any:
    probe = model.model_construct(**{**values, field: D})
    digest = canonical_digest(probe.model_dump(exclude={field}, mode="json"))
    return model.model_validate({**values, field: digest})


def _lease(*, expires_at: datetime = NOW + timedelta(minutes=10)) -> MainLeaseEvidenceRecord:
    values = {
        "operation_id": RB,
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "owner": "rollback-controller",
        "policy_epoch": D,
        "lease_epoch_digest": LEASE_EPOCH,
        "acquired_at": NOW,
        "expires_at": expires_at,
    }
    lease_digest = canonical_digest(
        MainLeaseEvidenceRecord.model_construct(
            **values, lease_digest=D, evidence_digest=D
        ).model_dump(exclude={"lease_digest", "evidence_digest"}, mode="json")
    )
    evidence_digest = canonical_digest(
        MainLeaseEvidenceRecord.model_construct(
            **values, lease_digest=lease_digest, evidence_digest=D
        ).model_dump(exclude={"evidence_digest"}, mode="json")
    )
    return MainLeaseEvidenceRecord.model_validate(
        {**values, "lease_digest": lease_digest, "evidence_digest": evidence_digest}
    )


def _rollback_intent(*, recorded_at: datetime = NOW + timedelta(minutes=2)) -> MainRollbackIntent:
    values = {
        "operation_id": RB,
        "source_operation_id": D,
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "completion_package_digest": D2,
        "original_delta_digest": D,
        "inverse_delta_digest": D2,
        "inverse_delta_artifact_digest": D,
        "base_commit": HEAD,
        "base_tree": TREE,
        "current_main_commit": HEAD,
        "current_main_tree": TREE,
        "current_main_parent_commit": BASE,
        "candidate_commit": RESULT,
        "candidate_tree": TREE,
        "candidate_parent_commit": HEAD,
        "candidate_ref": "refs/heads/avo/main-rollback/" + RB[7:],
        "inverse_tree": TREE,
        "lease_identity": "rollback-controller",
        "lease_digest": D,
        "lease_epoch_digest": LEASE_EPOCH,
        "policy_epoch": D,
        "authorization_digest": D,
        "recorded_at": recorded_at,
    }
    return _signed(MainRollbackIntent, values, "intent_digest")


def _rollback_authorization(
    *,
    authorized_at: datetime = NOW + timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(minutes=5),
) -> MainRollbackAuthorization:
    values = {
        "operation_id": RB,
        "source_operation_id": D,
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "completion_package_digest": D2,
        "original_delta_digest": D,
        "current_main_commit": HEAD,
        "current_main_tree": TREE,
        "current_main_parent_commit": BASE,
        "inverse_delta_digest": D2,
        "inverse_delta_artifact_digest": D,
        "inverse_tree": TREE,
        "lease_identity": "rollback-controller",
        "lease_digest": D,
        "lease_epoch_digest": LEASE_EPOCH,
        "policy_epoch": D,
        "controller_config_digest": D2,
        "release_issuer_identity": "isolated-release",
        "release_issuer_app_id": 9001,
        "issuer_isolation_digest": D,
        "authorized_at": authorized_at,
        "expires_at": expires_at,
    }
    return _signed(MainRollbackAuthorization, values, "authorization_digest")


def _rollback_preparation(
    intent: MainRollbackIntent, auth: MainRollbackAuthorization, *, authorized_at: datetime
) -> MainPreparationAuthorization:
    values = {
        "operation_id": RB,
        "repository_digest": R,
        "plan_digest": None,
        "intent_digest": intent.intent_digest,
        "package_digest": intent.completion_package_digest,
        "composition_digest": intent.inverse_delta_artifact_digest,
        "base_commit": intent.base_commit,
        "base_tree": intent.base_tree,
        "candidate_commit": intent.candidate_commit,
        "candidate_tree": intent.candidate_tree,
        "candidate_ref": intent.candidate_ref,
        "lease_identity": intent.lease_identity,
        "lease_digest": intent.lease_digest,
        "policy_epoch": auth.policy_epoch,
        "branch": "rollback",
        "rollback_authorization_digest": auth.authorization_digest,
        "rollback_intent_digest": intent.intent_digest,
        "authorized_at": authorized_at,
    }
    return _signed(MainPreparationAuthorization, values, "authorization_digest")


def _inverse(source: Any, *, policy_epoch: str = D) -> MainInverseDeltaArtifact:
    return MainInverseDeltaArtifact.model_construct(
        operation_id=RB,
        source_operation_id=source.operation_id,
        repository_digest=R,
        target_ref="refs/heads/main",
        completion_package_digest=canonical_digest(source),
        original_delta_digest=source.delta.delta_digest,
        current_main_commit=source.reconciliation.main_commit,
        current_main_tree=source.reconciliation.main_tree,
        current_main_parent_commit=source.reconciliation.main_parents[0],
        inverse_changed_paths=source.delta.changed_paths,
        inverse_tree=source.composition.base_tree,
        policy_epoch=policy_epoch,
        inverse_delta_digest=D2,
    )


def _result(
    source: Any,
    intent: MainRollbackIntent,
    auth: MainRollbackAuthorization,
    inverse: MainInverseDeltaArtifact,
    *,
    outcome: str = "applied",
    result_tree: str = TREE,
    result_parent: str = HEAD,
    result_parents: list[str] | None = None,
) -> MainRollbackResultReceipt:
    values = {
        "operation_id": RB,
        "source_operation_id": source.operation_id,
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "completion_package_digest": canonical_digest(source),
        "intent_digest": intent.intent_digest,
        "authorization_digest": auth.authorization_digest,
        "inverse_delta_digest": inverse.inverse_delta_digest,
        "inverse_delta_artifact_digest": canonical_digest(inverse),
        "current_main_commit": auth.current_main_commit,
        "inverse_tree": inverse.inverse_tree,
        "provider_identity": "github",
        "provider_api_version": "v1",
        "result_commit": RESULT,
        "result_tree": result_tree,
        "result_parent_commit": result_parent,
        "result_parents": [result_parent] if result_parents is None else result_parents,
        "outcome": outcome,
        "response_digest": D,
        "observed_at": NOW + timedelta(minutes=3),
    }
    return _signed(MainRollbackResultReceipt, values, "receipt_digest")


def _cleanup_intent(
    intent: MainRollbackIntent, auth: MainRollbackAuthorization, result: MainRollbackResultReceipt
) -> MainRollbackCleanupIntent:
    values = {
        "operation_id": RB,
        "source_operation_id": intent.source_operation_id,
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "completion_package_digest": result.completion_package_digest,
        "result_receipt_digest": result.receipt_digest,
        "authorization_digest": auth.authorization_digest,
        "candidate_ref": intent.candidate_ref,
        "candidate_commit": intent.candidate_commit,
        "pull_request_number": 17,
        "pull_request_url": "https://github.example/pr/17",
        "provider_identity": "github",
        "provider_api_version": "v1",
        "recorded_at": NOW + timedelta(minutes=4),
    }
    return _signed(MainRollbackCleanupIntent, values, "intent_digest")


def _cleanup_receipt(cleanup: MainRollbackCleanupIntent) -> MainRollbackCleanupReceipt:
    values = {
        "operation_id": RB,
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "intent_digest": cleanup.intent_digest,
        "authorization_digest": cleanup.authorization_digest,
        "candidate_ref": cleanup.candidate_ref,
        "candidate_commit": cleanup.candidate_commit,
        "pull_request_number": cleanup.pull_request_number,
        "pull_request_url": cleanup.pull_request_url,
        "outcome": "applied",
        "dispatch_started": True,
        "response_digest": D,
        "observed_at": NOW + timedelta(minutes=5),
    }
    return _signed(MainRollbackCleanupReceipt, values, "receipt_digest")


def _cleanup_observation(
    cleanup: MainRollbackCleanupIntent, receipt: MainRollbackCleanupReceipt
) -> MainRollbackCleanupObservation:
    values = {
        "operation_id": RB,
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "intent_digest": cleanup.intent_digest,
        "receipt_digest": receipt.receipt_digest,
        "candidate_ref": cleanup.candidate_ref,
        "candidate_commit": cleanup.candidate_commit,
        "pull_request_number": cleanup.pull_request_number,
        "pull_request_url": cleanup.pull_request_url,
        "outcome": "absent",
        "provider_identity": "github",
        "provider_api_version": "v1",
        "observed_at": NOW + timedelta(minutes=6),
    }
    return _signed(MainRollbackCleanupObservation, values, "observation_digest")


def _rollback_fixture() -> tuple[
    Any,
    MainInverseDeltaArtifact,
    MainRollbackIntent,
    MainRollbackAuthorization,
    MainLeaseEvidenceRecord,
    MainRollbackResultReceipt,
]:
    source = completion()
    inverse = _inverse(source)
    intent = _rollback_intent()
    auth = _rollback_authorization()
    lease = _lease()
    result = _result(source, intent, auth, inverse)
    return source, inverse, intent, auth, lease, result


class _AllowRollbackAuthority:
    def verify_rollback_result(self, *_args: Any) -> None:
        return None

    def verify_rollback_cleanup_receipt(self, *_args: Any) -> None:
        return None

    def verify_rollback_cleanup_intent(self, *_args: Any) -> None:
        return None

    def verify_rollback_cleanup_observation(self, *_args: Any) -> None:
        return None


def _journal_with_records(tmp_path: Path, records: dict[str, Any]) -> MainGraduationJournal:
    journal = MainGraduationJournal(
        tmp_path, policy_epoch=D, rollback_authority_verifier=_AllowRollbackAuthority()
    )
    journal._read = lambda kind, _key: (records[kind], _ref()) if kind in records else None  # type: ignore[method-assign]
    return journal


def test_rollback_intent_v3_binds_distinct_source_ref_and_lease_epoch() -> None:
    intent = _rollback_intent()
    assert intent.schema_version == 3
    assert intent.source_operation_id != intent.operation_id
    assert intent.candidate_ref == "refs/heads/avo/main-rollback/" + RB[7:]
    assert intent.lease_epoch_digest == LEASE_EPOCH

    same_source = intent.model_dump(mode="json")
    same_source.update({"source_operation_id": RB, "intent_digest": D})
    with pytest.raises(ValidationError):
        MainRollbackIntent.model_validate(same_source)
    with pytest.raises(ValidationError):
        MainRollbackIntent.model_validate(
            {
                **intent.model_dump(mode="json"),
                "candidate_ref": "refs/heads/avo/candidate/" + RB[7:],
                "intent_digest": D,
            }
        )
    missing_epoch = intent.model_dump(mode="json")
    del missing_epoch["lease_epoch_digest"]
    with pytest.raises(ValidationError):
        MainRollbackIntent.model_validate(missing_epoch)


def test_preparation_authorization_separates_graduation_and_rollback_branches() -> None:
    intent = _rollback_intent()
    auth = _rollback_authorization()
    rollback = _rollback_preparation(intent, auth, authorized_at=NOW + timedelta(minutes=3))
    assert rollback.branch == "rollback"
    assert rollback.plan_digest is None
    assert rollback.rollback_intent_digest == intent.intent_digest

    graduation_values = {
        "operation_id": D,
        "repository_digest": R,
        "plan_digest": D2,
        "intent_digest": D,
        "package_digest": D,
        "composition_digest": D2,
        "base_commit": BASE,
        "base_tree": TREE,
        "candidate_commit": HEAD,
        "candidate_tree": TREE,
        "lease_identity": "graduation-controller",
        "lease_digest": D,
        "policy_epoch": D,
        "authorized_at": NOW,
    }
    graduation = _signed(MainPreparationAuthorization, graduation_values, "authorization_digest")
    assert graduation.branch == "graduation"
    with pytest.raises(ValidationError):
        MainPreparationAuthorization.model_validate(
            {
                **graduation.model_dump(mode="json"),
                "branch": "graduation",
                "rollback_intent_digest": D,
                "authorization_digest": D,
            }
        )
    with pytest.raises(ValidationError):
        MainPreparationAuthorization.model_validate(
            {
                **rollback.model_dump(mode="json"),
                "plan_digest": D,
                "authorization_digest": D,
            }
        )


def test_c4_rollback_operation_kind_uses_private_namespace_and_rejects_downgrade() -> None:
    rollback_ref = "refs/heads/avo/main-rollback/" + RB[7:]
    request = CandidatePublicationRequest.build(
        operation_id=RB,
        repository_digest=R,
        lease_epoch_digest=LEASE_EPOCH,
        operation_kind="rollback",
        candidate_ref=rollback_ref,
        candidate_commit=RESULT,
        preparation_authorization_digest=D,
    )
    assert request.operation_kind == "rollback"
    assert request.candidate_ref == rollback_ref

    with pytest.raises(ValidationError, match="candidate ref"):
        CandidatePublicationRequest.build(
            operation_id=RB,
            repository_digest=R,
            lease_epoch_digest=LEASE_EPOCH,
            operation_kind="graduation",
            candidate_ref=rollback_ref,
            candidate_commit=RESULT,
            preparation_authorization_digest=D,
        )


def test_rollback_result_requires_exact_applied_topology() -> None:
    source, inverse, intent, auth, _lease_record, exact = _rollback_fixture()
    assert exact.outcome == "applied"
    assert exact.result_parent_commit == HEAD
    assert exact.result_parents == [HEAD]

    for updates in (
        {"result_parent_commit": BASE, "result_parents": [BASE]},
        {"result_tree": BASE},
        {"result_parent_commit": HEAD, "result_parents": [HEAD, BASE]},
    ):
        values = exact.model_dump(mode="json")
        values.update(updates)
        values["receipt_digest"] = D
        with pytest.raises(ValidationError):
            _signed(MainRollbackResultReceipt, values, "receipt_digest")

    records = {
        "rollback-intent": intent,
        "rollback-authorization": auth,
        "inverse-delta": inverse,
        "completion": source,
    }
    journal = _journal_with_records(Path("."), records)
    journal._require_rollback_result(exact)  # type: ignore[attr-defined]
    with pytest.raises(MainGraduationJournalError, match="topology"):
        journal._require_rollback_result(exact.model_copy(update={"result_tree": BASE}))  # type: ignore[attr-defined]


def test_cleanup_contracts_bind_ref_suffix_digests_and_dispatch_outcome() -> None:
    _source, _inverse, intent, auth, _lease_record, result = _rollback_fixture()
    cleanup = _cleanup_intent(intent, auth, result)
    receipt = _cleanup_receipt(cleanup)
    observation = _cleanup_observation(cleanup, receipt)
    assert observation.receipt_digest == receipt.receipt_digest

    bad_ref = cleanup.model_dump(mode="json")
    bad_ref["candidate_ref"] = cleanup.candidate_ref + "-suffix"
    bad_ref["intent_digest"] = D
    with pytest.raises(ValidationError):
        _signed(MainRollbackCleanupIntent, bad_ref, "intent_digest")

    invalid_dispatch = receipt.model_dump(mode="json")
    invalid_dispatch.update({"outcome": "applied", "dispatch_started": False, "receipt_digest": D})
    with pytest.raises(ValidationError):
        _signed(MainRollbackCleanupReceipt, invalid_dispatch, "receipt_digest")
    bad_observation = observation.model_dump(mode="json")
    bad_observation["observation_digest"] = D
    with pytest.raises(ValidationError):
        MainRollbackCleanupObservation.model_validate(bad_observation)

    records = {
        "rollback-result": result,
        "rollback-intent": intent,
        "rollback-authorization": auth,
        "rollback-cleanup-intent": cleanup,
        "rollback-cleanup-receipt": receipt,
    }
    journal = _journal_with_records(Path("."), records)
    journal._require_rollback_cleanup_intent(cleanup)  # type: ignore[attr-defined]
    journal._require_rollback_cleanup_receipt(receipt)  # type: ignore[attr-defined]
    journal._require_rollback_cleanup_observation(observation)  # type: ignore[attr-defined]
    with pytest.raises(MainGraduationJournalError, match="observation binding"):
        journal._require_rollback_cleanup_observation(  # type: ignore[attr-defined]
            observation.model_copy(update={"receipt_digest": D2})
        )


def test_journal_rejects_stale_policy_and_missing_or_mismatched_rollback_lease() -> None:
    source, inverse, intent, _auth, lease_record, _result_record = _rollback_fixture()
    stale = inverse.model_copy(update={"policy_epoch": D2})
    journal = MainGraduationJournal(Path("."), policy_epoch=D)
    journal._read = lambda kind, _key: (source, _ref()) if kind == "completion" else None  # type: ignore[method-assign]
    with pytest.raises(MainGraduationJournalError, match="policy epoch"):
        journal._require_inverse_source(stale)  # type: ignore[attr-defined]

    missing = MainGraduationJournal(Path("."), policy_epoch=D)
    missing._read = lambda _kind, _key: None  # type: ignore[method-assign]
    with pytest.raises(MainGraduationJournalError, match="fresh durable"):
        missing._require_rollback_lease_for_intent(intent)  # type: ignore[attr-defined]

    mismatched = lease_record.model_copy(update={"lease_epoch_digest": D2})
    fenced = MainGraduationJournal(Path("."), policy_epoch=D)
    fenced._read = lambda _kind, _key: (mismatched, _ref())  # type: ignore[method-assign]
    with pytest.raises(MainGraduationJournalError, match="lease binding"):
        fenced._require_rollback_lease_for_intent(intent)  # type: ignore[attr-defined]


def test_journal_rejects_post_expiry_rollback_intent_and_preparation() -> None:
    _source, _inverse, intent, auth, lease_record, _result_record = _rollback_fixture()
    expired_intent = _rollback_intent(recorded_at=lease_record.expires_at)
    journal = MainGraduationJournal(Path("."), policy_epoch=D)
    journal._read = lambda _kind, _key: (lease_record, _ref())  # type: ignore[method-assign]
    with pytest.raises(MainGraduationJournalError, match="lease binding"):
        journal._require_rollback_lease_for_intent(expired_intent)  # type: ignore[attr-defined]

    preparation = _rollback_preparation(
        intent, auth, authorized_at=auth.expires_at + timedelta(minutes=1)
    )
    records = {
        "rollback-authorization": auth,
        "rollback-intent": intent,
        "lease-evidence-record": lease_record,
    }
    prep_journal = _journal_with_records(Path("."), records)
    prep_journal._require_rollback_intent = lambda _auth: None  # type: ignore[method-assign]
    with pytest.raises(MainGraduationJournalError, match="authority binding"):
        prep_journal._require_rollback_preparation_chain(preparation)  # type: ignore[attr-defined]


def test_fresh_journal_rejects_missing_or_tampered_dependencies_on_restart(tmp_path: Path) -> None:
    source, inverse, intent, auth, _lease_record, result = _rollback_fixture()
    records = {
        "rollback-intent": intent,
        "rollback-authorization": auth,
        "inverse-delta": inverse,
        "completion": source,
    }
    restarted = _journal_with_records(tmp_path, records)
    restarted._require_rollback_result(result)  # type: ignore[attr-defined]

    for missing_kind in records:
        fresh = _journal_with_records(
            tmp_path / missing_kind,
            {k: v for k, v in records.items() if k != missing_kind},
        )
        with pytest.raises(MainGraduationJournalError, match="durable"):
            fresh._require_rollback_result(result)  # type: ignore[attr-defined]

    tampered = dict(records)
    tampered["inverse-delta"] = inverse.model_copy(update={"inverse_tree": BASE})
    fresh = _journal_with_records(tmp_path / "tampered", tampered)
    with pytest.raises(MainGraduationJournalError, match="authority binding"):
        fresh._require_rollback_result(result)  # type: ignore[attr-defined]
