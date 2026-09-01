"""Rollback branch coverage for the durable C3/C4 queue protocol."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.contracts.main_graduation import (
    MainAttestationManifest,
    MainCheckObservation,
    MainGraduationPlan,
    MainMergeGroupChecks,
    MainMergeGroupWebhookReceipt,
    MainProtectionManifest,
    MainQueueAdmissionObservation,
    MainQueueConfigurationObservation,
    MainQueueObservation,
    MainReleaseAuthorization,
    MainReleaseHoldObservation,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_main_rollback_lifecycle_contracts import (
    BASE,
    D2,
    HEAD,
    NOW,
    RB,
    RESULT,
    TREE,
    D,
    R,
    _journal_with_records,
    _rollback_fixture,
    _rollback_preparation,
)


def _records() -> dict[str, Any]:
    _source, _inverse, intent, rollback_auth, lease, _result = _rollback_fixture()
    intent = intent.model_copy(update={"authorization_digest": rollback_auth.authorization_digest})
    preparation = _rollback_preparation(
        intent, rollback_auth, authorized_at=NOW + timedelta(minutes=2)
    )
    qconfig = MainQueueConfigurationObservation.model_construct(
        operation_id=RB,
        repository_digest=R,
        target_ref="refs/heads/main",
        queue_configuration_digest=D,
        expected_base_commit=HEAD,
        expected_base_tree=TREE,
        protection_manifest_digest=D,
        protection_epoch=D,
        provider_identity="provider",
        provider_api_version="v1",
        merge_method="squash",
        isolated_release_issuer="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        observed_at=NOW,
    )
    protection = MainProtectionManifest.model_construct(
        operation_id=RB,
        repository_digest=R,
        target_ref="refs/heads/main",
        manifest_digest=D,
        provider_identity="provider",
        provider_api_version="v1",
        isolated_release_issuer="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        protection_epoch=D,
        observed_at=NOW,
    )
    admission = MainQueueAdmissionObservation.model_construct(
        operation_id=RB,
        repository_digest=R,
        target_ref="refs/heads/main",
        preparation_authorization_digest=canonical_digest(preparation),
        package_digest=preparation.package_digest,
        composition_digest=preparation.composition_digest,
        pull_request_number=7,
        pull_request_url="https://github.example/pull/7",
        base_commit=HEAD,
        base_tree=TREE,
        head_commit=RESULT,
        head_tree=BASE,
        admission_sha=RESULT,
        admission_run_id="rollback-admission",
        admission_nonce="rollback-admission-nonce",
        queue_configuration_digest=D,
        protection_manifest_digest=D,
        issuer_identity="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        observed_at=NOW + timedelta(minutes=3),
    )
    queue = MainQueueObservation.model_construct(
        operation_id=RB,
        repository_digest=R,
        target_ref="refs/heads/main",
        queue_generation_digest=D2,
        queue_manifest_digest=D,
        queue_configuration_digest=D,
        admission_observation_digest=canonical_digest(admission),
        expected_base_commit=HEAD,
        expected_base_tree=TREE,
        protection_manifest_digest=D,
        protection_epoch=D,
        provider_identity="provider",
        provider_api_version="v1",
        expected_group_parents=[HEAD, RESULT],
        group_topology_digest=D,
        merge_method="squash",
        isolated_release_issuer="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        observed_at=NOW + timedelta(minutes=3),
        pull_request_number=7,
    )
    check = MainCheckObservation.model_construct(
        name="validation",
        context="validate",
        app_id=15368,
        sha=D2,
        status="completed",
        conclusion="success",
        run_id="run",
        nonce="nonce",
        observed_at=NOW + timedelta(minutes=3),
    )
    checks = MainMergeGroupChecks.model_construct(
        operation_id=RB,
        repository_digest=R,
        target_ref="refs/heads/main",
        package_digest=preparation.package_digest,
        composition_digest=preparation.composition_digest,
        group_sha=D2,
        checks=[check],
        allowlisted_contexts=["validate"],
        config_digest=D,
        freshness_cutoff=NOW,
        observed_at=NOW + timedelta(minutes=3),
    )
    webhook = MainMergeGroupWebhookReceipt.model_construct(
        operation_id=RB,
        repository_digest=R,
        target_ref="refs/heads/main",
        group_sha=D2,
        group_tree=BASE,
        group_parents=[HEAD, RESULT],
        pull_request_number=7,
        queue_generation_digest=D2,
        delivery_id="rollback-delivery",
        body_digest=D,
        observed_at=NOW + timedelta(minutes=3),
        receipt_digest=D,
    )
    attestations = MainAttestationManifest.model_construct(
        operation_id=RB,
        repository_digest=R,
        package_digest=preparation.package_digest,
        composition_digest=preparation.composition_digest,
        policy_epoch=rollback_auth.policy_epoch,
        reviewer_identity="reviewer",
        reviewer_evidence_digest=D,
        evaluator_identity="evaluator",
        evaluator_evidence_digest=D2,
    )
    hold = MainReleaseHoldObservation.model_construct(
        operation_id=RB,
        repository_digest=R,
        target_ref="refs/heads/main",
        preparation_authorization_digest=canonical_digest(preparation),
        admission_observation_digest=canonical_digest(admission),
        package_digest=preparation.package_digest,
        composition_digest=preparation.composition_digest,
        pull_request_number=7,
        group_sha=D2,
        group_tree=BASE,
        group_parents=[HEAD, RESULT],
        expected_group_parents=[HEAD, RESULT],
        group_topology_digest=D,
        base_commit=HEAD,
        base_tree=TREE,
        composition_tree=BASE,
        queue_generation_digest=D2,
        queue_members=[7],
        hold_run_id="rollback-hold",
        hold_nonce="rollback-hold-nonce",
        issuer_identity="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        other_required_checks=checks,
        merge_group_receipt=webhook,
        protection_manifest_digest=D,
        attestation_manifest_digest=canonical_digest(attestations),
        observed_at=NOW + timedelta(minutes=4),
    )
    release = MainReleaseAuthorization.model_construct(
        operation_id=RB,
        repository_digest=R,
        target_ref="refs/heads/main",
        preparation_authorization_digest=canonical_digest(preparation),
        admission_observation_digest=canonical_digest(admission),
        hold_observation_digest=canonical_digest(hold),
        package_digest=preparation.package_digest,
        composition_digest=preparation.composition_digest,
        group_sha=D2,
        hold_run_id="rollback-hold",
        hold_nonce="rollback-hold-nonce",
        queue_generation_digest=D2,
        lease_identity=lease.owner,
        lease_digest=lease.lease_digest,
        policy_epoch=rollback_auth.policy_epoch,
        release_issuer_identity="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        authorization_digest=D,
        expires_at=NOW + timedelta(minutes=5),
        authorized_at=NOW + timedelta(minutes=4, seconds=30),
    )
    return {
        "rollback-preparation-authorization": preparation,
        "rollback-authorization": rollback_auth,
        "rollback-intent": intent,
        "lease-evidence-record": lease,
        "queue-configuration": qconfig,
        "protection": protection,
        "queue-admission": admission,
        "queue": queue,
        "attestations": attestations,
        "merge-group-checks": checks,
        "merge-group-webhook-receipt": webhook,
        "release-hold": hold,
        "release-authorization": release,
    }


def test_rollback_queue_hold_release_chain_uses_rollback_preparation(tmp_path: Path) -> None:
    records = _records()
    journal = _journal_with_records(tmp_path, records)
    # The fixture intentionally isolates this test to C3/C4 routing; the
    # rollback authority's inverse/source checks have dedicated coverage.
    journal._require_rollback_preparation_chain = lambda _record: None  # type: ignore[method-assign]
    journal._require_queue_admission(records["queue-admission"])
    journal._require_admission(records["release-hold"])
    journal._require_hold(records["release-authorization"])


def test_rollback_queue_chain_rejects_mixed_or_downgraded_authority(tmp_path: Path) -> None:
    records = _records()
    journal = _journal_with_records(tmp_path, records)
    journal._require_rollback_preparation_chain = lambda _record: None  # type: ignore[method-assign]
    records["plan"] = MainGraduationPlan.model_construct(operation_id=RB)
    plan_index = journal._indexes / "plan" / f"{RB.removeprefix('sha256:')}.json"  # type: ignore[attr-defined]
    plan_index.parent.mkdir(parents=True, exist_ok=True)
    plan_index.write_text("{}", encoding="utf-8")
    with pytest.raises(MainGraduationJournalError, match="mixed"):
        journal._require_queue_admission(records["queue-admission"])
    records.pop("plan")
    plan_index.unlink()
    records["preparation-authorization"] = MainGraduationPlan.model_construct(
        operation_id=RB
    )
    prep_index = (
        journal._indexes  # type: ignore[attr-defined]
        / "preparation-authorization"
        / f"{RB.removeprefix('sha256:')}.json"
    )
    prep_index.parent.mkdir(parents=True, exist_ok=True)
    prep_index.write_text("{}", encoding="utf-8")
    journal._require_rollback_preparation_chain = (
        MainGraduationJournal._require_rollback_preparation_chain.__get__(journal)
    )
    with pytest.raises(MainGraduationJournalError, match="mixed graduation and rollback"):
        journal._require_queue_admission(records["queue-admission"])
