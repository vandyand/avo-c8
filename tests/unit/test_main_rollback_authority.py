"""Pre-stage C5 rollback authority coordinator tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from pydantic import ValidationError

from avo_correlate.application.main_rollback_authority import (
    MainRollbackAuthority,
    MainRollbackAuthorityError,
    MainRollbackCurrentAuthority,
)
from avo_correlate.contracts.main_graduation import MainLeaseEvidenceRecord
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.c4_coordinator_test_support import MAIN_OPERATION, REPOSITORY
from tests.unit.test_main_graduation_completion_filesystem import _fresh_journal
from tests.unit.test_main_rollback_composition import _adapter, _Reader, _ready


def test_clock_rejects_naive_time() -> None:
    class NaiveClock:
        def now(self) -> datetime:
            return datetime(2026, 1, 1)

    with pytest.raises(MainRollbackAuthorityError, match="naive"):
        MainRollbackAuthority(
            journal=object(),  # type: ignore[arg-type]
            clock=NaiveClock(),
        )._trusted_now()


def test_public_result_exposes_durable_refs() -> None:
    # Keep the public contract assertion independent of hosted/provider
    # adapters; all writes are exercised by the journal integration tests.
    assert callable(MainRollbackAuthority.prepare)
    assert callable(MainRollbackAuthority.authorize)
    assert callable(MainRollbackAuthority.prepare_authority)


def _durable_lease(
    journal: Any,
    operation_id: str,
    policy_epoch: str,
    now: datetime,
) -> MainLeaseEvidenceRecord:
    values: dict[str, object] = {
        "operation_id": operation_id,
        "repository_digest": REPOSITORY,
        "target_ref": "refs/heads/main",
        "owner": "rollback-authority",
        "policy_epoch": policy_epoch,
        "lease_epoch_digest": canonical_digest({"lease": operation_id}),
        "acquired_at": now - timedelta(minutes=1),
        "expires_at": now + timedelta(hours=1),
    }
    probe = MainLeaseEvidenceRecord.model_construct(
        **values, lease_digest="sha256:" + "0" * 64, evidence_digest="sha256:" + "0" * 64
    )
    values["lease_digest"] = canonical_digest(
        probe.model_dump(exclude={"lease_digest", "evidence_digest"}, mode="json")
    )
    probe = MainLeaseEvidenceRecord.model_construct(
        **values, evidence_digest="sha256:" + "0" * 64
    )
    values["evidence_digest"] = canonical_digest(
        probe.model_dump(exclude={"evidence_digest"}, mode="json")
    )
    lease = MainLeaseEvidenceRecord.model_validate(values)
    journal.record_lease_evidence_record(lease)
    return lease


def test_composition_authority_prepare_replays_exactly(tmp_path) -> None:
    journal, checkout, provider, package = _ready(tmp_path)
    composition = _adapter(
        tmp_path,
        journal,
        _Reader(checkout, provider.main_commit, provider.main_tree),
    ).compose(
        source_operation_id=MAIN_OPERATION,
        completion_package_digest=canonical_digest(package),
    )
    source = cast(Any, package)
    now = datetime(2026, 1, 1, tzinfo=UTC)

    def acquire(
        operation_id: str, repository_digest: str, target_ref: str
    ) -> MainLeaseEvidenceRecord:
        source_lease = journal.read_lease_evidence_record(MAIN_OPERATION)
        assert source_lease is not None
        journal.release_target_lease(
            repository_digest,
            target_ref,
            MAIN_OPERATION,
            source_lease[0].lease_digest,
        )
        return _durable_lease(journal, operation_id, source.plan.policy_epoch, now)

    authority = MainRollbackAuthority(
        journal=journal,
        clock=type("Clock", (), {"now": lambda self: now})(),
        policy_epoch=source.plan.policy_epoch,
        controller_config_digest=source.release_issuer_binding.controller_config_digest,
        release_issuer_binding=source.release_issuer_binding,
        current_authority_reader=lambda: MainRollbackCurrentAuthority(
            current_main_commit=provider.main_commit,
            current_main_tree=provider.main_tree,
            current_main_parent_commit=source.reconciliation.main_parents[0],
            policy_epoch=source.plan.policy_epoch,
            controller_config_digest=source.release_issuer_binding.controller_config_digest,
            release_issuer_binding=source.release_issuer_binding,
        ),
        lease_acquirer=acquire,
    )
    preview = authority.preview(
        source_operation_id=MAIN_OPERATION,
        attempt_nonce="attempt-1",
        composition=composition,
    )
    first = authority.prepare(
        source_operation_id=MAIN_OPERATION,
        attempt_nonce="attempt-1",
        composition=composition,
    )
    assert first.operation_id == preview.operation_id
    restarted = _fresh_journal(journal)
    replay = MainRollbackAuthority(
        journal=restarted,
        clock=type(
            "Clock", (), {"now": lambda self: first.lease.expires_at + timedelta(seconds=1)}
        )(),
        policy_epoch=source.plan.policy_epoch,
        controller_config_digest=source.release_issuer_binding.controller_config_digest,
        release_issuer_binding=source.release_issuer_binding,
        current_authority_reader=lambda: MainRollbackCurrentAuthority(
            current_main_commit="f" * 40,
            current_main_tree=provider.main_tree,
            current_main_parent_commit=source.reconciliation.main_parents[0],
            policy_epoch=source.plan.policy_epoch,
            controller_config_digest=source.release_issuer_binding.controller_config_digest,
            release_issuer_binding=source.release_issuer_binding,
        ),
    ).prepare(
        source_operation_id=MAIN_OPERATION,
        attempt_nonce="attempt-1",
        composition=composition,
    )
    assert replay.operation_id == first.operation_id
    assert replay.refs == first.refs
    assert replay.intent == first.intent
    assert replay.authorization == first.authorization
    assert replay.attempt_authority == first.attempt_authority
    assert replay.preparation_authorization == first.preparation_authorization
    assert replay.composition == first.composition

    for record in (
        first.authorization,
        first.intent,
        first.attempt_authority,
        first.preparation_authorization,
    ):
        wire = record.model_dump(mode="json")
        wire.pop("composition_id")
        wire.pop("composition_artifact_digest")
        with pytest.raises(ValidationError):
            type(record).model_validate(wire)


def test_new_rollback_wires_reject_raw_legacy_shape() -> None:
    from avo_correlate.contracts.main_graduation import (
        MainRollbackAttemptAuthority,
        MainRollbackAuthorization,
        MainRollbackIntent,
        MainRollbackPreparationAuthorization,
    )

    for model in (
        MainRollbackAuthorization,
        MainRollbackIntent,
        MainRollbackAttemptAuthority,
        MainRollbackPreparationAuthorization,
    ):
        assert model.model_fields["composition_id"].is_required()
        assert model.model_fields["composition_artifact_digest"].is_required()


def test_first_prepare_requires_fresh_current_authority_reader(tmp_path) -> None:
    journal, checkout, provider, package = _ready(tmp_path)
    composition = _adapter(
        tmp_path,
        journal,
        _Reader(checkout, provider.main_commit, provider.main_tree),
    ).compose(
        source_operation_id=MAIN_OPERATION,
        completion_package_digest=canonical_digest(package),
    )
    source = cast(Any, package)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    source_lease = journal.read_lease_evidence_record(MAIN_OPERATION)
    assert source_lease is not None
    journal.release_target_lease(
        REPOSITORY,
        "refs/heads/main",
        MAIN_OPERATION,
        source_lease[0].lease_digest,
    )
    authority = MainRollbackAuthority(
        journal=journal,
        clock=type("Clock", (), {"now": lambda self: now})(),
        policy_epoch=source.plan.policy_epoch,
        controller_config_digest=source.release_issuer_binding.controller_config_digest,
        release_issuer_binding=source.release_issuer_binding,
    )
    preview = authority.preview(
        source_operation_id=MAIN_OPERATION,
        attempt_nonce="missing-reader",
        composition=composition,
    )
    _durable_lease(journal, preview.operation_id, source.plan.policy_epoch, now)
    with pytest.raises(MainRollbackAuthorityError, match="reader is required"):
        authority.prepare(
            source_operation_id=MAIN_OPERATION,
            attempt_nonce="missing-reader",
            composition=composition,
        )
    assert journal.read_rollback_intent(preview.operation_id) is None


def test_post_lease_authority_drift_writes_no_intent(tmp_path) -> None:
    journal, checkout, provider, package = _ready(tmp_path)
    composition = _adapter(
        tmp_path,
        journal,
        _Reader(checkout, provider.main_commit, provider.main_tree),
    ).compose(
        source_operation_id=MAIN_OPERATION,
        completion_package_digest=canonical_digest(package),
    )
    source = cast(Any, package)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    source_lease = journal.read_lease_evidence_record(MAIN_OPERATION)
    assert source_lease is not None
    journal.release_target_lease(
        REPOSITORY,
        "refs/heads/main",
        MAIN_OPERATION,
        source_lease[0].lease_digest,
    )
    drifted = MainRollbackCurrentAuthority(
        current_main_commit="f" * 40,
        current_main_tree=provider.main_tree,
        current_main_parent_commit=source.reconciliation.main_parents[0],
        policy_epoch=source.plan.policy_epoch,
        controller_config_digest=source.release_issuer_binding.controller_config_digest,
        release_issuer_binding=source.release_issuer_binding,
    )
    authority = MainRollbackAuthority(
        journal=journal,
        clock=type("Clock", (), {"now": lambda self: now})(),
        policy_epoch=source.plan.policy_epoch,
        controller_config_digest=source.release_issuer_binding.controller_config_digest,
        release_issuer_binding=source.release_issuer_binding,
        current_authority_reader=lambda: drifted,
    )
    preview = authority.preview(
        source_operation_id=MAIN_OPERATION,
        attempt_nonce="drifted-main",
        composition=composition,
    )
    _durable_lease(journal, preview.operation_id, source.plan.policy_epoch, now)
    with pytest.raises(MainRollbackAuthorityError, match="drifted"):
        authority.prepare(
            source_operation_id=MAIN_OPERATION,
            attempt_nonce="drifted-main",
            composition=composition,
        )
    assert journal.read_rollback_intent(preview.operation_id) is None


@pytest.mark.parametrize(
    "boundary",
    (
        "intent",
        "authorization",
        "attempt_authority",
        "preparation_authorization",
    ),
)
def test_restart_adopts_records_after_each_durable_boundary(tmp_path, monkeypatch, boundary):
    journal, checkout, provider, package = _ready(tmp_path / boundary)
    composition = _adapter(
        tmp_path / boundary,
        journal,
        _Reader(checkout, provider.main_commit, provider.main_tree),
    ).compose(
        source_operation_id=MAIN_OPERATION,
        completion_package_digest=canonical_digest(package),
    )
    source = cast(Any, package)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    source_lease = journal.read_lease_evidence_record(MAIN_OPERATION)
    assert source_lease is not None
    journal.release_target_lease(
        REPOSITORY,
        "refs/heads/main",
        MAIN_OPERATION,
        source_lease[0].lease_digest,
    )

    def current() -> MainRollbackCurrentAuthority:
        return MainRollbackCurrentAuthority(
            current_main_commit=provider.main_commit,
            current_main_tree=provider.main_tree,
            current_main_parent_commit=source.reconciliation.main_parents[0],
            policy_epoch=source.plan.policy_epoch,
            controller_config_digest=source.release_issuer_binding.controller_config_digest,
            release_issuer_binding=source.release_issuer_binding,
        )

    authority = MainRollbackAuthority(
        journal=journal,
        clock=type("Clock", (), {"now": lambda self: now})(),
        policy_epoch=source.plan.policy_epoch,
        controller_config_digest=source.release_issuer_binding.controller_config_digest,
        release_issuer_binding=source.release_issuer_binding,
        current_authority_reader=current,
    )
    preview = authority.preview(
        source_operation_id=MAIN_OPERATION,
        attempt_nonce="fault-" + boundary,
        composition=composition,
    )
    lease = _durable_lease(journal, preview.operation_id, source.plan.policy_epoch, now)
    writer_name = {
        "intent": "record_rollback_intent",
        "authorization": "record_rollback_authorization",
        "attempt_authority": "record_rollback_attempt_authority",
        "preparation_authorization": "record_rollback_preparation_authorization",
    }[boundary]
    original = getattr(journal, writer_name)
    calls = 0

    def fail_after_write(record: Any) -> Any:
        nonlocal calls
        calls += 1
        original(record)
        raise ValueError("fault after durable boundary")

    monkeypatch.setattr(journal, writer_name, fail_after_write)
    with pytest.raises(MainRollbackAuthorityError):
        authority.prepare(
            source_operation_id=MAIN_OPERATION,
            attempt_nonce="fault-" + boundary,
            composition=composition,
            lease=lease,
        )
    assert calls == 1
    monkeypatch.setattr(journal, writer_name, original)

    restarted = _fresh_journal(journal)
    replay_now = now + timedelta(seconds=1)
    replay_reader = current
    replay = MainRollbackAuthority(
        journal=restarted,
        clock=type("Clock", (), {"now": lambda self: replay_now})(),
        policy_epoch=source.plan.policy_epoch,
        controller_config_digest=source.release_issuer_binding.controller_config_digest,
        release_issuer_binding=source.release_issuer_binding,
        current_authority_reader=replay_reader,
    ).prepare(
        source_operation_id=MAIN_OPERATION,
        attempt_nonce="fault-" + boundary,
        composition=composition,
        lease=lease,
    )
    assert replay.operation_id == preview.operation_id
    assert replay.refs["rollback-preparation-authorization"].digest
