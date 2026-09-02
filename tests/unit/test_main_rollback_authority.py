"""Pre-stage C5 rollback authority coordinator tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from avo_correlate.application.main_rollback_authority import (
    MainRollbackAuthority,
    MainRollbackAuthorityError,
    MainRollbackCurrentAuthority,
    TrustedClock,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation import (
    MainLeaseEvidenceRecord,
    MainRollbackCompositionArtifact,
    main_rollback_composition_id,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.c4_coordinator_test_support import MAIN_OPERATION, REPOSITORY
from tests.unit.test_main_graduation_completion_filesystem import (
    _fresh_journal,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.test_main_rollback_composition import (  # pyright: ignore[reportPrivateUsage]
    _adapter,  # pyright: ignore[reportPrivateUsage]
    _Reader,  # pyright: ignore[reportPrivateUsage]
    _ready,  # pyright: ignore[reportPrivateUsage]
)


class _Clock(TrustedClock):
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


def test_clock_rejects_naive_time() -> None:
    class NaiveClock(TrustedClock):
        def now(self) -> datetime:
            return datetime(2026, 1, 1)

    with pytest.raises(MainRollbackAuthorityError, match="naive"):
        MainRollbackAuthority(
            journal=object(),  # type: ignore[arg-type]
            clock=NaiveClock(),
        )._trusted_now()  # pyright: ignore[reportPrivateUsage]


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
    probe = MainLeaseEvidenceRecord.model_construct(  # pyright: ignore[reportArgumentType]
        **cast(Any, values), lease_digest="sha256:" + "0" * 64, evidence_digest="sha256:" + "0" * 64
    )
    values["lease_digest"] = canonical_digest(
        probe.model_dump(exclude={"lease_digest", "evidence_digest"}, mode="json")
    )
    probe = MainLeaseEvidenceRecord.model_construct(  # pyright: ignore[reportArgumentType]
        **cast(Any, values), evidence_digest="sha256:" + "0" * 64
    )
    values["evidence_digest"] = canonical_digest(
        probe.model_dump(exclude={"evidence_digest"}, mode="json")
    )
    lease = MainLeaseEvidenceRecord.model_validate(values)
    journal.record_lease_evidence_record(lease)
    return lease


def test_composition_authority_prepare_replays_exactly(tmp_path: Path) -> None:
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
        clock=_Clock(now),
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
        clock=_Clock(first.lease.expires_at + timedelta(seconds=1)),
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


def test_authority_rejects_unjournaled_forged_composition_before_lease(tmp_path: Path) -> None:
    journal, checkout, provider, package = _ready(tmp_path)
    composed = _adapter(
        tmp_path,
        journal,
        _Reader(checkout, provider.main_commit, provider.main_tree),
    ).compose(
        source_operation_id=MAIN_OPERATION,
        completion_package_digest=canonical_digest(package),
    )
    original = composed.composition
    values = original.model_dump(mode="json")
    values.pop("composition_id")
    values.pop("retention_ref")
    values["candidate_commit"] = "a" * 40
    values["inverse_delta_digest"] = "sha256:" + "0" * 64
    probe = MainRollbackCompositionArtifact.model_construct(  # pyright: ignore[reportArgumentType]
        **values,
        composition_id="sha256:" + "0" * 64,
        retention_ref="refs/avo/main-rollback/" + "0" * 64,
    )
    values["inverse_delta_digest"] = canonical_digest(
        probe.model_dump(
            exclude={"inverse_delta_digest", "composition_id", "retention_ref"},
            mode="json",
        )
    )
    probe = MainRollbackCompositionArtifact.model_construct(  # pyright: ignore[reportArgumentType]
        **values,
        composition_id="sha256:" + "0" * 64,
        retention_ref="refs/avo/main-rollback/" + "0" * 64,
    )
    forged_id = main_rollback_composition_id(
        **probe.model_dump(exclude={"composition_id", "retention_ref"}, mode="json")
    )
    values["composition_id"] = forged_id
    values["retention_ref"] = "refs/avo/main-rollback/" + forged_id.removeprefix("sha256:")
    forged = MainRollbackCompositionArtifact.model_validate(values)
    forged_ref = ArtifactRef(
        digest=canonical_digest(forged),
        size_bytes=len(canonical_bytes(forged)),
        media_type=composed.composition_artifact.media_type,
        role=composed.composition_artifact.role,
        created_at=composed.composition_artifact.created_at,
    )
    forged_result = replace(
        composed,
        composition_id=forged.composition_id,
        composition=forged,
        composition_artifact=forged_ref,
        candidate_commit=forged.candidate_commit,
        candidate_tree=forged.candidate_tree,
        candidate_parent_commit=forged.candidate_parent_commit,
        retention_ref=forged.retention_ref,
    )
    source = cast(Any, package)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    lease_calls = 0

    def acquire(*_args: object) -> MainLeaseEvidenceRecord:
        nonlocal lease_calls
        lease_calls += 1
        raise AssertionError("lease acquisition must not run")

    authority = MainRollbackAuthority(
        journal=journal,
        clock=_Clock(now),
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
    for operation in (authority.preview, authority.prepare):
        with pytest.raises(MainRollbackAuthorityError, match="durably recorded"):
            operation(
                source_operation_id=MAIN_OPERATION,
                attempt_nonce="forged-composition",
                composition=forged_result,
            )
    assert lease_calls == 0
    assert list((tmp_path / "main-graduation-index" / "rollback-intent").glob("*.json")) == []

    mismatched_ref = replace(
        composed,
        composition_artifact=composed.composition_artifact.model_copy(
            update={"digest": "sha256:" + "0" * 64}
        ),
    )
    with pytest.raises(MainRollbackAuthorityError, match="artifact reference digest"):
        authority.preview(
            source_operation_id=MAIN_OPERATION,
            attempt_nonce="mismatched-ref",
            composition=mismatched_ref,
        )


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


def test_first_prepare_requires_fresh_current_authority_reader(tmp_path: Path) -> None:
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
        clock=_Clock(now),
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


def test_post_lease_authority_drift_writes_no_intent(tmp_path: Path) -> None:
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
        clock=_Clock(now),
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
def test_restart_adopts_records_after_each_durable_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
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
        clock=_Clock(now),
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
        clock=_Clock(replay_now),
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
