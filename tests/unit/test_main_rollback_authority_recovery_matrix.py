"""Filesystem-backed adversarial recovery matrix for the bounded C5 authority."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournalError,
    MainGraduationRecordConflictError,
)
from avo_correlate.adapters.git.main_rollback_composition import (
    MainRollbackCompositionError,
)
from avo_correlate.application.main_rollback_authority import (
    MainRollbackAuthority,
    MainRollbackAuthorityError,
    MainRollbackCurrentAuthority,
)
from avo_correlate.contracts.main_graduation import MainReleaseIssuerBinding
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_main_graduation_coordinator_preparation import _fresh_journal
from tests.unit.test_main_rollback_authority import _durable_lease
from tests.unit.test_main_rollback_composition import _adapter, _Reader, _ready

_NOW = datetime(2026, 1, 1, tzinfo=UTC)
_ZERO = "sha256:" + "0" * 64


@dataclass
class _RollbackFixture:
    journal: Any
    checkout: Path
    provider: Any
    package: Any
    composition: Any
    authority: MainRollbackAuthority
    now: datetime


def _fixture(tmp_path: Path) -> _RollbackFixture:
    journal, checkout, provider, package = _ready(tmp_path)
    composition = _adapter(
        tmp_path,
        journal,
        _Reader(checkout, provider.main_commit, provider.main_tree),
    ).compose(
        source_operation_id=package.operation_id,
        completion_package_digest=canonical_digest(package),
    )
    source_lease = journal.read_lease_evidence_record(package.operation_id)
    assert source_lease is not None
    assert journal.release_target_lease(
        package.repository_digest,
        package.target_ref,
        package.operation_id,
        source_lease[0].lease_digest,
    )

    def current() -> MainRollbackCurrentAuthority:
        return MainRollbackCurrentAuthority(
            current_main_commit=provider.main_commit,
            current_main_tree=provider.main_tree,
            current_main_parent_commit=package.reconciliation.main_parents[0],
            policy_epoch=package.plan.policy_epoch,
            controller_config_digest=package.release_issuer_binding.controller_config_digest,
            release_issuer_binding=package.release_issuer_binding,
        )

    def acquire(operation_id: str, repository_digest: str, target_ref: str) -> Any:
        assert repository_digest == package.repository_digest
        assert target_ref == package.target_ref
        return _durable_lease(journal, operation_id, package.plan.policy_epoch, _NOW)

    authority = MainRollbackAuthority(
        journal=journal,
        clock=type("Clock", (), {"now": lambda self: _NOW})(),
        policy_epoch=package.plan.policy_epoch,
        controller_config_digest=package.release_issuer_binding.controller_config_digest,
        release_issuer_binding=package.release_issuer_binding,
        current_authority_reader=current,
        lease_acquirer=acquire,
    )
    return _RollbackFixture(
        journal, checkout, provider, package, composition, authority, _NOW
    )


def _composition_index(journal: Any, composition_id: str) -> Path:
    return journal.root / "main-graduation-index" / "rollback-composition" / (
        composition_id.removeprefix("sha256:") + ".json"
    )


def _record_index(journal: Any, kind: str, operation_id: str) -> Path:
    return journal.root / "main-graduation-index" / kind / (
        operation_id.removeprefix("sha256:") + ".json"
    )


def _restart(fixture: _RollbackFixture, journal: Any) -> MainRollbackAuthority:
    package = fixture.package
    provider = fixture.provider
    return MainRollbackAuthority(
        journal=journal,
        clock=type("Clock", (), {"now": lambda self: fixture.now})(),
        policy_epoch=package.plan.policy_epoch,
        controller_config_digest=package.release_issuer_binding.controller_config_digest,
        release_issuer_binding=package.release_issuer_binding,
        current_authority_reader=lambda: MainRollbackCurrentAuthority(
            current_main_commit=provider.main_commit,
            current_main_tree=provider.main_tree,
            current_main_parent_commit=package.reconciliation.main_parents[0],
            policy_epoch=package.plan.policy_epoch,
            controller_config_digest=package.release_issuer_binding.controller_config_digest,
            release_issuer_binding=package.release_issuer_binding,
        ),
    )


def test_orphaned_retention_exact_recomposition_adopts_after_restart(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    original = fixture.composition
    _composition_index(fixture.journal, original.composition_id).unlink()

    restarted = _fresh_journal(fixture.journal)
    with restarted.rollback_authority_recovery(fixture.package.operation_id):
        recovered = _adapter(
            tmp_path,
            restarted,
            _Reader(
                fixture.checkout, fixture.provider.main_commit, fixture.provider.main_tree
            ),
        ).compose(
            source_operation_id=fixture.package.operation_id,
            completion_package_digest=canonical_digest(fixture.package),
        )

    assert recovered.composition_id == original.composition_id
    assert recovered.composition == original.composition
    assert recovered.composition_artifact.digest == original.composition_artifact.digest
    with restarted.rollback_authority_recovery(fixture.package.operation_id):
        assert restarted.read_rollback_composition(original.composition_id) is not None


@pytest.mark.parametrize("tamper", ["retention", "artifact"])
def test_orphaned_retention_conflict_or_cas_tamper_fails_closed(
    tmp_path: Path, tamper: str
) -> None:
    fixture = _fixture(tmp_path / tamper)
    original = fixture.composition
    _composition_index(fixture.journal, original.composition_id).unlink()
    if tamper == "retention":
        subprocess.run(
            ["git", "update-ref", original.retention_ref, fixture.provider.main_commit],
            cwd=fixture.checkout,
            check=True,
            capture_output=True,
        )
    else:
        artifact_path = fixture.journal._store.path_for_digest(  # pyright: ignore[reportPrivateUsage]
            original.composition_artifact.digest
        )
        artifact_path.write_bytes(artifact_path.read_bytes() + b"tampered")

    restarted = _fresh_journal(fixture.journal)
    with (
        pytest.raises(MainRollbackCompositionError),
        restarted.rollback_authority_recovery(fixture.package.operation_id),
    ):
        _adapter(
            tmp_path / tamper,
            restarted,
            _Reader(
                fixture.checkout, fixture.provider.main_commit, fixture.provider.main_tree
            ),
        ).compose(
            source_operation_id=fixture.package.operation_id,
            completion_package_digest=canonical_digest(fixture.package),
        )


def test_intent_survives_expiry_and_missing_authorization_restart(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    prepared = fixture.authority.prepare(
        source_operation_id=fixture.package.operation_id,
        attempt_nonce="restart-same-operation",
        composition=fixture.composition,
    )
    _record_index(fixture.journal, "rollback-authorization", prepared.operation_id).unlink()
    restarted_journal = _fresh_journal(fixture.journal)
    restarted = _restart(fixture, restarted_journal)
    restarted.clock = type(  # type: ignore[misc]
        "ExpiredClock", (), {"now": lambda self: prepared.lease.expires_at + timedelta(seconds=1)}
    )()

    replay = restarted.prepare(
        source_operation_id=fixture.package.operation_id,
        attempt_nonce="restart-same-operation",
        composition=fixture.composition,
        lease=prepared.lease,
    )
    assert replay.operation_id == prepared.operation_id
    assert replay.authorization == prepared.authorization
    assert replay.intent == prepared.intent
    assert _record_index(
        restarted_journal, "rollback-authorization", prepared.operation_id
    ).is_file()

    with pytest.raises(MainRollbackAuthorityError, match="policy epoch"):
        restarted.prepare(
            source_operation_id=fixture.package.operation_id,
            attempt_nonce="restart-same-operation",
            composition=fixture.composition,
            policy_epoch=_ZERO,
            lease=prepared.lease,
        )


def test_duplicate_runner_and_lease_claims_are_single_owner_or_conflicts(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    first = fixture.authority.prepare(
        source_operation_id=fixture.package.operation_id,
        attempt_nonce="single-owner",
        composition=fixture.composition,
    )
    restarted_journal = _fresh_journal(fixture.journal)
    second = _restart(fixture, restarted_journal).prepare(
        source_operation_id=fixture.package.operation_id,
        attempt_nonce="single-owner",
        composition=fixture.composition,
        lease=first.lease,
    )
    assert second.operation_id == first.operation_id
    assert second.refs == first.refs

    with pytest.raises(MainGraduationRecordConflictError):
        _durable_lease(
            restarted_journal,
            "sha256:" + "9" * 64,
            fixture.package.plan.policy_epoch,
            fixture.now,
        )

    conflicting_intent = first.intent.model_copy(
        update={"candidate_ref": "refs/heads/avo/main-rollback/conflicting"}
    )
    with pytest.raises((MainGraduationRecordConflictError, MainGraduationJournalError)):
        restarted_journal.record_rollback_intent(conflicting_intent)


@pytest.mark.parametrize("drift", ["source", "identity", "policy", "issuer", "topology"])
def test_authority_drift_is_rejected_before_intent_or_provider_mutation(
    tmp_path: Path, drift: str
) -> None:
    fixture = _fixture(tmp_path / drift)
    lease_calls = 0

    def never_acquire(*_: object) -> Any:
        nonlocal lease_calls
        lease_calls += 1
        raise AssertionError("drift must be rejected before lease acquisition")

    if drift == "source":
        drifted_composition = replace(
            fixture.composition,
            source_operation_id=_ZERO,
        )
        kwargs = {}
        reader = fixture.authority.current_authority_reader
    elif drift == "identity":
        drifted_composition = replace(
            fixture.composition,
            composition_id=_ZERO,
        )
        kwargs = {}
        reader = fixture.authority.current_authority_reader
    elif drift == "policy":
        drifted_composition = fixture.composition
        kwargs: dict[str, Any] = {"policy_epoch": _ZERO}
        reader = fixture.authority.current_authority_reader
    elif drift == "issuer":
        drifted_composition = fixture.composition
        original = fixture.package.release_issuer_binding
        values = original.model_dump(mode="json")
        values["issuer_id"] = "different-issuer"
        values["binding_digest"] = canonical_digest(
            {key: value for key, value in values.items() if key != "binding_digest"}
        )
        kwargs = {"release_issuer_binding": MainReleaseIssuerBinding.model_validate(values)}
        reader = fixture.authority.current_authority_reader
    else:
        drifted_composition = fixture.composition
        kwargs = {}
        package = fixture.package
        def reader() -> MainRollbackCurrentAuthority:
            return MainRollbackCurrentAuthority(
                current_main_commit=fixture.provider.main_commit,
                current_main_tree=fixture.provider.main_tree,
                current_main_parent_commit="f" * 40,
                policy_epoch=package.plan.policy_epoch,
                controller_config_digest=package.release_issuer_binding.controller_config_digest,
                release_issuer_binding=package.release_issuer_binding,
            )

    authority = MainRollbackAuthority(
        journal=fixture.journal,
        clock=type("Clock", (), {"now": lambda self: fixture.now})(),
        policy_epoch=fixture.package.plan.policy_epoch,
        controller_config_digest=fixture.package.release_issuer_binding.controller_config_digest,
        release_issuer_binding=fixture.package.release_issuer_binding,
        current_authority_reader=reader,
        lease_acquirer=never_acquire,
    )
    if drift in {"source", "identity"}:
        with pytest.raises(MainRollbackAuthorityError):
            authority.preview(
                source_operation_id=fixture.package.operation_id,
                attempt_nonce=drift,
                composition=drifted_composition,
                **kwargs,
            )
        assert lease_calls == 0
    elif drift == "topology":
        preview = authority.preview(
            source_operation_id=fixture.package.operation_id,
            attempt_nonce="topology-drift",
            composition=fixture.composition,
        )
        lease = _durable_lease(
            fixture.journal,
            preview.operation_id,
            fixture.package.plan.policy_epoch,
            fixture.now,
        )
        with pytest.raises(MainRollbackAuthorityError, match="drifted"):
            authority.prepare(
                source_operation_id=fixture.package.operation_id,
                attempt_nonce="topology-drift",
                composition=drifted_composition,
                lease=lease,
            )
        assert lease_calls == 0
        assert fixture.journal.read_rollback_intent(preview.operation_id) is None
    else:
        with pytest.raises(MainRollbackAuthorityError):
            authority.preview(
                source_operation_id=fixture.package.operation_id,
                attempt_nonce=drift,
                composition=drifted_composition,
                **kwargs,
            )
        assert lease_calls == 0


def test_stale_lease_is_rejected_before_rollback_intent(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    preview = fixture.authority.preview(
        source_operation_id=fixture.package.operation_id,
        attempt_nonce="expired-lease",
        composition=fixture.composition,
    )
    expired = _durable_lease(
        fixture.journal,
        preview.operation_id,
        fixture.package.plan.policy_epoch,
        fixture.now - timedelta(hours=2),
    )
    with pytest.raises(MainRollbackAuthorityError, match="current target-scoped authority"):
        fixture.authority.prepare(
            source_operation_id=fixture.package.operation_id,
            attempt_nonce="expired-lease",
            composition=fixture.composition,
            lease=expired,
        )
    assert fixture.journal.read_rollback_intent(preview.operation_id) is None


@pytest.mark.parametrize("tamper_kind", ["artifact", "index", "cas", "schema"])
def test_fresh_process_rejects_rollback_artifact_index_cas_or_schema_tamper(
    tmp_path: Path, tamper_kind: str
) -> None:
    fixture = _fixture(tmp_path / tamper_kind)
    prepared = fixture.authority.prepare(
        source_operation_id=fixture.package.operation_id,
        attempt_nonce="tamper-reconstruction",
        composition=fixture.composition,
    )
    restarted = _fresh_journal(fixture.journal)
    if tamper_kind == "artifact":
        path = restarted._store.path_for_digest(  # pyright: ignore[reportPrivateUsage]
            prepared.refs["rollback-intent"].digest
        )
        path.write_bytes(path.read_bytes() + b"corruption")
        with pytest.raises(MainGraduationJournalError):
            restarted.read_rollback_intent(prepared.operation_id)
    elif tamper_kind == "index":
        path = _record_index(restarted, "rollback-intent", prepared.operation_id)
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["role"] = "tampered-schema"
        path.write_bytes(canonical_bytes(raw))
        with pytest.raises(MainGraduationJournalError):
            restarted.read_rollback_intent(prepared.operation_id)
    elif tamper_kind == "cas":
        scope = canonical_digest(
            {
                "repository_digest": fixture.package.repository_digest,
                "target_ref": "refs/heads/main",
            }
        )
        path = restarted.root / "main-graduation-index" / "target-lease" / (
            scope.removeprefix("sha256:") + ".json"
        )
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["operation_id"] = fixture.package.operation_id
        path.write_bytes(canonical_bytes(raw))
        with pytest.raises(MainRollbackAuthorityError):
            _restart(fixture, restarted).prepare(
                source_operation_id=fixture.package.operation_id,
                attempt_nonce="tamper-reconstruction",
                composition=fixture.composition,
                lease=prepared.lease,
            )
    else:
        path = _record_index(restarted, "rollback-preparation-authorization", prepared.operation_id)
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["schema_version"] = 99
        path.write_bytes(canonical_bytes(raw))
        with pytest.raises(MainGraduationJournalError):
            restarted.read_rollback_preparation_authorization(prepared.operation_id)
