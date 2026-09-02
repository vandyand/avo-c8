"""Additional focused coverage for promotion authority and replay boundaries."""
# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportArgumentType=false, reportCallIssue=false, reportMissingImports=false, reportUnusedImport=false, reportUnusedVariable=false, reportUnnecessaryCast=false, reportAttributeAccessIssue=false, reportIndexIssue=false

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.filesystem import ArtifactIntegrityError
from avo_correlate.application.promotion_service import (
    PromotionController,
    PromotionEvidenceError,
    RollbackPromotionAuthorizationJournal,
    _evidence_verified,  # pyright: ignore[reportPrivateUsage]
    _provenance_verified,  # pyright: ignore[reportPrivateUsage]
    _strict_object_pairs,  # pyright: ignore[reportPrivateUsage]
)
from avo_correlate.contracts.base import ArtifactRef
from tests.unit.test_rollback_promotion_authority import _authorization


def test_strict_verifiers_accept_bools_and_verified_objects() -> None:
    class Report:
        verified = True

    class FalseReport:
        verified = False

    assert _provenance_verified(lambda *_: True, "d", "c", "b")
    assert not _provenance_verified(lambda *_: False, "d", "c", "b")
    assert _provenance_verified(lambda *_: Report(), "d", "c", "b")
    assert not _provenance_verified(lambda *_: FalseReport(), "d", "c", "b")
    assert _evidence_verified(lambda *_: True, "d", "i", "c", "b")
    assert _evidence_verified(lambda *_: Report(), "d", "i", "c", "b")
    assert not _evidence_verified(lambda *_: FalseReport(), "d", "i", "c", "b")
    with pytest.raises(ValueError, match="duplicate"):
        _strict_object_pairs([("x", 1), ("x", 2)])


def test_rollback_authorization_journal_create_once_tamper_and_child_binding(
    tmp_path: Path,
) -> None:
    authorization = _authorization()
    store = FilesystemArtifactStore(tmp_path)
    journal = RollbackPromotionAuthorizationJournal(store)
    reference = journal.record(authorization)
    journal.require(authorization)
    assert journal.record(authorization) == reference

    index = tmp_path / "rollback-promotion-authorizations" / (
        authorization.operation_id.removeprefix("sha256:")
    )
    data = json.loads(index.read_bytes())
    data["artifact"]["role"] = "tampered"
    index.write_bytes(json.dumps(data).encode())
    with pytest.raises(ValueError, match="not durably"):
        journal.require(authorization)

    index.write_bytes(b'{"x":1,"x":2}')
    with pytest.raises(ValueError, match="not durably"):
        journal.require(authorization)

    # A child supplied at record time is immutable and cannot be rebound.
    child = ArtifactRef(
        digest=authorization.canary_package_digest,
        size_bytes=1,
        media_type="application/vnd.avo.integration-campaign+json",
        role="integration-campaign-package",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    child_journal = RollbackPromotionAuthorizationJournal(
        FilesystemArtifactStore(tmp_path / "child")
    )
    child_journal.record(authorization, canary_package_artifact=child)
    other_child = child.model_copy(update={"size_bytes": 2})
    with pytest.raises(ValueError, match="canary"):
        child_journal.record(authorization, canary_package_artifact=other_child)


def test_rollback_authorization_journal_artifact_corruption_is_rejected(tmp_path: Path) -> None:
    authorization = _authorization()
    store = FilesystemArtifactStore(tmp_path)
    journal = RollbackPromotionAuthorizationJournal(store)
    reference = journal.record(authorization)
    path = store.path_for_digest(reference.digest)
    path.write_bytes(b"corrupt")
    with pytest.raises(ArtifactIntegrityError, match="size mismatch"):
        journal.require(authorization)


def test_rollback_fact_validators_fail_before_provider_use() -> None:
    with pytest.raises(ValueError, match="stale"):
        PromotionController._validate_drill_authorization(  # pyright: ignore[reportPrivateUsage]
            SimpleNamespace(operation_id="x"),
            SimpleNamespace(operation_id="y"),
            SimpleNamespace(policy=SimpleNamespace(rollback_issuer_ids=[])),
        )
    with pytest.raises((AttributeError, ValueError)):
        PromotionController._validate_rollback_facts(  # pyright: ignore[reportPrivateUsage]
            SimpleNamespace(repository_digest="wrong"),
            SimpleNamespace(intent=SimpleNamespace()),
            SimpleNamespace(),
            SimpleNamespace(repository_digest="right"),
        )


def test_dry_run_surfaces_evidence_verifier_exception_as_evidence_error(tmp_path: Path) -> None:
    from tests.unit.test_promotion_service import FakeRepository, _config, _input

    (tmp_path / "candidate").mkdir()
    controller = PromotionController(
        FakeRepository(),
        lambda *_: True,
        lambda *_: False,
        FilesystemArtifactStore(tmp_path / "artifacts"),
        trusted_config=_config(),
        trusted_repository_root=tmp_path.parent / "trusted",
        trusted_artifact_root=tmp_path / "artifacts",
    )
    with pytest.raises(PromotionEvidenceError):
        controller.dry_run(_input(), candidate_root=tmp_path / "candidate")
