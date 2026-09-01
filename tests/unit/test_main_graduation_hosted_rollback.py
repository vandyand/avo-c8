"""Focused tests for the non-hosted rollback evidence inventory."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

import avo_correlate.application.main_graduation_hosted_rollback as module
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation_ledger import MainLedgerHostedRollbackProof
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

D = "sha256:" + "a" * 64
NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def _draft() -> module.MainHostedRollbackEvidenceDraft:
    values: dict[str, Any] = {
        "operation_id": D,
        "repository_digest": D,
        "completion_package_artifact_digest": D,
        "rollback_authority_manifest_digest": D,
        "rollback_result_evidence_digest": D,
        "post_state_evidence_digest": D,
        "cleanup_terminal_evidence_digest": D,
        "observed_at": NOW,
    }
    probe = module.MainHostedRollbackEvidenceDraft.model_construct(
        **values, draft_digest=D
    )
    values["draft_digest"] = canonical_digest(
        probe.model_dump(exclude={"draft_digest"}, mode="json")
    )
    return module.MainHostedRollbackEvidenceDraft.model_validate(values)


def test_offline_draft_cannot_validate_as_hosted_proof() -> None:
    draft = _draft()
    assert draft.activation_consumable is False
    assert draft.hosted_drill_executed is False
    assert draft.completion_package_artifact_digest == D
    with pytest.raises(ValidationError):
        MainLedgerHostedRollbackProof.model_validate(draft.model_dump(mode="json"))


def test_inventory_requires_content_addressed_completion_and_is_create_once(
    tmp_path: Path,
) -> None:
    package = SimpleNamespace(operation_id=D)
    package_ref = ArtifactRef(
        digest=D,
        size_bytes=1,
        role="main-graduation-rollback-completion",
        media_type="application/vnd.avo.main-graduation-rollback-completion+json",
        created_at=NOW,
    )
    monkey = pytest.MonkeyPatch()
    monkey.setattr(module, "_pair", lambda *_args: (package, package_ref))
    monkey.setattr(module, "_strict_reload", lambda value, *_args: value)
    monkey.setattr(module, "_validate_inputs", lambda *_args: None)
    monkey.setattr(
        module.MainHostedRollbackEvidenceDraft,
        "from_completion",
        classmethod(lambda cls, *_args: _draft()),
    )
    try:
        first = module.prepare_hosted_rollback_evidence(
            tmp_path / "draft.json",
            operation_id=D,
            completion_reader=lambda _operation: (package, package_ref),
            clock=lambda: NOW,
        )
        second = module.prepare_hosted_rollback_evidence(
            tmp_path / "draft.json",
            operation_id=D,
            completion_reader=lambda _operation: (package, package_ref),
            clock=lambda: NOW,
        )
    finally:
        monkey.undo()
    assert first.path.read_bytes() == canonical_bytes(first.draft)
    assert second.artifact_ref.digest == first.artifact_ref.digest
