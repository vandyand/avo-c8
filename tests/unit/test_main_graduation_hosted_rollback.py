"""Focused tests for the local C8 hosted rollback proof boundary."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import avo_correlate.application.main_graduation_hosted_rollback as module
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation_ledger import (
    MainLedgerControllerAuthority,
    MainLedgerHostedRollbackProof,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

D = "sha256:" + "a" * 64
NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def _authority() -> MainLedgerControllerAuthority:
    values: dict[str, Any] = {
        "repository_digest": D,
        "protocol_digest": D,
        "controller_config_digest": D,
        "policy_digest": D,
        "policy_epoch": D,
        "issuer_identity": "controller",
        "issuer_authority_digest": D,
        "authorized_at": NOW,
        "expires_at": NOW,
    }
    values["expires_at"] = datetime(2026, 9, 1, 13, 0, tzinfo=UTC)
    probe = MainLedgerControllerAuthority.model_construct(**values, authority_digest=D)
    values["authority_digest"] = canonical_digest(
        probe.model_dump(exclude={"authority_digest"}, mode="json")
    )
    return MainLedgerControllerAuthority.model_validate(values)


def _proof() -> MainLedgerHostedRollbackProof:
    values: dict[str, Any] = {
        "operation_id": D,
        "repository_digest": D,
        "proof_artifact_digest": D,
        "controller_authority_digest": _authority().authority_digest,
        "rollback_authority_identity": "rollback",
        "rollback_authority_digest": D,
        "result_evidence_digest": D,
        "completed_at": NOW,
    }
    probe = MainLedgerHostedRollbackProof.model_construct(**values, proof_digest=D)
    values["proof_digest"] = canonical_digest(
        probe.model_dump(exclude={"proof_digest"}, mode="json")
    )
    return MainLedgerHostedRollbackProof.model_validate(values)


class _Verifier:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls = 0

    def verify_hosted_rollback(self, _authority: object, _package: object) -> object:
        self.calls += 1
        return self.result


def _prepare(tmp_path: Path, verifier: object) -> Any:
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
    monkey.setattr(module, "_proof", lambda *_args: _proof())
    try:
        return module.prepare_hosted_rollback_proof(
            tmp_path / "proof.json",
            operation_id=D,
            completion_reader=lambda _operation: (package, package_ref),
            controller_authority_reader=_authority,
            authority_verifier=verifier,
        )
    finally:
        monkey.undo()


def test_preparer_requires_literal_true_authority_verification(tmp_path: Path) -> None:
    with pytest.raises(
        module.HostedRollbackProofPreparationError,
        match="literal True",
    ):
        _prepare(tmp_path, _Verifier(None))


def test_preparer_publishes_canonical_create_once_artifact(tmp_path: Path) -> None:
    verifier = _Verifier(True)
    first = _prepare(tmp_path, verifier)
    assert first.path.read_bytes() == canonical_bytes(first.proof)
    second = _prepare(tmp_path, _Verifier(True))
    assert second.artifact_ref.digest == first.artifact_ref.digest
    assert second.proof.proof_digest == first.proof.proof_digest
