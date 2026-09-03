"""Canaries for the offline personal exact-CAS composition root."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from avo_correlate.adapters.artifacts import (
    main_personal_exact_cas_controller_composition as module,
)
from avo_correlate.adapters.artifacts.durable_backend_gate import DurableBackendQualification
from avo_correlate.contracts import MainPersonalExactCasControllerComposition
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_personal_exact_cas import (
    personal_cas_claim_digest,
    personal_cas_operation_id,
)
from avo_correlate.domain.canonical import canonical_bytes

_TIME = datetime(2026, 1, 1, tzinfo=UTC)
_DIGEST = "sha256:" + "a" * 64
_BASE = "b" * 40
_CANDIDATE = "c" * 40
_TREE = "d" * 40


def _ref(role: str, media: str) -> ArtifactRef:
    return ArtifactRef(
        digest=_DIGEST,
        size_bytes=7,
        role=role,
        media_type=media,
        created_at=_TIME,
    )


def _root() -> MainPersonalExactCasControllerComposition:
    values: dict[str, Any] = {
        "activation_digest": _DIGEST,
        "repository_digest": _DIGEST,
        "hosted_identity_root_artifact": _ref(
            "main-personal-exact-cas-hosted-identity-root",
            "application/vnd.avo.main-personal-exact-cas-hosted-identity-root+json",
        ),
        "hosted_identity_bundle_digest": _DIGEST,
        "activation_artifact": _ref(
            "main-personal-exact-cas-activation",
            "application/vnd.avo.main-personal-exact-cas-activation+json",
        ),
        "source_operation_id": "sha256:" + "1" * 64,
        "source_plan_digest": _DIGEST,
        "source_plan_artifact": _ref(
            "main-graduation-plan", "application/vnd.avo.main-graduation-plan+json"
        ),
        "source_package_digest": _DIGEST,
        "source_package_artifact": _ref(
            "integration-campaign-package", "application/vnd.avo.integration-campaign+json"
        ),
        "source_composition_digest": _DIGEST,
        "source_composition_artifact": _ref(
            "main-graduation-composition",
            "application/vnd.avo.main-graduation-composition+json",
        ),
        "source_composition_proof_artifact": _ref(
            "main-graduation-composition-proof",
            "application/vnd.avo.main-graduation-composition-proof+json",
        ),
        "base_commit": _BASE,
        "base_tree": _TREE,
        "candidate_commit": _CANDIDATE,
        "candidate_tree": _TREE,
        "candidate_ref": "refs/heads/avo/candidate/" + "1" * 64,
        "candidate_parents": (_BASE,),
        "writer_app_id": 1,
        "writer_installation_id": 2,
        "writer_identity": "writer",
        "writer_configuration_digest": _DIGEST,
        "observer_configuration_digest": _DIGEST,
        "protection_ruleset_digest": _DIGEST,
        "lease_identity": "lease",
        "lease_digest": _DIGEST,
        "lease_artifact": _ref(
            "main-graduation-lease-evidence-record",
            "application/vnd.avo.main-graduation-lease-evidence-record+json",
        ),
        "lease_expires_at": datetime(2026, 1, 2, tzinfo=UTC),
        "claim_nonce": "nonce",
        "policy_digest": _DIGEST,
        "protocol_digest": _DIGEST,
    }
    values["operation_id"] = personal_cas_operation_id(
        activation_digest=values["activation_digest"],
        repository_digest=values["repository_digest"],
        target_ref="refs/heads/main",
        source_operation_id=values["source_operation_id"],
        source_plan_digest=values["source_plan_digest"],
        source_composition_digest=values["source_composition_digest"],
        base_commit=_BASE,
        base_tree=_TREE,
        candidate_commit=_CANDIDATE,
        candidate_tree=_TREE,
        candidate_ref=values["candidate_ref"],
        candidate_parents=(_BASE,),
        protection_ruleset_digest=values["protection_ruleset_digest"],
        writer_app_id=1,
        writer_installation_id=2,
        writer_identity="writer",
        lease_identity="lease",
        lease_digest=_DIGEST,
        lease_expires_at=values["lease_expires_at"],
        claim_nonce="nonce",
    )
    values["claim_digest"] = personal_cas_claim_digest(
        operation_id=values["operation_id"],
        lease_identity="lease",
        lease_digest=_DIGEST,
        lease_expires_at=values["lease_expires_at"],
        claim_nonce="nonce",
    )
    return MainPersonalExactCasControllerComposition.build(**values)


def test_contract_is_frozen_canonical_and_non_authoritative() -> None:
    root = _root()
    assert canonical_bytes(root) == canonical_bytes(
        MainPersonalExactCasControllerComposition.model_validate_json(canonical_bytes(root))
    )
    assert all(
        getattr(root, name) is False
        for name in (
            "activation_authority_sufficient",
            "is_authoritative",
            "is_terminal",
            "readiness_authorized",
            "mutation_performed",
            "receipt_issued",
            "completion_claimed",
            "deploy_performed",
        )
    )
    with pytest.raises(ValidationError):
        MainPersonalExactCasControllerComposition.model_validate(
            root.model_dump() | {"unexpected": True}
        )
    forged_values = root.model_dump()
    forged_values["is_authoritative"] = True
    forged = MainPersonalExactCasControllerComposition.model_construct(**forged_values)
    with pytest.raises(ValidationError):
        MainPersonalExactCasControllerComposition.model_validate_json(canonical_bytes(forged))


def test_bounded_read_rejects_oversized_regular_file(tmp_path: Path) -> None:
    path = tmp_path / "hostile.json"
    path.write_bytes(b"x" * 32)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(ValueError):
            module._read_bounded(descriptor, 8)
    finally:
        os.close(descriptor)


def test_close_is_idempotent_and_blocks_operations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def qualified(root: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=root.resolve(),
            qualified=True,
            reason="test-qualified",
            mount_id=1,
            device="8:0",
        )

    monkeypatch.setattr(module, "require_durable_backend", qualified)

    def no_fsync(_path: Path) -> None:
        return None

    monkeypatch.setattr(module, "_fsync_directory", no_fsync)
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "journal")
    journal.close()
    journal.close()
    with pytest.raises(module.MainPersonalExactCasControllerCompositionError):
        journal.read(_DIGEST)


def test_journal_create_once_reuse_conflict_and_reuse_fsync_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def qualified(root: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=root.resolve(),
            qualified=True,
            reason="test-qualified",
            mount_id=1,
            device="8:0",
        )

    def no_fsync(_path: Path) -> None:
        return None

    def no_fd_fsync(_descriptor: int) -> None:
        return None

    monkeypatch.setattr(module, "require_durable_backend", qualified)
    monkeypatch.setattr(module, "_fsync_directory", no_fsync)
    monkeypatch.setattr(module.os, "fsync", no_fd_fsync)
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "journal")
    root = _root()
    assert journal._publish(root.operation_id, root) == root
    assert journal.read(root.operation_id) == root
    with pytest.raises(module.MainPersonalExactCasControllerCompositionConflictError):
        forged_values = root.model_dump()
        forged_values["protocol_digest"] = "sha256:" + "f" * 64
        forged = MainPersonalExactCasControllerComposition.model_construct(**forged_values)
        journal._publish(root.operation_id, forged)

    def fail_fsync(_path: Path) -> None:
        raise OSError("reuse directory fsync failure")

    monkeypatch.setattr(module, "_fsync_directory", fail_fsync)
    with pytest.raises(OSError, match="reuse directory fsync failure"):
        journal._publish(root.operation_id, root)
