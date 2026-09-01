from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.contracts.main_graduation_ledger import (
    MainLedgerC8CapabilityEvidence,
    MainLedgerControllerAuthority,
    MainLedgerHostedRollbackProof,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from scripts.prepare_avo0047_hosted_activation import (
    HostedActivationPreparationError,
    prepare_hosted_activation_from_files,
)

D = "sha256:" + "b" * 64
NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def _model(model_type: Any, values: dict[str, Any], digest_field: str) -> Any:
    probe = model_type.model_construct(**values, **{digest_field: D})
    return model_type.model_validate(
        {
            **values,
            digest_field: canonical_digest(
                probe.model_dump(exclude={digest_field}, mode="json")
            ),
        }
    )


def _records() -> tuple[Any, Any, Any]:
    authority = _model(
        MainLedgerControllerAuthority,
        {
            "repository_digest": D,
            "protocol_digest": D,
            "controller_config_digest": D,
            "policy_digest": D,
            "policy_epoch": D,
            "issuer_identity": "controller",
            "issuer_authority_digest": D,
            "authorized_at": NOW - timedelta(minutes=5),
            "expires_at": NOW + timedelta(hours=1),
        },
        "authority_digest",
    )
    proof = _model(
        MainLedgerHostedRollbackProof,
        {
            "operation_id": D,
            "repository_digest": D,
            "proof_artifact_digest": D,
            "controller_authority_digest": authority.authority_digest,
            "rollback_authority_identity": "rollback",
            "rollback_authority_digest": D,
            "result_evidence_digest": D,
            "completed_at": NOW - timedelta(minutes=1),
        },
        "proof_digest",
    )
    capability = _model(
        MainLedgerC8CapabilityEvidence,
        {
            "repository_digest": D,
            "controller_authority_digest": authority.authority_digest,
            "hosting_authority_identity": "hosting",
            "queue_configuration_digest": D,
            "queue_generation_digest": D,
            "release_issuer_identity": "release",
            "release_issuer_app_id": 9001,
            "release_issuer_authority_digest": D,
            "observed_at": NOW - timedelta(minutes=1),
        },
        "evidence_digest",
    )
    return authority, capability, proof


def test_file_preparation_loads_canonical_records_and_never_activates(tmp_path: Path) -> None:
    authority, capability, proof = _records()
    paths = []
    for name, model in (("authority", authority), ("capability", capability), ("proof", proof)):
        path = tmp_path / f"{name}.json"
        path.write_bytes(canonical_bytes(model.model_dump(mode="json")))
        paths.append(path)

    draft = prepare_hosted_activation_from_files(
        paths[0],
        paths[1],
        paths[2],
        tmp_path / "activation.json",
        freshness_cutoff=NOW - timedelta(minutes=2),
        activated_at=NOW,
        scheduler_sequence_watermark=0,
        authority_verifier=lambda _value: True,
        capability_verifier=lambda _value: True,
        rollback_verifier=lambda _value: True,
    )
    assert draft.activation.deploy_performed is False
    assert draft.artifact_path.exists()


def test_file_preparation_rejects_noncanonical_or_missing_verifier(tmp_path: Path) -> None:
    authority, capability, proof = _records()
    files = []
    for name, model in (("authority", authority), ("capability", capability), ("proof", proof)):
        path = tmp_path / f"{name}.json"
        path.write_bytes(canonical_bytes(model.model_dump(mode="json")))
        files.append(path)
    files[1].write_text(json.dumps(capability.model_dump(mode="json"), indent=2), encoding="utf-8")
    with pytest.raises(HostedActivationPreparationError, match="canonical"):
        prepare_hosted_activation_from_files(
            files[0],
            files[1],
            files[2],
            tmp_path / "activation.json",
            freshness_cutoff=NOW - timedelta(minutes=2),
            activated_at=NOW,
            scheduler_sequence_watermark=0,
            authority_verifier=lambda _value: True,
            capability_verifier=lambda _value: True,
            rollback_verifier=lambda _value: True,
        )
