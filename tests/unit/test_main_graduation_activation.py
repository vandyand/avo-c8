from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.application.main_graduation_activation import (
    MainGraduationActivationPreparationError,
    prepare_main_graduation_activation,
)
from avo_correlate.contracts.main_graduation_ledger import (
    MainLedgerC8CapabilityEvidence,
    MainLedgerControllerAuthority,
    MainLedgerHostedRollbackProof,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

D = "sha256:" + "a" * 64
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


def _evidence() -> tuple[Any, Any, Any]:
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


def _prepare(tmp_path: Path, **updates: Any) -> Any:
    authority, capability, proof = _evidence()
    values: dict[str, Any] = {
        "output_file": tmp_path / "activation.json",
        "controller_authority": authority,
        "c8_capability_evidence": capability,
        "hosted_rollback_proof": proof,
        "freshness_cutoff": NOW - timedelta(minutes=2),
        "activated_at": NOW,
        "scheduler_sequence_watermark": 0,
        "authority_verifier": lambda _value: True,
        "capability_verifier": lambda _value: True,
        "rollback_verifier": lambda _value: True,
    }
    values.update(updates)
    return prepare_main_graduation_activation(**values)


def test_valid_evidence_is_deterministic_and_create_once(tmp_path: Path) -> None:
    draft = _prepare(tmp_path)
    assert draft.artifact_path.read_bytes() == canonical_bytes(
        draft.activation.model_dump(mode="json")
    )
    replay = _prepare(tmp_path)
    assert replay.artifact_digest == draft.artifact_digest
    assert replay.semantic_digest == draft.semantic_digest


@pytest.mark.parametrize(
    "name,value",
    [
        ("authority_verifier", None),
        ("capability_verifier", lambda _value: 1),
        ("rollback_verifier", lambda _value, _extra: True),
    ],
)
def test_verifiers_are_required_exact_and_literal_true(
    tmp_path: Path, name: str, value: Any
) -> None:
    with pytest.raises(MainGraduationActivationPreparationError, match="verifier"):
        _prepare(tmp_path, **{name: value})


def test_stale_or_tampered_evidence_and_output_fail_closed(tmp_path: Path) -> None:
    _authority, capability, proof = _evidence()
    stale = proof.model_copy(update={"completed_at": NOW - timedelta(hours=2)})
    with pytest.raises(MainGraduationActivationPreparationError, match="rollback proof"):
        _prepare(tmp_path, hosted_rollback_proof=stale)
    forged = capability.model_copy(update={"repository_digest": D[:-1] + "b"})
    with pytest.raises(MainGraduationActivationPreparationError, match="capability evidence"):
        _prepare(tmp_path, c8_capability_evidence=forged)
    _prepare(tmp_path)
    (tmp_path / "activation.json").write_bytes(b"tampered")
    with pytest.raises(MainGraduationActivationPreparationError, match="conflicting"):
        _prepare(tmp_path)
