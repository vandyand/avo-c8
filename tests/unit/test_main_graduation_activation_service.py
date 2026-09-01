from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar, cast

import pytest

from avo_correlate.application.main_graduation_activation_service import (
    C8_CAPABILITY_MEDIA_TYPE,
    C8_CAPABILITY_ROLE,
    CONTROLLER_AUTHORITY_MEDIA_TYPE,
    CONTROLLER_AUTHORITY_ROLE,
    HOSTED_ROLLBACK_PROOF_MEDIA_TYPE,
    HOSTED_ROLLBACK_PROOF_ROLE,
    MainGraduationActivationService,
    MainGraduationActivationServiceError,
)
from avo_correlate.application.main_graduation_ledger_service import (
    MainGraduationLedgerService,
)
from avo_correlate.contracts.base import ArtifactRef, StrictModel
from avo_correlate.contracts.main_graduation_ledger import (
    MainLedgerActivation,
    MainLedgerC8CapabilityEvidence,
    MainLedgerControllerAuthority,
    MainLedgerHostedRollbackProof,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

DIGEST = "sha256:" + "1" * 64
NOW = datetime(2026, 9, 1, tzinfo=UTC)
ModelT = TypeVar("ModelT", bound=StrictModel)


def _with_digest(model_type: type[ModelT], values: dict[str, Any], field: str) -> ModelT:  # noqa: UP047
    probe = model_type.model_construct(  # pyright: ignore[reportArgumentType]
        **{key: value for key, value in values.items() if key != field},  # pyright: ignore[reportArgumentType]
        **{field: DIGEST},  # pyright: ignore[reportArgumentType]
    )
    return model_type.model_validate(
        {**values, field: canonical_digest(probe.model_dump(exclude={field}, mode="json"))}
    )


def _evidence() -> tuple[
    MainLedgerControllerAuthority,
    MainLedgerC8CapabilityEvidence,
    MainLedgerHostedRollbackProof,
]:
    authority = _with_digest(
        MainLedgerControllerAuthority,
        {
            "repository_digest": DIGEST,
            "protocol_digest": DIGEST,
            "controller_config_digest": DIGEST,
            "policy_digest": DIGEST,
            "policy_epoch": DIGEST,
            "issuer_identity": "ledger-controller",
            "issuer_authority_digest": DIGEST,
            "authorized_at": NOW - timedelta(minutes=5),
            "expires_at": NOW + timedelta(hours=1),
        },
        "authority_digest",
    )
    proof = _with_digest(
        MainLedgerHostedRollbackProof,
        {
            "operation_id": DIGEST,
            "repository_digest": DIGEST,
            "proof_artifact_digest": DIGEST,
            "controller_authority_digest": authority.authority_digest,
            "rollback_authority_identity": "rollback-service",
            "rollback_authority_digest": DIGEST,
            "result_evidence_digest": DIGEST,
            "completed_at": NOW - timedelta(minutes=1),
        },
        "proof_digest",
    )
    capability = _with_digest(
        MainLedgerC8CapabilityEvidence,
        {
            "repository_digest": DIGEST,
            "controller_authority_digest": authority.authority_digest,
            "hosting_authority_identity": "org-hosting",
            "queue_configuration_digest": DIGEST,
            "queue_generation_digest": DIGEST,
            "release_issuer_identity": "rollback-service",
            "release_issuer_app_id": 9001,
            "release_issuer_authority_digest": DIGEST,
            "observed_at": NOW,
        },
        "evidence_digest",
    )
    return authority, capability, proof


def _ref(value: StrictModel, role: str, media_type: str) -> ArtifactRef:
    payload = canonical_bytes(value)
    return ArtifactRef(
        digest=canonical_digest(value),
        size_bytes=len(payload),
        media_type=media_type,
        role=role,
        created_at=NOW,
    )


class _Root:
    def __init__(
        self,
        authority: MainLedgerControllerAuthority,
        capability: MainLedgerC8CapabilityEvidence,
        proof: MainLedgerHostedRollbackProof,
    ) -> None:
        self.authority = authority
        self.capability = capability
        self.proof = proof

    def load_verified_controller_authority(
        self, reference: ArtifactRef
    ) -> MainLedgerControllerAuthority:
        return self.authority

    def load_verified_c8_capability(
        self, reference: ArtifactRef
    ) -> MainLedgerC8CapabilityEvidence:
        return self.capability

    def load_verified_hosted_rollback_proof(
        self, reference: ArtifactRef
    ) -> MainLedgerHostedRollbackProof:
        return self.proof


class _Clock:
    def __init__(self) -> None:
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return NOW


class _Watermark:
    def __init__(self) -> None:
        self.calls = 0

    def read_scheduler_sequence_watermark(self) -> int:
        self.calls += 1
        return 10


class _Journal:
    def __init__(self) -> None:
        self.recorded: tuple[MainLedgerActivation, ArtifactRef] | None = None

    def read_activation(self) -> tuple[MainLedgerActivation, ArtifactRef] | None:
        return self.recorded


class _Ledger:
    def __init__(self, journal: _Journal, *, conflict: bool = False) -> None:
        self.journal = journal
        self.conflict = conflict

    def activate(self, activation: MainLedgerActivation) -> ArtifactRef:
        if self.conflict:
            values = activation.model_dump(mode="python")
            values.pop("activation_digest")
            values["activated_at"] = NOW + timedelta(seconds=30)
            values["freshness_cutoff"] = activation.controller_authority.authorized_at
            probe = MainLedgerActivation.model_construct(
                **values,
                activation_digest="sha256:" + "0" * 64,
            )
            values["activation_digest"] = canonical_digest(
                probe.model_dump(exclude={"activation_digest"}, mode="json")
            )
            winner = MainLedgerActivation.model_validate(values)
            artifact = _ref(
                winner,
                "main-ledger-activation",
                "application/vnd.avo.main-ledger.activation+json",
            )
            self.journal.recorded = (winner, artifact)
            raise RuntimeError("simulated create-once race")
        if self.journal.recorded is not None:
            if self.journal.recorded[0] != activation:
                raise RuntimeError("conflicting activation")
            return self.journal.recorded[1]
        artifact = _ref(
            activation,
            "main-ledger-activation",
            "application/vnd.avo.main-ledger.activation+json",
        )
        self.journal.recorded = (activation, artifact)
        return artifact


def _service(*, conflict: bool = False) -> tuple[
    MainGraduationActivationService,
    ArtifactRef,
    ArtifactRef,
    ArtifactRef,
]:
    authority, capability, proof = _evidence()
    journal = _Journal()
    ledger = _Ledger(journal, conflict=conflict)
    service = MainGraduationActivationService(
        trust_root=_Root(authority, capability, proof),
        clock=_Clock(),
        scheduler_watermark_reader=_Watermark(),
        ledger_service=cast(MainGraduationLedgerService, ledger),
        journal=journal,
    )
    return (
        service,
        _ref(authority, CONTROLLER_AUTHORITY_ROLE, CONTROLLER_AUTHORITY_MEDIA_TYPE),
        _ref(capability, C8_CAPABILITY_ROLE, C8_CAPABILITY_MEDIA_TYPE),
        _ref(proof, HOSTED_ROLLBACK_PROOF_ROLE, HOSTED_ROLLBACK_PROOF_MEDIA_TYPE),
    )


def test_activation_binds_raw_proof_record_separately() -> None:
    service, authority_ref, capability_ref, proof_ref = _service()

    result = service.activate(authority_ref, capability_ref, proof_ref)

    assert result.activation.hosted_rollback_raw_artifact_digest == proof_ref.digest
    assert (
        result.activation.hosted_rollback_artifact_digest
        == result.activation.hosted_rollback_proof.proof_artifact_digest
    )
    assert result.activation.hosted_rollback_artifact_digest != proof_ref.digest
    assert result.artifact.digest == canonical_digest(result.activation)


def test_activation_rejects_draft_or_wrong_role_before_trust_root() -> None:
    service, authority_ref, capability_ref, proof_ref = _service()
    draft = authority_ref.model_copy(update={"role": "local-activation-draft"})

    with pytest.raises(MainGraduationActivationServiceError):
        service.activate(draft, capability_ref, proof_ref)


def test_activation_rejects_raw_proof_ref_that_is_completion_digest() -> None:
    service, authority_ref, capability_ref, proof_ref = _service()
    invalid_proof_ref = proof_ref.model_copy(
        update={"digest": DIGEST, "size_bytes": proof_ref.size_bytes}
    )

    with pytest.raises(MainGraduationActivationServiceError):
        service.activate(authority_ref, capability_ref, invalid_proof_ref)


def test_activation_rejects_capability_with_wrong_release_authority() -> None:
    service, authority_ref, _, proof_ref = _service()
    root = cast(_Root, service._trust_root)  # pyright: ignore[reportPrivateUsage]
    values = root.capability.model_dump(mode="python")
    values["release_issuer_authority_digest"] = "sha256:" + "2" * 64
    root.capability = _with_digest(
        MainLedgerC8CapabilityEvidence, values, "evidence_digest"
    )
    mismatched_ref = _ref(
        root.capability,
        C8_CAPABILITY_ROLE,
        C8_CAPABILITY_MEDIA_TYPE,
    )

    with pytest.raises(MainGraduationActivationServiceError):
        service.activate(authority_ref, mismatched_ref, proof_ref)


def test_legacy_activation_wire_bytes_round_trip_without_raw_binding() -> None:
    service, authority_ref, capability_ref, proof_ref = _service()
    activation = service.activate(authority_ref, capability_ref, proof_ref).activation
    legacy_values = activation.model_dump(
        mode="json", exclude={"hosted_rollback_raw_artifact_digest"}
    )
    legacy_values["activation_digest"] = canonical_digest(
        {key: value for key, value in legacy_values.items() if key != "activation_digest"}
    )
    legacy_payload = canonical_bytes(legacy_values)

    parsed = MainLedgerActivation.model_validate_json(legacy_payload)

    assert canonical_bytes(parsed) == legacy_payload
    assert parsed.hosted_rollback_raw_artifact_digest is None


def test_raw_binding_tamper_cannot_retain_activation_digest() -> None:
    service, authority_ref, capability_ref, proof_ref = _service()
    activation = service.activate(authority_ref, capability_ref, proof_ref).activation
    tampered = activation.model_dump(mode="json")
    tampered["hosted_rollback_raw_artifact_digest"] = "sha256:" + "2" * 64

    with pytest.raises(ValueError, match="activation digest"):
        MainLedgerActivation.model_validate(tampered)


def test_durable_replay_skips_clock_and_watermark_after_expiry() -> None:
    service, authority_ref, capability_ref, proof_ref = _service()
    first = service.activate(authority_ref, capability_ref, proof_ref)
    clock = cast(_Clock, service._clock)  # pyright: ignore[reportPrivateUsage]
    watermark = cast(_Watermark, service._watermark_reader)  # pyright: ignore[reportPrivateUsage]
    clock.calls = 0
    watermark.calls = 0

    replay = service.activate(authority_ref, capability_ref, proof_ref)

    assert replay == first
    assert clock.calls == 0
    assert watermark.calls == 0


def test_create_once_race_adopts_same_inputs_with_winner_timestamp() -> None:
    service, authority_ref, capability_ref, proof_ref = _service(conflict=True)

    result = service.activate(authority_ref, capability_ref, proof_ref)

    assert result.activation.activated_at == NOW + timedelta(seconds=30)
    assert result.activation.hosted_rollback_raw_artifact_digest == proof_ref.digest
