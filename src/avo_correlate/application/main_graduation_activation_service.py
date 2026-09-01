"""Controller-rooted hosted ledger activation.

The local preparation modules intentionally cannot activate the ledger.  This
service is the opposite boundary: it accepts exactly three durable artifact
references, asks a concrete trust root to reload and authenticate each role,
and only then derives and records one immutable activation.  The raw proof
artifact reference is kept separate from the completion-package digest inside
the proof, avoiding a self-digest cycle.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

from avo_correlate.application.main_graduation_activation import (
    MainLedgerActivationTrustRoot,
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

CONTROLLER_AUTHORITY_ROLE = "main-ledger-controller-authority"
CONTROLLER_AUTHORITY_MEDIA_TYPE = (
    "application/vnd.avo.main-ledger-controller-authority+json"
)
C8_CAPABILITY_ROLE = "main-ledger-c8-capability-evidence"
C8_CAPABILITY_MEDIA_TYPE = "application/vnd.avo.main-ledger-c8-capability-evidence+json"
HOSTED_ROLLBACK_PROOF_ROLE = "main-ledger-hosted-rollback-proof"
HOSTED_ROLLBACK_PROOF_MEDIA_TYPE = (
    "application/vnd.avo.main-ledger-hosted-rollback-proof+json"
)
ACTIVATION_ROLE = "main-ledger-activation"
ACTIVATION_MEDIA_TYPE = "application/vnd.avo.main-ledger.activation+json"


class MainGraduationActivationServiceError(RuntimeError):
    """Hosted activation evidence is missing, stale, or not trust-rooted."""


class TrustedActivationClock(Protocol):
    def now(self) -> datetime: ...


class TrustedSchedulerWatermarkReader(Protocol):
    def read_scheduler_sequence_watermark(self) -> int: ...


@dataclass(frozen=True, slots=True)
class MainGraduationActivationResult:
    activation: MainLedgerActivation
    artifact: ArtifactRef

    @property
    def activation_digest(self) -> str:
        return self.activation.activation_digest


def _raw_digest(value: StrictModel) -> str:
    return canonical_digest(value)


def _validate_ref(reference: ArtifactRef, role: str, media_type: str) -> None:
    if (
        type(reference) is not ArtifactRef
        or reference.role != role
        or reference.media_type != media_type
        or reference.size_bytes <= 0
        or not reference.digest.startswith("sha256:")
    ):
        raise MainGraduationActivationServiceError(
            f"artifact reference is invalid for {role}"
        )


def _load(
    trust_root: MainLedgerActivationTrustRoot,
    reference: ArtifactRef,
    *,
    role: str,
    media_type: str,
    model: type[StrictModel],
    method_name: str,
) -> StrictModel:
    _validate_ref(reference, role, media_type)
    loader = getattr(trust_root, method_name, None)
    if not callable(loader):
        raise MainGraduationActivationServiceError(
            f"trust root lacks {method_name}"
        )
    try:
        value = loader(reference)
    except Exception as exc:
        raise MainGraduationActivationServiceError(
            f"trust root rejected {role}"
        ) from exc
    if type(value) is not model:
        raise MainGraduationActivationServiceError(
            f"trust root returned an untyped {role}"
        )
    try:
        checked = model.model_validate_json(canonical_bytes(value))
    except Exception as exc:
        raise MainGraduationActivationServiceError(
            f"trust-root {role} failed canonical reload"
        ) from exc
    payload = canonical_bytes(checked)
    if reference.digest != _raw_digest(checked) or reference.size_bytes != len(payload):
        raise MainGraduationActivationServiceError(
            f"trust-root {role} raw CAS binding mismatch"
        )
    return checked


def _watermark(reader: TrustedSchedulerWatermarkReader) -> int:
    method = getattr(reader, "read_scheduler_sequence_watermark", None)
    if not callable(method):
        raise MainGraduationActivationServiceError(
            "trusted scheduler watermark reader is unavailable"
        )
    try:
        value = method()
    except Exception as exc:
        raise MainGraduationActivationServiceError(
            "trusted scheduler watermark could not be read"
        ) from exc
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MainGraduationActivationServiceError(
            "trusted scheduler watermark is invalid"
        )
    return value


def _activation_values(
    authority: MainLedgerControllerAuthority,
    capability: MainLedgerC8CapabilityEvidence,
    proof: MainLedgerHostedRollbackProof,
    *,
    watermark: int,
    now: datetime,
    freshness_cutoff: datetime,
    hosted_proof_raw_digest: str,
) -> dict[str, Any]:
    values: dict[str, Any] = {
        "repository_digest": authority.repository_digest,
        "target_ref": authority.target_ref,
        "protocol_digest": authority.protocol_digest,
        "controller_config_digest": authority.controller_config_digest,
        "policy_digest": authority.policy_digest,
        "policy_epoch": authority.policy_epoch,
        "controller_issuer_identity": authority.issuer_identity,
        "controller_issuer_authority_digest": authority.issuer_authority_digest,
        "scheduler_sequence_watermark": watermark,
        "freshness_cutoff": freshness_cutoff,
        "controller_authority": authority,
        "hosted_rollback_proof": proof,
        "c8_capability_evidence": capability,
        "hosted_rollback_proof_digest": proof.proof_digest,
        "hosted_rollback_artifact_digest": proof.proof_artifact_digest,
        "rollback_authority_identity": proof.rollback_authority_identity,
        "rollback_authority_digest": proof.rollback_authority_digest,
        "c8_capability_evidence_digest": capability.evidence_digest,
        "activated_at": now,
        "hosted_rollback_raw_artifact_digest": hosted_proof_raw_digest,
    }
    probe = MainLedgerActivation.model_construct(
        **values, activation_digest=_ZERO_DIGEST
    )
    values["activation_digest"] = canonical_digest(
        probe.model_dump(exclude={"activation_digest"}, mode="json")
    )
    return values


_ZERO_DIGEST = "sha256:" + "0" * 64


class MainGraduationActivationService:
    """Derive one activation from trust-rooted, raw-CAS-bound evidence."""

    def __init__(
        self,
        *,
        trust_root: MainLedgerActivationTrustRoot,
        clock: TrustedActivationClock,
        scheduler_watermark_reader: TrustedSchedulerWatermarkReader,
        ledger_service: MainGraduationLedgerService,
        journal: object | None = None,
        freshness_window: timedelta = timedelta(hours=1),
    ) -> None:
        if freshness_window <= timedelta(0):
            raise ValueError("freshness_window must be positive")
        if not callable(getattr(clock, "now", None)):
            raise ValueError("trusted clock is required")
        if not callable(
            getattr(scheduler_watermark_reader, "read_scheduler_sequence_watermark", None)
        ):
            raise ValueError("trusted scheduler watermark reader is required")
        if not callable(getattr(trust_root, "load_verified_controller_authority", None)):
            raise ValueError("controller-rooted trust root is required")
        if not callable(getattr(trust_root, "load_verified_c8_capability", None)):
            raise ValueError("controller-rooted trust root is required")
        if not callable(getattr(trust_root, "load_verified_hosted_rollback_proof", None)):
            raise ValueError("controller-rooted trust root is required")
        self._trust_root = trust_root
        self._clock = clock
        self._watermark_reader = scheduler_watermark_reader
        self._ledger = ledger_service
        self._journal = journal or ledger_service.journal
        self._freshness_window = freshness_window

    def _read_durable_activation(
        self,
    ) -> tuple[MainLedgerActivation, ArtifactRef] | None:
        reader = getattr(self._journal, "read_activation", None)
        if not callable(reader):
            raise MainGraduationActivationServiceError(
                "activation journal cannot be reloaded"
            )
        try:
            loaded = cast(tuple[object, object] | None, reader())
        except Exception as exc:
            raise MainGraduationActivationServiceError(
                "activation journal could not be read"
            ) from exc
        if loaded is None:
            return None
        if (
            type(loaded) is not tuple
            or len(loaded) != 2
            or type(loaded[0]) is not MainLedgerActivation
            or type(loaded[1]) is not ArtifactRef
        ):
            raise MainGraduationActivationServiceError(
                "activation journal returned an untyped record"
            )
        activation = loaded[0]
        reference = loaded[1]
        _validate_ref(reference, ACTIVATION_ROLE, ACTIVATION_MEDIA_TYPE)
        payload = canonical_bytes(activation)
        if (
            reference.digest != canonical_digest(activation)
            or reference.size_bytes != len(payload)
        ):
            raise MainGraduationActivationServiceError(
                "activation journal CAS binding mismatch"
            )
        return activation, reference

    @staticmethod
    def _require_exact_binding(
        activation: MainLedgerActivation,
        authority: MainLedgerControllerAuthority,
        capability: MainLedgerC8CapabilityEvidence,
        proof: MainLedgerHostedRollbackProof,
        hosted_proof_raw_digest: str,
    ) -> None:
        if (
            activation.controller_authority != authority
            or activation.c8_capability_evidence != capability
            or activation.hosted_rollback_proof != proof
            or activation.repository_digest != authority.repository_digest
            or activation.target_ref != authority.target_ref
            or activation.hosted_rollback_proof_digest != proof.proof_digest
            or activation.hosted_rollback_artifact_digest != proof.proof_artifact_digest
            or activation.hosted_rollback_raw_artifact_digest
            != hosted_proof_raw_digest
            or activation.c8_capability_evidence_digest != capability.evidence_digest
            or activation.rollback_authority_identity != proof.rollback_authority_identity
            or activation.rollback_authority_digest != proof.rollback_authority_digest
            or capability.release_issuer_identity != proof.rollback_authority_identity
            or capability.release_issuer_authority_digest != proof.rollback_authority_digest
        ):
            raise MainGraduationActivationServiceError(
                "durable activation does not bind the supplied evidence"
            )

    def _adopt_if_exact(
        self,
        loaded: tuple[MainLedgerActivation, ArtifactRef] | None,
        authority: MainLedgerControllerAuthority,
        capability: MainLedgerC8CapabilityEvidence,
        proof: MainLedgerHostedRollbackProof,
        hosted_proof_raw_digest: str,
        expected: MainLedgerActivation,
    ) -> MainGraduationActivationResult | None:
        if loaded is None:
            return None
        recorded, reference = loaded
        self._require_exact_binding(
            recorded,
            authority,
            capability,
            proof,
            hosted_proof_raw_digest,
        )
        recorded_inputs = recorded.model_dump(
            exclude={"activated_at", "freshness_cutoff", "activation_digest"},
            mode="json",
        )
        expected_inputs = expected.model_dump(
            exclude={"activated_at", "freshness_cutoff", "activation_digest"},
            mode="json",
        )
        if recorded_inputs != expected_inputs:
            raise MainGraduationActivationServiceError(
                "a different activation is already recorded"
            )
        return MainGraduationActivationResult(recorded, reference)

    def activate(
        self,
        controller_authority: ArtifactRef,
        c8_capability: ArtifactRef,
        hosted_rollback_proof: ArtifactRef,
    ) -> MainGraduationActivationResult:
        """Authenticate all role-separated inputs, then activate exactly once."""
        if not all(type(item) is ArtifactRef for item in (
            controller_authority,
            c8_capability,
            hosted_rollback_proof,
        )):
            raise MainGraduationActivationServiceError(
                "activation accepts exactly three ArtifactRefs"
            )
        authority = cast(
            MainLedgerControllerAuthority,
            _load(
                self._trust_root,
                controller_authority,
                role=CONTROLLER_AUTHORITY_ROLE,
                media_type=CONTROLLER_AUTHORITY_MEDIA_TYPE,
                model=MainLedgerControllerAuthority,
                method_name="load_verified_controller_authority",
            ),
        )
        capability = cast(
            MainLedgerC8CapabilityEvidence,
            _load(
                self._trust_root,
                c8_capability,
                role=C8_CAPABILITY_ROLE,
                media_type=C8_CAPABILITY_MEDIA_TYPE,
                model=MainLedgerC8CapabilityEvidence,
                method_name="load_verified_c8_capability",
            ),
        )
        proof = cast(
            MainLedgerHostedRollbackProof,
            _load(
                self._trust_root,
                hosted_rollback_proof,
                role=HOSTED_ROLLBACK_PROOF_ROLE,
                media_type=HOSTED_ROLLBACK_PROOF_MEDIA_TYPE,
                model=MainLedgerHostedRollbackProof,
                method_name="load_verified_hosted_rollback_proof",
            ),
        )
        try:
            existing = self._read_durable_activation()
            if existing is not None:
                # A durable activation is authoritative for retries.  In
                # particular, do not consult the clock or watermark again;
                # evidence freshness is enforced only while creating it.
                recorded, reference = existing
                self._require_exact_binding(
                    recorded,
                    authority,
                    capability,
                    proof,
                    hosted_rollback_proof.digest,
                )
                return MainGraduationActivationResult(recorded, reference)
            now = self._clock.now()
            if now.tzinfo is None or now.utcoffset() is None:
                raise MainGraduationActivationServiceError(
                    "trusted clock must return an aware timestamp"
                )
            now = now.astimezone(UTC)
            freshness_cutoff = max(
                authority.authorized_at,
                now - self._freshness_window,
            )
            if (
                proof.proof_artifact_digest == hosted_rollback_proof.digest
                or proof.repository_digest != authority.repository_digest
                or proof.target_ref != authority.target_ref
                or proof.controller_authority_digest != authority.authority_digest
                or capability.repository_digest != authority.repository_digest
                or capability.target_ref != authority.target_ref
                or capability.controller_authority_digest != authority.authority_digest
                or capability.release_issuer_identity
                != proof.rollback_authority_identity
                or capability.release_issuer_authority_digest
                != proof.rollback_authority_digest
                or proof.completed_at < freshness_cutoff
                or proof.completed_at > now
                or capability.observed_at < freshness_cutoff
                or capability.observed_at > now
            ):
                raise MainGraduationActivationServiceError(
                    "hosted activation evidence is stale or authority-mismatched"
                )
            watermark = _watermark(self._watermark_reader)
            values = _activation_values(
                authority,
                capability,
                proof,
                watermark=watermark,
                now=now,
                freshness_cutoff=freshness_cutoff,
                hosted_proof_raw_digest=hosted_rollback_proof.digest,
            )
            try:
                activation = MainLedgerActivation.model_validate(values)
            except Exception as exc:
                raise MainGraduationActivationServiceError(
                    "hosted activation contract validation failed"
                ) from exc
            try:
                artifact = self._ledger.activate(activation)
            except Exception as exc:
                adopted = self._adopt_if_exact(
                    self._read_durable_activation(),
                    authority,
                    capability,
                    proof,
                    hosted_rollback_proof.digest,
                    activation,
                )
                if adopted is not None:
                    return adopted
                raise MainGraduationActivationServiceError(
                    "ledger activation was rejected"
                ) from exc
            loaded = self._read_durable_activation()
            if loaded is None:
                raise MainGraduationActivationServiceError(
                    "ledger activation was not durably readable"
                )
            recorded, recorded_ref = loaded
            if (
                recorded != activation
                or recorded_ref != artifact
            ):
                raise MainGraduationActivationServiceError(
                    "ledger activation replay differs from derived activation"
                )
            self._require_exact_binding(
                recorded,
                authority,
                capability,
                proof,
                hosted_rollback_proof.digest,
            )
            return MainGraduationActivationResult(activation, recorded_ref)
        except MainGraduationActivationServiceError:
            raise
        except Exception as exc:
            raise MainGraduationActivationServiceError(
                "hosted activation failed"
            ) from exc


__all__ = [
    "ACTIVATION_MEDIA_TYPE",
    "ACTIVATION_ROLE",
    "C8_CAPABILITY_MEDIA_TYPE",
    "C8_CAPABILITY_ROLE",
    "CONTROLLER_AUTHORITY_MEDIA_TYPE",
    "CONTROLLER_AUTHORITY_ROLE",
    "HOSTED_ROLLBACK_PROOF_MEDIA_TYPE",
    "HOSTED_ROLLBACK_PROOF_ROLE",
    "MainGraduationActivationResult",
    "MainGraduationActivationService",
    "MainGraduationActivationServiceError",
    "TrustedActivationClock",
    "TrustedSchedulerWatermarkReader",
]
