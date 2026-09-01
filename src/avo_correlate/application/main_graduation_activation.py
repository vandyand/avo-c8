# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false
"""Prepare (but never activate) the hosted main-ledger activation artifact.

This module is deliberately an application boundary, rather than a ledger
service.  It consumes controller-observed, already typed evidence and writes
one canonical activation draft.  It does not know how to contact a hosted
provider, mutate the ledger journal, or count an attempt.  Authentication is
also deliberately injected: the DTO self-digests prove integrity, while the
verifiers prove provenance and authority.
"""

from __future__ import annotations

import hashlib
import inspect
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

from avo_correlate.contracts.main_graduation_ledger import (
    MainLedgerActivation,
    MainLedgerC8CapabilityEvidence,
    MainLedgerControllerAuthority,
    MainLedgerHostedRollbackProof,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

MAX_ACTIVATION_BYTES = 8 * 1024 * 1024
_ZERO_DIGEST = "sha256:" + "0" * 64
EvidenceT = TypeVar("EvidenceT")
Verifier = Callable[[EvidenceT], object]


class MainGraduationActivationPreparationError(RuntimeError):
    """The supplied observations cannot produce a safe activation draft."""


@dataclass(frozen=True, slots=True)
class PreparedMainGraduationActivation:
    """A canonical activation draft and its raw artifact identity."""

    activation: MainLedgerActivation
    artifact_path: Path
    artifact_digest: str

    @property
    def semantic_digest(self) -> str:
        """Return the activation's self-digest (distinct from raw bytes)."""
        return self.activation.activation_digest

    @property
    def raw_digest(self) -> str:
        """Return the digest of the canonical serialized artifact."""
        return self.artifact_digest

    @property
    def path(self) -> Path:
        """Compatibility alias for artifact consumers."""
        return self.artifact_path


def _safe_existing_path(path: Path, label: str) -> None:
    """Reject symlinks/reparse points in the existing part of a path chain."""
    current = Path(path)
    while True:
        try:
            exists = current.exists() or current.is_symlink()
        except OSError as exc:
            raise MainGraduationActivationPreparationError(
                f"{label} path cannot be inspected"
            ) from exc
        if exists:
            if current.is_symlink():
                raise MainGraduationActivationPreparationError(
                    f"{label} path cannot contain a symlink"
                )
            try:
                attributes = getattr(
                    os.stat(current, follow_symlinks=False), "st_file_attributes", 0
                )
            except OSError as exc:
                raise MainGraduationActivationPreparationError(
                    f"{label} path cannot be inspected"
                ) from exc
            if attributes & 0x400:
                raise MainGraduationActivationPreparationError(
                    f"{label} path cannot contain a reparse point"
                )
            return
        parent = current.parent
        if parent == current:
            return
        current = parent


def _raw_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _write_create_once(path: Path, data: bytes) -> str:
    """Atomically create the artifact; replay only an identical winner."""
    if len(data) > MAX_ACTIVATION_BYTES:
        raise MainGraduationActivationPreparationError("activation artifact exceeds size bound")
    _safe_existing_path(path.parent, "activation output parent")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise MainGraduationActivationPreparationError(
            "activation output parent could not be created"
        ) from exc
    _safe_existing_path(path, "activation output")
    expected = _raw_digest(data)
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise MainGraduationActivationPreparationError(
                "activation output must be a regular file"
            )
        try:
            existing = path.read_bytes()
        except OSError as exc:
            raise MainGraduationActivationPreparationError(
                "activation output is unreadable"
            ) from exc
        if existing != data:
            raise MainGraduationActivationPreparationError(
                "conflicting activation artifact already exists"
            )
        return expected

    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", suffix=".partial", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            # Linking is create-once: it never replaces a concurrent winner.
            os.link(temporary, path)
        except FileExistsError:
            if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                raise MainGraduationActivationPreparationError(
                    "conflicting activation artifact already exists"
                ) from None
    except MainGraduationActivationPreparationError:
        raise
    except OSError as exc:
        raise MainGraduationActivationPreparationError(
            "activation artifact could not be published"
        ) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return expected


def _revalidate[T](value: T, expected: type[T], label: str) -> T:
    """Require an exact DTO instance and run its validators again."""
    if type(value) is not expected:
        raise MainGraduationActivationPreparationError(
            f"{label} must be an exact {expected.__name__} instance"
        )
    try:
        return expected.model_validate(value.model_dump(mode="json"))  # type: ignore[union-attr]
    except (TypeError, ValueError) as exc:
        raise MainGraduationActivationPreparationError(
            f"{label} failed contract validation"
        ) from exc


def _verify[T](
    value: T,
    verifier: object | None,
    expected: type[T],
    label: str,
) -> None:
    """Invoke one exact one-argument verifier and require literal ``True``."""
    if verifier is None:
        raise MainGraduationActivationPreparationError(f"{label} verifier is required")
    candidate: object = verifier
    if not callable(candidate):
        method_names = {
            "controller authority": ("verify_controller_authority", "verify_authority"),
            "C8 capability": ("verify_c8_capability", "verify_capability"),
            "hosted rollback": ("verify_hosted_rollback", "verify_rollback"),
        }.get(label, ())
        candidate = next(
            (
                getattr(verifier, name)
                for name in method_names
                if callable(getattr(verifier, name, None))
            ),
            None,
        )
    if not callable(candidate):
        raise MainGraduationActivationPreparationError(f"{label} verifier is unavailable")
    try:
        signature = inspect.signature(candidate)
    except (TypeError, ValueError) as exc:
        raise MainGraduationActivationPreparationError(
            f"{label} verifier signature is invalid"
        ) from exc
    parameters = tuple(signature.parameters.values())
    if len(parameters) != 1 or parameters[0].kind not in (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
    ):
        raise MainGraduationActivationPreparationError(
            f"{label} verifier signature must accept exactly one typed evidence argument"
        )
    # Requiring an exact runtime value here prevents a verifier from being
    # handed an untrusted mapping or a caller-controlled boolean.
    if type(value) is not expected:
        raise MainGraduationActivationPreparationError(f"{label} evidence type is invalid")
    try:
        result = candidate(value)
    except Exception as exc:
        raise MainGraduationActivationPreparationError(
            f"{label} verifier rejected evidence"
        ) from exc
    if result is not True:
        raise MainGraduationActivationPreparationError(
            f"{label} verifier did not return literal True"
        )


def _activation_values(
    authority: MainLedgerControllerAuthority,
    proof: MainLedgerHostedRollbackProof,
    capability: MainLedgerC8CapabilityEvidence,
    *,
    scheduler_sequence_watermark: int,
    freshness_cutoff: datetime,
    activated_at: datetime,
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
        "scheduler_sequence_watermark": scheduler_sequence_watermark,
        "freshness_cutoff": freshness_cutoff,
        "controller_authority": authority,
        "hosted_rollback_proof": proof,
        "c8_capability_evidence": capability,
        "hosted_rollback_proof_digest": proof.proof_digest,
        "hosted_rollback_artifact_digest": proof.proof_artifact_digest,
        "rollback_authority_identity": proof.rollback_authority_identity,
        "rollback_authority_digest": proof.rollback_authority_digest,
        "c8_capability_evidence_digest": capability.evidence_digest,
        "activated_at": activated_at,
        "deploy_performed": False,
    }
    stub = MainLedgerActivation.model_construct(**values, activation_digest=_ZERO_DIGEST)
    values["activation_digest"] = canonical_digest(
        stub.model_dump(exclude={"activation_digest"}, mode="json")
    )
    return values


def prepare_main_graduation_activation(
    output_file: Path,
    *,
    controller_authority: MainLedgerControllerAuthority,
    c8_capability_evidence: MainLedgerC8CapabilityEvidence,
    hosted_rollback_proof: MainLedgerHostedRollbackProof,
    freshness_cutoff: datetime,
    activated_at: datetime,
    scheduler_sequence_watermark: int,
    authority_verifier: object | None = None,
    capability_verifier: object | None = None,
    rollback_verifier: object | None = None,
    verifier: object | None = None,
    controller_verifier: object | None = None,
) -> PreparedMainGraduationActivation:
    """Prepare one canonical activation draft without invoking activation authority.

    ``activated_at`` is the controller-selected draft timestamp; this function
    does not obtain a clock value or call a service.  The ledger service must
    still perform the eventual activation, if separately authorized.
    """
    if not isinstance(output_file, Path):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise MainGraduationActivationPreparationError("output_file must be a Path")
    authority = _revalidate(
        controller_authority, MainLedgerControllerAuthority, "controller authority"
    )
    capability = _revalidate(
        c8_capability_evidence,
        MainLedgerC8CapabilityEvidence,
        "C8 capability evidence",
    )
    proof = _revalidate(
        hosted_rollback_proof, MainLedgerHostedRollbackProof, "hosted rollback proof"
    )
    if controller_verifier is not None:
        if authority_verifier is not None:
            raise MainGraduationActivationPreparationError(
                "supply only one controller authority verifier"
            )
        authority_verifier = controller_verifier
    if verifier is not None:
        capability_verifier = capability_verifier or verifier
        rollback_verifier = rollback_verifier or verifier
        authority_verifier = authority_verifier or verifier

    for label, value in (("freshness_cutoff", freshness_cutoff), ("activated_at", activated_at)):
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise MainGraduationActivationPreparationError(f"{label} must be timezone-aware")
    if type(scheduler_sequence_watermark) is not int:
        raise MainGraduationActivationPreparationError(
            "scheduler_sequence_watermark must be an integer"
        )
    if scheduler_sequence_watermark < 0:
        raise MainGraduationActivationPreparationError(
            "scheduler_sequence_watermark must be non-negative"
        )
    if not authority.authorized_at <= freshness_cutoff <= activated_at <= authority.expires_at:
        raise MainGraduationActivationPreparationError(
            "activation window is outside controller authority"
        )
    if not freshness_cutoff <= capability.observed_at <= activated_at:
        raise MainGraduationActivationPreparationError(
            "C8 capability evidence is stale or future-dated"
        )
    if not freshness_cutoff <= proof.completed_at <= activated_at:
        raise MainGraduationActivationPreparationError(
            "hosted rollback proof is stale or future-dated"
        )
    if (
        capability.repository_digest != authority.repository_digest
        or capability.target_ref != authority.target_ref
    ):
        raise MainGraduationActivationPreparationError(
            "C8 capability target differs from controller authority"
        )
    if capability.controller_authority_digest != authority.authority_digest:
        raise MainGraduationActivationPreparationError(
            "C8 capability is not bound to controller authority"
        )
    if (
        proof.repository_digest != authority.repository_digest
        or proof.target_ref != authority.target_ref
    ):
        raise MainGraduationActivationPreparationError(
            "hosted rollback target differs from controller authority"
        )
    if proof.controller_authority_digest != authority.authority_digest:
        raise MainGraduationActivationPreparationError(
            "hosted rollback is not bound to controller authority"
        )
    _verify(authority, authority_verifier, MainLedgerControllerAuthority, "controller authority")
    _verify(capability, capability_verifier, MainLedgerC8CapabilityEvidence, "C8 capability")
    _verify(proof, rollback_verifier, MainLedgerHostedRollbackProof, "hosted rollback")
    values = _activation_values(
        authority,
        proof,
        capability,
        scheduler_sequence_watermark=scheduler_sequence_watermark,
        freshness_cutoff=freshness_cutoff,
        activated_at=activated_at,
    )
    try:
        activation = MainLedgerActivation.model_validate(values)
    except (TypeError, ValueError) as exc:
        raise MainGraduationActivationPreparationError(
            "activation contract validation failed"
        ) from exc
    data = canonical_bytes(activation.model_dump(mode="json"))
    artifact_digest = _write_create_once(output_file, data)
    return PreparedMainGraduationActivation(activation, output_file, artifact_digest)


# Friendly aliases for callers that use the roadmap's shorter terminology.
prepare_hosted_activation = prepare_main_graduation_activation
prepare_activation = prepare_main_graduation_activation
prepare_main_ledger_activation = prepare_main_graduation_activation
MainGraduationActivationPreparation = PreparedMainGraduationActivation
MainLedgerActivationArtifact = PreparedMainGraduationActivation

__all__ = [
    "MAX_ACTIVATION_BYTES",
    "MainGraduationActivationPreparation",
    "MainGraduationActivationPreparationError",
    "MainLedgerActivationArtifact",
    "PreparedMainGraduationActivation",
    "prepare_activation",
    "prepare_hosted_activation",
    "prepare_main_graduation_activation",
    "prepare_main_ledger_activation",
]
