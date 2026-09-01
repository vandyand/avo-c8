# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportUnusedVariable=false
"""Local preparation of the C8 hosted-main rollback proof.

This module is deliberately an evidence boundary, not a rollback runner.  It
loads an already completed, content-addressed C5 package from an injected
reader, asks an injected controller verifier to authenticate the complete
evidence, and publishes the small ledger proof required by C8.  There are no
provider objects, transports, credentials, or mutation methods in this
module.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

from avo_correlate.contracts.base import ArtifactRef, StrictModel
from avo_correlate.contracts.main_graduation import (
    MainRollbackCompletionPackage,
    MainRollbackPostStateObservation,
)
from avo_correlate.contracts.main_graduation_ledger import (
    MainLedgerControllerAuthority,
    MainLedgerHostedRollbackProof,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

_ZERO_DIGEST = "sha256:" + "0" * 64
_MAX_PROOF_BYTES = 1024 * 1024
_PACKAGE_ROLE = "main-graduation-rollback-completion"
_PACKAGE_MEDIA_TYPE = "application/vnd.avo.main-graduation-rollback-completion+json"
_PROOF_ROLE = "main-ledger-hosted-rollback-proof"
_PROOF_MEDIA_TYPE = "application/vnd.avo.main-ledger-hosted-rollback-proof+json"


class HostedRollbackProofPreparationError(RuntimeError):
    """Durable hosted rollback evidence cannot be consumed as C8 proof."""


class HostedRollbackCompletionReader(Protocol):
    def __call__(
        self, operation_id: str
    ) -> tuple[MainRollbackCompletionPackage, ArtifactRef] | None: ...


class HostedRollbackAuthorityVerifier(Protocol):
    """A controller-owned verifier must return the literal boolean ``True``."""

    def verify_hosted_rollback(
        self,
        authority: MainLedgerControllerAuthority,
        completion: MainRollbackCompletionPackage,
    ) -> bool: ...


class HostedRollbackAuthorityReader(Protocol):
    def __call__(
        self,
    ) -> MainLedgerControllerAuthority | tuple[
        MainLedgerControllerAuthority, ArtifactRef
    ]: ...


@dataclass(frozen=True, slots=True)
class MainHostedRollbackProofArtifact:
    """The canonical proof plus its local content-addressed output metadata."""

    proof: MainLedgerHostedRollbackProof
    artifact_ref: ArtifactRef
    path: Path

    @property
    def artifact_digest(self) -> str:
        return self.artifact_ref.digest

    @property
    def proof_digest(self) -> str:
        return self.proof.proof_digest

    @property
    def raw_digest(self) -> str:
        return self.artifact_ref.digest

    @property
    def artifact_path(self) -> Path:
        return self.path


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(char in "0123456789abcdef" for char in value[7:])
    )


def _strict_reload(value: object, expected: type[StrictModel], label: str) -> StrictModel:
    if not isinstance(value, expected):
        raise HostedRollbackProofPreparationError(f"{label} is not typed durable evidence")
    try:
        # Reparse the wire form so a model_construct() caller cannot smuggle
        # an unchecked DTO into this boundary.
        return expected.model_validate_json(canonical_bytes(value))
    except Exception as exc:
        raise HostedRollbackProofPreparationError(f"{label} failed durable reload") from exc


def _pair(
    value: object, expected: type[StrictModel], label: str
) -> tuple[StrictModel, ArtifactRef]:
    if not isinstance(value, tuple) or len(value) != 2:
        raise HostedRollbackProofPreparationError(f"{label} reader did not return an evidence pair")
    record = _strict_reload(value[0], expected, label)
    reference = _strict_reload(value[1], ArtifactRef, f"{label} artifact")
    assert isinstance(reference, ArtifactRef)
    payload = canonical_bytes(record)
    if (
        reference.digest != canonical_digest(record)
        or reference.size_bytes != len(payload)
        or not reference.role
        or not reference.media_type
    ):
        raise HostedRollbackProofPreparationError(f"{label} artifact is not content-addressed")
    return record, reference


def _authority(value: object) -> MainLedgerControllerAuthority:
    raw = value
    reference: ArtifactRef | None = None
    if isinstance(value, tuple) and len(value) == 2:
        raw, reference = value
    checked = _strict_reload(raw, MainLedgerControllerAuthority, "controller authority")
    assert isinstance(checked, MainLedgerControllerAuthority)
    if reference is not None:
        ref = _strict_reload(reference, ArtifactRef, "controller authority artifact")
        assert isinstance(ref, ArtifactRef)
        if ref.digest != canonical_digest(checked) or ref.size_bytes != len(
            canonical_bytes(checked)
        ):
            raise HostedRollbackProofPreparationError(
                "controller authority artifact is not content-addressed"
            )
    return checked


def _verify(
    verifier: object,
    authority: MainLedgerControllerAuthority,
    package: MainRollbackCompletionPackage,
) -> None:
    if verifier is None:
        raise HostedRollbackProofPreparationError("controller authority verifier is required")
    method: object | None = None
    for name in (
        "verify_hosted_rollback",
        "verify_main_hosted_rollback",
        "verify_rollback_completion",
    ):
        candidate = getattr(verifier, name, None)
        if callable(candidate):
            method = candidate
            break
    if method is None and callable(verifier):
        method = verifier
    if method is None:
        raise HostedRollbackProofPreparationError("controller authority verifier is unavailable")
    try:
        result = cast(Callable[[Any, Any], object], method)(authority, package)
    except Exception as exc:
        raise HostedRollbackProofPreparationError(
            "controller authority verification failed"
        ) from exc
    if result is not True:
        raise HostedRollbackProofPreparationError(
            "controller authority verification was not literal True"
        )


def _same_record(left: StrictModel, right: StrictModel, label: str) -> None:
    if canonical_bytes(left) != canonical_bytes(right):
        raise HostedRollbackProofPreparationError(
            f"durable {label} differs from completion package"
        )


def _has_deployment_claim(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            (key == "deploy_performed" and item is not False)
            or _has_deployment_claim(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_has_deployment_claim(item) for item in value)
    return False


def _validate_inputs(
    package: MainRollbackCompletionPackage,
    package_ref: ArtifactRef,
    authority: MainLedgerControllerAuthority,
    operation_id: str,
    current_tip_reader: Callable[..., object] | None,
) -> None:
    if not _is_digest(operation_id) or package.operation_id != operation_id:
        raise HostedRollbackProofPreparationError(
            "rollback operation identity is stale or mismatched"
        )
    package_payload = canonical_bytes(package)
    if (
        package_ref.digest != canonical_digest(package)
        or package_ref.size_bytes != len(package_payload)
        or package_ref.role != _PACKAGE_ROLE
        or package_ref.media_type != _PACKAGE_MEDIA_TYPE
    ):
        raise HostedRollbackProofPreparationError(
            "rollback completion artifact metadata is invalid"
        )
    if package.deploy_performed is not False:
        raise HostedRollbackProofPreparationError("rollback completion claims deployment")
    # Every child is contract data, but retain this explicit recursive check so
    # future package fields cannot silently introduce a deployment claim.
    if _has_deployment_claim(package.model_dump(mode="python")):
        raise HostedRollbackProofPreparationError("rollback evidence contains a deployment claim")
    attempt = package.attempt_authority
    result = package.rollback_result
    post = package.post_state
    terminal = package.cleanup_terminal
    if (
        authority.repository_digest != package.repository_digest
        or authority.target_ref != package.target_ref
        or authority.controller_config_digest != attempt.controller_config_digest
        or authority.policy_epoch != attempt.policy_epoch
        or attempt.release_issuer_identity
        != package.rollback_authorization.release_issuer_identity
        or attempt.release_issuer_app_id
        != package.rollback_authorization.release_issuer_app_id
        or attempt.issuer_isolation_digest
        != package.rollback_authorization.issuer_isolation_digest
    ):
        raise HostedRollbackProofPreparationError(
            "rollback evidence is outside controller authority"
        )
    if (
        result.outcome not in {"applied", "already_applied"}
        or result.result_commit is None
        or result.result_tree != attempt.inverse_tree
        or result.result_parent_commit != attempt.current_main_commit
        or result.result_parents != [attempt.current_main_commit]
        or result.current_main_commit != attempt.current_main_commit
        or post.current_main_commit != attempt.current_main_commit
        or post.result_commit != result.result_commit
        or post.result_tree != attempt.inverse_tree
        or post.result_parents != [attempt.current_main_commit]
        or post.inverse_tree != attempt.inverse_tree
        or post.result_receipt_digest != result.receipt_digest
        or post.attempt_manifest_digest != attempt.manifest_digest
    ):
        raise HostedRollbackProofPreparationError(
            "rollback result topology or main-before binding is invalid"
        )
    if (
        terminal.terminal is not True
        or terminal.outcome not in {"absent", "already_absent"}
        or terminal.candidate_ref_absent is not True
        or terminal.pull_request_state != "closed"
        or terminal.pull_request_merged is not True
        or terminal.cleanup_intent_digest != package.cleanup_intent.intent_digest
        or terminal.cleanup_receipt_digest != package.cleanup_receipt.receipt_digest
        or terminal.candidate_ref != package.cleanup_intent.candidate_ref
        or terminal.candidate_commit != package.cleanup_intent.candidate_commit
        or terminal.pull_request_number != package.cleanup_intent.pull_request_number
    ):
        raise HostedRollbackProofPreparationError("rollback cleanup is not terminal")
    if (
        package.queue_configuration.expected_base_commit != attempt.current_main_commit
        or package.queue_configuration.expected_base_tree != attempt.current_main_tree
        or package.queue_observation.queue_configuration_digest
        != package.queue_configuration.queue_configuration_digest
        or package.queue_observation.pull_request_number
        != package.admission_observation.pull_request_number
    ):
        raise HostedRollbackProofPreparationError("rollback queue protocol evidence is stale")
    if current_tip_reader is not None:
        try:
            observed = current_tip_reader(package.repository_digest, package.target_ref)
        except TypeError:
            try:
                observed = current_tip_reader()
            except Exception as exc:
                raise HostedRollbackProofPreparationError(
                    "current main tip could not be re-read"
                ) from exc
        except Exception as exc:
            raise HostedRollbackProofPreparationError(
                "current main tip could not be re-read"
            ) from exc
        if isinstance(observed, tuple) and len(observed) == 2:
            observed, _ = _pair(observed, MainRollbackPostStateObservation, "current main tip")
        observed = _strict_reload(observed, MainRollbackPostStateObservation, "current main tip")
        assert isinstance(observed, MainRollbackPostStateObservation)
        _same_record(observed, post, "current main tip")
    # These are the replay identities that must remain immutable across a
    # second read.  In particular, no fresh operation can be minted here.
    if (
        attempt.operation_id != package.operation_id
        or attempt.completion_package_digest != canonical_digest(package.source_completion)
        or package.composition.composition_id != package.composition_id
    ):
        raise HostedRollbackProofPreparationError("rollback replay identity is not durable")


def _proof(
    package: MainRollbackCompletionPackage,
    authority: MainLedgerControllerAuthority,
    package_artifact_digest: str,
) -> MainLedgerHostedRollbackProof:
    values: dict[str, Any] = {
        "operation_id": package.operation_id,
        "repository_digest": package.repository_digest,
        "target_ref": package.target_ref,
        "proof_artifact_digest": package_artifact_digest,
        "controller_authority_digest": authority.authority_digest,
        "rollback_authority_identity": package.attempt_authority.release_issuer_identity,
        "rollback_authority_digest": package.attempt_authority.manifest_digest,
        "result_evidence_digest": package.rollback_result.receipt_digest,
        "completed_at": package.cleanup_terminal.observed_at,
    }
    probe = MainLedgerHostedRollbackProof.model_construct(**values, proof_digest=_ZERO_DIGEST)
    values["proof_digest"] = canonical_digest(
        probe.model_dump(exclude={"proof_digest"}, mode="json")
    )
    try:
        return MainLedgerHostedRollbackProof.model_validate(values)
    except Exception as exc:
        raise HostedRollbackProofPreparationError(
            "hosted rollback proof schema validation failed"
        ) from exc


def _publish(path: Path, payload: bytes) -> str:
    if len(payload) > _MAX_PROOF_BYTES:
        raise HostedRollbackProofPreparationError("hosted rollback proof exceeds size bound")
    if path.is_symlink():
        raise HostedRollbackProofPreparationError(
            "hosted rollback proof output must be a regular file"
        )
    path = path.absolute()
    if path.parent.is_symlink():
        raise HostedRollbackProofPreparationError(
            "hosted rollback proof output parent cannot be a symlink"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
            raise HostedRollbackProofPreparationError(
                "conflicting hosted rollback proof already exists"
            )
        return "sha256:" + hashlib.sha256(payload).hexdigest()
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".partial",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
                raise HostedRollbackProofPreparationError(
                    "conflicting hosted rollback proof already exists"
                ) from None
    except OSError as exc:
        raise HostedRollbackProofPreparationError(
            "hosted rollback proof could not be published"
        ) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def prepare_hosted_rollback_proof(
    output_file: Path,
    *,
    operation_id: str,
    completion_reader: HostedRollbackCompletionReader,
    controller_authority_reader: HostedRollbackAuthorityReader,
    authority_verifier: HostedRollbackAuthorityVerifier | object,
    current_tip_reader: Callable[..., object] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> MainHostedRollbackProofArtifact:
    """Prepare one activation-consumable proof from durable evidence only."""
    if not callable(completion_reader) or not callable(controller_authority_reader):
        raise HostedRollbackProofPreparationError("durable evidence readers are required")
    try:
        loaded = completion_reader(operation_id)
    except Exception as exc:
        raise HostedRollbackProofPreparationError("rollback completion could not be read") from exc
    if loaded is None:
        raise HostedRollbackProofPreparationError("rollback completion is not durably recorded")
    package_raw, package_ref = _pair(
        loaded, MainRollbackCompletionPackage, "rollback completion"
    )
    package_raw = cast(MainRollbackCompletionPackage, package_raw)
    try:
        authority = _authority(controller_authority_reader())
    except HostedRollbackProofPreparationError:
        raise
    except Exception as exc:
        raise HostedRollbackProofPreparationError(
            "controller authority could not be read"
        ) from exc
    _verify(authority_verifier, authority, package_raw)
    _validate_inputs(package_raw, package_ref, authority, operation_id, current_tip_reader)
    proof = _proof(package_raw, authority, package_ref.digest)
    now = (clock or (lambda: datetime.now(UTC)))()
    if now.tzinfo is None or now.utcoffset() is None:
        raise HostedRollbackProofPreparationError("clock must return a timezone-aware timestamp")
    payload = canonical_bytes(proof)
    digest = _publish(output_file, payload)
    reference = ArtifactRef(
        digest=digest,
        size_bytes=len(payload),
        media_type=_PROOF_MEDIA_TYPE,
        role=_PROOF_ROLE,
        created_at=now,
    )
    return MainHostedRollbackProofArtifact(proof=proof, artifact_ref=reference, path=output_file)


# Explicit aliases make the C8 terminology convenient to callers while
# retaining one implementation and one mutation-free public surface.
prepare_main_hosted_rollback_proof = prepare_hosted_rollback_proof
MainLedgerHostedRollbackProofArtifact = MainHostedRollbackProofArtifact


__all__ = [
    "HostedRollbackAuthorityReader",
    "HostedRollbackAuthorityVerifier",
    "HostedRollbackCompletionReader",
    "HostedRollbackProofPreparationError",
    "MainHostedRollbackProofArtifact",
    "MainLedgerHostedRollbackProofArtifact",
    "prepare_hosted_rollback_proof",
    "prepare_main_hosted_rollback_proof",
]
