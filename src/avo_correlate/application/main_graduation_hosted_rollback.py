# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownParameterType=false
"""Prepare a non-hosted inventory of recorded C5 rollback evidence.

This module is intentionally incapable of producing an activation input. A
provider-rooted runner must perform and authenticate a fresh hosted drill
before constructing the ledger's hosted rollback proof. Local preparation only
reloads an existing typed completion package and writes an inventory whose
``activation_consumable`` discriminator is permanently false.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from avo_correlate.contracts.base import ArtifactRef, Sha256Digest, StrictModel
from avo_correlate.contracts.main_graduation import (
    MainRollbackCompletionPackage,
    MainRollbackPostStateObservation,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

_ZERO_DIGEST = "sha256:" + "0" * 64
_MAX_DRAFT_BYTES = 1024 * 1024
_PACKAGE_ROLE = "main-graduation-rollback-completion"
_PACKAGE_MEDIA_TYPE = "application/vnd.avo.main-graduation-rollback-completion+json"
_DRAFT_ROLE = "main-ledger-hosted-rollback-evidence-draft"
_DRAFT_MEDIA_TYPE = "application/vnd.avo.main-ledger-hosted-rollback-evidence-draft+json"


class HostedRollbackProofPreparationError(RuntimeError):
    """Recorded rollback evidence cannot be safely inventoried."""


class HostedRollbackCompletionReader(Protocol):
    def __call__(
        self, operation_id: str
    ) -> tuple[MainRollbackCompletionPackage, ArtifactRef] | None: ...


class MainHostedRollbackEvidenceDraft(StrictModel):
    """Non-hosted evidence inventory; it cannot satisfy ledger activation."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/main"] = "refs/heads/main"
    completion_package_artifact_digest: Sha256Digest
    rollback_authority_manifest_digest: Sha256Digest
    rollback_result_evidence_digest: Sha256Digest
    post_state_evidence_digest: Sha256Digest
    cleanup_terminal_evidence_digest: Sha256Digest
    observed_at: datetime
    activation_consumable: Literal[False] = False
    hosted_drill_executed: Literal[False] = False
    ledger_activated: Literal[False] = False
    deploy_performed: Literal[False] = False
    draft_digest: Sha256Digest

    @classmethod
    def from_completion(
        cls,
        package: MainRollbackCompletionPackage,
        package_artifact_digest: Sha256Digest,
    ) -> MainHostedRollbackEvidenceDraft:
        values: dict[str, Any] = {
            "operation_id": package.operation_id,
            "repository_digest": package.repository_digest,
            "target_ref": package.target_ref,
            "completion_package_artifact_digest": package_artifact_digest,
            "rollback_authority_manifest_digest": package.attempt_authority.manifest_digest,
            "rollback_result_evidence_digest": package.rollback_result.receipt_digest,
            "post_state_evidence_digest": package.post_state.observation_digest,
            "cleanup_terminal_evidence_digest": package.cleanup_terminal.evidence_digest,
            "observed_at": package.cleanup_terminal.observed_at,
        }
        probe = cls.model_construct(**values, draft_digest=_ZERO_DIGEST)
        values["draft_digest"] = canonical_digest(
            probe.model_dump(exclude={"draft_digest"}, mode="json")
        )
        try:
            return cls.model_validate(values)
        except Exception as exc:
            raise HostedRollbackProofPreparationError(
                "hosted rollback evidence draft schema validation failed"
            ) from exc


@dataclass(frozen=True, slots=True)
class MainHostedRollbackEvidenceDraftArtifact:
    """The draft and its separate completion-package artifact identity."""

    draft: MainHostedRollbackEvidenceDraft
    artifact_ref: ArtifactRef
    completion_package_artifact: ArtifactRef
    path: Path

    @property
    def artifact_digest(self) -> str:
        return self.artifact_ref.digest

    @property
    def draft_digest(self) -> str:
        return self.draft.draft_digest

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
        return expected.model_validate_json(canonical_bytes(value))
    except Exception as exc:
        raise HostedRollbackProofPreparationError(f"{label} failed durable reload") from exc


def _pair(
    value: object, expected: type[StrictModel], label: str
) -> tuple[StrictModel, ArtifactRef]:
    if not isinstance(value, tuple) or len(value) != 2:
        raise HostedRollbackProofPreparationError(
            f"{label} reader did not return an evidence pair"
        )
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
    if _has_deployment_claim(package.model_dump(mode="python")):
        raise HostedRollbackProofPreparationError(
            "rollback evidence contains a deployment claim"
        )
    attempt = package.attempt_authority
    result = package.rollback_result
    post = package.post_state
    terminal = package.cleanup_terminal
    if (
        attempt.release_issuer_identity
        != package.rollback_authorization.release_issuer_identity
        or attempt.release_issuer_app_id
        != package.rollback_authorization.release_issuer_app_id
        or attempt.issuer_isolation_digest
        != package.rollback_authorization.issuer_isolation_digest
    ):
        raise HostedRollbackProofPreparationError("rollback issuer binding is inconsistent")
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
            observed, _ = _pair(
                observed, MainRollbackPostStateObservation, "current main tip"
            )
        observed = _strict_reload(observed, MainRollbackPostStateObservation, "current main tip")
        assert isinstance(observed, MainRollbackPostStateObservation)
        if canonical_bytes(observed) != canonical_bytes(post):
            raise HostedRollbackProofPreparationError(
                "durable current main tip differs from completion package"
            )
    if (
        attempt.operation_id != package.operation_id
        or attempt.completion_package_digest != canonical_digest(package.source_completion)
        or package.composition.composition_id != package.composition_id
    ):
        raise HostedRollbackProofPreparationError("rollback replay identity is not durable")


def _publish(path: Path, payload: bytes) -> str:
    if len(payload) > _MAX_DRAFT_BYTES:
        raise HostedRollbackProofPreparationError("evidence draft exceeds size bound")
    if path.is_symlink():
        raise HostedRollbackProofPreparationError(
            "evidence draft output must be a regular file"
        )
    path = path.absolute()
    if path.parent.is_symlink():
        raise HostedRollbackProofPreparationError(
            "evidence draft output parent cannot be a symlink"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
            raise HostedRollbackProofPreparationError("conflicting evidence draft already exists")
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
                    "conflicting evidence draft already exists"
                ) from None
    except OSError as exc:
        raise HostedRollbackProofPreparationError(
            "evidence draft could not be published"
        ) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def prepare_hosted_rollback_evidence(
    output_file: Path,
    *,
    operation_id: str,
    completion_reader: HostedRollbackCompletionReader,
    current_tip_reader: Callable[..., object] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> MainHostedRollbackEvidenceDraftArtifact:
    """Inventory recorded rollback evidence without claiming a hosted drill."""
    if not callable(completion_reader):
        raise HostedRollbackProofPreparationError("durable completion reader is required")
    try:
        loaded = completion_reader(operation_id)
    except Exception as exc:
        raise HostedRollbackProofPreparationError("rollback completion could not be read") from exc
    if loaded is None:
        raise HostedRollbackProofPreparationError("rollback completion is not durably recorded")
    package_raw, package_ref = _pair(
        loaded, MainRollbackCompletionPackage, "rollback completion"
    )
    package = cast(MainRollbackCompletionPackage, package_raw)
    _validate_inputs(package, package_ref, operation_id, current_tip_reader)
    now = (clock or (lambda: datetime.now(UTC)))()
    if now.tzinfo is None or now.utcoffset() is None:
        raise HostedRollbackProofPreparationError(
            "clock must return a timezone-aware timestamp"
        )
    draft = MainHostedRollbackEvidenceDraft.from_completion(package, package_ref.digest)
    payload = canonical_bytes(draft)
    digest = _publish(output_file, payload)
    reference = ArtifactRef(
        digest=digest,
        size_bytes=len(payload),
        media_type=_DRAFT_MEDIA_TYPE,
        role=_DRAFT_ROLE,
        created_at=now,
    )
    return MainHostedRollbackEvidenceDraftArtifact(
        draft=draft,
        artifact_ref=reference,
        completion_package_artifact=package_ref,
        path=output_file,
    )


prepare_main_hosted_rollback_evidence = prepare_hosted_rollback_evidence


__all__ = [
    "HostedRollbackCompletionReader",
    "HostedRollbackProofPreparationError",
    "MainHostedRollbackEvidenceDraft",
    "MainHostedRollbackEvidenceDraftArtifact",
    "prepare_hosted_rollback_evidence",
    "prepare_main_hosted_rollback_evidence",
]
