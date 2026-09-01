"""Prepare a local, non-consumable inventory for a future C8 activation.

This module deliberately cannot prepare ``MainLedgerActivation``. Local files,
parsed DTOs, and self-digests are candidate evidence only: they do not establish
issuer authority, provider observations, CAS durability, freshness, or
activation authority. A future service-owned boundary must obtain and verify
those facts through its configured trust root before it can construct or record
an activation.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from pydantic import Field, model_validator

from avo_correlate.contracts.base import (
    ArtifactRef,
    NonEmptyString,
    NonNegativeInt,
    Sha256Digest,
    StrictModel,
)
from avo_correlate.contracts.main_graduation_ledger import (
    MainLedgerC8CapabilityEvidence,
    MainLedgerControllerAuthority,
    MainLedgerHostedRollbackProof,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

MAX_LOCAL_DRAFT_BYTES = 8 * 1024 * 1024
_ZERO_DIGEST = "sha256:" + "0" * 64
_LOCAL_DRAFT_KIND = "avo.main.ledger.local-activation-preparation-draft.v1"
_CANDIDATE_ROLES = (
    "controller-authority-candidate",
    "c8-capability-evidence-candidate",
    "hosted-rollback-proof-candidate",
)


class MainGraduationActivationPreparationError(RuntimeError):
    """Local candidate inventory cannot be safely prepared."""


class LocalActivationCandidateArtifact(StrictModel):
    """A local file inventory entry, explicitly not trusted evidence."""

    schema_version: Literal[1] = 1
    role: Literal[
        "controller-authority-candidate",
        "c8-capability-evidence-candidate",
        "hosted-rollback-proof-candidate",
    ]
    artifact_digest: Sha256Digest
    size_bytes: NonNegativeInt
    media_type: NonEmptyString
    canonical_json: Literal[True] = True


class LocalMainLedgerActivationPreparationDraft(StrictModel):
    """An unverified local handoff; it can never be sent to the ledger."""

    schema_version: Literal[1] = 1
    draft_kind: Literal["avo.main.ledger.local-activation-preparation-draft.v1"] = (
        _LOCAL_DRAFT_KIND
    )
    prepared_only: Literal[True] = True
    activation_consumable: Literal[False] = False
    rooted_verification: Literal[False] = False
    candidate_artifacts: tuple[LocalActivationCandidateArtifact, ...] = Field(
        min_length=len(_CANDIDATE_ROLES), max_length=len(_CANDIDATE_ROLES)
    )
    draft_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_local_draft(self) -> LocalMainLedgerActivationPreparationDraft:
        if tuple(item.role for item in self.candidate_artifacts) != _CANDIDATE_ROLES:
            raise ValueError("local activation draft candidates must use the fixed role order")
        if self.draft_digest != canonical_digest(
            self.model_dump(exclude={"draft_digest"}, mode="json")
        ):
            raise ValueError("local activation draft digest mismatch")
        return self


class MainLedgerActivationTrustRoot(Protocol):
    """Future service seam for role-separated, CAS-backed verification.

    This protocol is intentionally not accepted by the local preparer. Its
    implementation must re-read immutable artifact bytes by ``ArtifactRef``,
    authenticate the provider/controller identity for each role, and apply a
    trusted clock before constructing ``MainLedgerActivation``.
    """

    def load_verified_controller_authority(
        self, reference: ArtifactRef
    ) -> MainLedgerControllerAuthority: ...

    def load_verified_c8_capability(
        self, reference: ArtifactRef
    ) -> MainLedgerC8CapabilityEvidence: ...

    def load_verified_hosted_rollback_proof(
        self, reference: ArtifactRef
    ) -> MainLedgerHostedRollbackProof: ...


@dataclass(frozen=True, slots=True)
class PreparedLocalMainLedgerActivationDraft:
    """The local draft plus its raw on-disk artifact identity."""

    draft: LocalMainLedgerActivationPreparationDraft
    artifact_path: Path
    artifact_digest: str

    @property
    def semantic_digest(self) -> str:
        """Return the draft self-digest, distinct from its raw file digest."""
        return self.draft.draft_digest

    @property
    def raw_digest(self) -> str:
        """Return the digest of the canonical serialized draft."""
        return self.artifact_digest

    @property
    def path(self) -> Path:
        """Compatibility convenience for local artifact consumers."""
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
    """Atomically create the local draft; replay only an identical winner."""
    if len(data) > MAX_LOCAL_DRAFT_BYTES:
        raise MainGraduationActivationPreparationError("local activation draft exceeds size bound")
    _safe_existing_path(path.parent, "local activation draft output parent")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise MainGraduationActivationPreparationError(
            "local activation draft output parent could not be created"
        ) from exc
    _safe_existing_path(path, "local activation draft output")
    expected = _raw_digest(data)
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise MainGraduationActivationPreparationError(
                "local activation draft output must be a regular file"
            )
        try:
            existing = path.read_bytes()
        except OSError as exc:
            raise MainGraduationActivationPreparationError(
                "local activation draft output is unreadable"
            ) from exc
        if existing != data:
            raise MainGraduationActivationPreparationError(
                "conflicting local activation draft already exists"
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
                    "conflicting local activation draft already exists"
                ) from None
    except MainGraduationActivationPreparationError:
        raise
    except OSError as exc:
        raise MainGraduationActivationPreparationError(
            "local activation draft could not be published"
        ) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return expected


def _revalidate_candidate(value: object) -> LocalActivationCandidateArtifact:
    if type(value) is not LocalActivationCandidateArtifact:
        raise MainGraduationActivationPreparationError(
            "local activation candidate must be an exact LocalActivationCandidateArtifact"
        )
    try:
        return LocalActivationCandidateArtifact.model_validate(value.model_dump(mode="json"))
    except (TypeError, ValueError) as exc:
        raise MainGraduationActivationPreparationError(
            "local activation candidate failed contract validation"
        ) from exc


def _draft_values(
    candidate_artifacts: tuple[LocalActivationCandidateArtifact, ...],
) -> dict[str, object]:
    values: dict[str, object] = {"candidate_artifacts": candidate_artifacts}
    stub = LocalMainLedgerActivationPreparationDraft.model_construct(
        candidate_artifacts=candidate_artifacts, draft_digest=_ZERO_DIGEST
    )
    values["draft_digest"] = canonical_digest(
        stub.model_dump(exclude={"draft_digest"}, mode="json")
    )
    return values


def prepare_local_main_graduation_activation_draft(
    output_file: Path,
    *,
    candidate_artifacts: Sequence[LocalActivationCandidateArtifact],
) -> PreparedLocalMainLedgerActivationDraft:
    """Write an explicitly non-consumable inventory of local candidate files.

    No verifier, authority DTO, clock, ledger, provider, or CAS reader is
    accepted here. The future ``MainLedgerActivationTrustRoot`` service is
    responsible for establishing those facts and is deliberately outside this
    local preparation boundary.
    """
    if not isinstance(output_file, Path):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise MainGraduationActivationPreparationError("output_file must be a Path")
    if len(candidate_artifacts) != len(_CANDIDATE_ROLES):
        raise MainGraduationActivationPreparationError(
            "local activation draft requires exactly three candidate artifacts"
        )
    candidates = tuple(_revalidate_candidate(item) for item in candidate_artifacts)
    values = _draft_values(candidates)
    try:
        draft = LocalMainLedgerActivationPreparationDraft.model_validate(values)
    except (TypeError, ValueError) as exc:
        raise MainGraduationActivationPreparationError(
            "local activation draft contract validation failed"
        ) from exc
    data = canonical_bytes(draft.model_dump(mode="json"))
    artifact_digest = _write_create_once(output_file, data)
    return PreparedLocalMainLedgerActivationDraft(draft, output_file, artifact_digest)


__all__ = [
    "MAX_LOCAL_DRAFT_BYTES",
    "LocalActivationCandidateArtifact",
    "LocalMainLedgerActivationPreparationDraft",
    "MainGraduationActivationPreparationError",
    "MainLedgerActivationTrustRoot",
    "PreparedLocalMainLedgerActivationDraft",
    "prepare_local_main_graduation_activation_draft",
]
