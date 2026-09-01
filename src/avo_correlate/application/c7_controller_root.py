"""Strict local loader for the controller root consumed by C7.

The controller root is an operator-supplied, canonical JSON artifact.  Its
self-digest is semantic authority; the SHA-256 of its raw canonical bytes is
an independent out-of-band artifact pin.  Loading this module performs no
network or hosted mutation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import Field, field_validator, model_validator

from avo_correlate.contracts.base import Sha256Digest, StrictModel, require_aware_datetime
from avo_correlate.contracts.main_graduation_offline_drill import GitObject
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

MAX_CONTROLLER_ROOT_BYTES = 8 * 1024 * 1024
# The root authorizes one bounded offline run.  Two hours leaves room for the
# exact 47-node matrix while ensuring a forgotten or stale root cannot remain
# usable indefinitely.
MAX_CONTROLLER_ROOT_WINDOW_SECONDS = 2 * 60 * 60


class C7ControllerRootError(ValueError):
    """The controller root is unavailable, malformed, or not pinned."""


class C7ControllerRoot(StrictModel):
    """Typed controller root for one exact C7 execution authority window."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/main"] = "refs/heads/main"
    issuer_identity: str = Field(min_length=1, max_length=256)
    source_commit: GitObject
    source_tree: GitObject
    source_tree_digest: Sha256Digest
    protocol_digest: Sha256Digest
    configuration_digest: Sha256Digest
    policy_digest: Sha256Digest
    activation_digest: Sha256Digest
    authorized_at: datetime
    expires_at: datetime
    nonce: Sha256Digest
    controller_authority_digest: Sha256Digest

    _aware_authorized = field_validator("authorized_at", "expires_at")(
        require_aware_datetime
    )

    @model_validator(mode="after")
    def validate_root(self) -> C7ControllerRoot:
        if self.expires_at <= self.authorized_at:
            raise ValueError("controller root expiry must follow authorization")
        if (
            self.expires_at - self.authorized_at
        ).total_seconds() > MAX_CONTROLLER_ROOT_WINDOW_SECONDS:
            raise ValueError("controller root window exceeds maximum")
        expected = canonical_digest(
            {
                "domain": "avo-004.7-c7/controller-root/v1",
                "value": self.model_dump(exclude={"controller_authority_digest"}, mode="json"),
            }
        )
        if self.controller_authority_digest != expected:
            raise ValueError("controller root semantic digest mismatch")
        return self


@dataclass(frozen=True, slots=True)
class C7ControllerRootArtifact:
    """Validated root plus its separately pinned raw artifact identity."""

    root: C7ControllerRoot
    raw_digest: str
    path: Path

    @property
    def controller_authority_digest(self) -> str:
        return self.root.controller_authority_digest

    @property
    def controller_authority_ref(self) -> str:
        """The authority ref is the exact raw artifact digest, never a caller label."""
        return self.raw_digest


def load_controller_root(path: Path, expected_raw_digest: str) -> C7ControllerRootArtifact:
    """Strict-load and raw-CAS-verify one canonical controller-root artifact."""
    if not expected_raw_digest.startswith("sha256:") or len(expected_raw_digest) != 71:
        raise C7ControllerRootError("controller root raw digest is required")
    if any(char not in "0123456789abcdef" for char in expected_raw_digest[7:]):
        raise C7ControllerRootError("controller root raw digest is invalid")
    if path.is_symlink() or not path.is_file():
        raise C7ControllerRootError("controller root must be a regular file")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise C7ControllerRootError("controller root is unreadable") from exc
    if len(raw) > MAX_CONTROLLER_ROOT_BYTES:
        raise C7ControllerRootError("controller root exceeds size bound")
    actual = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    if actual != expected_raw_digest:
        raise C7ControllerRootError("controller root raw digest mismatch")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise C7ControllerRootError("controller root contains duplicate key")
            result[key] = value
        return result

    try:
        parsed = json.loads(raw, object_pairs_hook=reject_duplicates)
    except C7ControllerRootError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise C7ControllerRootError("controller root is invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise C7ControllerRootError("controller root must be a JSON object")
    try:
        value = cast(dict[str, Any], parsed)
        if canonical_bytes(value) != raw:
            raise C7ControllerRootError("controller root is not canonical")
        root = C7ControllerRoot.model_validate(value)
    except C7ControllerRootError:
        raise
    except ValueError as exc:
        raise C7ControllerRootError("controller root schema validation failed") from exc
    if canonical_bytes(root.model_dump(mode="json")) != raw:
        raise C7ControllerRootError("controller root model is not canonical")
    return C7ControllerRootArtifact(root=root, raw_digest=actual, path=path)


__all__ = [
    "MAX_CONTROLLER_ROOT_BYTES",
    "MAX_CONTROLLER_ROOT_WINDOW_SECONDS",
    "C7ControllerRoot",
    "C7ControllerRootArtifact",
    "C7ControllerRootError",
    "load_controller_root",
]
