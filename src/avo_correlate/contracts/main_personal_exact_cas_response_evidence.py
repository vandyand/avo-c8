"""Nonterminal durable response evidence for personal main exact-CAS.

This contract records only a sanitized provider response and its request scope.
It is intentionally not a receipt, authority decision, or controller state.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Literal, cast

from pydantic import (
    Field,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)

from avo_correlate.contracts.base import ArtifactRef, NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.contracts.main_personal_exact_cas import GitObject, MainRef
from avo_correlate.domain.canonical import canonical_digest

MainPersonalExactCasResponseClassification = Literal[
    "candidate_response",
    "conflict_or_rejected",
    "configuration_or_validation_rejected",
    "authentication_or_authorization_rejected",
    "rate_limited",
    "ambiguous",
    "unverifiable",
]
SanitizedRequestId = Annotated[str, StringConstraints(min_length=1, max_length=256)]
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_UNSIGNED_INTEGER_PATTERN = re.compile(r"^[0-9]{1,20}$")
_RESOURCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_PAYLOAD_ROLE = "main-personal-exact-cas-response"
_PAYLOAD_MEDIA_TYPE = "application/vnd.avo.main-personal-exact-cas-response+json"
_ALLOWED_METADATA = frozenset(
    {
        "retry-after",
        "x-github-request-id",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "x-ratelimit-resource",
    }
)


def main_personal_exact_cas_request_digest(
    *, repository_digest: str, target_ref: str, candidate_commit: str
) -> Sha256Digest:
    """Digest the only request shape admitted by the personal CAS transport."""

    return canonical_digest(
        {
            "repository_digest": repository_digest,
            "target_ref": target_ref,
            "method": "PATCH",
            "candidate_sha": candidate_commit,
            "force": False,
        }
    )


def _classification_for_status(status: int) -> MainPersonalExactCasResponseClassification:
    if status == 200:
        return "candidate_response"
    if status == 409:
        return "conflict_or_rejected"
    if status == 422:
        return "configuration_or_validation_rejected"
    if status in {401, 403}:
        return "authentication_or_authorization_rejected"
    if status == 429:
        return "rate_limited"
    if 500 <= status <= 599:
        return "ambiguous"
    return "unverifiable"


def _aware(value: datetime) -> datetime:
    if type(value) is not datetime:
        raise ValueError("timestamp must be timezone-aware")
    failed = False
    tzinfo = None
    offset = None
    try:
        tzinfo = value.tzinfo
        offset = value.utcoffset()
    except Exception:
        failed = True
    if failed or tzinfo is None or offset is None:
        raise ValueError("timestamp must be timezone-aware")
    return value


def _request_id(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str or _REQUEST_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("request ID is not sanitized")
    return value


def _metadata(value: object) -> dict[str, str]:
    if type(value) is not dict:
        raise ValueError("response metadata is not sanitized")
    raw = cast(dict[object, object], value)
    for key, item in raw.items():
        if type(key) is not str or type(item) is not str:
            raise ValueError("response metadata is not sanitized")
        if (
            not key
            or key.lower() != key
            or key not in _ALLOWED_METADATA
            or len(key) > 128
            or len(item) > 2048
            or any(ord(char) < 0x20 or ord(char) > 0x7E for char in key)
            or any(ord(char) < 0x20 or ord(char) > 0x7E for char in item)
        ):
            raise ValueError("response metadata is not sanitized")
        if key == "x-github-request-id":
            valid = _REQUEST_ID_PATTERN.fullmatch(item) is not None
        elif key == "x-ratelimit-resource":
            valid = _RESOURCE_PATTERN.fullmatch(item) is not None
        else:
            valid = _UNSIGNED_INTEGER_PATTERN.fullmatch(item) is not None
        if not valid:
            raise ValueError("response metadata is not sanitized")
    return cast(dict[str, str], raw)


class MainPersonalExactCasResponseEvidence(StrictModel):
    """Restart-safe sanitized evidence; never terminal or authoritative."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"
    writer_app_id: StrictInt = Field(gt=0)
    writer_installation_id: StrictInt = Field(gt=0)
    writer_identity: NonEmptyString
    intent_digest: Sha256Digest
    dispatch_marker_digest: Sha256Digest
    candidate_commit: GitObject
    request_digest: Sha256Digest
    response_status: StrictInt = Field(ge=100, le=599)
    response_classification: MainPersonalExactCasResponseClassification
    response_request_id: SanitizedRequestId | None = None
    response_metadata: dict[str, str]
    response_metadata_digest: Sha256Digest
    response_payload_artifact: ArtifactRef
    observed_at: datetime
    is_terminal: Literal[False] = False
    is_authoritative: Literal[False] = False
    evidence_digest: Sha256Digest

    _aware_observed_at = field_validator("observed_at")(_aware)
    _strict_request_id = field_validator("response_request_id", mode="before")(_request_id)
    _strict_metadata = field_validator("response_metadata", mode="before")(_metadata)

    @model_validator(mode="after")
    def validate_evidence(self) -> MainPersonalExactCasResponseEvidence:
        if self.target_ref != "refs/heads/main":
            raise ValueError("response evidence target is not exact main")
        if any(
            type(key) is not str
            or key.lower() != key
            or key not in _ALLOWED_METADATA
            or type(value) is not str
            for key, value in self.response_metadata.items()
        ):
            raise ValueError("response metadata is not sanitized")
        if self.response_request_id != self.response_metadata.get("x-github-request-id"):
            raise ValueError("response request ID binding differs")
        if self.response_classification != _classification_for_status(self.response_status):
            raise ValueError("response status classification mismatch")
        if self.response_metadata_digest != canonical_digest(self.response_metadata):
            raise ValueError("response metadata digest mismatch")
        if self.request_digest != main_personal_exact_cas_request_digest(
            repository_digest=self.repository_digest,
            target_ref=self.target_ref,
            candidate_commit=self.candidate_commit,
        ):
            raise ValueError("response evidence request digest mismatch")
        if (
            self.response_payload_artifact.role != _PAYLOAD_ROLE
            or self.response_payload_artifact.media_type != _PAYLOAD_MEDIA_TYPE
            or self.response_payload_artifact.created_at != self.observed_at
        ):
            raise ValueError("response evidence payload artifact is not exact")
        if self.evidence_digest != canonical_digest(
            self.model_dump(exclude={"evidence_digest"}, mode="json")
        ):
            raise ValueError("response evidence digest mismatch")
        return self

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasResponseEvidence:
        values["evidence_digest"] = "sha256:" + "0" * 64
        probe = cast(
            MainPersonalExactCasResponseEvidence,
            cast(Any, cls).model_construct(**values),
        )
        values["evidence_digest"] = canonical_digest(
            probe.model_dump(exclude={"evidence_digest"}, mode="json")
        )
        return cast(MainPersonalExactCasResponseEvidence, cls.model_validate(values))


__all__ = [
    "MainPersonalExactCasResponseClassification",
    "MainPersonalExactCasResponseEvidence",
    "SanitizedRequestId",
    "main_personal_exact_cas_request_digest",
]
