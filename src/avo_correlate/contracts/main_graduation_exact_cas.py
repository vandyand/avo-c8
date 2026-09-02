"""Strict contracts for the personal C8 exact-CAS main-ref boundary.

This is intentionally a small, capability-specific protocol.  It describes a
single compare-and-swap of ``refs/heads/main`` from an observed commit ``B``
to a pre-built candidate commit ``C``.  It is not a generic ref writer and it
does not contain a force, delete, merge, or retry capability.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    AliasChoices,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)

from avo_correlate.contracts.base import (
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.domain.canonical import canonical_digest

GitObject = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")] 
MainRef = Literal["refs/heads/main"]
CandidateRef = Annotated[str, StringConstraints(pattern=r"^refs/heads/avo/candidate/[0-9a-f]{64}$")]
SanitizedRequestId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$",
    ),
]
type JsonPrimitive = str | int | float | bool | None
type JsonValue = JsonPrimitive | list[JsonValue] | dict[str, JsonValue]

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


def _sanitize_request_id(value: object) -> str:
    if not isinstance(value, str) or _REQUEST_ID_PATTERN.fullmatch(value) is None:
        raise ValueError("request ID is not sanitized")
    return value


def _sanitize_optional_request_id(value: object) -> str | None:
    if value is None:
        return None
    return _sanitize_request_id(value)
ExactCasOutcome = Literal["applied", "rejected", "ambiguous"]
ExactCasErrorCode = Literal[
    "cas_conflict", "auth_failed", "protection_failed", "configuration_failed",
    "rate_limited", "lease_expired", "verifier_rejected", "malformed_response",
    "stale_response", "server_ambiguous", "transport_ambiguous",
    "reconciliation_unverified",
]


def _aware(value: datetime) -> datetime:
    return require_aware_datetime(value)


def exact_cas_operation_id(
    *,
    repository_digest: str,
    target_ref: str,
    base_commit: str,
    base_tree: str,
    candidate_commit: str,
    candidate_tree: str,
    candidate_ref: str,
    candidate_parents: tuple[str, ...],
    protection_ruleset_digest: str,
    writer_app_id: int,
    writer_installation_id: int,
    writer_identity: str,
    lease_identity: str,
    lease_digest: str,
    lease_expires_at: datetime,
    claim_nonce: str,
    raw_request_digest: str,
) -> Sha256Digest:
    """Derive the stable operation identity from every CAS input binding."""

    return canonical_digest(
        {
            "repository_digest": repository_digest,
            "target_ref": target_ref,
            "base_commit": base_commit,
            "base_tree": base_tree,
            "candidate_commit": candidate_commit,
            "candidate_tree": candidate_tree,
            "candidate_ref": candidate_ref,
            "candidate_parents": list(candidate_parents),
            "protection_ruleset_digest": protection_ruleset_digest,
            "writer_app_id": writer_app_id,
            "writer_installation_id": writer_installation_id,
            "writer_identity": writer_identity,
            "lease_identity": lease_identity,
            "lease_digest": lease_digest,
            "lease_expires_at": lease_expires_at.isoformat(),
            "claim_nonce": claim_nonce,
            "raw_request_digest": raw_request_digest,
        }
    )


def exact_cas_claim_digest(
    *,
    operation_id: str,
    lease_identity: str,
    lease_digest: str,
    lease_expires_at: datetime,
    claim_nonce: str,
) -> Sha256Digest:
    """Derive the immutable one-use claim from its operation and lease fence."""

    return canonical_digest(
        {
            "operation_id": operation_id,
            "lease_identity": lease_identity,
            "lease_digest": lease_digest,
            "lease_expires_at": lease_expires_at.isoformat(),
            "claim_nonce": claim_nonce,
            "one_use": True,
        }
    )


def exact_cas_raw_request_digest(
    *, repository_digest: str, target_ref: str, candidate_commit: str
) -> Sha256Digest:
    """Derive the digest of the only request this capability may emit."""

    return canonical_digest(
        {
            "repository_digest": repository_digest,
            "target_ref": target_ref,
            "method": "PATCH",
            "candidate_sha": candidate_commit,
            "force": False,
        }
    )


class MainExactCasBinding(StrictModel):
    """Common immutable scope and authority facts for all exact-CAS records."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"
    base_commit: GitObject = Field(
        validation_alias=AliasChoices("base_commit", "expected_base_commit")
    )
    base_tree: GitObject = Field(
        validation_alias=AliasChoices("base_tree", "expected_base_tree")
    )
    candidate_commit: GitObject = Field(
        validation_alias=AliasChoices(
            "candidate_commit", "candidate_sha", "expected_candidate_commit"
        )
    )
    candidate_tree: GitObject = Field(
        validation_alias=AliasChoices("candidate_tree", "expected_candidate_tree")
    )
    candidate_ref: CandidateRef = Field(
        validation_alias=AliasChoices(
            "candidate_ref", "immutable_candidate_ref", "candidate_head_ref"
        )
    )
    candidate_parents: tuple[GitObject, ...] = Field(
        validation_alias=AliasChoices(
            "candidate_parents", "parents", "candidate_parent_commits"
        )
    )
    candidate_ref_immutable: StrictBool = Field(
        True, validation_alias=AliasChoices("candidate_ref_immutable", "immutable_candidate")
    )
    candidate_reachable: StrictBool = Field(
        True, validation_alias=AliasChoices("candidate_reachable", "candidate_ref_reachable")
    )
    protection_ruleset_digest: Sha256Digest = Field(
        validation_alias=AliasChoices(
            "protection_ruleset_digest",
            "ruleset_digest",
            "protection_digest",
            "protection_evidence_digest",
        )
    )
    writer_app_id: StrictInt = Field(
        gt=0, validation_alias=AliasChoices("writer_app_id", "app_id")
    )
    writer_installation_id: StrictInt = Field(
        gt=0,
        validation_alias=AliasChoices("writer_installation_id", "installation_id", "install_id"),
    )
    writer_identity: NonEmptyString = Field(
        validation_alias=AliasChoices(
            "writer_identity", "install_identity", "writer_app_install_identity"
        )
    )
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    lease_expires_at: datetime = Field(
        validation_alias=AliasChoices("lease_expires_at", "expires_at", "lease_expiry")
    )
    claim_nonce: NonEmptyString = Field(validation_alias=AliasChoices("claim_nonce", "nonce"))
    one_use: Literal[True] = True
    claim_digest: Sha256Digest = Field(
        validation_alias=AliasChoices("claim_digest", "one_use_claim_digest")
    )
    raw_request_digest: Sha256Digest = Field(
        validation_alias=AliasChoices("raw_request_digest", "request_digest")
    )
    deploy_performed: Literal[False] = False

    _aware_lease_expires_at = field_validator("lease_expires_at")(_aware)

    @model_validator(mode="after")
    def validate_binding(self) -> MainExactCasBinding:
        if self.candidate_parents != (self.base_commit,):
            raise ValueError("exact-CAS candidate must have exactly base commit as its sole parent")
        if not self.candidate_ref_immutable:
            raise ValueError("candidate ref must be immutable")
        if not self.candidate_reachable:
            raise ValueError("candidate ref must be reachable")
        if self.claim_digest != exact_cas_claim_digest(
            operation_id=self.operation_id,
            lease_identity=self.lease_identity,
            lease_digest=self.lease_digest,
            lease_expires_at=self.lease_expires_at,
            claim_nonce=self.claim_nonce,
        ):
            raise ValueError("exact-CAS one-use claim digest mismatch")
        if self.raw_request_digest != exact_cas_raw_request_digest(
            repository_digest=self.repository_digest,
            target_ref=self.target_ref,
            candidate_commit=self.candidate_commit,
        ):
            raise ValueError("exact-CAS raw request digest mismatch")
        if self.operation_id != exact_cas_operation_id(
            repository_digest=self.repository_digest,
            target_ref=self.target_ref,
            base_commit=self.base_commit,
            base_tree=self.base_tree,
            candidate_commit=self.candidate_commit,
            candidate_tree=self.candidate_tree,
            candidate_ref=self.candidate_ref,
            candidate_parents=self.candidate_parents,
            protection_ruleset_digest=self.protection_ruleset_digest,
            writer_app_id=self.writer_app_id,
            writer_installation_id=self.writer_installation_id,
            writer_identity=self.writer_identity,
            lease_identity=self.lease_identity,
            lease_digest=self.lease_digest,
            lease_expires_at=self.lease_expires_at,
            claim_nonce=self.claim_nonce,
            raw_request_digest=self.raw_request_digest,
        ):
            raise ValueError("exact-CAS operation ID mismatch")
        return self


class MainExactCasAuthorization(MainExactCasBinding):
    """Controller-issued authorization for one personal exact-CAS attempt."""

    authorized_at: datetime
    authorization_digest: Sha256Digest

    _aware_authorized_at = field_validator("authorized_at")(_aware)

    @model_validator(mode="after")
    def validate_authorization(self) -> MainExactCasAuthorization:
        if self.lease_expires_at <= self.authorized_at:
            raise ValueError("authorization must be issued before lease expiry")
        if self.authorization_digest != canonical_digest(
            self.model_dump(exclude={"authorization_digest"}, mode="json")
        ):
            raise ValueError("exact-CAS authorization digest mismatch")
        return self


class MainExactCasIntent(MainExactCasBinding):
    """Intent recorded immediately before the sole PATCH dispatch."""

    authorization_digest: Sha256Digest
    recorded_at: datetime
    intent_digest: Sha256Digest

    _aware_recorded_at = field_validator("recorded_at")(_aware)

    @model_validator(mode="after")
    def validate_intent(self) -> MainExactCasIntent:
        if self.lease_expires_at <= self.recorded_at:
            raise ValueError("intent must be recorded before lease expiry")
        if self.intent_digest != canonical_digest(
            self.model_dump(exclude={"intent_digest"}, mode="json")
        ):
            raise ValueError("exact-CAS intent digest mismatch")
        return self


class MainExactCasReceipt(MainExactCasBinding):
    """Immutable result of the one PATCH attempt; ambiguity is never success."""

    authorization_digest: Sha256Digest
    intent_digest: Sha256Digest
    response_digest: Sha256Digest
    http_status: StrictInt | None = Field(default=None, ge=100, le=599)
    request_id: SanitizedRequestId | None = None
    observed_at: datetime
    outcome: ExactCasOutcome
    dispatch_started: StrictBool
    response_ref: MainRef | None = None
    response_sha: GitObject | None = None
    error_code: ExactCasErrorCode | None = None
    receipt_digest: Sha256Digest

    _aware_observed_at = field_validator("observed_at")(_aware)
    _strict_request_id = field_validator("request_id", mode="before")(
        _sanitize_optional_request_id
    )

    @model_validator(mode="after")
    def validate_receipt(self) -> MainExactCasReceipt:
        if (self.http_status is None) != (self.request_id is None):
            raise ValueError("delivered exact-CAS responses require a sanitized request ID")
        if self.outcome == "applied":
            if not self.dispatch_started or self.http_status != 200:
                raise ValueError("applied exact-CAS receipt requires one dispatched HTTP 200")
            if self.response_ref != self.target_ref or self.response_sha != self.candidate_commit:
                raise ValueError("applied response is not the exact main ref and candidate SHA")
            if self.error_code is not None:
                raise ValueError("applied receipt cannot contain an error")
        elif self.outcome == "ambiguous":
            if self.response_ref is not None or self.response_sha is not None:
                raise ValueError("ambiguous receipt cannot claim an authoritative response")
            if self.error_code is None:
                raise ValueError("ambiguous receipt requires an allowlisted error code")
        elif self.response_ref is not None or self.response_sha is not None:
            raise ValueError("rejected receipt cannot contain a successful response")
        if self.outcome == "rejected" and self.error_code is None:
            raise ValueError("rejected receipt requires an allowlisted error code")
        if self.receipt_digest != canonical_digest(
            self.model_dump(exclude={"receipt_digest"}, mode="json")
        ):
            raise ValueError("exact-CAS receipt digest mismatch")
        return self


class MainExactCasTransportResponse(StrictModel):
    """Sanitized, parsed result delivered by the one exact-CAS transport call."""

    schema_version: Literal[1] = 1
    http_status: StrictInt = Field(ge=100, le=599)
    payload: JsonValue
    request_id: SanitizedRequestId

    _strict_request_id = field_validator("request_id", mode="before")(_sanitize_request_id)


class MainExactCasPostStateObservation(MainExactCasBinding):
    """Read-after-write proof of exact main topology."""

    authorization_digest: Sha256Digest
    intent_digest: Sha256Digest
    receipt_digest: Sha256Digest
    receipt_outcome: ExactCasOutcome
    observed_ref: MainRef
    observed_commit: GitObject
    observed_tree: GitObject
    observed_parents: tuple[GitObject, ...]
    observed_at: datetime
    observation_digest: Sha256Digest

    _aware_observed_at = field_validator("observed_at")(_aware)

    @model_validator(mode="after")
    def validate_post_state(self) -> MainExactCasPostStateObservation:
        if self.receipt_outcome == "applied":
            if (
                self.observed_ref != self.target_ref
                or self.observed_commit != self.candidate_commit
                or self.observed_tree != self.candidate_tree
                or self.observed_parents != (self.base_commit,)
            ):
                raise ValueError("applied post-state is not the exact candidate topology")
        elif (
            self.observed_commit == self.candidate_commit
            and self.observed_tree == self.candidate_tree
        ):
            raise ValueError("rejected or ambiguous receipt cannot self-validate as applied")
        if self.observation_digest != canonical_digest(
            self.model_dump(exclude={"observation_digest"}, mode="json")
        ):
            raise ValueError("exact-CAS post-state observation digest mismatch")
        return self


class MainExactCasTopologyObservation(StrictModel):
    """Authenticated read-only exact B-to-C topology used for reconciliation."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"
    observed_ref: MainRef = "refs/heads/main"
    base_commit: GitObject
    base_tree: GitObject
    candidate_commit: GitObject
    candidate_tree: GitObject
    observed_commit: GitObject
    observed_tree: GitObject
    observed_parents: tuple[GitObject, ...]
    observed_at: datetime
    observation_digest: Sha256Digest

    _aware_observed_at = field_validator("observed_at")(_aware)

    @model_validator(mode="after")
    def validate_observation(self) -> MainExactCasTopologyObservation:
        if self.observed_ref != self.target_ref:
            raise ValueError("topology observation ref does not match exact main ref")
        if (
            self.observed_commit == self.candidate_commit
            and self.observed_tree == self.candidate_tree
            and self.observed_parents != (self.base_commit,)
        ):
            raise ValueError("observed applied topology must have base as sole parent")
        if self.observation_digest != canonical_digest(
            self.model_dump(exclude={"observation_digest"}, mode="json")
        ):
            raise ValueError("exact-CAS topology observation digest mismatch")
        return self


class MainExactCasReconciliation(StrictModel):
    """Durable reconciliation result that retains the original ambiguity."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    ambiguous_receipt: MainExactCasReceipt
    observation: MainExactCasTopologyObservation
    outcome: Literal["applied", "ambiguous"]
    reconciled_at: datetime
    reconciliation_digest: Sha256Digest

    _aware_reconciled_at = field_validator("reconciled_at")(_aware)

    @model_validator(mode="after")
    def validate_reconciliation(self) -> MainExactCasReconciliation:
        if self.ambiguous_receipt.outcome != "ambiguous":
            raise ValueError("reconciliation must preserve an ambiguous receipt")
        if self.operation_id != self.ambiguous_receipt.operation_id:
            raise ValueError("reconciliation operation binding mismatch")
        if self.observation.operation_id != self.operation_id:
            raise ValueError("reconciliation observation binding mismatch")
        for field_name in (
            "repository_digest",
            "target_ref",
            "base_commit",
            "base_tree",
            "candidate_commit",
            "candidate_tree",
        ):
            if getattr(self.observation, field_name) != getattr(
                self.ambiguous_receipt, field_name
            ):
                raise ValueError("reconciliation observation scope mismatch")
        exact = (
            self.observation.observed_ref == self.observation.target_ref
            and
            self.observation.observed_commit == self.observation.candidate_commit
            and self.observation.observed_tree == self.observation.candidate_tree
            and self.observation.observed_parents == (self.observation.base_commit,)
        )
        if self.outcome == "applied" and not exact:
            raise ValueError("applied reconciliation lacks exact B-to-C topology")
        if self.reconciliation_digest != canonical_digest(
            self.model_dump(exclude={"reconciliation_digest"}, mode="json")
        ):
            raise ValueError("exact-CAS reconciliation digest mismatch")
        return self

__all__ = [
    "CandidateRef",
    "ExactCasErrorCode",
    "ExactCasOutcome",
    "JsonValue",
    "MainExactCasAuthorization",
    "MainExactCasBinding",
    "MainExactCasIntent",
    "MainExactCasPostStateObservation",
    "MainExactCasReceipt",
    "MainExactCasReconciliation",
    "MainExactCasTopologyObservation",
    "MainExactCasTransportResponse",
    "SanitizedRequestId",
    "exact_cas_claim_digest",
    "exact_cas_operation_id",
    "exact_cas_raw_request_digest",
]
