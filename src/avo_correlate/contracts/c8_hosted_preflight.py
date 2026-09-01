"""Non-authoritative, read-only C8 hosted preflight contracts.

These contracts intentionally describe configuration observations only.  They
cannot represent a pull request, check run, queue entry, hold, release,
authority, activation, or rollback proof.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictInt, model_validator

from avo_correlate.contracts.base import (
    NonEmptyString,
    Sha256Digest,
    StrictModel,
)
from avo_correlate.domain.canonical import canonical_digest

StrictPositiveInt = Annotated[StrictInt, Field(gt=0)]


class C8ObservationBinding(StrictModel):
    """Scope/freshness facts shared by every diagnostic observation."""

    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/main"] = "refs/heads/main"
    configuration_epoch: NonEmptyString
    source_observation_digest: Sha256Digest
    observed_at: datetime
    freshness_cutoff: datetime

    @model_validator(mode="after")
    def timestamps_and_freshness(self) -> C8ObservationBinding:
        if any(
            v.tzinfo is None or v.utcoffset() is None
            for v in (self.observed_at, self.freshness_cutoff)
        ):
            raise ValueError("observation timestamps must be timezone-aware")
        if self.observed_at < self.freshness_cutoff:
            raise ValueError("observation is stale")
        return self


class C8RepositoryRead(StrictModel):
    """Authenticated repository and immutable protected-main topology read."""

    binding: C8ObservationBinding | None = None
    owner: NonEmptyString
    repo: NonEmptyString
    owner_type: Literal["Organization", "User", "Bot", "Unknown"]
    main_commit: NonEmptyString
    main_tree: NonEmptyString
    main_parents: list[NonEmptyString] = Field(min_length=0)


class C8ProtectionRead(StrictModel):
    """Sanitized effective protection/ruleset configuration."""

    binding: C8ObservationBinding | None = None
    effective: StrictBool
    ruleset_ids: list[StrictPositiveInt] = Field(min_length=0)
    queue_required: StrictBool
    bypass_allowed: StrictBool
    direct_merge_allowed: StrictBool

    @model_validator(mode="after")
    def rulesets_are_canonical(self) -> C8ProtectionRead:
        if self.ruleset_ids != sorted(set(self.ruleset_ids)):
            raise ValueError("ruleset_ids must be sorted and unique")
        return self


class C8QueueConfigurationRead(StrictModel):
    """Merge-queue availability and configuration, without queue state."""

    binding: C8ObservationBinding | None = None
    available: StrictBool
    maximum_entries_to_merge: StrictPositiveInt | None = None
    maximum_entries_to_build: StrictPositiveInt | None = None
    merge_method: NonEmptyString | None = None
    merging_strategy: NonEmptyString | None = None


class C8WorkflowRead(StrictModel):
    """Workflow/event requirements derived from authenticated repository bytes."""

    binding: C8ObservationBinding | None = None
    path: NonEmptyString
    workflow_digest: Sha256Digest | None = None
    policy_digest: Sha256Digest | None = None
    validation_check_identity_digest: Sha256Digest | None = None
    # ``None`` means the adapter intentionally could not complete semantic
    # workflow analysis; it must never be interpreted as a negative assertion.
    pull_request_event: StrictBool | None
    merge_group_event: StrictBool | None
    exact_sha_checkout: StrictBool | None
    checkout_persist_credentials_false: StrictBool | None


class C8ValidationIdentityRead(StrictModel):
    """Validation identity observation; App 15368 is fixed by the contract."""

    binding: C8ObservationBinding | None = None
    app_id: Literal[15368] | None = None
    identity: NonEmptyString | None = None


class C8IsolatedIssuerRead(StrictModel):
    """Sanitized availability observation for the isolated release issuer.

    This is deliberately capability metadata only.  It contains no token,
    credential, check run, authorization, or transition payload.
    """

    binding: C8ObservationBinding | None = None
    available: StrictBool
    identity: NonEmptyString | None = None
    app_id: StrictPositiveInt | None = None
    isolation_digest: Sha256Digest | None = None

    @model_validator(mode="after")
    def require_identity_when_available(self) -> C8IsolatedIssuerRead:
        if self.available and (
            self.identity is None or self.app_id is None or self.isolation_digest is None
        ):
            raise ValueError("available issuer observation is incomplete")
        if self.app_id == 15368:
            raise ValueError("validation App 15368 cannot be the isolated release issuer")
        return self


class C8RollbackNamespaceRead(StrictModel):
    """Read-only controls observed for the rollback ref namespace."""

    binding: C8ObservationBinding | None = None
    namespace: NonEmptyString
    controller_exclusive_create_write: StrictBool = False
    controller_delete_authorized: StrictBool = False
    non_controller_create_denied: StrictBool = False
    non_controller_delete_denied: StrictBool = False
    bypass_allowed: StrictBool


class HostedC8PreflightReport(StrictModel):
    """Deterministic diagnostics that are never activation evidence."""

    schema_version: Literal[1] = 1
    result: Literal["blocked", "unverifiable", "no_detected_configuration_blocker"]
    passed_codes: list[NonEmptyString] = Field(min_length=0)
    blocker_codes: list[NonEmptyString] = Field(min_length=0)
    unverifiable_codes: list[NonEmptyString] = Field(min_length=0)
    observation_digests: dict[str, Sha256Digest] = Field(default_factory=dict)
    authority_consumable: Literal[False] = False
    authoritative: Literal[False] = False
    readiness_established: Literal[False] = False
    report_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_report(self) -> HostedC8PreflightReport:
        for values, label in (
            (self.passed_codes, "passed codes"),
            (self.blocker_codes, "blocker codes"),
            (self.unverifiable_codes, "unverifiable codes"),
        ):
            if values != sorted(set(values)):
                raise ValueError(f"{label} must be sorted and unique")
        expected_outcome = (
            "blocked"
            if self.blocker_codes
            else "unverifiable"
            if self.unverifiable_codes
            else "no_detected_configuration_blocker"
        )
        if self.result != expected_outcome:
            raise ValueError("preflight outcome does not match diagnostic codes")
        expected = canonical_digest(self.model_dump(exclude={"report_digest"}, mode="json"))
        if self.report_digest != expected:
            raise ValueError("preflight report digest mismatch")
        return self

    @classmethod
    def build(
        cls,
        *,
        passed_codes: list[str] | tuple[str, ...],
        blocker_codes: list[str] | tuple[str, ...],
        unverifiable_codes: list[str] | tuple[str, ...],
        observation_digests: dict[str, str],
    ) -> HostedC8PreflightReport:
        passed = sorted(set(passed_codes))
        blockers = sorted(set(blocker_codes))
        unverifiable = sorted(set(unverifiable_codes))
        result: Literal["blocked", "unverifiable", "no_detected_configuration_blocker"] = (
            "blocked"
            if blockers
            else "unverifiable"
            if unverifiable
            else "no_detected_configuration_blocker"
        )
        values = {
            "schema_version": 1,
            "result": result,
            "passed_codes": passed,
            "blocker_codes": blockers,
            "unverifiable_codes": unverifiable,
            "observation_digests": dict(sorted(observation_digests.items())),
            "authority_consumable": False,
            "authoritative": False,
            "readiness_established": False,
        }
        return cls.model_validate({**values, "report_digest": canonical_digest(values)})

    @property
    def outcome(self) -> Literal["blocked", "unverifiable", "no_detected_configuration_blocker"]:
        """Compatibility spelling; it is not serialized or authority-bearing."""
        return self.result


# The shorter name is useful to adapters and keeps callers independent of the
# report's hosted implementation detail.
C8HostedPreflightReport = HostedC8PreflightReport


__all__ = [
    "C8HostedPreflightReport",
    "C8IsolatedIssuerRead",
    "C8ObservationBinding",
    "C8ProtectionRead",
    "C8QueueConfigurationRead",
    "C8RepositoryRead",
    "C8RollbackNamespaceRead",
    "C8ValidationIdentityRead",
    "C8WorkflowRead",
    "HostedC8PreflightReport",
]
