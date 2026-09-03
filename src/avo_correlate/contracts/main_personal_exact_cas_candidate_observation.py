"""Non-authoritative hosted candidate observation contracts.

These records describe what a read-only observer saw.  They deliberately do
not describe publication, admission, readiness, completion, or mutation.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, Literal, Self, cast

from pydantic import Field, field_validator, model_validator

from avo_correlate.contracts.base import (
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.contracts.main_personal_exact_cas import GitObject
from avo_correlate.domain.canonical import canonical_digest

_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_OPERATION = re.compile(r"^sha256:[0-9a-f]{64}$")
_CANDIDATE = re.compile(r"^refs/heads/avo/candidate/[0-9a-f]{64}$")
_ZERO = "sha256:" + "0" * 64


def candidate_ref_for_operation(operation_id: str) -> str:
    """Return the only forward candidate namespace accepted by this leaf."""

    if type(operation_id) is not str or _OPERATION.fullmatch(operation_id) is None:
        raise ValueError("candidate operation ID is malformed")
    return "refs/heads/avo/candidate/" + operation_id.removeprefix("sha256:")


class MainPersonalExactCasCandidateObservationRequest(StrictModel):
    """Exact operation/repository/ref scope supplied to the observer."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    candidate_ref: NonEmptyString

    @model_validator(mode="after")
    def bind_scope(self) -> Self:
        if self.candidate_ref != candidate_ref_for_operation(self.operation_id):
            raise ValueError("candidate ref is not operation-derived")
        return self


class MainPersonalExactCasCandidatePolicyEvidence(StrictModel):
    """Static namespace policy facts, or a precise statement of why absent."""

    schema_version: Literal[1] = 1
    namespace: Literal["refs/heads/avo/candidate/*"]
    deletion_coverage: Literal["covered", "unverifiable"]
    force_update_coverage: Literal["covered", "unverifiable"]
    status: Literal["verified", "unverifiable"]
    ruleset_digest: Sha256Digest | None = None
    missing_prerequisite: NonEmptyString | None = None
    evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        covered = self.deletion_coverage == "covered" and self.force_update_coverage == "covered"
        if self.status == "verified" and not covered:
            raise ValueError("verified policy must cover deletion and force update")
        if self.status == "verified" and self.ruleset_digest is None:
            raise ValueError("verified policy requires ruleset evidence")
        if self.status == "unverifiable" and self.missing_prerequisite is None:
            raise ValueError("unverifiable policy requires missing prerequisite")
        if self.status == "unverifiable" and (
            self.deletion_coverage != "unverifiable"
            or self.force_update_coverage != "unverifiable"
            or self.ruleset_digest is not None
        ):
            raise ValueError("unverifiable policy cannot claim partial coverage")
        if self.status == "verified" and self.missing_prerequisite is not None:
            raise ValueError("verified policy cannot have a missing prerequisite")
        expected = canonical_digest(self.model_dump(exclude={"evidence_digest"}, mode="json"))
        if self.evidence_digest != expected:
            raise ValueError("candidate policy evidence digest mismatch")
        return self

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasCandidatePolicyEvidence:
        payload = dict(values)
        payload["evidence_digest"] = _ZERO
        probe = cast(Any, cls).model_construct(**payload)
        payload["evidence_digest"] = canonical_digest(
            probe.model_dump(exclude={"evidence_digest"}, mode="json")
        )
        return cls.model_validate(payload, strict=True)


class MainPersonalExactCasCandidateObservation(StrictModel):
    """A fenced, read-only candidate topology observation."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    owner: NonEmptyString
    owner_id: int = Field(gt=0)
    repository: NonEmptyString
    repository_id: int = Field(gt=0)
    candidate_ref: NonEmptyString
    candidate_commit: GitObject
    candidate_tree: GitObject
    candidate_parents: tuple[GitObject, ...]
    initial_ref_digest: Sha256Digest
    commit_digest: Sha256Digest
    final_ref_digest: Sha256Digest
    policy: MainPersonalExactCasCandidatePolicyEvidence
    started_at: datetime
    finished_at: datetime
    verification_status: Literal["observed"] = "observed"
    is_authoritative: Literal[False] = False
    readiness_authorized: Literal[False] = False
    is_terminal: Literal[False] = False
    completion_authorized: Literal[False] = False
    mutation_performed: Literal[False] = False
    deploy_performed: Literal[False] = False
    observation_digest: Sha256Digest

    _aware_started_at = field_validator("started_at")(require_aware_datetime)
    _aware_finished_at = field_validator("finished_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_observation(self) -> Self:
        if self.finished_at < self.started_at or self.finished_at - self.started_at > timedelta(
            minutes=5
        ):
            raise ValueError("candidate observation window is invalid")
        if self.candidate_ref != candidate_ref_for_operation(self.operation_id):
            raise ValueError("candidate ref is not operation-derived")
        if not _CANDIDATE.fullmatch(self.candidate_ref):
            raise ValueError("candidate ref is outside forward candidate namespace")
        for value in (self.candidate_commit, self.candidate_tree, *self.candidate_parents):
            if _OBJECT.fullmatch(value) is None:
                raise ValueError("candidate Git object is malformed")
        expected_commit = canonical_digest(
            {
                "commit": self.candidate_commit,
                "tree": self.candidate_tree,
                "parents": self.candidate_parents,
            }
        )
        if self.commit_digest != expected_commit:
            raise ValueError("candidate commit evidence digest mismatch")
        if self.initial_ref_digest != self.final_ref_digest:
            raise ValueError("candidate ref fence digests differ")
        if self.observation_digest != canonical_digest(
            self.model_dump(exclude={"observation_digest"}, mode="json")
        ):
            raise ValueError("candidate observation digest mismatch")
        return self

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasCandidateObservation:
        payload = dict(values)
        payload["observation_digest"] = _ZERO
        probe = cast(Any, cls).model_construct(**payload)
        payload["observation_digest"] = canonical_digest(
            probe.model_dump(exclude={"observation_digest"}, mode="json")
        )
        return cls.model_validate(payload, strict=True)


__all__ = [
    "MainPersonalExactCasCandidateObservation",
    "MainPersonalExactCasCandidateObservationRequest",
    "MainPersonalExactCasCandidatePolicyEvidence",
    "candidate_ref_for_operation",
]
