"""Self-consistent, nonterminal read-only personal CAS post-state data."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal, cast

from pydantic import StringConstraints, field_validator, model_validator

from avo_correlate.contracts.base import Sha256Digest, StrictModel
from avo_correlate.contracts.main_personal_exact_cas import GitObject, MainRef
from avo_correlate.domain.canonical import canonical_digest

GitHubOwner = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?$")
]
GitHubRepository = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$")
]


def _aware(value: datetime) -> datetime:
    if type(value) is not datetime:
        raise ValueError("post-state timestamp must be timezone-aware")
    failed = False
    try:
        tzinfo = value.tzinfo
        offset = value.utcoffset()
    except Exception:
        failed = True
        tzinfo = None
        offset = None
    if failed or tzinfo is None or offset is None:
        raise ValueError("post-state timestamp must be timezone-aware")
    return value


class MainPersonalExactCasReadOnlyPostState(StrictModel):
    """Three-read exact topology observation; never a receipt or authority."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    intent_digest: Sha256Digest
    repository_digest: Sha256Digest
    owner: GitHubOwner
    repository: GitHubRepository
    target_ref: MainRef = "refs/heads/main"
    observed_ref: MainRef = "refs/heads/main"
    base_commit: GitObject
    candidate_commit: GitObject
    observed_commit: GitObject
    observed_tree: GitObject
    observed_parents: tuple[GitObject, ...]
    response_ref_digest: Sha256Digest
    response_commit_digest: Sha256Digest
    response_fence_digest: Sha256Digest
    source_digest: Sha256Digest
    started_at: datetime
    finished_at: datetime
    is_terminal: Literal[False] = False
    is_authoritative: Literal[False] = False
    observation_digest: Sha256Digest

    _aware_started_at = field_validator("started_at")(_aware)
    _aware_finished_at = field_validator("finished_at")(_aware)

    @model_validator(mode="after")
    def validate_observation(self) -> MainPersonalExactCasReadOnlyPostState:
        if self.target_ref != "refs/heads/main" or self.observed_ref != self.target_ref:
            raise ValueError("post-state target is not exact main")
        if self.started_at > self.finished_at:
            raise ValueError("post-state timestamps are not ordered")
        if self.source_digest != canonical_digest(
            {
                "ref": self.response_ref_digest,
                "commit": self.response_commit_digest,
                "fence": self.response_fence_digest,
            }
        ):
            raise ValueError("post-state source digest mismatch")
        if self.observation_digest != canonical_digest(
            self.model_dump(exclude={"observation_digest"}, mode="json")
        ):
            raise ValueError("post-state observation digest mismatch")
        return self

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasReadOnlyPostState:
        zero = "sha256:" + "0" * 64
        source = canonical_digest(
            {
                "ref": values["response_ref_digest"],
                "commit": values["response_commit_digest"],
                "fence": values["response_fence_digest"],
            }
        )
        values = dict(values, source_digest=source, observation_digest=zero)
        probe = cast(Any, cls).model_construct(**values)
        digest = canonical_digest(probe.model_dump(exclude={"observation_digest"}, mode="json"))
        return cast(
            MainPersonalExactCasReadOnlyPostState,
            cls.model_validate({**values, "observation_digest": digest}),
        )


__all__ = [
    "GitHubOwner",
    "GitHubRepository",
    "MainPersonalExactCasReadOnlyPostState",
]
