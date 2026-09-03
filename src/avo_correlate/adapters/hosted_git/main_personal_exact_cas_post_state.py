"""Read-only fixed-origin GitHub main post-state observation.

The adapter performs three bounded GETs (ref, exact commit, ref fence).  It
returns only a nonterminal topology observation and never constructs the
receipt-bound application post-state contract.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from datetime import datetime
from typing import cast

from avo_correlate.adapters.hosted_git.github import (
    GitHubRejected,
    GitHubTransportError,
    github_repository_digest,
)
from avo_correlate.adapters.hosted_git.github_transport import GitHubJsonTransport
from avo_correlate.contracts.main_personal_exact_cas import MainPersonalExactCasIntent
from avo_correlate.contracts.main_personal_exact_cas_post_state import (
    MainPersonalExactCasReadOnlyPostState,
)
from avo_correlate.domain.canonical import canonical_digest

_API_ORIGIN = "https://api.github.com"
_API_VERSION = "2022-11-28"
_TARGET_REF = "refs/heads/main"
_OWNER_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?$")
_REPO_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$")
_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class MainPersonalExactCasPostStateTransportError(RuntimeError):
    """Value-free read-only observation failure."""

    def __init__(self, code: str = "post_state_unresolved") -> None:
        self.code = (
            code
            if code in {"post_state_unresolved", "malformed_response"}
            else "post_state_unresolved"
        )
        super().__init__(self.code)

    def __repr__(self) -> str:
        return f"MainPersonalExactCasPostStateTransportError({self.code!r})"


class MainPersonalExactCasGitHubPostStateReader:
    """Constructor-pinned, no-redirect, read-only GitHub topology reader."""

    def __init__(
        self,
        *,
        owner: str,
        repo: str,
        repository_digest: str,
        token: str,
        trusted_clock: Callable[[], datetime],
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        if _OWNER_PATTERN.fullmatch(owner) is None or _REPO_PATTERN.fullmatch(repo) is None:
            raise ValueError("invalid GitHub repository binding")
        if repository_digest != github_repository_digest(owner, repo):
            raise ValueError("repository digest does not match pinned GitHub repository")
        if type(token) is not str or not token.strip():
            raise ValueError("authenticated read token is required")
        if (
            type(timeout_seconds) not in {int, float}
            or not math.isfinite(float(timeout_seconds))
            or timeout_seconds <= 0
            or timeout_seconds > 60
        ):
            raise ValueError("timeout must be between 0 and 60 seconds")
        if (
            type(max_response_bytes) is not int
            or max_response_bytes <= 0
            or max_response_bytes > _MAX_RESPONSE_BYTES
        ):
            raise ValueError("response bound must be positive")
        if not callable(trusted_clock):
            raise ValueError("trusted clock must be callable")
        self._owner = owner
        self._repo = repo
        self._repository_digest = repository_digest
        self._token = token
        self._clock = trusted_clock
        self._timeout = float(timeout_seconds)
        self._max_response_bytes = max_response_bytes
        self._transport = GitHubJsonTransport(
            origin=_API_ORIGIN,
            timeout_seconds=self._timeout,
            max_response_bytes=max_response_bytes,
        )

    def observe(self, intent: MainPersonalExactCasIntent) -> MainPersonalExactCasReadOnlyPostState:
        """Read ref, exact commit, and ref fence for one pinned operation."""

        if type(intent) is not MainPersonalExactCasIntent:
            raise TypeError("personal exact-CAS intent is required")
        validation_failed = False
        checked: MainPersonalExactCasIntent | None = None
        try:
            checked = MainPersonalExactCasIntent.model_validate(
                intent.model_dump(mode="json", warnings="error")
            )
            if (
                checked != intent
                or checked.target_ref != _TARGET_REF
                or checked.repository_digest != self._repository_digest
            ):
                raise ValueError("intent is not canonical exact main scope")
        except Exception:
            validation_failed = True
        if validation_failed or checked is None:
            raise MainPersonalExactCasPostStateTransportError()
        started = self._now()
        failure = False
        result: MainPersonalExactCasReadOnlyPostState | None = None
        try:
            ref_status, ref_body = self._get(
                f"/repos/{self._owner}/{self._repo}/git/ref/heads/main"
            )
            ref_sha, ref_digest = _parse_ref(ref_status, ref_body)
            commit_status, commit_body = self._get(
                f"/repos/{self._owner}/{self._repo}/git/commits/{ref_sha}"
            )
            commit_sha, tree_sha, parents, commit_digest = _parse_commit(
                commit_status, commit_body, ref_sha
            )
            fence_status, fence_body = self._get(
                f"/repos/{self._owner}/{self._repo}/git/ref/heads/main"
            )
            fence_sha, fence_digest = _parse_ref(fence_status, fence_body)
            if fence_sha != ref_sha or commit_sha != ref_sha:
                raise ValueError("main ref drifted during observation")
            finished = self._now()
            result = MainPersonalExactCasReadOnlyPostState.build(
                operation_id=checked.operation_id,
                intent_digest=checked.intent_digest,
                repository_digest=checked.repository_digest,
                owner=self._owner,
                repository=self._repo,
                target_ref=_TARGET_REF,
                observed_ref=_TARGET_REF,
                base_commit=checked.base_commit,
                candidate_commit=checked.candidate_commit,
                observed_commit=ref_sha,
                observed_tree=tree_sha,
                observed_parents=parents,
                response_ref_digest=ref_digest,
                response_commit_digest=commit_digest,
                response_fence_digest=fence_digest,
                source_digest=canonical_digest(
                    {"ref": ref_digest, "commit": commit_digest, "fence": fence_digest}
                ),
                started_at=started,
                finished_at=finished,
            )
        except MainPersonalExactCasPostStateTransportError:
            failure = True
        except (GitHubRejected, GitHubTransportError, ValueError, TypeError, KeyError):
            failure = True
        except Exception:
            failure = True
        if failure or result is None:
            raise MainPersonalExactCasPostStateTransportError()
        return result

    def _get(self, path: str) -> tuple[int, object]:
        url = _API_ORIGIN + path
        failure = False
        result: tuple[int, object] | None = None
        try:
            status, body = self._transport(
                "GET",
                url,
                None,
                {
                    "Accept": "application/vnd.github+json",
                    "Authorization": "Bearer " + self._token,
                    "X-GitHub-Api-Version": _API_VERSION,
                },
            )
            result = (status, body)
        except (GitHubRejected, GitHubTransportError):
            failure = True
        except Exception:
            failure = True
        if failure or result is None:
            raise MainPersonalExactCasPostStateTransportError()
        status, body = result
        if type(status) is not int or status != 200:
            raise MainPersonalExactCasPostStateTransportError()
        return status, body

    def _now(self) -> datetime:
        failure = False
        value: datetime | None = None
        try:
            candidate = self._clock()
            if (
                type(candidate) is not datetime
                or candidate.tzinfo is None
                or candidate.utcoffset() is None
            ):
                failure = True
            else:
                value = candidate
        except Exception:
            failure = True
        if failure or value is None:
            raise MainPersonalExactCasPostStateTransportError()
        return value


def _parse_ref(status: int, body: object) -> tuple[str, str]:
    if status != 200 or type(body) is not dict:
        raise ValueError("invalid ref response")
    typed_body = cast(dict[str, object], body)
    ref = typed_body.get("ref")
    obj = typed_body.get("object")
    typed_obj = cast(dict[str, object], obj) if type(obj) is dict else None
    if (
        ref != _TARGET_REF
        or typed_obj is None
        or typed_obj.get("type") != "commit"
        or type(typed_obj.get("sha")) is not str
        or _OBJECT_PATTERN.fullmatch(cast(str, typed_obj["sha"])) is None
    ):
        raise ValueError("invalid ref topology")
    return cast(str, typed_obj["sha"]), canonical_digest(typed_body)


def _parse_commit(
    status: int, body: object, expected_sha: str
) -> tuple[str, str, tuple[str, ...], str]:
    if status != 200 or type(body) is not dict:
        raise ValueError("invalid commit response")
    typed_body = cast(dict[str, object], body)
    sha = typed_body.get("sha")
    tree = typed_body.get("tree")
    parents = typed_body.get("parents")
    typed_tree = cast(dict[str, object], tree) if type(tree) is dict else None
    if (
        type(sha) is not str
        or sha != expected_sha
        or typed_tree is None
        or type(typed_tree.get("sha")) is not str
        or _OBJECT_PATTERN.fullmatch(cast(str, typed_tree["sha"])) is None
        or type(parents) is not list
    ):
        raise ValueError("invalid commit topology")
    parsed_parents: list[str] = []
    for parent in cast(list[object], parents):
        typed_parent = cast(dict[str, object], parent) if type(parent) is dict else None
        if (
            typed_parent is None
            or type(typed_parent.get("sha")) is not str
            or _OBJECT_PATTERN.fullmatch(cast(str, typed_parent["sha"])) is None
        ):
            raise ValueError("invalid parent topology")
        parsed_parents.append(cast(str, typed_parent["sha"]))
    return (
        sha,
        cast(str, typed_tree["sha"]),
        tuple(parsed_parents),
        canonical_digest(typed_body),
    )


__all__ = [
    "MainPersonalExactCasGitHubPostStateReader",
    "MainPersonalExactCasPostStateTransportError",
]
