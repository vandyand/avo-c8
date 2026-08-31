"""Capability-separated GitHub executor for C4 main graduation.

This module deliberately does not share a mutation client with the ordinary
GitHub integration provider.  Every mutating capability receives its own
transport and principal binding and the only mutations exposed here are the
five C4 operations (candidate ref, PR, queue admission, checks, and release
check).  In particular, there is no ref update or merge operation for main.
"""
# pyright: reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownParameterType=false, reportUnknownLambdaType=false, reportUnnecessaryIsInstance=false, reportAttributeAccessIssue=false, reportOptionalMemberAccess=false, reportUnnecessaryComparison=false, reportCallIssue=false

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast
from urllib.parse import quote

from avo_correlate.adapters.hosted_git.github import (
    GitHubRejected,
    GitHubTransportError,
    JsonBody,
    JsonObject,
    JsonValue,
    github_repository_digest,
)
from avo_correlate.application.c4_capabilities import (
    AdmissionIssueRequest,
    AdmissionIssueResult,
    AdmissionObservationRequest,
    AdmissionObservationResult,
    CandidateObservationRequest,
    CandidateObservationResult,
    CandidatePublicationRequest,
    CandidatePublicationResult,
    GroupHoldIssueRequest,
    GroupHoldIssueResult,
    GroupHoldObservationRequest,
    GroupHoldObservationResult,
    PullRequestCreateRequest,
    PullRequestCreateResult,
    PullRequestLookupRequest,
    PullRequestObservationRequest,
    PullRequestObservationResult,
    PullRequestReconcileRequest,
    QueueEnqueueRequest,
    QueueEnqueueResult,
    QueueObservationRequest,
    QueueObservationResult,
    ReleaseIssueRequest,
    ReleaseIssueResult,
    ReleaseObservationRequest,
    ReleaseObservationResult,
)
from avo_correlate.contracts.main_graduation import MainQueueConfigurationObservation
from avo_correlate.contracts.main_graduation_phase_a import main_stage_nonce
from avo_correlate.domain.canonical import canonical_digest

_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CANDIDATE = re.compile(r"^refs/heads/avo/candidate/[0-9a-f]{64}$")
_URL = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/pull/([1-9][0-9]*)$")
_REPOSITORY_COMPONENT = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")

# This query and mutation are intentionally pinned strings.  A REST merge (or
# an invented queue endpoint) is not an equivalent operation on GitHub.
_QUEUE_QUERY = """
query AvoMainGraduationQueue($owner: String!, $name: String!, $branch: String!) {
  repository(owner: $owner, name: $name) {
    mergeQueue(branch: $branch) {
      id
      configuration {
        maximumEntriesToBuild
        maximumEntriesToMerge
        mergeMethod
        mergingStrategy
      }
      entries(first: 100) {
        totalCount
        nodes {
          id
          position
          state
          solo
          pullRequest { number }
          baseCommit { oid }
          headCommit { oid }
        }
      }
    }
  }
}
"""
_QUEUE_MUTATION = """
mutation AvoMainGraduationEnqueue($pullRequestId: ID!, $expectedHeadOid: GitObjectID!) {
  enqueuePullRequest(input: {pullRequestId: $pullRequestId, expectedHeadOid: $expectedHeadOid}) {
    mergeQueueEntry { id }
  }
}
"""


class GitHubMainGraduationError(RuntimeError):
    """A malformed, stale, or non-authoritative GitHub result."""


class GitHubMainGraduationRejected(GitHubMainGraduationError):
    """An authoritative precondition or 4xx rejection."""


class GitHubMainGraduationAmbiguous(GitHubMainGraduationError):
    """A call crossed the transport boundary without an authoritative result."""


def _repository_binding(owner: object, repo: object) -> tuple[str, str]:
    if (
        not isinstance(owner, str)
        or not isinstance(repo, str)
        or _REPOSITORY_COMPONENT.fullmatch(owner) is None
        or _REPOSITORY_COMPONENT.fullmatch(repo) is None
    ):
        raise ValueError("invalid GitHub repository binding")
    return owner, repo


class GraduationTransport(Protocol):
    def __call__(
        self, method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]: ...


@dataclass(frozen=True, slots=True)
class GitHubPrincipalBinding:
    """Non-secret identity attached to one isolated credential binding."""

    identity: str
    app_id: int
    isolation_digest: str
    token: str

    def __post_init__(self) -> None:
        if not self.identity.strip() or isinstance(self.app_id, bool) or self.app_id <= 0:
            raise ValueError("principal identity and positive app ID are required")
        if not _DIGEST.fullmatch(self.isolation_digest):
            raise ValueError("principal isolation must be a sha256 digest")
        if not self.token or not self.token.strip():
            raise ValueError("principal requires an authenticated credential")


# Short name useful to callers that model principals as credentials.
GitHubCredentialBinding = GitHubPrincipalBinding


def _obj(value: JsonValue, context: str) -> JsonObject:
    if not isinstance(value, dict):
        raise GitHubMainGraduationError(f"malformed {context}")
    return value


def _str(value: JsonObject, key: str, context: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item or "\x00" in item:
        raise GitHubMainGraduationError(f"malformed {context}: missing {key}")
    return item


def _int(value: JsonObject, key: str, context: str) -> int:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int):
        raise GitHubMainGraduationError(f"malformed {context}: missing {key}")
    return item


def _git(value: str, context: str) -> str:
    if not _OBJECT.fullmatch(value):
        raise GitHubMainGraduationError(f"malformed {context}")
    return value


def _nested(value: JsonObject, key: str, context: str) -> JsonObject:
    return _obj(value.get(key), f"{context}.{key}")


def _stable_observation(value: JsonValue) -> JsonValue:
    """Match the protected-main configuration projection exactly."""
    if isinstance(value, list):
        return [_stable_observation(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _stable_observation(item)
            for key, item in value.items()
            if key.casefold() not in {"observed_at", "updated_at", "created_at", "timestamp"}
        }
    return value


class _Precondition(GitHubMainGraduationRejected):
    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class GitHubMainGraduationAdapter:
    """GitHub implementation of the finalized C4 capability protocols."""

    def __init__(
        self,
        owner: str,
        repo: str,
        repository_digest: str,
        *,
        source_publisher_transport: GraduationTransport,
        source_publisher_principal: GitHubPrincipalBinding,
        preparation_transport: GraduationTransport,
        preparation_principal: GitHubPrincipalBinding,
        admission_issuer_transport: GraduationTransport,
        admission_issuer_principal: GitHubPrincipalBinding,
        group_hold_issuer_transport: GraduationTransport,
        group_hold_issuer_principal: GitHubPrincipalBinding,
        release_issuer_transport: GraduationTransport,
        release_issuer_principal: GitHubPrincipalBinding,
        observer_transport: GraduationTransport | None = None,
        observer_principal: GitHubPrincipalBinding | None = None,
        read_only_observer: Any | None = None,
        mutation_authorize: Callable[[ReleaseIssueRequest], None],
        trusted_clock: Callable[[], datetime],
        release_freshness_cutoff: Callable[[ReleaseIssueRequest], datetime],
        admission_request: Callable[[str], AdmissionIssueRequest],
        admission_freshness_cutoff: Callable[[Any], datetime],
        trusted_check_contexts: tuple[str, ...],
        validation_app_id: int = 15368,
        provider_identity: str = "github-protected-main",
        api_base: str = "https://api.github.com",
        provider_api_version: str = "2022-11-28",
    ) -> None:
        owner, repo = _repository_binding(owner, repo)
        if repository_digest != github_repository_digest(owner, repo):
            raise ValueError("repository digest does not match GitHub repository")
        if not _DIGEST.fullmatch(repository_digest):
            raise ValueError("repository digest is malformed")
        if not api_base.startswith("https://"):
            raise ValueError("GitHub API base must use HTTPS")
        transports = (
            source_publisher_transport,
            preparation_transport,
            admission_issuer_transport,
            group_hold_issuer_transport,
            release_issuer_transport,
        )
        if len({id(item) for item in transports}) != len(transports):
            raise ValueError("each mutation capability requires a distinct transport")
        if observer_transport is not None and id(observer_transport) in {
            id(item) for item in transports
        }:
            raise ValueError("read-only observer requires a distinct transport")
        principals = (
            source_publisher_principal,
            preparation_principal,
            admission_issuer_principal,
            group_hold_issuer_principal,
            release_issuer_principal,
        )
        if len({id(item) for item in principals}) != len(principals):
            raise ValueError("each capability requires a distinct principal binding")
        issuers = (
            admission_issuer_principal,
            group_hold_issuer_principal,
            release_issuer_principal,
        )
        issuer_identity = (issuers[0].identity, issuers[0].app_id, issuers[0].isolation_digest)
        if any((p.identity, p.app_id, p.isolation_digest) != issuer_identity for p in issuers):
            raise ValueError("admission, hold, and release issuer identity is inconsistent")
        if issuers[0].app_id == 15368:
            raise ValueError("validation App 15368 cannot issue C4 authority")
        if observer_transport is None or observer_principal is None:
            raise ValueError("release-capable adapter requires observer transport and principal")
        if read_only_observer is not None:
            raise ValueError("injected observer cannot replace authoritative GitHub reads")
        if not callable(mutation_authorize):
            raise ValueError("release-capable adapter requires a mutation authorization callback")
        if (
            not callable(trusted_clock)
            or not callable(release_freshness_cutoff)
            or not callable(admission_request)
            or not callable(admission_freshness_cutoff)
        ):
            raise ValueError("release admission freshness requires controller-bound callbacks")
        if (
            validation_app_id != 15368
            or not trusted_check_contexts
            or len(set(trusted_check_contexts)) != len(trusted_check_contexts)
            or any(not item or item == "avo-main-release" for item in trusted_check_contexts)
            or not provider_identity.strip()
        ):
            raise ValueError("protected-main check configuration is invalid")
        if observer_principal is not None and id(observer_principal) in {id(p) for p in principals}:
            raise ValueError("observer requires a distinct principal binding")
        self._owner, self._repo = owner, repo
        self.repository_digest = repository_digest
        self.api_base = api_base.rstrip("/")
        self.provider_api_version = provider_api_version
        self._transports = {
            "source": source_publisher_transport,
            "preparation": preparation_transport,
            "admission": admission_issuer_transport,
            "hold": group_hold_issuer_transport,
            "release": release_issuer_transport,
        }
        self._principals: dict[str, GitHubPrincipalBinding | None] = {
            "source": source_publisher_principal,
            "preparation": preparation_principal,
            "admission": admission_issuer_principal,
            "hold": group_hold_issuer_principal,
            "release": release_issuer_principal,
            "observer": observer_principal,
        }
        # Keep the observer in a read-only map: observation paths must never
        # accidentally borrow a preparation or issuer credential.
        self._read_only_transports = (
            {"observer": observer_transport} if observer_transport is not None else {}
        )
        self._observer = read_only_observer
        self._mutation_authorize = mutation_authorize
        self._trusted_clock = trusted_clock
        self._release_freshness_cutoff = release_freshness_cutoff
        self._admission_request = admission_request
        self._admission_freshness_cutoff = admission_freshness_cutoff
        self.trusted_check_contexts = trusted_check_contexts
        self.validation_app_id = validation_app_id
        self.provider_identity = provider_identity

    @property
    def owner(self) -> str:
        return self._owner

    @property
    def repo(self) -> str:
        return self._repo

    @property
    def repository_name(self) -> str:
        """The immutable owner/repository identity used by the coordinator."""
        return f"{self.owner}/{self.repo}"

    @property
    def repository_url(self) -> str:
        """The canonical HTTPS URL for this repository (without a suffix)."""
        return f"https://github.com/{self.repository_name}"

    @property
    def repository_path(self) -> str:
        return f"/repos/{quote(self.owner, safe='')}/{quote(self.repo, safe='')}"

    @staticmethod
    def _expected_nonce(external_identity: str) -> str:
        return main_stage_nonce(external_identity)

    def _headers(
        self, principal: GitHubPrincipalBinding, *, graphql: bool = False
    ) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.provider_api_version,
            "Authorization": "Bearer " + principal.token,
        }
        if graphql:
            headers["Content-Type"] = "application/json"
        return headers

    @staticmethod
    def _validate_request(request: Any, expected: type[Any], repository: str) -> Any:
        if not isinstance(request, expected):
            raise ValueError(f"expected {expected.__name__}")
        # Reparsing closes the model_construct escape hatch before a call.
        checked = expected.model_validate(request.model_dump())
        if checked.repository_digest != repository or checked.target_ref != "refs/heads/main":
            raise ValueError("request is not bound to this protected main repository")
        return checked

    def _result(
        self,
        cls: type[Any],
        request: Any,
        *,
        outcome: str,
        response: Any,
        dispatch: bool,
        extra: Mapping[str, Any] | None = None,
    ) -> Any:
        values = request.model_dump()
        if extra:
            values.update(extra)
        values.update(
            outcome=outcome,
            response_digest=canonical_digest(response),
            observed_at=datetime.now(UTC),
            dispatch_started=dispatch,
        )
        return cls.build(**values)

    def _invoke(
        self,
        role: str,
        method: str,
        path: str,
        body: JsonBody | None,
        request: Any,
        result_cls: type[Any],
        parser: Callable[[JsonValue], Any],
        result_fields: Callable[[Any], Mapping[str, Any]] | None = None,
    ) -> Any:
        transport = self._transports[role]
        principal = cast(GitHubPrincipalBinding, self._principals[role])
        try:
            status, payload = transport(
                method,
                self.api_base + path,
                body,
                self._headers(principal, graphql=path == "/graphql"),
            )
        except GitHubRejected as exc:
            status = getattr(exc, "status", None)
            if isinstance(status, int) and 400 <= status < 500:
                return self._result(
                    result_cls, request, outcome="rejected", response=str(exc), dispatch=False
                )
            return self._result(
                result_cls, request, outcome="ambiguous", response=str(exc), dispatch=True
            )
        except GitHubTransportError as exc:
            return self._result(
                result_cls, request, outcome="ambiguous", response=str(exc), dispatch=True
            )
        except Exception as exc:
            return self._result(
                result_cls, request, outcome="ambiguous", response=str(exc), dispatch=True
            )
        if not isinstance(status, int):
            return self._result(
                result_cls, request, outcome="ambiguous", response=payload, dispatch=True
            )
        if 400 <= status < 500:
            return self._result(
                result_cls, request, outcome="rejected", response=payload, dispatch=False
            )
        if status >= 500 or status < 200 or status >= 300:
            return self._result(
                result_cls, request, outcome="ambiguous", response=payload, dispatch=True
            )
        try:
            response = parser(payload)
        except Exception as exc:
            return self._result(
                result_cls, request, outcome="ambiguous", response=str(exc), dispatch=True
            )
        extra = result_fields(response) if result_fields is not None else None
        return self._result(
            result_cls, request, outcome="applied", response=response, dispatch=True, extra=extra
        )

    def _post(
        self,
        role: str,
        request: Any,
        result_cls: type[Any],
        path: str,
        body: JsonBody,
        parser: Callable[[JsonValue], Any],
        result_fields: Callable[[Any], Mapping[str, Any]] | None = None,
    ) -> Any:
        return self._invoke(role, "POST", path, body, request, result_cls, parser, result_fields)

    def _read(self, role: str, method: str, path: str, body: JsonBody | None = None) -> JsonValue:
        principal = cast(GitHubPrincipalBinding, self._principals[role])
        transport = self._read_only_transports.get(role, self._transports.get(role))
        if transport is None:
            raise GitHubMainGraduationError("read capability transport is unavailable")
        try:
            status, payload = transport(
                method,
                self.api_base + path,
                body,
                self._headers(principal, graphql=path == "/graphql"),
            )
        except GitHubRejected as exc:
            status = exc.status
            if isinstance(status, int) and 400 <= status < 500:
                # Callers may treat a 404 as exact-object absence only; all
                # other 4xx values remain authoritative provider rejection.
                raise _Precondition(str(exc), status=status) from exc
            raise GitHubMainGraduationAmbiguous(
                "GitHub observation rejection was malformed"
            ) from exc
        except GitHubTransportError as exc:
            raise GitHubMainGraduationAmbiguous("GitHub observation transport failed") from exc
        except Exception as exc:
            raise GitHubMainGraduationAmbiguous("GitHub observation transport failed") from exc
        if not isinstance(status, int):
            raise GitHubMainGraduationAmbiguous("GitHub observation status was malformed")
        if 400 <= status < 500:
            raise _Precondition(f"GitHub rejected observation ({status})", status=status)
        if status < 200 or status >= 300:
            raise GitHubMainGraduationAmbiguous("GitHub observation was not authoritative")
        return payload

    def publish_candidate(self, request: CandidatePublicationRequest) -> CandidatePublicationResult:
        request = self._validate_request(
            request, CandidatePublicationRequest, self.repository_digest
        )
        if not _CANDIDATE.fullmatch(request.candidate_ref):
            raise ValueError("candidate ref is not an exact operation ref")
        # Reconcile the exact operation ref before attempting creation.  A
        # non-404 response is never treated as absence and therefore cannot
        # turn an existing wrong-object ref into an overwrite attempt.
        candidate_path = (
            self.repository_path
            + "/git/ref/heads/"
            + quote(request.candidate_ref.removeprefix("refs/heads/"), safe="")
        )
        try:
            existing = _obj(self._read("source", "GET", candidate_path), "candidate ref")
        except _Precondition as exc:
            if exc.status == 404:
                existing = None
            else:
                return cast(
                    CandidatePublicationResult,
                    self._result(
                        CandidatePublicationResult,
                        request,
                        outcome="rejected",
                        response=str(exc),
                        dispatch=False,
                    ),
                )
        else:
            obj = _nested(existing, "object", "candidate ref")
            if (
                existing.get("ref") != request.candidate_ref
                or obj.get("type") != "commit"
                or obj.get("sha") != request.candidate_commit
            ):
                raise _Precondition("existing candidate ref differs")
            return cast(
                CandidatePublicationResult,
                self._result(
                    CandidatePublicationResult,
                    request,
                    outcome="already_applied",
                    response=existing,
                    dispatch=True,
                ),
            )
        body: JsonBody = {"ref": request.candidate_ref, "sha": request.candidate_commit}

        def parse(value: JsonValue) -> JsonObject:
            raw = _obj(value, "candidate ref")
            if _str(raw, "ref", "candidate ref") != request.candidate_ref:
                raise _Precondition("candidate ref response differs")
            obj = _nested(raw, "object", "candidate ref")
            if (
                _str(obj, "type", "candidate ref object") != "commit"
                or _git(_str(obj, "sha", "candidate ref object"), "candidate SHA")
                != request.candidate_commit
            ):
                raise _Precondition("candidate commit response differs")
            return raw

        return cast(
            CandidatePublicationResult,
            self._post(
                "source",
                request,
                CandidatePublicationResult,
                self.repository_path + "/git/refs",
                body,
                parse,
            ),
        )

    def _read_commit(
        self,
        role: str,
        sha: str,
        *,
        expected_tree: str | None = None,
        expected_parents: list[str] | tuple[str, ...] | None = None,
    ) -> tuple[str, str, tuple[str, ...]]:
        raw = _obj(
            self._read(role, "GET", self.repository_path + "/git/commits/" + sha),
            "commit",
        )
        actual = _git(_str(raw, "sha", "commit"), "commit SHA")
        tree = _git(_str(_nested(raw, "tree", "commit"), "sha", "commit tree"), "commit tree")
        parents_raw = raw.get("parents")
        if not isinstance(parents_raw, list) or any(not isinstance(p, dict) for p in parents_raw):
            raise GitHubMainGraduationError("malformed commit parents")
        parents = tuple(
            _git(_str(cast(JsonObject, p), "sha", "commit parent"), "commit parent")
            for p in parents_raw
        )
        if actual != sha or (expected_tree is not None and tree != expected_tree):
            raise _Precondition("authoritative commit differs")
        if expected_parents is not None and parents != tuple(expected_parents):
            raise _Precondition("authoritative commit parents differ")
        return actual, tree, parents

    def _authoritative_pr(
        self,
        role: str,
        number: int,
        *,
        candidate_ref: str,
        head_commit: str,
        head_tree: str,
        base_commit: str,
        base_tree: str,
    ) -> dict[str, Any]:
        parsed = self._parse_pr(
            self._read(role, "GET", self.repository_path + f"/pulls/{number}"), number
        )
        if (
            parsed["head_ref"] != candidate_ref
            or parsed["head_commit"] != head_commit
            or parsed["base_commit"] != base_commit
            or parsed["state"] != "open"
            or parsed["draft"]
            or parsed["merged"] is not False
            or parsed["head_commit"] == parsed["base_commit"]
        ):
            raise _Precondition("pull request is not the exact open non-draft candidate")
        self._read_commit(role, head_commit, expected_tree=head_tree)
        self._read_commit(role, base_commit, expected_tree=base_tree)
        return parsed

    def _authoritative_protection(
        self, role: str, *, queue_configuration: JsonObject | None = None
    ) -> tuple[str, str]:
        """Return a digest of the active, no-bypass main queue protection.

        GitHub's GraphQL queue configuration is not itself an authorization
        policy.  Bind it to the effective ruleset GitHub says applies to
        ``main`` and to branch protection before using it in queue generation.
        """
        raw = _obj(
            self._read(role, "GET", self.repository_path + "/branches/main/protection"),
            "main protection",
        )
        required = _nested(raw, "required_status_checks", "main protection")
        contexts = required.get("contexts")
        checks = required.get("checks")
        if not isinstance(contexts, list) or any(not isinstance(item, str) for item in contexts):
            raise GitHubMainGraduationError("main protection contexts are malformed")
        if not isinstance(checks, list) or any(not isinstance(item, dict) for item in checks):
            raise GitHubMainGraduationError("main protection checks are malformed")
        principal = cast(GitHubPrincipalBinding, self._principals["release"])
        check_objects = cast(list[JsonObject], checks)
        expected_contexts = {*self.trusted_check_contexts, "avo-main-release"}
        expected_apps = {
            **{context: self.validation_app_id for context in self.trusted_check_contexts},
            "avo-main-release": principal.app_id,
        }
        check_apps: dict[str, int] = {}
        for item in check_objects:
            context = _str(item, "context", "main protection check")
            app_id = _int(item, "app_id", "main protection check")
            if context in check_apps:
                raise _Precondition("main protection check context is duplicated")
            check_apps[context] = app_id
        if len(contexts) != len(expected_contexts) or set(contexts) != expected_contexts:
            raise _Precondition("main protection required contexts differ")
        if check_apps != expected_apps:
            raise _Precondition("main protection check issuer bindings differ")
        for key in ("allow_force_pushes", "allow_deletions"):
            if raw.get(key) is True:
                raise _Precondition("main protection permits unsafe mutation")
        effective = self._read(role, "GET", self.repository_path + "/rules/branches/main")
        if not isinstance(effective, list) or not effective:
            raise _Precondition("active effective main rules are missing")
        resolved: dict[tuple[str, str, int], JsonObject] = {}
        merge_rules: list[JsonObject] = []
        for value in effective:
            rule = _obj(value, "effective main rule")
            source_type = _str(rule, "ruleset_source_type", "effective main rule")
            source = _str(rule, "ruleset_source", "effective main rule")
            ident = _int(rule, "ruleset_id", "effective main rule")
            if ident <= 0:
                raise GitHubMainGraduationError("effective main rule ID is malformed")
            key = (source_type.casefold(), source.casefold(), ident)
            if key in resolved:
                continue
            if source_type.casefold() == "organization":
                path = f"/orgs/{quote(source, safe='')}/rulesets/{ident}"
            elif source_type.casefold() == "repository":
                path = self.repository_path + f"/rulesets/{ident}"
            else:
                raise _Precondition("effective main rule source is unsupported")
            full = _obj(self._read(role, "GET", path), "main ruleset")
            if (
                _int(full, "id", "main ruleset") != ident
                or not _str(full, "name", "main ruleset")
                or _str(full, "source_type", "main ruleset").casefold()
                != source_type.casefold()
                or _str(full, "source", "main ruleset").casefold() != source.casefold()
                or _str(full, "target", "main ruleset") != "branch"
                or _str(full, "enforcement", "main ruleset").casefold() != "active"
            ):
                raise _Precondition("effective main ruleset identity or state differs")
            bypass = full.get("bypass_actors")
            if not isinstance(bypass, list) or bypass:
                raise _Precondition("main ruleset permits bypass actors")
            rules = full.get("rules")
            if not isinstance(rules, list) or any(not isinstance(item, dict) for item in rules):
                raise GitHubMainGraduationError("main ruleset rules are malformed")
            resolved[key] = full
            for full_rule in cast(list[JsonObject], rules):
                if _str(full_rule, "type", "main ruleset rule") == "merge_queue":
                    merge_rules.append(_nested(full_rule, "parameters", "merge queue rule"))
        if len(merge_rules) != 1:
            raise _Precondition("active effective merge_queue rule is missing or conflicting")
        config = queue_configuration
        if config is None:
            raise GitHubMainGraduationError("queue configuration is required for protection")
        parameters = merge_rules[0]
        if (
            _int(parameters, "max_entries_to_merge", "merge queue rule")
            != _int(config, "maximumEntriesToMerge", "merge queue configuration")
            or _str(parameters, "merge_method", "merge queue rule").casefold()
            != _str(config, "mergeMethod", "merge queue configuration").casefold()
            or _str(parameters, "grouping_strategy", "merge queue rule").casefold()
            != _str(config, "mergingStrategy", "merge queue configuration").casefold()
        ):
            raise _Precondition("effective merge_queue rule differs from queue configuration")
        normalized = [
            {
                key: value
                for key, value in ruleset.items()
                if key
                in {
                    "id",
                    "name",
                    "source_type",
                    "source",
                    "target",
                    "enforcement",
                    "conditions",
                    "rules",
                    "bypass_actors",
                }
            }
            for ruleset in resolved.values()
        ]
        ruleset_epoch = canonical_digest(
            {"rulesets": normalized, "graphql_queue_configuration": config}
        )
        protection_epoch = canonical_digest(
            {
                "branch_protection": _stable_observation(raw),
                "ruleset_epoch": ruleset_epoch,
            }
        )
        manifest = canonical_digest(
            {
                "repository_digest": self.repository_digest,
                "target_ref": "refs/heads/main",
                "operation_id": canonical_digest(
                    {
                        "repository_digest": self.repository_digest,
                        "protection_epoch": protection_epoch,
                    }
                ),
                "provider_identity": self.provider_identity,
                "provider_api_version": self.provider_api_version,
                "required": True,
                "queue_required": True,
                "max_entries_per_group": 1,
                "bypass_allowed": False,
                "direct_merge_allowed": False,
                "isolated_release_issuer": principal.identity,
                "release_issuer_app_id": principal.app_id,
                "issuer_isolation_digest": principal.isolation_digest,
                "validation_app_id": self.validation_app_id,
                "release_context": "avo-main-release",
                "protection_epoch": protection_epoch,
            }
        )
        return manifest, protection_epoch

    def _authoritative_queue(
        self, role: str, request: Any, *, require_entry: bool = True
    ) -> JsonObject:
        state = self._queue_state(
            role,
            request.pull_request_number,
            request.pull_request_head,
            request.base_commit,
            request.base_tree,
            require_entry=require_entry,
        )
        if not require_entry and state.get("state") != "empty":
            raise _Precondition("pre-enqueue queue must be empty")
        expected_generation = getattr(request, "queue_generation_digest", None)
        observed_generation = state.get("queue_generation_digest")
        if expected_generation is not None and observed_generation != expected_generation:
            raise _Precondition("queue generation differs from authorization")
        expected_configuration = getattr(request, "queue_configuration_digest", None)
        observed_configuration = state.get("queue_configuration_digest")
        if expected_configuration is not None and (
            not isinstance(expected_configuration, str)
            or not _DIGEST.fullmatch(expected_configuration)
            or observed_configuration != expected_configuration
        ):
            raise _Precondition("queue configuration differs from authorization")
        return state

    def _authoritative_group(self, role: str, request: Any) -> JsonObject:
        self._authoritative_pr(
            role,
            request.pull_request_number,
            candidate_ref=request.candidate_ref
            if hasattr(request, "candidate_ref")
            else "refs/heads/avo/candidate/" + request.operation_id.removeprefix("sha256:"),
            head_commit=request.pull_request_head,
            head_tree=request.pull_request_tree,
            base_commit=request.base_commit,
            base_tree=request.base_tree,
        )
        self._read_commit(
            role,
            request.group_sha,
            expected_tree=request.group_tree,
            expected_parents=request.expected_group_parents,
        )
        return self._authoritative_queue(role, request)

    def _parse_pr(self, value: JsonValue, number: int | None = None) -> dict[str, Any]:
        raw = _obj(value, "pull request")
        n = _int(raw, "number", "pull request")
        if number is not None and n != number:
            raise _Precondition("pull request number differs")
        url = _str(raw, "html_url", "pull request")
        match = _URL.fullmatch(url)
        if match is None or url != f"{self.repository_url}/pull/{n}":
            raise _Precondition("foreign or malformed pull request URL")
        base, head = _nested(raw, "base", "pull request"), _nested(raw, "head", "pull request")
        base_repo, head_repo = (
            _nested(base, "repo", "pull request base"),
            _nested(head, "repo", "pull request head"),
        )
        expected_repo = self.repository_name
        if (
            _str(base_repo, "full_name", "pull request base repo") != expected_repo
            or _str(head_repo, "full_name", "pull request head repo") != expected_repo
        ):
            raise _Precondition("foreign pull request")
        base_ref, head_ref = (
            _str(base, "ref", "pull request base"),
            _str(head, "ref", "pull request head"),
        )
        if base_ref not in {"main", "refs/heads/main"} or not _CANDIDATE.fullmatch(
            head_ref if head_ref.startswith("refs/") else "refs/heads/" + head_ref
        ):
            raise _Precondition("pull request ref is outside exact target")
        base_sha, head_sha = (
            _git(_str(base, "sha", "pull request base"), "base SHA"),
            _git(_str(head, "sha", "pull request head"), "head SHA"),
        )
        state = _str(raw, "state", "pull request")
        draft = raw.get("draft")
        merged = raw.get("merged")
        if not isinstance(draft, bool) or not isinstance(merged, bool):
            raise GitHubMainGraduationError("malformed pull request draft or merged flag")
        return {
            "number": n,
            "url": url,
            "base_commit": base_sha,
            "head_commit": head_sha,
            "base_ref": "refs/heads/main",
            "head_ref": head_ref if head_ref.startswith("refs/") else "refs/heads/" + head_ref,
            "state": state,
            "draft": draft,
            "merged": merged,
            "node_id": raw.get("node_id"),
        }

    def _pr_result_values(
        self, request: PullRequestCreateRequest, parsed: Mapping[str, Any]
    ) -> dict[str, Any]:
        # Candidate/base trees are supplied by the signed request; GitHub's PR
        # response is trusted only for exact PR identity and commit topology.
        return {
            "pull_request_number": parsed["number"],
            "pull_request_url": parsed["url"],
            "pull_request_identity": canonical_digest(
                {
                    "operation_id": request.operation_id,
                    "repository_digest": request.repository_digest,
                    "pull_request_number": parsed["number"],
                    "pull_request_url": parsed["url"],
                }
            ),
        }

    def create_pull_request(self, request: PullRequestCreateRequest) -> PullRequestCreateResult:
        request = self._validate_request(request, PullRequestCreateRequest, self.repository_digest)
        branch = request.candidate_ref.removeprefix("refs/heads/")
        items: list[JsonValue] = []
        for page in range(1, 101):
            search = self._read(
                "preparation",
                "GET",
                self.repository_path
                + "/pulls?state=all&head="
                + quote(self.owner + ":" + branch, safe="")
                + f"&base=main&per_page=100&page={page}",
            )
            page_items = (
                search
                if isinstance(search, list)
                else _obj(search, "pull request search").get("items", [])
            )
            if not isinstance(page_items, list):
                raise GitHubMainGraduationAmbiguous("malformed pull request search")
            items.extend(page_items)
            if len(page_items) < 100:
                break
        else:
            raise GitHubMainGraduationAmbiguous("pull request search exceeded bounds")
        exact: list[dict[str, Any]] = []
        for item in items:
            parsed = self._parse_pr(item)
            if (
                parsed["head_commit"] == request.candidate_commit
                and parsed["base_commit"] == request.base_commit
            ):
                exact.append(parsed)
            elif (
                parsed["head_ref"] == request.candidate_ref
                or parsed["base_ref"] == "refs/heads/main"
            ):
                raise _Precondition("foreign or conflicting pull request")
        if len({item["number"] for item in exact}) != len(exact):
            raise _Precondition("pull request search contains duplicate identities")
        if len(exact) > 1:
            raise _Precondition("ambiguous pull request identity")
        if exact:
            exact[0] = self._authoritative_pr(
                "preparation",
                exact[0]["number"],
                candidate_ref=request.candidate_ref,
                head_commit=request.candidate_commit,
                head_tree=request.candidate_tree,
                base_commit=request.base_commit,
                base_tree=request.base_tree,
            )
            values = request.model_dump()
            values.update(self._pr_result_values(request, exact[0]))
            return PullRequestCreateResult.build(
                **values,
                outcome="already_applied",
                response_digest=canonical_digest(exact[0]),
                observed_at=datetime.now(UTC),
                # A prior authoritative mutation may have crossed the
                # boundary; ``already_applied`` cannot claim a rejected/no-
                # dispatch state under StageMutationResult semantics.
                dispatch_started=True,
            )
        body: JsonBody = {
            "title": "AVO main graduation " + request.operation_id,
            "head": branch,
            "base": "main",
            "body": "AVO operation " + request.operation_id,
        }

        def parse(value: JsonValue) -> dict[str, Any]:
            parsed = self._parse_pr(value)
            if (
                parsed["head_ref"] != request.candidate_ref
                or parsed["head_commit"] != request.candidate_commit
                or parsed["base_commit"] != request.base_commit
            ):
                raise _Precondition("created pull request identity differs")
            return self._authoritative_pr(
                "preparation",
                parsed["number"],
                candidate_ref=request.candidate_ref,
                head_commit=request.candidate_commit,
                head_tree=request.candidate_tree,
                base_commit=request.base_commit,
                base_tree=request.base_tree,
            )

        return cast(
            PullRequestCreateResult,
            self._post(
                "preparation",
                request,
                PullRequestCreateResult,
                self.repository_path + "/pulls",
                body,
                parse,
                lambda parsed: self._pr_result_values(request, parsed),
            ),
        )

    def reconcile_pull_request(
        self, request: PullRequestReconcileRequest
    ) -> PullRequestObservationResult:
        request = self._validate_request(
            request, PullRequestReconcileRequest, self.repository_digest
        )
        if request.repository_name != self.repository_name:
            raise ValueError("pull request repository binding differs")
        parsed = self._authoritative_pr(
            "observer" if self._read_only_transports else "preparation",
            request.pull_request_number,
            candidate_ref=request.candidate_ref,
            head_commit=request.head_commit,
            head_tree=request.head_tree,
            base_commit=request.base_commit,
            base_tree=request.base_tree,
        )
        values = request.model_dump()
        values.pop("repository_name", None)
        values["object_id"] = request.repository_name + ":pull/" + str(request.pull_request_number)
        values.update(
            outcome="observed",
            evidence_digest=canonical_digest(parsed),
            observed_at=datetime.now(UTC),
        )
        return PullRequestObservationResult.build(**values)

    def lookup_pull_request(
        self, request: PullRequestLookupRequest
    ) -> PullRequestObservationResult:
        """Find the unique PR for an exact operation-derived candidate.

        Search results are paginated to completion.  A missing, malformed, or
        conflicting result is never treated as a successful lookup, and more
        than one exact identity fails closed as ambiguous.
        """

        request = self._validate_request(request, PullRequestLookupRequest, self.repository_digest)
        branch = request.candidate_ref.removeprefix("refs/heads/")
        role = "observer" if self._read_only_transports else "preparation"
        items: list[JsonValue] = []
        for page in range(1, 101):
            raw = self._read(
                role,
                "GET",
                self.repository_path
                + "/pulls?state=all&head="
                + quote(self.owner + ":" + branch, safe="")
                + f"&base=main&per_page=100&page={page}",
            )
            page_items = (
                raw
                if isinstance(raw, list)
                else _obj(raw, "pull request search").get("items", [])
            )
            if not isinstance(page_items, list):
                raise GitHubMainGraduationAmbiguous("malformed pull request search")
            items.extend(page_items)
            if len(page_items) < 100:
                break
        else:
            raise GitHubMainGraduationAmbiguous("pull request search exceeded bounds")

        exact: list[dict[str, Any]] = []
        for item in items:
            parsed = self._parse_pr(item)
            if parsed["head_ref"] != request.candidate_ref:
                raise _Precondition("pull request search returned a foreign head ref")
            if parsed["base_commit"] != request.base_commit:
                raise _Precondition("pull request search returned a foreign base")
            if parsed["head_commit"] == request.candidate_commit:
                exact.append(parsed)
            else:
                raise _Precondition("pull request search returned a conflicting candidate")
        if len({item["number"] for item in exact}) != len(exact):
            raise _Precondition("pull request search contains duplicate identities")
        if len(exact) != 1:
            raise _Precondition("pull request lookup is missing or ambiguous")

        parsed = self._authoritative_pr(
            role,
            exact[0]["number"],
            candidate_ref=request.candidate_ref,
            head_commit=request.candidate_commit,
            head_tree=request.candidate_tree,
            base_commit=request.base_commit,
            base_tree=request.base_tree,
        )
        values = {
            "operation_id": request.operation_id,
            "repository_digest": request.repository_digest,
            "target_ref": request.target_ref,
            "lease_epoch_digest": request.lease_epoch_digest,
            "stage": "pull_request_open",
            "object_id": parsed["url"],
            "pull_request_number": parsed["number"],
            "candidate_ref": request.candidate_ref,
            "head_commit": request.candidate_commit,
            "head_tree": request.candidate_tree,
            "base_commit": request.base_commit,
            "base_tree": request.base_tree,
            "outcome": "observed",
            "evidence_digest": canonical_digest(parsed),
            "observed_at": datetime.now(UTC),
        }
        return PullRequestObservationResult.build(**values)

    # Compatibility spelling used by recovery callers.
    find_pull_request = lookup_pull_request

    def _graphql(self, role: str, query: str, variables: JsonObject) -> JsonObject:
        payload = self._read(role, "POST", "/graphql", {"query": query, "variables": variables})
        raw = _obj(payload, "GraphQL response")
        errors = raw.get("errors")
        if errors is not None and (not isinstance(errors, list) or errors):
            raise _Precondition("GitHub GraphQL operation failed")
        return _obj(raw.get("data"), "GraphQL data")

    def enqueue(self, request: QueueEnqueueRequest) -> QueueEnqueueResult:
        request = self._validate_request(request, QueueEnqueueRequest, self.repository_digest)
        parsed = self._authoritative_pr(
            "preparation",
            request.pull_request_number,
            candidate_ref="refs/heads/avo/candidate/"
            + request.operation_id.removeprefix("sha256:"),
            head_commit=request.pull_request_head,
            head_tree=request.pull_request_tree,
            base_commit=request.base_commit,
            base_tree=request.base_tree,
        )
        if (
            parsed["url"] != request.pull_request_url
            or parsed["head_commit"] != request.pull_request_head
            or parsed["base_commit"] != request.base_commit
        ):
            raise _Precondition("queue pull request identity differs")
        node_id = parsed.get("node_id")
        if not isinstance(node_id, str) or not node_id:
            raise _Precondition("pull request node identity is unavailable")
        # The queue configuration is a pre-enqueue fence.  It must be read
        # while empty and match the durable configuration digest bound by the
        # admission and enqueue requests.
        self._authoritative_queue("preparation", request, require_entry=False)
        self._authoritative_admission("preparation", request)
        try:
            data = self._graphql(
                "preparation",
                _QUEUE_MUTATION,
                {
                    "pullRequestId": node_id,
                    "expectedHeadOid": request.pull_request_head,
                },
            )
        except _Precondition as exc:
            return cast(
                QueueEnqueueResult,
                self._result(
                    QueueEnqueueResult,
                    request,
                    outcome="rejected",
                    response=str(exc),
                    dispatch=False,
                ),
            )
        except Exception as exc:
            return cast(
                QueueEnqueueResult,
                self._result(
                    QueueEnqueueResult,
                    request,
                    outcome="ambiguous",
                    response=str(exc),
                    dispatch=True,
                ),
            )
        try:
            payload = _nested(data, "enqueuePullRequest", "GraphQL data")
            entry = _nested(payload, "mergeQueueEntry", "enqueuePullRequest")
            _str(entry, "id", "enqueuePullRequest")
            # Exact singleton observation is mandatory after enqueue.  It is
            # kept in the response digest and never inferred from the mutation.
            # A queue generation is created by this dispatch.  Observe the
            # exact singleton directly; comparing it with a pre-enqueue
            # generation would conflate two different evidence objects.
            queue = self._queue_state(
                "preparation",
                request.pull_request_number,
                request.pull_request_head,
                request.base_commit,
                request.base_tree,
                require_entry=True,
            )
        except Exception as exc:
            return cast(
                QueueEnqueueResult,
                self._result(
                    QueueEnqueueResult,
                    request,
                    outcome="ambiguous",
                    response=str(exc),
                    dispatch=True,
                ),
            )
        result = request.model_dump()
        result.update(
            outcome="applied",
            response_digest=canonical_digest({"mutation": data, "queue": queue}),
            observed_at=datetime.now(UTC),
            dispatch_started=True,
        )
        return QueueEnqueueResult.build(**result)

    def _queue_state(
        self,
        role: str,
        number: int,
        head: str,
        base: str,
        base_tree: str,
        *,
        require_entry: bool = True,
    ) -> JsonObject:
        data = self._graphql(
            role, _QUEUE_QUERY, {"owner": self.owner, "name": self.repo, "branch": "main"}
        )
        repository = _nested(data, "repository", "GraphQL data")
        queue = _nested(repository, "mergeQueue", "GraphQL data")
        config = _nested(queue, "configuration", "merge queue")
        max_entries = config.get("maximumEntriesToMerge")
        max_build = config.get("maximumEntriesToBuild")
        method = config.get("mergeMethod")
        strategy = config.get("mergingStrategy")
        if (
            isinstance(max_entries, bool)
            or not isinstance(max_entries, int)
            or max_entries != 1
            or isinstance(max_build, bool)
            or not isinstance(max_build, int)
            or max_build < 1
            or not isinstance(method, str)
            or method.casefold() != "squash"
            or not isinstance(strategy, str)
            or strategy.casefold() != "allgreen"
        ):
            raise _Precondition("queue configuration is not singleton squash all-green")
        protection_digest, protection_epoch = self._authoritative_protection(
            role, queue_configuration=config
        )
        queue_configuration_digest = canonical_digest(
            {
                "queue_id": _str(queue, "id", "merge queue"),
                "configuration": _stable_observation(config),
                "expected_base_commit": base,
                "expected_base_tree": base_tree,
                "protection_manifest_digest": protection_digest,
                "protection_epoch": protection_epoch,
                "provider_identity": self.provider_identity,
                "provider_api_version": self.provider_api_version,
            }
        )
        main_ref = _obj(
            self._read(role, "GET", self.repository_path + "/git/ref/heads/main"),
            "main ref",
        )
        main_object = _nested(main_ref, "object", "main ref")
        if (
            main_ref.get("ref") != "refs/heads/main"
            or main_object.get("type") != "commit"
            or _git(_str(main_object, "sha", "main ref"), "main ref") != base
        ):
            raise _Precondition("queue main base differs")
        self._read_commit(role, base, expected_tree=base_tree)
        entries = _nested(queue, "entries", "merge queue")
        total = _int(entries, "totalCount", "merge queue entries")
        nodes = entries.get("nodes")
        if not isinstance(nodes, list) or total != len(nodes) or total < 0:
            raise _Precondition("queue must contain exactly one entry")
        if total == 0 and not require_entry:
            entry_id, entry_base, entry_head, state, solo = "empty", base, base, "empty", True
            pr_number = 0
        else:
            if total != 1:
                raise _Precondition("queue must contain exactly one entry")
            entry = _obj(nodes[0], "merge queue entry")
            pr = _nested(entry, "pullRequest", "merge queue entry")
            entry_base = _str(
                _nested(entry, "baseCommit", "merge queue entry"), "oid", "queue base"
            )
            entry_head = _str(
                _nested(entry, "headCommit", "merge queue entry"), "oid", "queue head"
            )
            pr_number = _int(pr, "number", "merge queue entry")
            if (
                pr_number != number
                or _git(entry_base, "queue base") != base
                or _git(entry_head, "queue head") != head
                or entry_head == entry_base
            ):
                raise _Precondition("queue singleton topology differs")
            if entry.get("solo") is not True:
                raise _Precondition("queue entry is not singleton")
            entry_state = _str(entry, "state", "merge queue entry")
            if entry_state not in {"QUEUED", "AWAITING_CHECKS", "PENDING"}:
                raise _Precondition("queue entry is not in an accepted state")
            entry_id = _str(entry, "id", "merge queue entry")
            state, solo = entry_state.casefold(), True
        queue_id = _str(queue, "id", "merge queue")
        manifest = canonical_digest(
            {
                "enabled": True,
                "max_entries_per_group": max_entries,
                "bypass_allowed": False,
                "direct_merge_allowed": False,
                "expected_base_commit": base,
                "expected_base_tree": base_tree,
                "queue_id": queue_id,
                "entry_id": entry_id,
                "pull_request_number": pr_number,
                "entry_base": entry_base,
                "entry_head": entry_head,
                "entry_state": state,
                "entry_solo": solo,
                "merge_method": method.casefold(),
                "merging_strategy": strategy.casefold(),
                "protection_manifest_digest": protection_digest,
                "protection_epoch": protection_epoch,
                "isolated_release_issuer": cast(
                    GitHubPrincipalBinding, self._principals["release"]
                ).identity,
                "release_issuer_app_id": cast(
                    GitHubPrincipalBinding, self._principals["release"]
                ).app_id,
                "issuer_isolation_digest": cast(
                    GitHubPrincipalBinding, self._principals["release"]
                ).isolation_digest,
                "queue_configuration_digest": queue_configuration_digest,
            }
        )
        generation = canonical_digest(
            {
                "queue_generation": canonical_digest({"queue_id": queue_id, "entry_id": entry_id}),
                "queue_manifest_digest": manifest,
            }
        )
        return {
            "queue_id": queue_id,
            "entry_id": entry_id,
            "state": state,
            "solo": solo,
            "merge_method": method.casefold(),
            "merging_strategy": strategy.casefold(),
            "max_entries_per_group": max_entries,
            "max_entries_to_build": max_build,
            "protection_manifest_digest": protection_digest,
            "protection_epoch": protection_epoch,
            "queue_manifest_digest": manifest,
            "queue_generation_digest": generation,
            "queue_configuration_digest": queue_configuration_digest,
        }

    def _check(
        self,
        role: str,
        sha: str,
        run_id: str,
        nonce: str,
        *,
        status: str,
        conclusion: str,
        issuer: tuple[str, int, str] | None = None,
    ) -> JsonObject:
        runs = self._enumerate_checks(role, sha)
        context_runs = [run for run in runs if run.get("name") == "avo-main-release"]
        if len(context_runs) != 1:
            raise _Precondition("check context is missing or duplicated")
        matches = [
            run for run in runs if str(run.get("id")) == run_id or run.get("external_id") == nonce
        ]
        if len(matches) != 1:
            raise _Precondition("check run is missing or ambiguous")
        run = matches[0]
        principal = cast(GitHubPrincipalBinding, self._principals[role])
        identity, app_id_expected, isolation = issuer or (
            principal.identity,
            principal.app_id,
            principal.isolation_digest,
        )
        if not _DIGEST.fullmatch(isolation):
            raise GitHubMainGraduationError("check issuer isolation is malformed")
        app = run.get("app")
        app_id = app.get("id") if isinstance(app, dict) else None
        owner = app.get("owner") if isinstance(app, dict) else None
        app_identity = app.get("slug") if isinstance(app, dict) else None
        owner_identity = owner.get("login") if isinstance(owner, dict) else None
        if (
            str(run.get("id")) != run_id
            or run.get("external_id") != nonce
            or run.get("name") != "avo-main-release"
            or run.get("head_sha") != sha
            or run.get("status") != status
            or (run.get("conclusion") or "pending") != conclusion
            or app_id != app_id_expected
            or (
                app_identity != identity
                and owner_identity != identity
            )
        ):
            raise _Precondition("check run identity or state differs")
        return run

    def _enumerate_checks(self, role: str, sha: str) -> list[JsonObject]:
        """Read the complete check-run collection, rejecting pagination drift."""
        runs: list[JsonObject] = []
        total_count: int | None = None
        for page in range(1, 11):
            suffix = f"?per_page=100&page={page}"
            raw = _obj(
                self._read(
                    role,
                    "GET",
                    self.repository_path + f"/commits/{sha}/check-runs" + suffix,
                ),
                "check runs",
            )
            page_runs = raw.get("check_runs")
            if not isinstance(page_runs, list) or any(
                not isinstance(item, dict) for item in page_runs
            ):
                raise GitHubMainGraduationError("malformed check runs")
            runs.extend(cast(JsonObject, item) for item in page_runs)
            total = raw.get("total_count")
            if isinstance(total, bool) or not isinstance(total, int):
                raise GitHubMainGraduationError("check run total_count is malformed")
            if total_count is None:
                total_count = total
            elif total != total_count:
                raise GitHubMainGraduationError("check run total_count changed")
            if total == 0 and not page_runs:
                break
            if total < 0 or total > 1000 or not page_runs or len(runs) > total:
                raise GitHubMainGraduationError("check run pagination is incomplete")
            if len(runs) == total:
                break
        else:
            raise GitHubMainGraduationError("check run pagination exceeded bounds")
        if total_count is None or len(runs) != total_count:
            raise GitHubMainGraduationError("check run pagination is incomplete")
        ids: list[str] = []
        nonces: list[str] = []
        for run in runs:
            run_id_value = run.get("id")
            nonce_value = run.get("external_id")
            if isinstance(run_id_value, bool) or not isinstance(run_id_value, (int, str)):
                raise GitHubMainGraduationError("check run ID is malformed")
            if not isinstance(nonce_value, str) or not nonce_value:
                raise GitHubMainGraduationError("check run external_id is malformed")
            ids.append(str(run_id_value))
            nonces.append(nonce_value)
        if len(set(ids)) != len(ids) or len(set(nonces)) != len(nonces):
            raise _Precondition("duplicate or rerun check observed")
        return runs

    def _issue_check(
        self,
        role: str,
        request: Any,
        result_cls: type[Any],
        sha: str,
        run_id: str,
        nonce: str,
        status: str,
        conclusion: str,
    ) -> Any:
        expected_nonce = self._expected_nonce(request.external_identity)
        if nonce != expected_nonce:
            raise ValueError("check external_id is not deterministic from external identity")
        existing = self._enumerate_checks(role, sha)
        same_context = [run for run in existing if run.get("name") == "avo-main-release"]
        if len(same_context) > 1:
            raise _Precondition("check context is duplicated or rerun")
        if same_context:
            run = same_context[0]
            if str(run.get("id")) != run_id or run.get("external_id") != nonce:
                raise _Precondition("check context belongs to a different run or nonce")
        matches = [
            run
            for run in existing
            if str(run.get("id")) == run_id or run.get("external_id") == nonce
        ]
        if matches:
            if len(matches) != 1:
                raise _Precondition("check run is duplicated or ambiguous")
            run = matches[0]
            principal = cast(GitHubPrincipalBinding, self._principals[role])
            app = run.get("app")
            owner = app.get("owner") if isinstance(app, dict) else None
            if (
                str(run.get("id")) == run_id
                and run.get("external_id") == nonce
                and run.get("name") == "avo-main-release"
                and run.get("head_sha") == sha
                and run.get("status") == status
                and (run.get("conclusion") or "pending") == conclusion
                and isinstance(app, dict)
                and app.get("id") == principal.app_id
                and (
                    app.get("slug") == principal.identity
                    or (isinstance(owner, dict) and owner.get("login") == principal.identity)
                )
            ):
                return self._result(
                    result_cls,
                    request,
                    outcome="already_applied",
                    response=run,
                    dispatch=True,
                )
            raise _Precondition("existing check run identity or state differs")
        body: JsonBody = {
            "name": "avo-main-release",
            "head_sha": sha,
            "status": status,
            "external_id": nonce,
        }
        # GitHub only accepts a conclusion for a completed check run; the C4
        # pending conclusion is represented by the in-progress status.
        if status == "completed":
            body["conclusion"] = conclusion

        def parse(value: JsonValue) -> JsonObject:
            run = _obj(value, "check run")
            app = run.get("app")
            owner = app.get("owner") if isinstance(app, dict) else None
            app_id = app.get("id") if isinstance(app, dict) else None
            principal = cast(GitHubPrincipalBinding, self._principals[role])
            if (
                run.get("external_id") != nonce
                or run.get("name") != "avo-main-release"
                or run.get("head_sha") != sha
                or run.get("status") != status
                or (run.get("conclusion") or "pending") != conclusion
                or app_id != principal.app_id
                or (
                    not isinstance(app, dict)
                    or (
                        app.get("slug") != principal.identity
                        and (
                            not isinstance(owner, dict)
                            or owner.get("login") != principal.identity
                        )
                    )
                )
            ):
                raise _Precondition("check run response differs")
            if str(run.get("id")) != run_id:
                raise _Precondition("check run ID differs")
            return run

        return self._post(
            role, request, result_cls, self.repository_path + "/check-runs", body, parse
        )

    def _authoritative_admission(self, role: str, request: Any) -> JsonObject:
        """Re-read the durable admission authority; a digest is not authority."""
        observed_digest = getattr(request, "admission_observation_digest", None)
        if not isinstance(observed_digest, str) or not _DIGEST.fullmatch(observed_digest):
            raise _Precondition("admission observation digest is missing or malformed")
        admission = self._admission_request(observed_digest)
        admission = self._validate_request(
            admission, AdmissionIssueRequest, self.repository_digest
        )
        if (
            admission.operation_id != request.operation_id
            or admission.lease_epoch_digest != request.lease_epoch_digest
            or admission.pull_request_number != request.pull_request_number
            or admission.pull_request_head != request.pull_request_head
            or admission.pull_request_tree != request.pull_request_tree
            or admission.base_commit != request.base_commit
            or admission.base_tree != request.base_tree
            or (
                getattr(request, "queue_configuration_digest", None) is not None
                and admission.queue_configuration_digest
                != request.queue_configuration_digest
            )
        ):
            raise _Precondition("durable admission identity differs from current stage")
        downstream_preparation = getattr(request, "preparation_authorization_digest", None)
        if (
            downstream_preparation is not None
            and admission.preparation_authorization_digest != downstream_preparation
        ):
            raise _Precondition("durable admission preparation authorization differs")
        principal = cast(GitHubPrincipalBinding, self._principals["admission"])
        if (
            admission.issuer_identity,
            admission.issuer_app_id,
            admission.issuer_isolation_digest,
        ) != (principal.identity, principal.app_id, principal.isolation_digest):
            raise _Precondition("durable admission issuer differs")
        now = self._trusted_clock()
        cutoff = self._admission_freshness_cutoff(request)
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or not isinstance(cutoff, datetime)
            or cutoff.tzinfo is None
            or cutoff > now
        ):
            raise GitHubMainGraduationError("admission freshness boundary is malformed")
        run = self._check(
            role,
            admission.pull_request_head,
            admission.admission_run_id,
            admission.admission_nonce,
            status="completed",
            conclusion="success",
            issuer=(
                admission.issuer_identity,
                admission.issuer_app_id,
                admission.issuer_isolation_digest,
            ),
        )
        completed_at = run.get("completed_at")
        if not isinstance(completed_at, str):
            raise _Precondition("admission check freshness is unavailable")
        try:
            completed = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise _Precondition("admission check freshness is malformed") from exc
        if (
            completed.tzinfo is None
            or completed.astimezone(UTC) < cutoff.astimezone(UTC)
            or completed.astimezone(UTC) > now.astimezone(UTC)
        ):
            raise _Precondition("admission check is stale")
        if canonical_digest(run) != observed_digest:
            raise _Precondition("admission observation digest differs from provider evidence")
        return run

    def issue_admission(self, request: AdmissionIssueRequest) -> AdmissionIssueResult:
        request = self._validate_request(request, AdmissionIssueRequest, self.repository_digest)
        principal = cast(GitHubPrincipalBinding, self._principals["admission"])
        if (request.issuer_identity, request.issuer_app_id, request.issuer_isolation_digest) != (
            principal.identity,
            principal.app_id,
            principal.isolation_digest,
        ) or principal.app_id == 15368:
            raise ValueError("admission issuer binding differs")
        self._authoritative_pr(
            "admission",
            request.pull_request_number,
            candidate_ref="refs/heads/avo/candidate/"
            + request.operation_id.removeprefix("sha256:"),
            head_commit=request.pull_request_head,
            head_tree=request.pull_request_tree,
            base_commit=request.base_commit,
            base_tree=request.base_tree,
        )
        self._authoritative_queue("admission", request, require_entry=False)
        return cast(
            AdmissionIssueResult,
            self._issue_check(
                "admission",
                request,
                AdmissionIssueResult,
                request.pull_request_head,
                request.admission_run_id,
                request.admission_nonce,
                "completed",
                "success",
            ),
        )

    def issue_group_hold(self, request: GroupHoldIssueRequest) -> GroupHoldIssueResult:
        request = self._validate_request(request, GroupHoldIssueRequest, self.repository_digest)
        principal = cast(GitHubPrincipalBinding, self._principals["hold"])
        if (request.issuer_identity, request.issuer_app_id, request.issuer_isolation_digest) != (
            principal.identity,
            principal.app_id,
            principal.isolation_digest,
        ) or principal.app_id == 15368:
            raise ValueError("group hold issuer binding differs")
        if request.group_sha == request.pull_request_head:
            raise ValueError("group hold must be on distinct group SHA")
        self._authoritative_group("hold", request)
        self._authoritative_admission("hold", request)
        return cast(
            GroupHoldIssueResult,
            self._issue_check(
                "hold",
                request,
                GroupHoldIssueResult,
                request.group_sha,
                request.hold_run_id,
                request.hold_nonce,
                "in_progress",
                "pending",
            ),
        )

    def _final_revalidate_release(self, request: ReleaseIssueRequest) -> None:
        """Perform the last authoritative read set before the release fence."""
        now = self._trusted_clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise GitHubMainGraduationError("trusted clock returned a naive or malformed time")
        now = now.astimezone(UTC)
        freshness_cutoff = self._release_freshness_cutoff(request)
        if (
            not isinstance(freshness_cutoff, datetime)
            or freshness_cutoff.tzinfo is None
            or freshness_cutoff > now
        ):
            raise GitHubMainGraduationError("controller freshness cutoff is malformed")
        freshness_cutoff = freshness_cutoff.astimezone(UTC)
        if now >= request.authorization_expires_at:
            raise _Precondition("release authorization has expired")
        self._authoritative_group("release", request)
        self._authoritative_admission("release", request)
        main_ref = _obj(
            self._read(
                "release",
                "GET",
                self.repository_path + "/git/ref/heads/main",
            ),
            "main ref",
        )
        main_obj = _nested(main_ref, "object", "main ref")
        if main_ref.get("ref") != "refs/heads/main" or main_obj.get("type") != "commit":
            raise _Precondition("main ref identity differs")
        main_sha = _git(_str(main_obj, "sha", "main ref"), "main SHA")
        if main_sha != request.base_commit:
            raise _Precondition("main base changed")
        _, main_tree, main_parents = self._read_commit(
            "release", main_sha, expected_tree=request.base_tree
        )
        if main_tree != request.base_tree or len(main_parents) != 1:
            raise _Precondition("main topology is incomplete")
        # Re-read the exact required contexts before scanning the complete,
        # current check-run list.  Context names and issuing App IDs are both
        # part of GitHub branch protection, so a success by a lookalike App is
        # never sufficient.
        protection = _obj(
            self._read("release", "GET", self.repository_path + "/branches/main/protection"),
            "main protection",
        )
        required = _nested(protection, "required_status_checks", "main protection")
        contexts = required.get("contexts")
        configured = required.get("checks")
        if (
            not isinstance(contexts, list)
            or any(not isinstance(item, str) or not item for item in contexts)
            or len(set(cast(list[str], contexts))) != len(contexts)
            or not isinstance(configured, list)
            or any(not isinstance(item, dict) for item in configured)
            or len(configured) != len(contexts)
        ):
            raise GitHubMainGraduationError("required main check bindings are malformed")
        bindings: dict[str, int] = {}
        for value in cast(list[JsonObject], configured):
            context = _str(value, "context", "required main check")
            app_id = _int(value, "app_id", "required main check")
            if context in bindings:
                raise _Precondition("required main check context is duplicated")
            bindings[context] = app_id
        if set(bindings) != set(cast(list[str], contexts)):
            raise _Precondition("required main check bindings differ from contexts")
        release_principal = cast(GitHubPrincipalBinding, self._principals["release"])
        expected_contexts = {*self.trusted_check_contexts, request.check_context}
        expected_apps = {
            **{context: self.validation_app_id for context in self.trusted_check_contexts},
            request.check_context: release_principal.app_id,
        }
        if (
            set(cast(list[str], contexts)) != expected_contexts
            or bindings != expected_apps
        ):
            raise _Precondition("release check is not bound in main protection")

        # Every required non-release context must be a single fresh completed
        # success on this exact merge-group SHA.  The only release context is
        # the one still-pending, bound hold; a duplicate context is a rerun or
        # substitute release and therefore fails closed.
        checks = self._enumerate_checks("release", request.group_sha)
        release_checks = [check for check in checks if check.get("name") == request.check_context]
        if len(release_checks) != 1:
            raise _Precondition("release check context is missing or duplicated")
        self._check(
            "release",
            request.group_sha,
            request.hold_run_id,
            request.hold_nonce,
            status="in_progress",
            conclusion="pending",
        )
        for context, app_id in bindings.items():
            if context == request.check_context:
                continue
            matches = [check for check in checks if check.get("name") == context]
            if len(matches) != 1:
                raise _Precondition("required group check is missing or duplicated")
            check = matches[0]
            app = check.get("app")
            if not isinstance(app, dict) or app.get("id") != app_id:
                raise _Precondition("required group check issuer differs")
            completed_at = check.get("completed_at")
            if not isinstance(completed_at, str):
                raise _Precondition("required group check freshness is unavailable")
            try:
                completed = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise _Precondition("required group check freshness is malformed") from exc
            if (
                completed.tzinfo is None
                or completed.astimezone(UTC) < freshness_cutoff
                or completed.astimezone(UTC) > now
            ):
                raise _Precondition("required group check is not fresh")
            if (
                check.get("head_sha") != request.group_sha
                or check.get("status") != "completed"
                or check.get("conclusion") != "success"
            ):
                raise _Precondition("non-release group check is not successful")
        for check in checks:
            if check.get("name") == request.check_context:
                continue
            if check.get("head_sha") != request.group_sha:
                raise _Precondition("group check SHA differs")

    def issue_release(self, request: ReleaseIssueRequest) -> ReleaseIssueResult:
        request = self._validate_request(request, ReleaseIssueRequest, self.repository_digest)
        principal = cast(GitHubPrincipalBinding, self._principals["release"])
        if (request.issuer_identity, request.issuer_app_id, request.issuer_isolation_digest) != (
            principal.identity,
            principal.app_id,
            principal.isolation_digest,
        ) or principal.app_id == 15368:
            raise ValueError("release issuer binding differs")
        self._final_revalidate_release(request)
        # This is the single final fence: there are no reads between this
        # authorization and the isolated PATCH below, and callback failures
        # are deliberately propagated rather than reinterpreted or retried.
        self._mutation_authorize(request)
        body: JsonBody = {"status": "completed", "conclusion": "success"}
        result = self._invoke(
            "release",
            "PATCH",
            self.repository_path + f"/check-runs/{quote(request.hold_run_id, safe='')}",
            body,
            request,
            ReleaseIssueResult,
            lambda value: self._check_response(value, request),
        )
        return cast(ReleaseIssueResult, result)

    def _check_response(self, value: JsonValue, request: ReleaseIssueRequest) -> JsonObject:
        run = _obj(value, "release check run")
        principal = cast(GitHubPrincipalBinding, self._principals["release"])
        app = run.get("app")
        owner = app.get("owner") if isinstance(app, dict) else None
        if (
            str(run.get("id")) != request.hold_run_id
            or run.get("external_id") != request.hold_nonce
            or run.get("name") != request.check_context
            or run.get("head_sha") != request.group_sha
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or not isinstance(app, dict)
            or app.get("id") != principal.app_id
            or (
                app.get("slug") != principal.identity
                and (not isinstance(owner, dict) or owner.get("login") != principal.identity)
            )
            or request.issuer_identity != principal.identity
            or request.issuer_app_id != principal.app_id
            or request.issuer_isolation_digest != principal.isolation_digest
        ):
            raise _Precondition("release check response differs")
        return run

    def _observation(
        self, cls: type[Any], request: Any, value: Any, outcome: str = "observed"
    ) -> Any:
        values = request.model_dump()
        values.update(
            outcome=outcome, evidence_digest=canonical_digest(value), observed_at=datetime.now(UTC)
        )
        return cls.build(**values)

    @staticmethod
    def _request_issuer(request: Any) -> tuple[str, int, str]:
        identity = getattr(request, "issuer_identity", None)
        app_id = getattr(request, "issuer_app_id", None)
        isolation = getattr(request, "issuer_isolation_digest", None)
        if (
            not isinstance(identity, str)
            or not isinstance(app_id, int)
            or isinstance(app_id, bool)
            or app_id <= 0
            or not isinstance(isolation, str)
            or not _DIGEST.fullmatch(isolation)
        ):
            raise GitHubMainGraduationError("observation request issuer is malformed")
        return identity, app_id, isolation

    def _delegate_observer(self, name: str, request: Any, result_cls: type[Any]) -> Any | None:
        if self._observer is None:
            return None
        method = getattr(self._observer, name, None)
        if not callable(method):
            raise GitHubMainGraduationError("injected observer does not implement C4 observations")
        result = method(request)
        if not isinstance(result, result_cls):
            raise GitHubMainGraduationError("injected observer returned the wrong result type")
        # Re-validate instead of accepting a ``model_construct`` result.
        result_values = result_cls.model_validate(result.model_dump()).model_dump()
        request_values = request.model_dump()
        for key, expected in request_values.items():
            if result_values.get(key) != expected:
                raise GitHubMainGraduationError(
                    "injected observer result is not bound to its request"
                )
        return result

    def observe_candidate(self, request: CandidateObservationRequest) -> CandidateObservationResult:
        request = self._validate_request(
            request, CandidateObservationRequest, self.repository_digest
        )
        delegated = self._delegate_observer(
            "observe_candidate", request, CandidateObservationResult
        )
        if delegated is not None:
            return cast(CandidateObservationResult, delegated)
        raw = _obj(
            self._read(
                "observer" if self._read_only_transports else "preparation",
                "GET",
                self.repository_path
                + "/git/ref/heads/"
                + quote(request.candidate_ref.removeprefix("refs/heads/"), safe=""),
            ),
            "candidate ref",
        )
        obj = _nested(raw, "object", "candidate ref")
        if (
            raw.get("ref") != request.candidate_ref
            or obj.get("type") != "commit"
            or obj.get("sha") != request.candidate_commit
        ):
            raise _Precondition("candidate observation differs")
        self._read_commit(
            "observer" if self._read_only_transports else "preparation",
            request.candidate_commit,
        )
        return cast(
            CandidateObservationResult, self._observation(CandidateObservationResult, request, raw)
        )

    def observe_queue_configuration(
        self, *, operation_id: str | None = None
    ) -> MainQueueConfigurationObservation:
        """Observe the stable, empty pre-enqueue queue configuration.

        The digest intentionally excludes queue entries and observation
        timestamps.  It therefore remains the same across the enqueue
        transition, while the post-enqueue queue generation is a separate
        fact observed by :meth:`observe_queue`.
        """

        role = "observer" if self._read_only_transports else "preparation"
        main_ref = _obj(
            self._read(role, "GET", self.repository_path + "/git/ref/heads/main"),
            "main ref",
        )
        main_object = _nested(main_ref, "object", "main ref")
        if main_ref.get("ref") != "refs/heads/main" or main_object.get("type") != "commit":
            raise _Precondition("main ref identity differs")
        base = _git(_str(main_object, "sha", "main ref"), "main base")
        _, base_tree, _ = self._read_commit(role, base)
        state = self._queue_state(role, 0, base, base, base_tree, require_entry=False)
        if state.get("state") != "empty":
            raise _Precondition("pre-enqueue queue must be empty")
        release = cast(GitHubPrincipalBinding, self._principals["release"])
        config_digest = state.get("queue_configuration_digest")
        protection_digest = state.get("protection_manifest_digest")
        protection_epoch = state.get("protection_epoch")
        if (
            not isinstance(config_digest, str)
            or not _DIGEST.fullmatch(config_digest)
            or not isinstance(protection_digest, str)
            or not isinstance(protection_epoch, str)
        ):
            raise GitHubMainGraduationError("queue configuration evidence is malformed")
        values: dict[str, Any] = {
            "repository_digest": self.repository_digest,
            "target_ref": "refs/heads/main",
            "operation_id": operation_id
            or canonical_digest(
                {
                    "repository_digest": self.repository_digest,
                    "queue_configuration_digest": config_digest,
                }
            ),
            "queue_configuration_digest": config_digest,
            "expected_base_commit": base,
            "expected_base_tree": base_tree,
            "protection_manifest_digest": protection_digest,
            "protection_epoch": protection_epoch,
            "provider_identity": self.provider_identity,
            "provider_api_version": self.provider_api_version,
            "merge_method": "squash",
            "isolated_release_issuer": release.identity,
            "release_issuer_app_id": release.app_id,
            "issuer_isolation_digest": release.isolation_digest,
            "observed_at": datetime.now(UTC),
        }
        return MainQueueConfigurationObservation.model_validate(values)

    def observe_pull_request(
        self, request: PullRequestObservationRequest
    ) -> PullRequestObservationResult:
        request = self._validate_request(
            request, PullRequestObservationRequest, self.repository_digest
        )
        delegated = self._delegate_observer(
            "observe_pull_request", request, PullRequestObservationResult
        )
        if delegated is not None:
            return cast(PullRequestObservationResult, delegated)
        parsed = self._authoritative_pr(
            "observer" if self._read_only_transports else "preparation",
            request.pull_request_number,
            candidate_ref=request.candidate_ref,
            head_commit=request.head_commit,
            head_tree=request.head_tree,
            base_commit=request.base_commit,
            base_tree=request.base_tree,
        )
        return cast(
            PullRequestObservationResult,
            self._observation(PullRequestObservationResult, request, parsed),
        )

    def observe_admission(self, request: Any) -> AdmissionObservationResult:
        request = self._validate_request(
            request, AdmissionObservationRequest, self.repository_digest
        )
        delegated = self._delegate_observer(
            "observe_admission", request, AdmissionObservationResult
        )
        if delegated is not None:
            return cast(AdmissionObservationResult, delegated)
        run = self._check(
            "observer" if self._read_only_transports else "admission",
            request.pull_request_head,
            request.admission_run_id,
            request.admission_nonce,
            status="completed",
            conclusion="success",
            issuer=self._request_issuer(request),
        )
        return cast(
            AdmissionObservationResult, self._observation(AdmissionObservationResult, request, run)
        )

    def observe_queue(self, request: QueueObservationRequest) -> QueueObservationResult:
        request = self._validate_request(request, QueueObservationRequest, self.repository_digest)
        delegated = self._delegate_observer("observe_queue", request, QueueObservationResult)
        if delegated is not None:
            return cast(QueueObservationResult, delegated)
        state = self._authoritative_queue(
            "observer" if self._read_only_transports else "preparation",
            request,
        )
        return cast(
            QueueObservationResult, self._observation(QueueObservationResult, request, state)
        )

    def observe_group_hold(
        self, request: GroupHoldObservationRequest
    ) -> GroupHoldObservationResult:
        request = self._validate_request(
            request, GroupHoldObservationRequest, self.repository_digest
        )
        delegated = self._delegate_observer(
            "observe_group_hold", request, GroupHoldObservationResult
        )
        if delegated is not None:
            return cast(GroupHoldObservationResult, delegated)
        self._authoritative_group(
            "observer" if self._read_only_transports else "hold", request
        )
        run = self._check(
            "observer" if self._read_only_transports else "hold",
            request.group_sha,
            request.hold_run_id,
            request.hold_nonce,
            status="in_progress",
            conclusion="pending",
            issuer=self._request_issuer(request),
        )
        return cast(
            GroupHoldObservationResult, self._observation(GroupHoldObservationResult, request, run)
        )

    def observe_release(self, request: ReleaseObservationRequest) -> ReleaseObservationResult:
        request = self._validate_request(request, ReleaseObservationRequest, self.repository_digest)
        delegated = self._delegate_observer("observe_release", request, ReleaseObservationResult)
        if delegated is not None:
            return cast(ReleaseObservationResult, delegated)
        self._authoritative_group(
            "observer" if self._read_only_transports else "release", request
        )
        run = self._check(
            "observer" if self._read_only_transports else "release",
            request.group_sha,
            request.hold_run_id,
            request.hold_nonce,
            status="completed",
            conclusion="success",
            issuer=self._request_issuer(request),
        )
        return cast(
            ReleaseObservationResult, self._observation(ReleaseObservationResult, request, run)
        )


# Names used by integrations that call the component a provider rather than
# an adapter.  They are aliases, not additional authority surfaces.
GitHubMainGraduationProvider = GitHubMainGraduationAdapter

__all__ = [
    "GitHubCredentialBinding",
    "GitHubMainGraduationAdapter",
    "GitHubMainGraduationAmbiguous",
    "GitHubMainGraduationError",
    "GitHubMainGraduationProvider",
    "GitHubMainGraduationRejected",
    "GitHubPrincipalBinding",
]
