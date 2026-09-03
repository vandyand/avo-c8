"""Fixed-origin, read-only observation of one forward candidate ref.

The observer authenticates the exact App-bound configuration model, verifies
repository identity, reads the operation-derived candidate ref, inspects the
exact commit, and reads the same ref again as a fence.  It has no publication,
provider, controller, receipt, or authority surface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal, cast

from avo_correlate.adapters.hosted_git.github import (
    GitHubRejected,
    GitHubTransportError,
    JsonBody,
    JsonValue,
)
from avo_correlate.adapters.hosted_git.github_main_base_reader import (
    GitHubMainBaseReaderConfiguration,
    GitHubMainBaseReaderCredentials,
)
from avo_correlate.adapters.hosted_git.github_read_provenance import GitHubReadRequest
from avo_correlate.adapters.hosted_git.github_transport import GitHubJsonTransport
from avo_correlate.contracts.main_personal_exact_cas_candidate_observation import (
    MainPersonalExactCasCandidateObservation,
    MainPersonalExactCasCandidateObservationRequest,
    MainPersonalExactCasCandidatePolicyEvidence,
    candidate_ref_for_operation,
)
from avo_correlate.domain.canonical import canonical_digest

_API_ORIGIN = "https://api.github.com"
_API_VERSION = "2022-11-28"
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CANDIDATE = re.compile(r"^refs/heads/avo/candidate/[0-9a-f]{64}$")
_READER_IDENTITY = "github_candidate_ref_observer"


class MainPersonalExactCasCandidateObservationError(RuntimeError):
    """Value-free failure to obtain the bounded candidate observation."""

    def __init__(self) -> None:
        super().__init__("candidate_observation_unresolved")

    def __repr__(self) -> str:
        return "MainPersonalExactCasCandidateObservationError()"


@dataclass(frozen=True, slots=True)
class GitHubCandidateReadProvenance:
    """Secret-free provenance for the candidate observer's successful reads."""

    reader_identity: str
    api_origin: Literal["https://api.github.com"]
    api_version: Literal["2022-11-28"]
    owner: str
    owner_id: int
    repository: str
    repository_id: int
    repository_digest: str
    operation_id: str
    candidate_ref: str
    candidate_commit: str
    app_slug: str
    app_id: int
    installation_id: int
    requests: tuple[GitHubReadRequest, ...]
    endpoint_observation_digests: tuple[tuple[str, str], ...]
    configuration_digest: str
    initial_ref_digest: str
    commit_digest: str
    final_ref_digest: str
    policy_digest: str
    started_at: datetime
    finished_at: datetime
    provenance_digest: str = field(init=False)

    def __post_init__(self) -> None:
        self.assert_valid(include_digest=False)
        object.__setattr__(self, "provenance_digest", canonical_digest(self._payload()))

    def _payload(self) -> dict[str, object]:
        return {
            "reader_identity": self.reader_identity,
            "api_origin": self.api_origin,
            "api_version": self.api_version,
            "owner": self.owner,
            "owner_id": self.owner_id,
            "repository": self.repository,
            "repository_id": self.repository_id,
            "repository_digest": self.repository_digest,
            "operation_id": self.operation_id,
            "candidate_ref": self.candidate_ref,
            "candidate_commit": self.candidate_commit,
            "app_slug": self.app_slug,
            "app_id": self.app_id,
            "installation_id": self.installation_id,
            "requests": tuple(
                {"method": item.method, "path": item.path, "credential_role": item.credential_role}
                for item in self.requests
            ),
            "endpoint_observation_digests": self.endpoint_observation_digests,
            "configuration_digest": self.configuration_digest,
            "initial_ref_digest": self.initial_ref_digest,
            "commit_digest": self.commit_digest,
            "final_ref_digest": self.final_ref_digest,
            "policy_digest": self.policy_digest,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
        }

    def assert_valid(self, *, include_digest: bool = True) -> None:
        if self.reader_identity != _READER_IDENTITY:
            raise ValueError("candidate provenance reader identity is invalid")
        if self.api_origin != _API_ORIGIN or self.api_version != _API_VERSION:
            raise ValueError("candidate provenance API binding is invalid")
        if not _CANDIDATE.fullmatch(self.candidate_ref):
            raise ValueError("candidate provenance ref is invalid")
        if self.candidate_ref != candidate_ref_for_operation(self.operation_id):
            raise ValueError("candidate provenance operation binding is invalid")
        if _OBJECT.fullmatch(self.candidate_commit) is None:
            raise ValueError("candidate provenance commit is invalid")
        if self.started_at.tzinfo is None or self.started_at.utcoffset() is None:
            raise ValueError("candidate provenance start time is invalid")
        if self.finished_at.tzinfo is None or self.finished_at.utcoffset() is None:
            raise ValueError("candidate provenance finish time is invalid")
        if self.finished_at < self.started_at or self.finished_at - self.started_at > timedelta(
            minutes=5
        ):
            raise ValueError("candidate provenance observation window is invalid")
        if any(
            type(value) is not str or _DIGEST.fullmatch(value) is None
            for value in (
                self.repository_digest,
                self.configuration_digest,
                self.initial_ref_digest,
                self.commit_digest,
                self.final_ref_digest,
                self.policy_digest,
            )
        ):
            raise ValueError("candidate provenance digest is invalid")
        if (
            type(self.requests) is not tuple
            or not self.requests
            or any(type(item) is not GitHubReadRequest for item in self.requests)
        ):
            raise ValueError("candidate provenance request trace is malformed")
        token_path = f"/app/installations/{self.installation_id}/access_tokens"
        repo_path = f"/repositories/{self.repository_id}"
        candidate_path = (
            f"/repos/{self.owner}/{self.repository}/git/ref/heads/"
            + self.candidate_ref.removeprefix("refs/heads/")
        )
        commit_path = f"/repos/{self.owner}/{self.repository}/git/commits/" + self.candidate_commit
        expected_methods_paths_roles = (
            ("GET", "/app", "app_jwt"),
            ("GET", f"/app/installations/{self.installation_id}", "app_jwt"),
            ("POST", token_path, "app_jwt"),
            ("GET", repo_path, "installation_token"),
            ("GET", candidate_path, "installation_token"),
            ("GET", commit_path, "installation_token"),
            ("GET", candidate_path, "installation_token"),
        )
        actual = tuple((item.method, item.path, item.credential_role) for item in self.requests)
        if actual != expected_methods_paths_roles:
            raise ValueError("candidate provenance request trace is not exact")
        if type(self.endpoint_observation_digests) is not tuple:
            raise ValueError("candidate provenance endpoint observations are malformed")
        labels = tuple(label for label, _ in self.endpoint_observation_digests)
        if labels != tuple(sorted(labels)) or len(set(labels)) != len(labels):
            raise ValueError("candidate provenance endpoint labels are not canonical")
        required = {"app", "installation", "repository", "initial_ref", "commit", "final_ref"}
        if not required.issubset(labels):
            raise ValueError("candidate provenance endpoint identities are incomplete")
        if include_digest and self.provenance_digest != canonical_digest(self._payload()):
            raise ValueError("candidate provenance digest does not match semantic state")


@dataclass(frozen=True, slots=True)
class GitHubCandidateReadWithProvenance:
    result: MainPersonalExactCasCandidateObservation
    provenance: GitHubCandidateReadProvenance

    def __post_init__(self) -> None:
        if type(self.result) is not MainPersonalExactCasCandidateObservation:
            raise TypeError("candidate observation result is required")
        if type(self.provenance) is not GitHubCandidateReadProvenance:
            raise TypeError("candidate provenance is required")
        self.result.model_validate(self.result.model_dump(mode="python"), strict=True)
        self.provenance.assert_valid()
        if (
            self.result.operation_id != self.provenance.operation_id
            or self.result.repository_digest != self.provenance.repository_digest
            or self.result.candidate_ref != self.provenance.candidate_ref
            or self.result.candidate_commit != self.provenance.candidate_commit
            or self.result.initial_ref_digest != self.provenance.initial_ref_digest
            or self.result.commit_digest != self.provenance.commit_digest
            or self.result.final_ref_digest != self.provenance.final_ref_digest
            or self.result.policy.evidence_digest != self.provenance.policy_digest
            or self.result.started_at != self.provenance.started_at
            or self.result.finished_at != self.provenance.finished_at
        ):
            raise ValueError("candidate observation is not bound to provenance")


@dataclass(frozen=True, slots=True, init=False, repr=False)
class GitHubCandidateRefObserver:
    """App-bound candidate observer with no repository mutation capability."""

    _configuration: GitHubMainBaseReaderConfiguration
    _credentials: GitHubMainBaseReaderCredentials = field(repr=False, compare=False)
    _transport: GitHubJsonTransport = field(repr=False, compare=False)

    def __init__(
        self,
        configuration: GitHubMainBaseReaderConfiguration,
        credentials: GitHubMainBaseReaderCredentials,
    ) -> None:
        if type(configuration) is not GitHubMainBaseReaderConfiguration:
            raise TypeError("exact GitHub main base reader configuration is required")
        if type(credentials) is not GitHubMainBaseReaderCredentials:
            raise TypeError("exact GitHub main base reader credentials are required")
        configuration.assert_valid()
        credentials.assert_valid()
        object.__setattr__(self, "_configuration", configuration)
        object.__setattr__(self, "_credentials", credentials)
        object.__setattr__(
            self,
            "_transport",
            GitHubJsonTransport(
                origin=_API_ORIGIN,
                timeout_seconds=float(configuration.timeout_seconds),
                max_response_bytes=configuration.max_response_bytes,
            ),
        )

    @property
    def configuration_digest(self) -> str:
        self._configuration.assert_valid()
        return self._configuration.configuration_digest

    @property
    def repository_digest(self) -> str:
        self._configuration.assert_valid()
        return self._configuration.repository_digest

    def observe(
        self, request: MainPersonalExactCasCandidateObservationRequest
    ) -> MainPersonalExactCasCandidateObservation:
        return self.observe_with_provenance(request).result

    def observe_with_provenance(
        self, request: MainPersonalExactCasCandidateObservationRequest
    ) -> GitHubCandidateReadWithProvenance:
        failed = False
        observed: GitHubCandidateReadWithProvenance | None = None
        try:
            checked = _revalidate_request(request, self._configuration)
            self._configuration.assert_valid()
            started = _utc_now()
            trace: list[GitHubReadRequest] = []
            app = self._get("/app", self._credentials.app_jwt, trace)
            self._verify_app(app)
            installation_path = f"/app/installations/{self._configuration.observer_installation_id}"
            installation = self._get(installation_path, self._credentials.app_jwt, trace)
            self._verify_installation(installation)
            repository_path = f"/repositories/{self._configuration.repository_id}"
            installation_token = self._mint_installation_token(trace)
            repository = self._get(repository_path, installation_token, trace)
            self._verify_repository(repository)
            candidate_path = (
                f"/repos/{self._configuration.owner}/{self._configuration.repo}/git/ref/heads/"
                + checked.candidate_ref.removeprefix("refs/heads/")
            )
            initial = self._get(candidate_path, installation_token, trace)
            commit = _parse_ref(initial, checked.candidate_ref)
            commit_path = (
                f"/repos/{self._configuration.owner}/{self._configuration.repo}"
                f"/git/commits/{commit[0]}"
            )
            commit_body = self._get(commit_path, installation_token, trace)
            commit_sha, tree, parents = _parse_commit(commit_body, commit[0])
            final = self._get(candidate_path, installation_token, trace)
            final_commit = _parse_ref(final, checked.candidate_ref)
            if commit_sha != commit[0] or final_commit[0] != commit[0]:
                raise ValueError("candidate ref drifted during observation")
            policy, policy_digest = _unverifiable_policy(
                "separate-owner-admin-ruleset-read-credential"
            )
            finished = _utc_now()
            initial_digest = canonical_digest(_safe_ref(commit[0], checked.candidate_ref))
            final_digest = canonical_digest(_safe_ref(final_commit[0], checked.candidate_ref))
            result = MainPersonalExactCasCandidateObservation.build(
                operation_id=checked.operation_id,
                repository_digest=checked.repository_digest,
                owner=self._configuration.owner,
                owner_id=self._configuration.owner_id,
                repository=self._configuration.repo,
                repository_id=self._configuration.repository_id,
                candidate_ref=checked.candidate_ref,
                candidate_commit=commit[0],
                candidate_tree=tree,
                candidate_parents=parents,
                initial_ref_digest=initial_digest,
                commit_digest=canonical_digest(
                    {"commit": commit[0], "tree": tree, "parents": parents}
                ),
                final_ref_digest=final_digest,
                policy=policy,
                started_at=started,
                finished_at=finished,
                is_authoritative=False,
                readiness_authorized=False,
                is_terminal=False,
                completion_authorized=False,
                mutation_performed=False,
                deploy_performed=False,
            )
            endpoint = tuple(
                sorted(
                    (
                        ("app", canonical_digest(_safe_app(app))),
                        ("installation", canonical_digest(_safe_installation(installation))),
                        ("repository", canonical_digest(_safe_repository(repository))),
                        ("initial_ref", initial_digest),
                        ("commit", result.commit_digest),
                        ("final_ref", final_digest),
                    )
                )
            )
            provenance = GitHubCandidateReadProvenance(
                reader_identity=_READER_IDENTITY,
                api_origin=_API_ORIGIN,
                api_version=_API_VERSION,
                owner=self._configuration.owner,
                owner_id=self._configuration.owner_id,
                repository=self._configuration.repo,
                repository_id=self._configuration.repository_id,
                repository_digest=self._configuration.repository_digest,
                operation_id=checked.operation_id,
                candidate_ref=checked.candidate_ref,
                app_slug=self._configuration.observer_identity,
                app_id=self._configuration.observer_app_id,
                installation_id=self._configuration.observer_installation_id,
                requests=tuple(trace),
                endpoint_observation_digests=endpoint,
                configuration_digest=self._configuration.configuration_digest,
                initial_ref_digest=initial_digest,
                commit_digest=result.commit_digest,
                final_ref_digest=final_digest,
                policy_digest=policy_digest,
                started_at=started,
                finished_at=finished,
                candidate_commit=commit[0],
            )
            observed = GitHubCandidateReadWithProvenance(result, provenance)
        except Exception:
            failed = True
        if failed or observed is None:
            error = MainPersonalExactCasCandidateObservationError()
            error.__cause__ = None
            error.__context__ = None
            raise error
        return observed

    def _get(self, path: str, token: str, trace: list[GitHubReadRequest]) -> JsonValue:
        status, body = self._request("GET", path, token, None, expected_status=200)
        if status != 200:
            raise ValueError("GitHub candidate read failed")
        role = (
            "app_jwt"
            if path == "/app" or path.startswith("/app/installations")
            else "installation_token"
        )
        trace.append(GitHubReadRequest("GET", path, role))
        return body

    def _request(
        self,
        method: Literal["GET", "POST"],
        path: str,
        token: str,
        request_body: JsonBody | None,
        *,
        expected_status: int,
    ) -> tuple[int, JsonValue]:
        try:
            result = self._transport(
                method,
                _API_ORIGIN + path,
                request_body,
                {
                    "Accept": "application/vnd.github+json",
                    "Authorization": "Bearer " + token,
                    **({"Content-Type": "application/json"} if request_body is not None else {}),
                    "X-GitHub-Api-Version": _API_VERSION,
                },
            )
        except (GitHubRejected, GitHubTransportError):
            raise ValueError("GitHub candidate transport failed") from None
        except Exception:
            raise ValueError("GitHub candidate transport failed") from None
        status, body = result
        if type(status) is not int:
            raise ValueError("GitHub candidate status is malformed")
        if status != expected_status:
            raise ValueError("GitHub candidate response status differs")
        return status, body

    def _mint_installation_token(self, trace: list[GitHubReadRequest]) -> str:
        path = f"/app/installations/{self._configuration.observer_installation_id}/access_tokens"
        body: JsonBody = {
            "repository_ids": [self._configuration.repository_id],
            "permissions": {"contents": "read"},
        }
        _, response = self._request(
            "POST",
            path,
            self._credentials.app_jwt,
            body,
            expected_status=201,
        )
        trace.append(GitHubReadRequest("POST", path, "app_jwt"))
        value = _object(response)
        token = value.get("token")
        expires_at = value.get("expires_at")
        repositories = value.get("repositories")
        if (
            type(token) is not str
            or not token.strip()
            or value.get("permissions") != {"contents": "read", "metadata": "read"}
            or value.get("repository_selection") != "selected"
            or type(expires_at) is not str
            or type(repositories) is not list
            or len(repositories) != 1
        ):
            raise ValueError("installation token scope differs")
        self._verify_repository(repositories[0])
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", expires_at):
            raise ValueError("installation token expiry is malformed")
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        now = _utc_now()
        if expires <= now or expires > now + timedelta(minutes=65):
            raise ValueError("installation token expiry differs")
        return token

    def _verify_app(self, body: JsonValue) -> None:
        value = _object(body)
        owner = _object(value.get("owner"))
        if (
            value.get("id") != self._configuration.observer_app_id
            or value.get("slug") != self._configuration.observer_identity
            or value.get("name") != self._configuration.observer_app_name
            or value.get("permissions") != {"contents": "read", "metadata": "read"}
            or value.get("events") != []
            or value.get("public", False) is not False
            or value.get("webhook_active", False) is not False
            or owner.get("login") != self._configuration.owner
            or owner.get("id") != self._configuration.owner_id
            or owner.get("type") != "User"
        ):
            raise ValueError("observer App identity differs")

    def _verify_installation(self, body: JsonValue) -> None:
        value = _object(body)
        account = _object(value.get("account"))
        if (
            value.get("id") != self._configuration.observer_installation_id
            or value.get("app_id") != self._configuration.observer_app_id
            or value.get("app_slug") != self._configuration.observer_identity
            or value.get("repository_selection") != "selected"
            or value.get("target_id") != self._configuration.owner_id
            or value.get("target_type") != "User"
            or value.get("suspended_at") is not None
            or value.get("permissions") != {"contents": "read", "metadata": "read"}
            or value.get("events") != []
            or account.get("login") != self._configuration.owner
            or account.get("id") != self._configuration.owner_id
            or account.get("type") != "User"
        ):
            raise ValueError("observer installation identity differs")

    def _verify_repository(self, body: JsonValue) -> None:
        value = _object(body)
        owner = _object(value.get("owner"))
        if (
            value.get("id") != self._configuration.repository_id
            or value.get("name") != self._configuration.repo
            or value.get("full_name") != f"{self._configuration.owner}/{self._configuration.repo}"
            or owner.get("login") != self._configuration.owner
            or owner.get("id") != self._configuration.owner_id
            or owner.get("type") != "User"
        ):
            raise ValueError("candidate repository identity differs")


def _revalidate_request(
    request: MainPersonalExactCasCandidateObservationRequest,
    configuration: GitHubMainBaseReaderConfiguration,
) -> MainPersonalExactCasCandidateObservationRequest:
    if type(request) is not MainPersonalExactCasCandidateObservationRequest:
        raise TypeError("candidate observation request is required")
    checked = MainPersonalExactCasCandidateObservationRequest.model_validate(
        request.model_dump(mode="python"), strict=True
    )
    if (
        checked != request
        or checked.repository_digest != configuration.repository_digest
        or checked.candidate_ref != candidate_ref_for_operation(checked.operation_id)
    ):
        raise ValueError("candidate observation request is not exactly bound")
    return checked


def _object(value: object) -> dict[str, JsonValue]:
    if type(value) is not dict:
        raise ValueError("GitHub candidate object is malformed")
    return cast(dict[str, JsonValue], value)


def _parse_ref(body: JsonValue, expected_ref: str) -> tuple[str, str]:
    value = _object(body)
    obj = _object(value.get("object"))
    sha = obj.get("sha")
    if (
        value.get("ref") != expected_ref
        or obj.get("type") != "commit"
        or type(sha) is not str
        or _OBJECT.fullmatch(sha) is None
    ):
        raise ValueError("candidate ref topology is malformed")
    return sha, expected_ref


def _parse_commit(body: JsonValue, expected_sha: str) -> tuple[str, str, tuple[str, ...]]:
    value = _object(body)
    tree = _object(value.get("tree"))
    sha = value.get("sha")
    tree_sha = tree.get("sha")
    parents = value.get("parents")
    if (
        type(sha) is not str
        or sha != expected_sha
        or type(tree_sha) is not str
        or _OBJECT.fullmatch(tree_sha) is None
        or type(parents) is not list
    ):
        raise ValueError("candidate commit topology is malformed")
    parsed: list[str] = []
    for parent in cast(list[JsonValue], parents):
        item = _object(parent)
        parent_sha = item.get("sha")
        if type(parent_sha) is not str or _OBJECT.fullmatch(parent_sha) is None:
            raise ValueError("candidate parent topology is malformed")
        parsed.append(parent_sha)
    return sha, tree_sha, tuple(parsed)


def _safe_ref(sha: str, ref: str) -> dict[str, object]:
    return {"ref": ref, "object": {"type": "commit", "sha": sha}}


def _safe_app(body: JsonValue) -> dict[str, JsonValue]:
    value = _object(body)
    owner = _object(value["owner"])
    return {
        "id": value["id"],
        "name": value["name"],
        "slug": value["slug"],
        "owner": {key: owner[key] for key in ("login", "id", "type")},
        "permissions": value["permissions"],
        "events": value["events"],
    }


def _safe_installation(body: JsonValue) -> dict[str, JsonValue]:
    value = _object(body)
    account = _object(value["account"])
    result = {
        key: value[key]
        for key in (
            "id",
            "app_id",
            "app_slug",
            "repository_selection",
            "target_id",
            "target_type",
            "suspended_at",
            "permissions",
            "events",
        )
    }
    result["account"] = {key: account[key] for key in ("login", "id", "type")}
    return result


def _safe_repository(body: JsonValue) -> dict[str, JsonValue]:
    value = _object(body)
    owner = _object(value["owner"])
    return {
        "id": value["id"],
        "name": value["name"],
        "full_name": value["full_name"],
        "owner": {key: owner[key] for key in ("login", "id", "type")},
    }


def _unverifiable_policy(
    prerequisite: str, ruleset_digest: str | None = None
) -> tuple[MainPersonalExactCasCandidatePolicyEvidence, str]:
    policy = MainPersonalExactCasCandidatePolicyEvidence.build(
        namespace="refs/heads/avo/candidate/*",
        deletion_coverage="unverifiable",
        force_update_coverage="unverifiable",
        status="unverifiable",
        ruleset_digest=ruleset_digest,
        missing_prerequisite=prerequisite,
    )
    return policy, policy.evidence_digest


def _utc_now() -> datetime:
    return datetime.now(UTC)


# Descriptive aliases keep the leaf easy to discover without creating a
# second implementation or a broader provider capability.
GitHubCandidateObserver = GitHubCandidateRefObserver
GitHubCandidateObserverError = MainPersonalExactCasCandidateObservationError


__all__ = [
    "GitHubCandidateObserver",
    "GitHubCandidateObserverError",
    "GitHubCandidateReadProvenance",
    "GitHubCandidateReadWithProvenance",
    "GitHubCandidateRefObserver",
    "MainPersonalExactCasCandidateObservationError",
]
