"""Fixed, bounded GitHub transport for creating one candidate ref.

This adapter has exactly one mutating operation: POST git/refs.  It emits
nonterminal evidence and never decides readiness, completion, or deployment.
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
from avo_correlate.adapters.hosted_git.github_transport import GitHubJsonTransport
from avo_correlate.contracts.main_personal_exact_cas_candidate_publication import (
    CandidatePublisherRequestTrace,
    MainPersonalExactCasCandidatePublicationDispatchStarted,
    MainPersonalExactCasCandidatePublicationIntent,
    MainPersonalExactCasCandidatePublicationResponseEvidence,
    candidate_publication_request_digest,
)
from avo_correlate.domain.canonical import canonical_digest

_ORIGIN = "https://api.github.com"
_VERSION = "2022-11-28"
_OWNER = "vandyand"
_REPO = "avo-c8"
_REPOSITORY_ID = 1354880741
_IDENTITY = "avo-c8-candidate-publisher-vandyand"
_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_EXPIRY = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class GitHubCandidatePublisherError(RuntimeError):
    def __init__(self, code: str = "candidate_publication_unresolved") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class GitHubCandidatePublisherConfiguration:
    owner: Literal["vandyand"] = _OWNER
    repository: Literal["avo-c8"] = _REPO
    repository_id: int = _REPOSITORY_ID
    app_id: int = 0
    installation_id: int = 0
    app_name: Literal["avo-c8-candidate-publisher-vandyand"] = _IDENTITY
    timeout_seconds: float = 30.0
    max_response_bytes: int = 4 * 1024 * 1024
    configuration_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if self.repository_id != _REPOSITORY_ID or self.owner != _OWNER or self.repository != _REPO:
            raise ValueError("candidate publisher repository is fixed")
        if self.app_id <= 0 or self.installation_id <= 0:
            raise ValueError("candidate publisher App and installation are not provisioned")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 60 or self.max_response_bytes <= 0:
            raise ValueError("candidate publisher bounds are invalid")
        object.__setattr__(self, "configuration_digest", canonical_digest(self._payload()))

    def _payload(self) -> dict[str, object]:
        return {
            "owner": self.owner,
            "repository": self.repository,
            "repository_id": self.repository_id,
            "app_id": self.app_id,
            "installation_id": self.installation_id,
            "app_name": self.app_name,
            "timeout_seconds": self.timeout_seconds,
            "max_response_bytes": self.max_response_bytes,
        }


@dataclass(frozen=True, slots=True, repr=False)
class GitHubCandidatePublisherCredentials:
    app_jwt: str = field(repr=False, compare=False)

    def assert_valid(self) -> None:
        if type(self.app_jwt) is not str or not self.app_jwt.strip():
            raise ValueError("candidate publisher App JWT is missing")

    def __repr__(self) -> str:
        return "GitHubCandidatePublisherCredentials(app_jwt=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False, init=False)
class GitHubCandidateRefPublisher:
    _configuration: GitHubCandidatePublisherConfiguration
    _credentials: GitHubCandidatePublisherCredentials = field(repr=False, compare=False)
    _transport: GitHubJsonTransport = field(repr=False, compare=False)

    def __init__(
        self,
        configuration: GitHubCandidatePublisherConfiguration,
        credentials: GitHubCandidatePublisherCredentials,
    ) -> None:
        if (
            type(configuration) is not GitHubCandidatePublisherConfiguration
            or type(credentials) is not GitHubCandidatePublisherCredentials
        ):
            raise TypeError("exact candidate publisher configuration and credentials are required")
        credentials.assert_valid()
        object.__setattr__(self, "_configuration", configuration)
        object.__setattr__(self, "_credentials", credentials)
        object.__setattr__(
            self,
            "_transport",
            GitHubJsonTransport(
                origin=_ORIGIN,
                timeout_seconds=configuration.timeout_seconds,
                max_response_bytes=configuration.max_response_bytes,
            ),
        )

    @property
    def configuration_digest(self) -> str:
        return self._configuration.configuration_digest

    @property
    def repository_id(self) -> int:
        return self._configuration.repository_id

    def create(
        self,
        intent: MainPersonalExactCasCandidatePublicationIntent,
        marker: MainPersonalExactCasCandidatePublicationDispatchStarted,
    ) -> MainPersonalExactCasCandidatePublicationResponseEvidence:
        checked = self._check_inputs(intent, marker)
        trace: list[CandidatePublisherRequestTrace] = []
        observed_at = datetime.now(UTC)
        status = 599
        body: JsonValue = {}
        try:
            app_status, app = self._call("GET", "/app", None, self._credentials.app_jwt, trace)
            if app_status != 200:
                return self._evidence(checked, marker, app_status, app, trace, observed_at)
            self._verify_app(app)
            installation_path = f"/app/installations/{self._configuration.installation_id}"
            installation_status, installation = self._call(
                "GET", installation_path, None, self._credentials.app_jwt, trace
            )
            if installation_status != 200:
                return self._evidence(
                    checked, marker, installation_status, installation, trace, observed_at
                )
            self._verify_installation(installation)
            token_path = f"{installation_path}/access_tokens"
            token_body: JsonBody = {
                "repository_ids": [_REPOSITORY_ID],
                "permissions": {"contents": "write"},
            }
            status, body = self._call(
                "POST", token_path, token_body, self._credentials.app_jwt, trace
            )
            if status != 201:
                return self._evidence(checked, marker, status, body, trace, observed_at)
            token = self._verify_mint(body)
            repository_status, repository = self._call(
                "GET", f"/repositories/{_REPOSITORY_ID}", None, token, trace
            )
            if repository_status != 200:
                return self._evidence(
                    checked, marker, repository_status, repository, trace, observed_at
                )
            self._verify_repository(repository)
            ref_path = f"/repos/{_OWNER}/{_REPO}/git/refs"
            request_body: JsonBody = {"ref": checked.candidate_ref, "sha": checked.candidate_commit}
            status, body = self._call("POST", ref_path, request_body, token, trace)
            return self._evidence(checked, marker, status, body, trace, observed_at)
        except GitHubRejected as exc:
            return self._evidence(checked, marker, exc.status or 599, {}, trace, observed_at)
        except (GitHubTransportError, ValueError, TypeError):
            return self._evidence(checked, marker, 599, {}, trace, observed_at)

    def _check_inputs(
        self,
        intent: MainPersonalExactCasCandidatePublicationIntent,
        marker: MainPersonalExactCasCandidatePublicationDispatchStarted,
    ) -> MainPersonalExactCasCandidatePublicationIntent:
        if (
            type(intent) is not MainPersonalExactCasCandidatePublicationIntent
            or type(marker) is not MainPersonalExactCasCandidatePublicationDispatchStarted
        ):
            raise TypeError("candidate publication intent and marker are required")
        checked = MainPersonalExactCasCandidatePublicationIntent.model_validate(
            intent.model_dump(mode="python"), strict=True
        )
        if (
            checked != intent
            or marker.intent_digest != intent.intent_digest
            or marker.configuration_digest != self.configuration_digest
            or intent.configuration_digest != self.configuration_digest
        ):
            raise ValueError("candidate publication inputs are not exactly bound")
        return checked

    def _call(
        self,
        method: Literal["GET", "POST"],
        path: str,
        body: JsonBody | None,
        token: str,
        trace: list[CandidatePublisherRequestTrace],
    ) -> tuple[int, JsonValue]:
        role: Literal["app_jwt", "installation_token"] = (
            "app_jwt" if token == self._credentials.app_jwt else "installation_token"
        )
        trace.append(CandidatePublisherRequestTrace(method=method, path=path, credential_role=role))
        return self._transport(
            method,
            _ORIGIN + path,
            body,
            {
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + token,
                "X-GitHub-Api-Version": _VERSION,
                **({"Content-Type": "application/json"} if body is not None else {}),
            },
        )

    def _evidence(
        self,
        intent: MainPersonalExactCasCandidatePublicationIntent,
        marker: MainPersonalExactCasCandidatePublicationDispatchStarted,
        status: int,
        body: JsonValue,
        trace: list[CandidatePublisherRequestTrace],
        observed_at: datetime,
    ) -> MainPersonalExactCasCandidatePublicationResponseEvidence:
        parsed = body if type(body) is dict else {}
        response_ref: str | None = None
        response_sha: str | None = None
        if status == 201:
            obj = parsed.get("object")
            if (
                isinstance(obj, dict)
                and parsed.get("ref") == intent.candidate_ref
                and obj.get("type") == "commit"
                and type(obj.get("sha")) is str
                and _OBJECT.fullmatch(cast(str, obj["sha"]))
            ):
                response_ref = cast(str, parsed["ref"])
                response_sha = cast(str, obj["sha"])
            else:
                status = 599
        return MainPersonalExactCasCandidatePublicationResponseEvidence.build(
            operation_id=intent.operation_id,
            repository_digest=intent.repository_digest,
            repository_id=intent.repository_id,
            candidate_ref=intent.candidate_ref,
            candidate_commit=intent.candidate_commit,
            intent_digest=intent.intent_digest,
            dispatch_marker_digest=marker.dispatch_marker_digest,
            configuration_digest=intent.configuration_digest,
            request_digest=candidate_publication_request_digest(
                repository_digest=intent.repository_digest,
                repository_id=intent.repository_id,
                candidate_ref=intent.candidate_ref,
                candidate_commit=intent.candidate_commit,
            ),
            response_status=status,
            response_classification="created"
            if status == 201
            else "conflict_or_rejected"
            if status in {409, 422}
            else "authentication_or_authorization_rejected"
            if status in {401, 403}
            else "rate_limited"
            if status == 429
            else "ambiguous"
            if status >= 500
            else "unverifiable",
            response_ref=response_ref,
            response_sha=response_sha,
            response_payload_digest=canonical_digest(parsed),
            response_request_id=None,
            response_metadata={},
            requests=tuple(trace),
            observed_at=observed_at,
        )

    def _verify_app(self, body: JsonValue) -> None:
        value = _object(body)
        owner = _object(value.get("owner"))
        if (
            value.get("id") != self._configuration.app_id
            or value.get("slug") != _IDENTITY
            or value.get("name") != _IDENTITY
            or value.get("permissions") != {"contents": "write", "metadata": "read"}
            or value.get("events") != []
            or owner.get("login") != _OWNER
        ):
            raise ValueError("publisher App identity differs")

    def _verify_installation(self, body: JsonValue) -> None:
        value = _object(body)
        account = _object(value.get("account"))
        if (
            value.get("id") != self._configuration.installation_id
            or value.get("app_id") != self._configuration.app_id
            or value.get("app_slug") != _IDENTITY
            or value.get("repository_selection") != "selected"
            or account.get("login") != _OWNER
        ):
            raise ValueError("publisher installation identity differs")

    def _verify_mint(self, body: JsonValue) -> str:
        value = _object(body)
        token = value.get("token")
        if (
            type(token) is not str
            or not token.strip()
            or value.get("permissions") != {"contents": "write", "metadata": "read"}
            or value.get("repository_selection") != "selected"
        ):
            raise ValueError("publisher token scope differs")
        repositories = value.get("repositories")
        if type(repositories) is not list or len(repositories) != 1:
            raise ValueError("publisher token repository selection differs")
        self._verify_repository(repositories[0])
        expires = value.get("expires_at")
        if type(expires) is not str or _EXPIRY.fullmatch(expires) is None:
            raise ValueError("publisher token expiry is malformed")
        when = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        if when <= datetime.now(UTC) or when > datetime.now(UTC) + timedelta(minutes=65):
            raise ValueError("publisher token expiry is outside bound")
        return token

    @staticmethod
    def _verify_repository(body: JsonValue) -> None:
        value = _object(body)
        owner = _object(value.get("owner"))
        if (
            value.get("id") != _REPOSITORY_ID
            or value.get("name") != _REPO
            or value.get("full_name") != f"{_OWNER}/{_REPO}"
            or owner.get("login") != _OWNER
        ):
            raise ValueError("publisher repository identity differs")


def _object(value: object) -> dict[str, JsonValue]:
    if type(value) is not dict:
        raise ValueError("GitHub response object is malformed")
    return cast(dict[str, JsonValue], value)


GitHubCandidatePublisher = GitHubCandidateRefPublisher
GitHubCandidatePublisherConfig = GitHubCandidatePublisherConfiguration


__all__ = [
    "GitHubCandidatePublisher",
    "GitHubCandidatePublisherConfig",
    "GitHubCandidatePublisherConfiguration",
    "GitHubCandidatePublisherCredentials",
    "GitHubCandidatePublisherError",
    "GitHubCandidateRefPublisher",
]
