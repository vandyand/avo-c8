"""Immutable, App-authenticated observation of one personal repository's main base.

The production reader owns its bounded GitHub transport.  Its only public
operation authenticates the installation and repository before reading the
main ref, its exact commit, and a final ref fence.  It has no provider mutation
surface and does not establish Phase-A or rollback authority by itself.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import cast

from avo_correlate.adapters.git.main_composition import MainBaseSnapshot
from avo_correlate.adapters.hosted_git.github import (
    GitHubRejected,
    GitHubTransportError,
    JsonBody,
    JsonValue,
    github_repository_digest,
)
from avo_correlate.adapters.hosted_git.github_transport import GitHubJsonTransport
from avo_correlate.domain.canonical import canonical_digest

from .github_read_provenance import (
    GitHubReadProvenance,
    GitHubReadRequest,
    GitHubReadWithProvenance,
)

_API_ORIGIN = "https://api.github.com"
_API_VERSION = "2022-11-28"
_TARGET_REF = "refs/heads/main"
_IMPLEMENTATION_ID = (
    "avo_correlate.adapters.hosted_git.github_main_base_reader.GitHubMainBaseReader"
)
_IMPLEMENTATION_VERSION = "1"
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_OWNER_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?\Z")
_REPO_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?\Z")
_APP_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?\Z")
_OBJECT_PATTERN = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_READER_IDENTITY = "github_main_base_reader"


class GitHubMainBaseReaderError(RuntimeError):
    """Value-free failure to authenticate or observe the protected base."""

    def __init__(self) -> None:
        super().__init__("trusted_main_base_unresolved")


@dataclass(frozen=True, slots=True)
class GitHubMainBaseReaderConfiguration:
    """Strict immutable constructor state for one observer installation."""

    owner: str
    owner_id: int
    repo: str
    repository_id: int
    repository_digest: str
    observer_identity: str
    observer_app_name: str
    observer_app_id: int
    observer_installation_id: int
    timeout_seconds: float = 30.0
    max_response_bytes: int = _MAX_RESPONSE_BYTES
    configuration_digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "configuration_digest", self._validated_digest())

    def assert_valid(self) -> None:
        """Recompute all semantic state so reflective tampering fails closed."""

        if self.configuration_digest != self._validated_digest():
            raise ValueError("GitHub main base reader configuration was modified")

    def _validated_digest(self) -> str:
        if (
            type(self.owner) is not str
            or _OWNER_PATTERN.fullmatch(self.owner) is None
            or type(self.repo) is not str
            or _REPO_PATTERN.fullmatch(self.repo) is None
        ):
            raise ValueError("invalid GitHub repository binding")
        if type(self.owner_id) is not int or self.owner_id <= 0:
            raise ValueError("repository owner ID must be positive")
        if type(self.repository_id) is not int or self.repository_id <= 0:
            raise ValueError("repository ID must be positive")
        if self.repository_digest != github_repository_digest(self.owner, self.repo):
            raise ValueError("repository digest does not match pinned GitHub repository")
        if (
            type(self.observer_identity) is not str
            or _APP_PATTERN.fullmatch(self.observer_identity) is None
        ):
            raise ValueError("observer App identity is invalid")
        if (
            type(self.observer_app_name) is not str
            or not self.observer_app_name
            or self.observer_app_name.strip() != self.observer_app_name
        ):
            raise ValueError("observer App name is required")
        if type(self.observer_app_id) is not int or self.observer_app_id <= 0:
            raise ValueError("observer App ID must be positive")
        if (
            type(self.observer_installation_id) is not int
            or self.observer_installation_id <= 0
        ):
            raise ValueError("observer installation ID must be positive")
        if (
            type(self.timeout_seconds) not in {int, float}
            or not math.isfinite(float(self.timeout_seconds))
            or self.timeout_seconds <= 0
            or self.timeout_seconds > 60
        ):
            raise ValueError("timeout must be between 0 and 60 seconds")
        if (
            type(self.max_response_bytes) is not int
            or self.max_response_bytes <= 0
            or self.max_response_bytes > _MAX_RESPONSE_BYTES
        ):
            raise ValueError("response bound must be positive and at most 4 MiB")
        return canonical_digest(
            {
                "api_origin": _API_ORIGIN,
                "api_version": _API_VERSION,
                "implementation_id": _IMPLEMENTATION_ID,
                "implementation_version": _IMPLEMENTATION_VERSION,
                "max_response_bytes": self.max_response_bytes,
                "observer_app_id": self.observer_app_id,
                "observer_app_name": self.observer_app_name,
                "observer_identity": self.observer_identity,
                "observer_installation_id": self.observer_installation_id,
                "owner": self.owner,
                "owner_id": self.owner_id,
                "repo": self.repo,
                "repository_digest": self.repository_digest,
                "repository_id": self.repository_id,
                "target_ref": _TARGET_REF,
                "timeout_seconds": float(self.timeout_seconds),
            }
        )


@dataclass(frozen=True, slots=True)
class GitHubMainBaseReaderCredentials:
    """One transient App JWT; installation credentials are never accepted."""

    app_jwt: str = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        self.assert_valid()

    def assert_valid(self) -> None:
        if type(self.app_jwt) is not str or not self.app_jwt.strip():
            raise ValueError("App JWT is required")


@dataclass(frozen=True, slots=True, init=False, repr=False)
class GitHubMainBaseReader:
    """Fixed-origin read-only observer for one App installation and repository."""

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

    def fresh_main_base(self) -> MainBaseSnapshot:
        """Authenticate the observer, then return one ref-fenced main snapshot."""

        return self.fresh_main_base_with_provenance().result

    def fresh_main_base_with_provenance(
        self,
    ) -> GitHubReadWithProvenance[MainBaseSnapshot]:
        """Return one authenticated base read and sanitized immutable provenance."""

        failure = False
        result: MainBaseSnapshot | None = None
        app: JsonValue | None = None
        installation: JsonValue | None = None
        repository: JsonValue | None = None
        initial_ref: JsonValue | None = None
        commit_body: JsonValue | None = None
        final_ref: JsonValue | None = None
        try:
            self._configuration.assert_valid()
            self._credentials.assert_valid()
            app = self._get("/app", self._credentials.app_jwt)
            self._verify_app(app)
            installation = self._get(
                f"/app/installations/{self._configuration.observer_installation_id}",
                self._credentials.app_jwt,
            )
            self._verify_installation(installation)
            installation_token = self._mint_installation_token(
                self._credentials.app_jwt
            )
            repository = self._get(
                f"/repositories/{self._configuration.repository_id}",
                installation_token,
            )
            self._verify_repository(repository)
            initial_ref = self._get(
                f"/repos/{self._configuration.owner}/{self._configuration.repo}"
                "/git/ref/heads/main",
                installation_token,
            )
            commit = _parse_ref(initial_ref)
            commit_body = self._get(
                f"/repos/{self._configuration.owner}/{self._configuration.repo}"
                f"/git/commits/{commit}",
                installation_token,
            )
            observed_commit, tree = _parse_commit(commit_body, commit)
            final_ref = self._get(
                f"/repos/{self._configuration.owner}/{self._configuration.repo}"
                "/git/ref/heads/main",
                installation_token,
            )
            fenced_commit = _parse_ref(final_ref)
            if fenced_commit != commit or observed_commit != commit:
                raise ValueError("main ref drifted during observation")
            result = MainBaseSnapshot(
                repository_digest=self._configuration.repository_digest,
                commit=commit,
                tree=tree,
                target_ref=_TARGET_REF,
            )
        except (
            GitHubMainBaseReaderError,
            GitHubRejected,
            GitHubTransportError,
            ValueError,
            TypeError,
            KeyError,
        ):
            failure = True
        except Exception:
            failure = True
        if failure or result is None:
            raise GitHubMainBaseReaderError()
        assert app is not None
        assert installation is not None
        assert repository is not None
        assert initial_ref is not None
        assert commit_body is not None
        assert final_ref is not None
        provenance = GitHubReadProvenance(
            reader_identity=_READER_IDENTITY,
            api_origin=_API_ORIGIN,
            api_version=_API_VERSION,
            owner=self._configuration.owner,
            owner_id=self._configuration.owner_id,
            repository=self._configuration.repo,
            repository_id=self._configuration.repository_id,
            repository_digest=self._configuration.repository_digest,
            target_ref=_TARGET_REF,
            app_slug=self._configuration.observer_identity,
            app_id=self._configuration.observer_app_id,
            installation_id=self._configuration.observer_installation_id,
            requested_repository_id=self._configuration.repository_id,
            requested_permissions=("contents:read",),
            observed_permissions=("contents:read", "metadata:read"),
            repository_selection="selected",
            token_expiry_policy="now<expires_at<=now+65m",
            requests=(
                GitHubReadRequest("GET", "/app", "app_jwt"),
                GitHubReadRequest(
                    "GET",
                    f"/app/installations/{self._configuration.observer_installation_id}",
                    "app_jwt",
                ),
                GitHubReadRequest(
                    "POST",
                    f"/app/installations/{self._configuration.observer_installation_id}"
                    "/access_tokens",
                    "app_jwt",
                ),
                GitHubReadRequest(
                    "GET",
                    f"/repositories/{self._configuration.repository_id}",
                    "installation_token",
                ),
                GitHubReadRequest(
                    "GET",
                    f"/repos/{self._configuration.owner}/{self._configuration.repo}"
                    "/git/ref/heads/main",
                    "installation_token",
                ),
                GitHubReadRequest(
                    "GET",
                    f"/repos/{self._configuration.owner}/{self._configuration.repo}"
                    f"/git/commits/{result.commit}",
                    "installation_token",
                ),
                GitHubReadRequest(
                    "GET",
                    f"/repos/{self._configuration.owner}/{self._configuration.repo}"
                    "/git/ref/heads/main",
                    "installation_token",
                ),
            ),
            endpoint_observation_digests=tuple(
                sorted(
                    (
                        ("app", canonical_digest(_safe_app_facts(app))),
                        ("installation", canonical_digest(_safe_installation_facts(installation))),
                        ("repository", canonical_digest(_safe_repository_facts(repository))),
                    )
                )
            ),
            initial_ref_digest=canonical_digest(initial_ref),
            commit_digest=canonical_digest(_safe_commit_facts(result.commit, result.tree)),
            final_ref_digest=canonical_digest(final_ref),
        )
        return GitHubReadWithProvenance(result=result, provenance=provenance)

    def _get(self, path: str, token: str) -> JsonValue:
        return self._request("GET", path, None, token, expected_status=200)

    def _request(
        self,
        method: str,
        path: str,
        body: JsonBody | None,
        token: str,
        *,
        expected_status: int,
    ) -> JsonValue:
        failure = False
        result: tuple[int, JsonValue] | None = None
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "X-GitHub-Api-Version": _API_VERSION,
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            result = self._transport(
                method,
                _API_ORIGIN + path,
                body,
                headers,
            )
        except (GitHubRejected, GitHubTransportError):
            failure = True
        except Exception:
            failure = True
        if failure or result is None:
            raise GitHubMainBaseReaderError()
        status, response_body = result
        if type(status) is not int or status != expected_status:
            raise GitHubMainBaseReaderError()
        return response_body

    def _mint_installation_token(self, app_jwt: str) -> str:
        body = self._request(
            "POST",
            f"/app/installations/{self._configuration.observer_installation_id}"
            "/access_tokens",
            {
                "repository_ids": [self._configuration.repository_id],
                "permissions": {"contents": "read"},
            },
            app_jwt,
            expected_status=201,
        )
        if type(body) is not dict:
            raise ValueError("malformed installation token")
        value = cast(dict[str, JsonValue], body)
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
        ):
            raise ValueError("installation token scope differs")
        typed_repositories = cast(list[JsonValue], repositories)
        if len(typed_repositories) != 1:
            raise ValueError("installation token repository scope differs")
        self._verify_repository(typed_repositories[0])
        expires = _parse_github_timestamp(expires_at)
        now = _utc_now()
        if expires <= now or expires > now + timedelta(minutes=65):
            raise ValueError("installation token expiry differs")
        return token

    def _verify_app(self, body: JsonValue) -> None:
        if type(body) is not dict:
            raise ValueError("malformed App")
        value = cast(dict[str, JsonValue], body)
        owner = value.get("owner")
        typed_owner = cast(dict[str, JsonValue], owner) if type(owner) is dict else None
        if (
            value.get("id") != self._configuration.observer_app_id
            or value.get("slug") != self._configuration.observer_identity
            or value.get("name") != self._configuration.observer_app_name
            or value.get("permissions") != {"contents": "read", "metadata": "read"}
            or value.get("events") != []
            or value.get("public") is not False
            or value.get("webhook_active") is not False
            or typed_owner is None
            or typed_owner.get("login") != self._configuration.owner
            or typed_owner.get("id") != self._configuration.owner_id
            or typed_owner.get("type") != "User"
        ):
            raise ValueError("observer App identity differs")

    def _verify_installation(self, body: JsonValue) -> None:
        if type(body) is not dict:
            raise ValueError("malformed installation")
        value = cast(dict[str, JsonValue], body)
        account = value.get("account")
        typed_account = cast(dict[str, JsonValue], account) if type(account) is dict else None
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
            or typed_account is None
            or typed_account.get("login") != self._configuration.owner
            or typed_account.get("id") != self._configuration.owner_id
            or typed_account.get("type") != "User"
        ):
            raise ValueError("observer installation identity differs")

    def _verify_repository(self, body: JsonValue) -> None:
        if type(body) is not dict:
            raise ValueError("malformed repository")
        repository = cast(dict[str, JsonValue], body)
        owner = repository.get("owner")
        typed_owner = cast(dict[str, JsonValue], owner) if type(owner) is dict else None
        if (
            repository.get("id") != self._configuration.repository_id
            or repository.get("name") != self._configuration.repo
            or repository.get("full_name")
            != f"{self._configuration.owner}/{self._configuration.repo}"
            or typed_owner is None
            or typed_owner.get("login") != self._configuration.owner
            or typed_owner.get("id") != self._configuration.owner_id
            or typed_owner.get("type") != "User"
        ):
            raise ValueError("repository identity differs")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _parse_github_timestamp(value: str) -> datetime:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ValueError("malformed GitHub timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("malformed GitHub timestamp")
    return parsed


def _parse_ref(body: JsonValue) -> str:
    if type(body) is not dict:
        raise ValueError("malformed ref")
    value = cast(dict[str, JsonValue], body)
    obj = value.get("object")
    typed_object = cast(dict[str, JsonValue], obj) if type(obj) is dict else None
    sha = typed_object.get("sha") if typed_object is not None else None
    if (
        value.get("ref") != _TARGET_REF
        or typed_object is None
        or typed_object.get("type") != "commit"
        or type(sha) is not str
        or _OBJECT_PATTERN.fullmatch(sha) is None
    ):
        raise ValueError("malformed ref topology")
    return sha


def _parse_commit(body: JsonValue, expected_sha: str) -> tuple[str, str]:
    if type(body) is not dict:
        raise ValueError("malformed commit")
    value = cast(dict[str, JsonValue], body)
    sha = value.get("sha")
    tree = value.get("tree")
    parents = value.get("parents")
    typed_tree = cast(dict[str, JsonValue], tree) if type(tree) is dict else None
    tree_sha = typed_tree.get("sha") if typed_tree is not None else None
    if (
        type(sha) is not str
        or sha != expected_sha
        or typed_tree is None
        or type(tree_sha) is not str
        or _OBJECT_PATTERN.fullmatch(tree_sha) is None
        or type(parents) is not list
    ):
        raise ValueError("malformed commit topology")
    for parent in cast(list[JsonValue], parents):
        typed_parent = cast(dict[str, JsonValue], parent) if type(parent) is dict else None
        parent_sha = typed_parent.get("sha") if typed_parent is not None else None
        if (
            typed_parent is None
            or type(parent_sha) is not str
            or _OBJECT_PATTERN.fullmatch(parent_sha) is None
        ):
            raise ValueError("malformed parent topology")
    return sha, tree_sha


def _safe_app_facts(value: JsonValue) -> dict[str, JsonValue]:
    body = cast(dict[str, JsonValue], value)
    return {
        "id": body["id"],
        "name": body["name"],
        "owner": body["owner"],
        "permissions": body["permissions"],
        "slug": body["slug"],
        "events": body["events"],
    }


def _safe_installation_facts(value: JsonValue) -> dict[str, JsonValue]:
    body = cast(dict[str, JsonValue], value)
    return {
        "account": body["account"],
        "app_id": body["app_id"],
        "app_slug": body["app_slug"],
        "events": body["events"],
        "id": body["id"],
        "permissions": body["permissions"],
        "repository_selection": body["repository_selection"],
        "suspended_at": body["suspended_at"],
        "target_id": body["target_id"],
        "target_type": body["target_type"],
    }


def _safe_repository_facts(value: JsonValue) -> dict[str, JsonValue]:
    body = cast(dict[str, JsonValue], value)
    return {
        "full_name": body["full_name"],
        "id": body["id"],
        "name": body["name"],
        "owner": body["owner"],
    }


def _safe_commit_facts(commit: str, tree: str) -> dict[str, str]:
    return {"commit": commit, "tree": tree}


__all__ = [
    "GitHubMainBaseReader",
    "GitHubMainBaseReaderConfiguration",
    "GitHubMainBaseReaderCredentials",
    "GitHubMainBaseReaderError",
    "GitHubReadProvenance",
    "GitHubReadRequest",
    "GitHubReadWithProvenance",
]
