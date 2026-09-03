"""Read-only exact hosted-configuration verification for personal main CAS."""

from __future__ import annotations

import copy
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, cast

from avo_correlate.contracts.main_personal_exact_cas import GitObject
from avo_correlate.contracts.main_personal_exact_cas_hosted_configuration import (
    MainPersonalExactCasHostedConfigurationDiagnostic,
)
from avo_correlate.domain.canonical import canonical_digest

from .github import JsonBody, JsonObject, JsonValue, github_repository_digest
from .github_read_provenance import (
    GitHubReadProvenance,
    GitHubReadRequest,
    GitHubReadWithProvenance,
)
from .github_transport import GitHubJsonTransport

_API_ORIGIN = "https://api.github.com"
_API_VERSION = "2022-11-28"
_OWNER = "vandyand"
_REPOSITORY = "avo-c8"
_REPOSITORY_ID = 1_354_880_741
_APP_SLUG = "avo-c8-main-writer-vandyand"
_TARGET_REF = "refs/heads/main"
_ROLLBACK_REF = "refs/heads/avo/main-rollback/*"
_MAX_PAGES = 10
_PAGE_SIZE = 100
_MAX_OBSERVATION = timedelta(minutes=5)
_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_GITHUB_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_READER_IDENTITY = "main_personal_exact_cas_hosted_configuration_verifier"


class MainPersonalExactCasHostedConfigurationUnverified(RuntimeError):
    """A value-free hosted configuration verification failure."""

    def __init__(self) -> None:
        super().__init__("hosted_configuration_unverified")

    def __repr__(self) -> str:
        return "MainPersonalExactCasHostedConfigurationUnverified()"


@dataclass(frozen=True)
class _Ruleset:
    ident: int
    name: str
    digest: str
    role: str


@dataclass(frozen=True)
class _ConfigurationPass:
    owner_id: int
    writer: _Ruleset
    safety: _Ruleset
    rollback: _Ruleset
    app_id: int
    installation_id: int
    branch_protection_digest: str
    app_configuration_digest: str
    installation_configuration_digest: str
    selected_repositories_digest: str
    raw_digest: str
    ruleset_request_ids: tuple[int, ...]


class MainPersonalExactCasGitHubHostedConfigurationVerifier:
    """Verify the one selected personal repository/App configuration exactly."""

    def __init__(
        self,
        *,
        owner_admin_token: str,
        app_jwt: str,
        trusted_clock: Callable[[], datetime],
        transport: Callable[
            [str, str, JsonBody | None, Mapping[str, str]], tuple[int, JsonValue]
        ]
        | None = None,
    ) -> None:
        if type(owner_admin_token) is not str or not owner_admin_token.strip():
            raise ValueError("GitHub owner/admin read token is required")
        if type(app_jwt) is not str or not app_jwt.strip():
            raise ValueError("GitHub App JWT is required")
        if not callable(trusted_clock):
            raise ValueError("trusted clock is required")
        self._owner_admin_token = owner_admin_token
        self._app_jwt = app_jwt
        self._clock = trusted_clock
        self._transport = transport or GitHubJsonTransport(origin=_API_ORIGIN)

    def verify(self) -> MainPersonalExactCasHostedConfigurationDiagnostic:
        """Perform two complete reads and fence them by the exact main ref."""

        wrapped: Any = self.verify_with_provenance()
        return cast(MainPersonalExactCasHostedConfigurationDiagnostic, wrapped.result)

    def verify_with_provenance(
        self,
    ) -> GitHubReadWithProvenance[MainPersonalExactCasHostedConfigurationDiagnostic]:
        """Return one exact configuration result and immutable read provenance."""

        result: MainPersonalExactCasHostedConfigurationDiagnostic | None = None
        failed = False
        requests: list[GitHubReadRequest] = []
        observed_owner_id = 0
        observed_app_id = 0
        observed_installation_id = 0
        try:
            started = self._now()
            initial_commit, initial_ref_digest = self._read_main_ref(requests)
            first = self._configuration_pass(requests)
            second = self._configuration_pass(requests)
            observed_owner_id = first.owner_id
            observed_app_id = first.app_id
            observed_installation_id = first.installation_id
            final_commit, final_ref_digest = self._read_main_ref(requests)
            finished = self._now()
            if (
                initial_commit != final_commit
                or first != second
                or first.raw_digest != second.raw_digest
                or finished < started
                or finished - started > _MAX_OBSERVATION
            ):
                raise ValueError("configuration observation drifted")
            if tuple(requests) != _expected_trace(first, second):
                raise ValueError("authenticated read trace is incomplete")
            result = MainPersonalExactCasHostedConfigurationDiagnostic.build(
                repository_digest=github_repository_digest(_OWNER, _REPOSITORY),
                owner=_OWNER,
                repository=_REPOSITORY,
                repository_id=_REPOSITORY_ID,
                owner_id=first.owner_id,
                owner_type="User",
                visibility="public",
                target_ref=_TARGET_REF,
                main_commit=initial_commit,
                writer_ruleset_id=first.writer.ident,
                writer_ruleset_name=first.writer.name,
                safety_ruleset_id=first.safety.ident,
                safety_ruleset_name=first.safety.name,
                writer_app_id=first.app_id,
                writer_app_slug=_APP_SLUG,
                writer_app_name=_APP_SLUG,
                writer_app_homepage="https://github.com/vandyand/avo-c8",
                writer_installation_id=first.installation_id,
                repository_selection="selected",
                selected_repository_ids=(_REPOSITORY_ID,),
                contents_permission="write",
                metadata_permission="read",
                subscribed_events=(),
                writer_ruleset_digest=first.writer.digest,
                safety_ruleset_digest=first.safety.digest,
                branch_protection_digest=first.branch_protection_digest,
                app_configuration_digest=first.app_configuration_digest,
                installation_configuration_digest=first.installation_configuration_digest,
                selected_repositories_digest=first.selected_repositories_digest,
                initial_ref_digest=initial_ref_digest,
                first_pass_digest=first.raw_digest,
                second_pass_digest=second.raw_digest,
                final_ref_digest=final_ref_digest,
                started_at=started,
                finished_at=finished,
            )
        except Exception:
            failed = True
        if failed or result is None:
            error = MainPersonalExactCasHostedConfigurationUnverified()
            error.__cause__ = None
            error.__context__ = None
            raise error
        typed_result = result
        provenance = GitHubReadProvenance(
                reader_identity=_READER_IDENTITY,
                api_origin=_API_ORIGIN,
                api_version=_API_VERSION,
                owner=_OWNER,
                owner_id=observed_owner_id,
                repository=_REPOSITORY,
                repository_id=_REPOSITORY_ID,
                repository_digest=typed_result.repository_digest,
                target_ref=_TARGET_REF,
                app_slug=_APP_SLUG,
                app_id=observed_app_id,
                installation_id=observed_installation_id,
                requested_repository_id=_REPOSITORY_ID,
                requested_permissions=("contents:read",),
                observed_permissions=("contents:read", "metadata:read"),
                repository_selection="selected",
                token_expiry_policy="now<expires_at<=now+65m",
                requests=tuple(requests),
                endpoint_observation_digests=tuple(
                    sorted(
                        (
                            ("app", typed_result.app_configuration_digest),
                            ("installation", typed_result.installation_configuration_digest),
                            ("repository", typed_result.repository_digest),
                            ("selected_repositories", typed_result.selected_repositories_digest),
                        )
                    )
                ),
                initial_ref_digest=typed_result.initial_ref_digest,
                commit_digest=canonical_digest({"commit": typed_result.main_commit}),
                final_ref_digest=typed_result.final_ref_digest,
                configuration_pass_digests=(
                    typed_result.first_pass_digest,
                    typed_result.second_pass_digest,
                ),
                configuration_digest=typed_result.configuration_digest,
            )
        return GitHubReadWithProvenance(result=typed_result, provenance=provenance)

    def _configuration_pass(self, trace: list[GitHubReadRequest]) -> _ConfigurationPass:
        raw: dict[str, JsonValue] = {}
        repo = self._object(self._get(self._repo_path(), self._owner_admin_token, trace))
        raw["repository"] = repo
        owner_id = self._verify_repository(repo)

        app = self._object(self._get("/app", self._app_jwt, trace))
        raw["app"] = app
        app_id = self._verify_app(app, owner_id)

        installations, installation_raw = self._read_array_pages(
            "/app/installations", self._app_jwt, trace
        )
        raw["installations"] = installation_raw
        if len(installations) != 1:
            raise ValueError("App installation is not exclusive")
        installation = self._object(installations[0])
        installation_id = self._verify_installation(installation, app_id, owner_id)
        installation_token = self._mint_read_token(installation_id, owner_id, trace)

        repositories, selected_raw = self._read_object_pages(
            "/installation/repositories", "repositories", installation_token, trace
        )
        raw["selected_repositories"] = selected_raw
        if len(repositories) != 1:
            raise ValueError("selected repository set is not exact")
        self._verify_selected_repository(self._object(repositories[0]), owner_id)

        summaries, ruleset_raw = self._read_array_pages(
            self._repo_path() + "/rulesets", self._owner_admin_token, trace
        )
        raw["rulesets"] = ruleset_raw
        if len(summaries) != 3:
            raise ValueError("ruleset set is not exact")
        details: list[JsonObject] = []
        ruleset_request_ids: list[int] = []
        seen: set[int] = set()
        for summary_value in summaries:
            summary = self._object(summary_value)
            ident = self._positive_int(summary, "id")
            ruleset_request_ids.append(ident)
            if ident in seen:
                raise ValueError("duplicate ruleset identity")
            seen.add(ident)
            self._verify_ruleset_summary(summary)
            detail = self._object(
                self._get(
                    self._repo_path() + f"/rulesets/{ident}", self._owner_admin_token, trace
                )
            )
            self._verify_summary_detail(summary, detail)
            details.append(detail)
        details.sort(key=lambda item: self._positive_int(item, "id"))
        raw["ruleset_details"] = cast(JsonValue, details)
        writer, safety, rollback = self._classify_rulesets(details, app_id)

        protection = self._object(
            self._get(
                self._repo_path() + "/branches/main/protection", self._owner_admin_token, trace
            )
        )
        raw["branch_protection"] = protection
        self._verify_branch_protection(protection)
        return _ConfigurationPass(
            owner_id=owner_id,
            writer=writer,
            safety=safety,
            rollback=rollback,
            app_id=app_id,
            installation_id=installation_id,
            branch_protection_digest=canonical_digest(protection),
            app_configuration_digest=canonical_digest(app),
            installation_configuration_digest=canonical_digest(installation),
            selected_repositories_digest=canonical_digest(selected_raw),
            raw_digest=canonical_digest(raw),
            ruleset_request_ids=tuple(ruleset_request_ids),
        )

    def _mint_read_token(
        self, installation_id: int, owner_id: int, trace: list[GitHubReadRequest]
    ) -> str:
        """Mint and validate the exact read-scoped token for this pass."""

        body: JsonBody = {
            "repository_ids": [_REPOSITORY_ID],
            "permissions": {"contents": "read"},
        }
        status, value = self._transport(
            "POST",
            _API_ORIGIN + f"/app/installations/{installation_id}/access_tokens",
            body,
            {
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self._app_jwt,
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": _API_VERSION,
            },
        )
        if type(status) is not int or status != 201:
            raise ValueError("installation token mint failed")
        trace.append(
            GitHubReadRequest(
                "POST",
                f"/app/installations/{installation_id}/access_tokens",
                "app_jwt",
            )
        )
        result = self._object(value)
        token = self._string(result, "token")
        expires_at = self._string(result, "expires_at")
        if _GITHUB_TIMESTAMP_PATTERN.fullmatch(expires_at) is None:
            raise ValueError("installation token expiry is malformed")
        if (
            result.get("permissions") != {"contents": "read", "metadata": "read"}
            or result.get("repository_selection") != "selected"
        ):
            raise ValueError("installation token scope is not exact")
        repositories = result.get("repositories")
        if type(repositories) is not list or len(repositories) != 1:
            raise ValueError("installation token repository scope is not exact")
        self._verify_selected_repository(self._object(repositories[0]), owner_id)
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            raise ValueError("installation token expiry is malformed") from None
        now = self._now()
        if (
            expiry.tzinfo is None
            or expiry.utcoffset() is None
            or expiry.utcoffset() != timedelta(0)
            or not (now < expiry <= now + timedelta(minutes=65))
        ):
            raise ValueError("installation token expiry is not exact")
        return token

    def _read_main_ref(self, trace: list[GitHubReadRequest]) -> tuple[GitObject, str]:
        value = self._object(
            self._get(self._repo_path() + "/git/ref/heads/main", self._owner_admin_token, trace)
        )
        obj = self._object(value.get("object"))
        sha = self._string(obj, "sha")
        if value.get("ref") != _TARGET_REF or obj.get("type") != "commit":
            raise ValueError("main ref is malformed")
        checked = sha
        if _OBJECT_PATTERN.fullmatch(checked) is None:
            raise ValueError("main ref object is malformed")
        return checked, canonical_digest(_safe_ref_projection(checked))

    def _read_array_pages(
        self, path: str, token: str, trace: list[GitHubReadRequest]
    ) -> tuple[list[JsonValue], JsonValue]:
        items: list[JsonValue] = []
        pages: list[JsonValue] = []
        for page in range(1, _MAX_PAGES + 1):
            value = self._get(f"{path}?per_page={_PAGE_SIZE}&page={page}", token, trace)
            if not isinstance(value, list):
                raise ValueError("paginated response is malformed")
            copied = copy.deepcopy(value)
            pages.append(copied)
            items.extend(copied)
            if len(value) < _PAGE_SIZE:
                return items, cast(JsonValue, pages)
        raise ValueError("pagination bound reached")

    def _read_object_pages(
        self, path: str, key: str, token: str, trace: list[GitHubReadRequest]
    ) -> tuple[list[JsonValue], JsonValue]:
        items: list[JsonValue] = []
        pages: list[JsonValue] = []
        expected_total: int | None = None
        for page in range(1, _MAX_PAGES + 1):
            value = self._object(
                self._get(f"{path}?per_page={_PAGE_SIZE}&page={page}", token, trace)
            )
            total = self._nonnegative_int(value, "total_count")
            page_items = value.get(key)
            if not isinstance(page_items, list) or len(page_items) > _PAGE_SIZE:
                raise ValueError("paginated response is malformed")
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                raise ValueError("paginated response total drifted")
            pages.append(copy.deepcopy(value))
            items.extend(copy.deepcopy(page_items))
            if len(items) == total and len(page_items) < _PAGE_SIZE:
                return items, cast(JsonValue, pages)
            if len(items) >= total:
                raise ValueError("paginated response count is ambiguous")
        raise ValueError("pagination bound reached")

    def _get(self, path: str, token: str, trace: list[GitHubReadRequest]) -> JsonValue:
        status, value = self._transport(
            "GET",
            _API_ORIGIN + path,
            None,
            {
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + token,
                "X-GitHub-Api-Version": _API_VERSION,
            },
        )
        if type(status) is not int or status != 200:
            raise ValueError("GitHub read failed")
        role = (
            "app_jwt"
            if path == "/app" or path.startswith("/app/installations")
            else "installation_token"
            if path.startswith("/installation/")
            else "owner_admin_token"
        )
        trace.append(GitHubReadRequest("GET", path, role))
        return copy.deepcopy(value)

    @staticmethod
    def _repo_path() -> str:
        return "/repos/vandyand/avo-c8"

    @staticmethod
    def _object(value: object) -> JsonObject:
        if type(value) is not dict:
            raise ValueError("GitHub object is malformed")
        return cast(JsonObject, value)

    @staticmethod
    def _string(value: JsonObject, key: str) -> str:
        item = value.get(key)
        if type(item) is not str or not item or "\x00" in item:
            raise ValueError("GitHub string is malformed")
        return item

    @staticmethod
    def _positive_int(value: JsonObject, key: str) -> int:
        item = value.get(key)
        if type(item) is not int or item <= 0:
            raise ValueError("GitHub identity is malformed")
        return item

    @staticmethod
    def _nonnegative_int(value: JsonObject, key: str) -> int:
        item = value.get(key)
        if type(item) is not int or item < 0:
            raise ValueError("GitHub count is malformed")
        return item

    @staticmethod
    def _permissions(value: JsonObject) -> None:
        permissions = value.get("permissions")
        if type(permissions) is not dict or permissions != {
            "contents": "write",
            "metadata": "read",
        }:
            raise ValueError("GitHub App permissions are not exact")
        if value.get("events") != []:
            raise ValueError("GitHub App events are not empty")

    def _verify_repository(self, value: JsonObject) -> int:
        owner = self._object(value.get("owner"))
        owner_id = self._positive_int(owner, "id")
        if (
            value.get("id") != _REPOSITORY_ID
            or value.get("name") != _REPOSITORY
            or value.get("full_name") != f"{_OWNER}/{_REPOSITORY}"
            or value.get("private") is not False
            or value.get("visibility") != "public"
            or value.get("default_branch") != "main"
            or value.get("archived") is not False
            or value.get("disabled") is not False
            or value.get("fork") is not False
            or owner.get("login") != _OWNER
            or owner.get("type") != "User"
        ):
            raise ValueError("repository is not exact")
        return owner_id

    def _verify_app(self, value: JsonObject, owner_id: int) -> int:
        owner = self._object(value.get("owner"))
        app_id = self._positive_int(value, "id")
        self._permissions(value)
        if (
            value.get("slug") != _APP_SLUG
            or value.get("name") != _APP_SLUG
            or value.get("external_url") != "https://github.com/vandyand/avo-c8"
            or owner.get("login") != _OWNER
            or owner.get("id") != owner_id
            or owner.get("type") != "User"
        ):
            raise ValueError("GitHub App identity is not exact")
        return app_id

    def _verify_installation(self, value: JsonObject, app_id: int, owner_id: int) -> int:
        account = self._object(value.get("account"))
        installation_id = self._positive_int(value, "id")
        self._permissions(value)
        if (
            value.get("app_id") != app_id
            or value.get("app_slug") != _APP_SLUG
            or value.get("target_id") != owner_id
            or value.get("target_type") != "User"
            or value.get("repository_selection") != "selected"
            or value.get("suspended_at") is not None
            or value.get("suspended_by") is not None
            or account.get("login") != _OWNER
            or account.get("id") != owner_id
            or account.get("type") != "User"
        ):
            raise ValueError("GitHub App installation is not exact")
        return installation_id

    def _verify_selected_repository(self, value: JsonObject, owner_id: int) -> None:
        owner = self._object(value.get("owner"))
        if (
            value.get("id") != _REPOSITORY_ID
            or value.get("name") != _REPOSITORY
            or value.get("full_name") != f"{_OWNER}/{_REPOSITORY}"
            or value.get("private") is not False
            or value.get("visibility") != "public"
            or owner.get("login") != _OWNER
            or owner.get("id") != owner_id
            or owner.get("type") != "User"
        ):
            raise ValueError("selected repository identity is not exact")

    @staticmethod
    def _verify_ruleset_summary(value: JsonObject) -> None:
        if (
            value.get("target") != "branch"
            or value.get("source_type") != "Repository"
            or value.get("source") != f"{_OWNER}/{_REPOSITORY}"
            or value.get("enforcement") != "active"
        ):
            raise ValueError("ruleset summary is not exact")

    def _verify_summary_detail(self, summary: JsonObject, detail: JsonObject) -> None:
        if (
            detail.get("id") != summary.get("id")
            or detail.get("name") != summary.get("name")
            or detail.get("source_type") != summary.get("source_type")
            or detail.get("source") != summary.get("source")
            or detail.get("target") != "branch"
            or detail.get("enforcement") != "active"
        ):
            raise ValueError("ruleset detail differs from summary")
        conditions = self._object(detail.get("conditions"))
        if set(conditions) != {"ref_name"}:
            raise ValueError("ruleset conditions are not exact")
        ref_name = self._object(conditions.get("ref_name"))
        if (
            set(ref_name) != {"include", "exclude"}
            or ref_name.get("include") not in ([_TARGET_REF], [_ROLLBACK_REF])
            or ref_name.get("exclude") != []
        ):
            raise ValueError("ruleset target is not exact")

    @staticmethod
    def _update_rule_is_restrictive(rule: JsonObject) -> bool:
        if set(rule) == {"type"}:
            # GitHub omits the optional parameters object for this non-fork repository.
            # An explicit allowance is never accepted.
            return True
        if set(rule) != {"type", "parameters"}:
            return False
        parameters = rule.get("parameters")
        return type(parameters) is dict and parameters == {
            "update_allows_fetch_and_merge": False
        }

    def _classify_rulesets(
        self, values: list[JsonObject], app_id: int
    ) -> tuple[_Ruleset, _Ruleset, _Ruleset]:
        writer: _Ruleset | None = None
        safety: _Ruleset | None = None
        rollback: _Ruleset | None = None
        for value in values:
            rules = value.get("rules")
            bypass = value.get("bypass_actors")
            if not isinstance(rules, list) or not isinstance(bypass, list):
                raise ValueError("ruleset body is malformed")
            rule_types: list[str] = []
            for rule_value in rules:
                rule = self._object(rule_value)
                rule_type = rule.get("type")
                if type(rule_type) is not str:
                    raise ValueError("ruleset rule is not exact")
                if rule_type == "update":
                    if not self._update_rule_is_restrictive(rule):
                        raise ValueError("writer update parameters are not exact")
                elif set(rule) != {"type"}:
                    raise ValueError("safety rule is not exact")
                rule_types.append(rule_type)
            ident = self._positive_int(value, "id")
            name = self._string(value, "name")
            digest = canonical_digest(value)
            ref_name = self._object(self._object(value.get("conditions")).get("ref_name"))
            include = ref_name.get("include")
            if rule_types == ["update"] and include == [_TARGET_REF]:
                if len(bypass) != 1:
                    raise ValueError("writer bypass is not exact")
                actor = self._object(bypass[0])
                if (
                    set(actor) != {"actor_id", "actor_type", "bypass_mode"}
                    or actor.get("actor_id") != app_id
                    or actor.get("actor_type") != "Integration"
                    or actor.get("bypass_mode") != "always"
                ):
                    raise ValueError("writer bypass actor is not exact")
                if name != "AVO C8 main writer":
                    raise ValueError("writer ruleset name is not exact")
                writer = _Ruleset(ident, name, digest, "writer")
            elif (
                sorted(rule_types)
                == ["deletion", "non_fast_forward", "required_linear_history"]
                and include == [_TARGET_REF]
            ):
                if bypass:
                    raise ValueError("safety ruleset permits bypass")
                if name != "AVO C8 main safety":
                    raise ValueError("safety ruleset name is not exact")
                safety = _Ruleset(ident, name, digest, "safety")
            elif (
                sorted(rule_types) == ["creation", "deletion", "non_fast_forward", "update"]
                and include == [_ROLLBACK_REF]
            ):
                if len(bypass) != 1:
                    raise ValueError("rollback bypass is not exact")
                actor = self._object(bypass[0])
                if (
                    set(actor) != {"actor_id", "actor_type", "bypass_mode"}
                    or actor.get("actor_id") != app_id
                    or actor.get("actor_type") != "Integration"
                    or actor.get("bypass_mode") != "always"
                ):
                    raise ValueError("rollback bypass actor is not exact")
                if name != "AVO C8 rollback namespace":
                    raise ValueError("rollback ruleset name is not exact")
                rollback = _Ruleset(ident, name, digest, "rollback")
            else:
                raise ValueError("ruleset rule set is not exact")
        if writer is None or safety is None or rollback is None:
            raise ValueError("required rulesets are missing")
        if len({writer.ident, safety.ident, rollback.ident}) != 3:
            raise ValueError("ruleset identities overlap")
        return writer, safety, rollback

    def _verify_branch_protection(self, value: JsonObject) -> None:
        def enabled(key: str) -> bool:
            raw = self._object(value.get(key)).get("enabled")
            if type(raw) is not bool:
                raise ValueError("branch protection flag is malformed")
            return raw

        required = {
            "enforce_admins",
            "required_linear_history",
            "allow_force_pushes",
            "allow_deletions",
        }
        if (
            not required.issubset(value)
            or not enabled("enforce_admins")
            or not enabled("required_linear_history")
            or enabled("allow_force_pushes")
            or enabled("allow_deletions")
            or value.get("required_status_checks") is not None
            or value.get("required_pull_request_reviews") is not None
            or value.get("restrictions") is not None
        ):
            raise ValueError("branch protection topology is not exact")

    def _now(self) -> datetime:
        value = self._clock()
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("trusted time is unavailable")
        return value


def _safe_ref_projection(sha: str) -> dict[str, object]:
    return {"ref": _TARGET_REF, "object": {"type": "commit", "sha": sha}}


def _expected_trace(
    first: _ConfigurationPass, second: _ConfigurationPass
) -> tuple[GitHubReadRequest, ...]:
    def pass_trace(configuration: _ConfigurationPass) -> tuple[GitHubReadRequest, ...]:
        base = "/repos/vandyand/avo-c8"
        return (
            GitHubReadRequest("GET", base, "owner_admin_token"),
            GitHubReadRequest("GET", "/app", "app_jwt"),
            GitHubReadRequest(
                "GET", "/app/installations?per_page=100&page=1", "app_jwt"
            ),
            GitHubReadRequest(
                "POST",
                f"/app/installations/{configuration.installation_id}/access_tokens",
                "app_jwt",
            ),
            GitHubReadRequest(
                "GET", "/installation/repositories?per_page=100&page=1", "installation_token"
            ),
            GitHubReadRequest("GET", base + "/rulesets?per_page=100&page=1", "owner_admin_token"),
            *(
                GitHubReadRequest("GET", base + f"/rulesets/{ident}", "owner_admin_token")
                for ident in configuration.ruleset_request_ids
            ),
            GitHubReadRequest(
                "GET", base + "/branches/main/protection", "owner_admin_token"
            ),
        )

    ref = GitHubReadRequest("GET", "/repos/vandyand/avo-c8/git/ref/heads/main", "owner_admin_token")
    return (ref, *pass_trace(first), *pass_trace(second), ref)


__all__ = [
    "GitHubReadProvenance",
    "GitHubReadRequest",
    "GitHubReadWithProvenance",
    "MainPersonalExactCasGitHubHostedConfigurationVerifier",
    "MainPersonalExactCasHostedConfigurationUnverified",
]
