"""Adversarial fixture tests for the personal exact-CAS hosted configuration."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import copy
import inspect
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from avo_correlate.adapters.hosted_git.github import JsonBody, JsonObject, JsonValue
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_hosted_configuration import (
    MainPersonalExactCasGitHubHostedConfigurationVerifier,
    MainPersonalExactCasHostedConfigurationUnverified,
)
from avo_correlate.contracts.main_personal_exact_cas_hosted_configuration import (
    MainPersonalExactCasHostedConfigurationDiagnostic,
)

NOW = datetime(2026, 9, 2, 12, tzinfo=UTC)
SHA = "a" * 40
OWNER_ID = 77
APP_ID = 88
INSTALLATION_ID = 99
REPOSITORY_ID = 1_354_880_741
OWNER_ADMIN_TOKEN = "owner-admin-token-secret"
APP_TOKEN = "app-jwt-secret"
MINTED_INSTALLATION_TOKEN = "minted-installation-token-secret"


class FakeTransport:
    def __init__(self, responses: list[tuple[int, JsonValue] | BaseException]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, JsonBody | None, Mapping[str, str]]] = []

    def __call__(
        self, method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        self.calls.append((method, url, body, dict(headers)))
        if not self.responses:
            raise RuntimeError("unexpected request")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return copy.deepcopy(response)


def _owner() -> dict[str, JsonValue]:
    return {"login": "vandyand", "id": OWNER_ID, "type": "User"}


def _repository() -> dict[str, JsonValue]:
    return {
        "id": REPOSITORY_ID,
        "name": "avo-c8",
        "full_name": "vandyand/avo-c8",
        "private": False,
        "visibility": "public",
        "default_branch": "main",
        "archived": False,
        "disabled": False,
        "fork": False,
        "owner": _owner(),
    }


def _ref(sha: str = SHA) -> dict[str, JsonValue]:
    return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": sha}}


def _permissions() -> dict[str, JsonValue]:
    return {"contents": "write", "metadata": "read"}


def _app() -> dict[str, JsonValue]:
    return {
        "id": APP_ID,
        "slug": "avo-c8-main-writer-vandyand",
        "name": "avo-c8-main-writer-vandyand",
        "external_url": "https://github.com/vandyand/avo-c8",
        "owner": _owner(),
        "permissions": _permissions(),
        "events": [],
    }


def _installation() -> dict[str, JsonValue]:
    return {
        "id": INSTALLATION_ID,
        "app_id": APP_ID,
        "app_slug": "avo-c8-main-writer-vandyand",
        "target_id": OWNER_ID,
        "target_type": "User",
        "account": _owner(),
        "repository_selection": "selected",
        "permissions": _permissions(),
        "events": [],
        "suspended_at": None,
        "suspended_by": None,
    }


def _minted_token() -> dict[str, JsonValue]:
    return {
        "token": MINTED_INSTALLATION_TOKEN,
        "expires_at": "2026-09-02T12:30:00Z",
        "permissions": {"contents": "read", "metadata": "read"},
        "repository_selection": "selected",
        "repositories": [_repository()],
    }


def _summary(ident: int, name: str) -> dict[str, JsonValue]:
    return {
        "id": ident,
        "name": name,
        "target": "branch",
        "source_type": "Repository",
        "source": "vandyand/avo-c8",
        "enforcement": "active",
        "node_id": f"RRS_{ident}",
        "_links": {
            "self": {"href": f"https://api.github.com/repos/vandyand/avo-c8/rulesets/{ident}"},
            "html": {"href": f"https://github.com/vandyand/avo-c8/rules/{ident}"},
        },
        "created_at": "2026-09-02T12:00:00Z",
        "updated_at": "2026-09-02T12:00:00Z",
    }


def _detail(
    ident: int,
    name: str,
    rules: list[str],
    bypass: list[dict[str, JsonValue]],
    *,
    target_ref: str = "refs/heads/main",
    include_update_parameters: bool = False,
) -> dict[str, JsonValue]:
    rule_values: list[JsonValue] = [
        (
            {"type": rule, "parameters": {"update_allows_fetch_and_merge": False}}
            if include_update_parameters
            else {"type": rule}
        )
        if rule == "update"
        else {"type": rule}
        for rule in rules
    ]
    bypass_values: list[JsonValue] = [item for item in bypass]
    return {
        "id": ident,
        "name": name,
        "target": "branch",
        "source_type": "Repository",
        "source": "vandyand/avo-c8",
        "enforcement": "active",
        "conditions": {
            "ref_name": {"include": [target_ref], "exclude": []},
        },
        "rules": rule_values,
        "bypass_actors": bypass_values,
        "node_id": f"RRS_{ident}",
        "_links": {
            "self": {"href": f"https://api.github.com/repos/vandyand/avo-c8/rulesets/{ident}"},
            "html": {"href": f"https://github.com/vandyand/avo-c8/rules/{ident}"},
        },
        "created_at": "2026-09-02T12:00:00Z",
        "updated_at": "2026-09-02T12:00:00Z",
    }


def _writer() -> dict[str, JsonValue]:
    return _detail(
        101,
        "AVO C8 main writer",
        ["update"],
        [{"actor_id": APP_ID, "actor_type": "Integration", "bypass_mode": "always"}],
    )


def _safety() -> dict[str, JsonValue]:
    return _detail(
        202,
        "AVO C8 main safety",
        ["deletion", "non_fast_forward", "required_linear_history"],
        [],
    )


def _rollback() -> dict[str, JsonValue]:
    return _detail(
        303,
        "AVO C8 rollback namespace",
        ["creation", "update", "deletion", "non_fast_forward"],
        [{"actor_id": APP_ID, "actor_type": "Integration", "bypass_mode": "always"}],
        target_ref="refs/heads/avo/main-rollback/*",
    )


def _protection() -> dict[str, JsonValue]:
    return {
        "enforce_admins": {"enabled": True},
        "required_linear_history": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
    }


def _pass() -> list[tuple[int, JsonValue]]:
    return [
        (200, _repository()),
        (200, _app()),
        (200, [_installation()]),
        (201, _minted_token()),
        (200, {"total_count": 1, "repositories": [_repository()]}),
        (
            200,
            [
                _summary(101, "AVO C8 main writer"),
                _summary(202, "AVO C8 main safety"),
                _summary(303, "AVO C8 rollback namespace"),
            ],
        ),
        (200, _writer()),
        (200, _safety()),
        (200, _rollback()),
        (200, _protection()),
    ]


def _responses() -> list[tuple[int, JsonValue] | BaseException]:
    return [(200, _ref()), *_pass(), *_pass(), (200, _ref())]


def _subject(
    responses: list[tuple[int, JsonValue] | BaseException] | None = None,
    *,
    finish: datetime | None = None,
) -> tuple[MainPersonalExactCasGitHubHostedConfigurationVerifier, FakeTransport]:
    transport = FakeTransport(_responses() if responses is None else responses)
    times = iter((NOW, NOW, NOW, finish or NOW + timedelta(seconds=1)))
    return (
        MainPersonalExactCasGitHubHostedConfigurationVerifier(
            owner_admin_token=OWNER_ADMIN_TOKEN,
            app_jwt=APP_TOKEN,
            trusted_clock=lambda: next(times),
            transport=transport,
        ),
        transport,
    )


def _as_object(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict)
    return value


def _as_list(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list)
    return value


def _mutated(indexes: tuple[int, ...], kind: str) -> list[tuple[int, JsonValue] | BaseException]:
    responses = _responses()
    for index in indexes:
        response = responses[index]
        assert not isinstance(response, BaseException)
        status, value = response
        copied = copy.deepcopy(value)
        _mutate(copied, kind)
        responses[index] = (status, copied)
    return responses


def _mutate(value: JsonValue, kind: str) -> None:
    if kind in {"wrong-installation-app", "all-repositories", "suspended-installation"}:
        installation = _as_object(_as_list(value)[0])
        if kind == "wrong-installation-app":
            installation["app_id"] = 777
        elif kind == "all-repositories":
            installation["repository_selection"] = "all"
        else:
            installation["suspended_at"] = "now"
        return
    if kind in {
        "summary-target",
        "summary-active",
        "summary-name-mismatch",
        "summary-source-mismatch",
    }:
        summary = _as_object(_as_list(value)[0])
        if kind == "summary-target":
            summary["target"] = "tag"
        elif kind == "summary-active":
            summary["enforcement"] = "enabled"
        elif kind == "summary-name-mismatch":
            summary["name"] = "renamed only in summary"
        else:
            summary["source"] = "vandyand/other"
        return
    obj = _as_object(value)
    if kind == "private-repository":
        obj["private"] = True
    elif kind == "fork-repository":
        obj["fork"] = True
    elif kind == "wrong-repository-id":
        obj["id"] = 123
    elif kind == "organization-owner":
        _as_object(obj["owner"])["type"] = "Organization"
    elif kind == "extra-app-permission":
        _as_object(obj["permissions"])["issues"] = "write"
    elif kind == "app-event":
        obj["events"] = ["push"]
    elif kind == "wrong-app":
        obj["slug"] = "foreign-app"
    elif kind == "wrong-selected-repository":
        repository = _as_object(_as_list(obj["repositories"])[0])
        repository["id"] = 123
    elif kind == "non-always-bypass":
        actor = _as_object(_as_list(obj["bypass_actors"])[0])
        actor["bypass_mode"] = "pull_request"
    elif kind == "missing-writer-bypass":
        obj["bypass_actors"] = []
    elif kind == "update-fetch-and-merge":
        update = _as_object(_as_list(obj["rules"])[0])
        update["parameters"] = {"update_allows_fetch_and_merge": True}
    elif kind == "explicit-safe-update-parameters":
        update = _as_object(_as_list(obj["rules"])[0])
        update["parameters"] = {"update_allows_fetch_and_merge": False}
    elif kind == "extra-update-parameter":
        update = _as_object(_as_list(obj["rules"])[0])
        update["parameters"] = {
            "update_allows_fetch_and_merge": False,
            "unexpected": False,
        }
    elif kind == "safety-bypass":
        _as_list(obj["bypass_actors"]).append(
            {"actor_id": APP_ID, "actor_type": "Integration", "bypass_mode": "always"}
        )
    elif kind in {"missing-safety-rule", "missing-rollback-rule"}:
        _as_list(obj["rules"]).pop()
    elif kind == "rollback-broad-ref-condition":
        conditions = _as_object(obj["conditions"])
        _as_object(conditions["ref_name"])["include"] = ["refs/heads/avo/*"]
    elif kind == "rollback-wrong-bypass":
        actor = _as_object(_as_list(obj["bypass_actors"])[0])
        actor["actor_id"] = APP_ID + 1
    elif kind == "broad-ref-condition":
        conditions = _as_object(obj["conditions"])
        _as_object(conditions["ref_name"])["include"] = ["refs/heads/*"]
    elif kind == "detail-tag-target":
        obj["target"] = "tag"
    elif kind == "detail-evaluate":
        obj["enforcement"] = "evaluate"
    elif kind == "admins-not-enforced":
        _as_object(obj["enforce_admins"])["enabled"] = False
    elif kind == "nonlinear-history":
        _as_object(obj["required_linear_history"])["enabled"] = False
    elif kind == "force-push":
        _as_object(obj["allow_force_pushes"])["enabled"] = True
    elif kind == "deletion":
        _as_object(obj["allow_deletions"])["enabled"] = True
    elif kind == "required-status":
        obj["required_status_checks"] = {"strict": True}
    else:
        raise AssertionError(f"unknown mutation: {kind}")


def test_exact_configuration_returns_non_authoritative_diagnostic() -> None:
    subject, transport = _subject()
    result = subject.verify()
    assert isinstance(result, MainPersonalExactCasHostedConfigurationDiagnostic)
    assert result.repository_id == REPOSITORY_ID
    assert result.writer_app_id == APP_ID
    assert result.writer_installation_id == INSTALLATION_ID
    assert result.selected_repository_ids == (REPOSITORY_ID,)
    assert result.first_pass_digest == result.second_pass_digest
    assert result.is_authoritative is False
    assert result.readiness_authorized is False
    assert result.deploy_performed is False
    assert len(transport.calls) == 22
    expected_pass = [
        "https://api.github.com/repos/vandyand/avo-c8",
        "https://api.github.com/app",
        "https://api.github.com/app/installations?per_page=100&page=1",
        "https://api.github.com/app/installations/99/access_tokens",
        "https://api.github.com/installation/repositories?per_page=100&page=1",
        "https://api.github.com/repos/vandyand/avo-c8/rulesets?per_page=100&page=1",
        "https://api.github.com/repos/vandyand/avo-c8/rulesets/101",
        "https://api.github.com/repos/vandyand/avo-c8/rulesets/202",
        "https://api.github.com/repos/vandyand/avo-c8/rulesets/303",
        "https://api.github.com/repos/vandyand/avo-c8/branches/main/protection",
    ]
    assert [call[1] for call in transport.calls] == [
        "https://api.github.com/repos/vandyand/avo-c8/git/ref/heads/main",
        *expected_pass,
        *expected_pass,
        "https://api.github.com/repos/vandyand/avo-c8/git/ref/heads/main",
    ]
    for call in transport.calls:
        if (
            call[1] == "https://api.github.com/app"
            or "/app/installations?" in call[1]
            or call[1].endswith("/access_tokens")
        ):
            expected_token = APP_TOKEN
        elif "/installation/repositories?" in call[1]:
            expected_token = MINTED_INSTALLATION_TOKEN
        else:
            expected_token = OWNER_ADMIN_TOKEN
        assert call[3]["Authorization"] == f"Bearer {expected_token}"
    mint_calls = [call for call in transport.calls if call[1].endswith("/access_tokens")]
    assert all(
        call[0] == "POST"
        and call[2]
        == {"repository_ids": [REPOSITORY_ID], "permissions": {"contents": "read"}}
        for call in mint_calls
    )


def test_documented_app_shape_without_optional_flags_is_accepted() -> None:
    app = _app()
    assert "public" not in app and "webhook_active" not in app
    subject, _ = _subject()
    assert subject.verify().verification_status == "matched"


@pytest.mark.parametrize(
    ("indexes", "mutation"),
    [
        ((1, 11), "private-repository"),
        ((1, 11), "fork-repository"),
        ((1, 11), "wrong-repository-id"),
        ((1, 11), "organization-owner"),
        ((2, 12), "extra-app-permission"),
        ((2, 12), "app-event"),
        ((2, 12), "wrong-app"),
        ((3, 13), "wrong-installation-app"),
        ((3, 13), "all-repositories"),
        ((3, 13), "suspended-installation"),
        ((5, 15), "wrong-selected-repository"),
        ((6, 16), "summary-target"),
        ((6, 16), "summary-active"),
        ((6, 16), "summary-name-mismatch"),
        ((6, 16), "summary-source-mismatch"),
        ((7, 17), "non-always-bypass"),
        ((7, 17), "missing-writer-bypass"),
        ((7, 17), "update-fetch-and-merge"),
        ((7, 17), "extra-update-parameter"),
        ((8, 18), "safety-bypass"),
        ((8, 18), "missing-safety-rule"),
        ((9, 19), "missing-rollback-rule"),
        ((9, 19), "rollback-broad-ref-condition"),
        ((9, 19), "rollback-wrong-bypass"),
        ((7, 17), "broad-ref-condition"),
        ((7, 17), "detail-tag-target"),
        ((7, 17), "detail-evaluate"),
        ((10, 20), "admins-not-enforced"),
        ((10, 20), "nonlinear-history"),
        ((10, 20), "force-push"),
        ((10, 20), "deletion"),
        ((10, 20), "required-status"),
    ],
    ids=[
        "private-repository",
        "fork-repository",
        "wrong-repository-id",
        "organization-owner",
        "extra-app-permission",
        "app-event",
        "wrong-app",
        "wrong-installation-app",
        "all-repositories",
        "suspended-installation",
        "wrong-selected-repository",
        "summary-wrong-target",
        "summary-wrong-enforcement",
        "summary-name-mismatch",
        "summary-source-mismatch",
        "non-always-bypass",
        "missing-writer-bypass",
        "fetch-and-merge-update",
        "extra-update-parameter",
        "safety-bypass",
        "missing-safety-rule",
        "missing-rollback-rule",
        "rollback-broad-ref-condition",
        "rollback-wrong-bypass",
        "broad-ref-condition",
        "detail-tag-target",
        "detail-evaluate",
        "admins-not-enforced",
        "nonlinear-history",
        "force-push",
        "deletion",
        "required-status",
    ],
)
def test_malformed_or_unsafe_configuration_fails_closed(
    indexes: tuple[int, ...], mutation: str
) -> None:
    subject, _ = _subject(_mutated(indexes, mutation))
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified) as caught:
        subject.verify()
    assert str(caught.value) == "hosted_configuration_unverified"
    assert caught.value.__cause__ is None and caught.value.__context__ is None


def test_configuration_pass_drift_fails_closed() -> None:
    responses = _responses()
    response = responses[1]
    assert not isinstance(response, BaseException)
    status, repository = response
    changed = copy.deepcopy(_as_object(repository))
    changed["updated_at"] = "2026-09-02T12:00:00Z"
    responses[1] = (status, changed)
    subject, _ = _subject(responses)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()


def test_explicit_false_update_parameter_is_also_accepted() -> None:
    responses = _responses()
    for index in (7, 9, 17, 19):
        response = responses[index]
        assert not isinstance(response, BaseException)
        status, value = response
        copied = copy.deepcopy(value)
        obj = _as_object(copied)
        update = next(
            _as_object(rule)
            for rule in _as_list(obj["rules"])
            if _as_object(rule).get("type") == "update"
        )
        update["parameters"] = {"update_allows_fetch_and_merge": False}
        responses[index] = (status, copied)
    subject, _ = _subject(responses)
    assert subject.verify().verification_status == "matched"


def test_documented_installation_and_repository_page_shapes_are_enforced() -> None:
    wrapped_installations = _responses()
    wrapped_installations[3] = (
        200,
        {"total_count": 1, "installations": [_installation()]},
    )
    subject, _ = _subject(wrapped_installations)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()

    bare_repositories = _responses()
    bare_repositories[5] = (200, [_repository()])
    subject, _ = _subject(bare_repositories)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()


def test_absent_rulesets_and_stale_observation_fail_closed() -> None:
    absent = _responses()
    absent[6] = (200, [])
    subject, _ = _subject(absent)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()

    subject, _ = _subject(finish=NOW + timedelta(minutes=5, microseconds=1))
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()


def test_final_main_ref_drift_fails_closed() -> None:
    responses = _responses()
    responses[-1] = (200, _ref("b" * 40))
    subject, _ = _subject(responses)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()


@pytest.mark.parametrize(
    "failure",
    [
        (404, {}),
        RuntimeError("transport failure token=installation-token-secret"),
    ],
)
def test_transport_failures_are_sanitized(failure: tuple[int, JsonValue] | BaseException) -> None:
    responses = _responses()
    responses[0] = failure
    subject, _ = _subject(responses)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified) as caught:
        subject.verify()
    assert "secret" not in str(caught.value)
    assert "secret" not in repr(caught.value)
    assert caught.value.__cause__ is None and caught.value.__context__ is None


def test_pagination_is_bounded_when_completion_is_ambiguous() -> None:
    full_page: JsonValue = [_summary(101, "duplicate") for _ in range(100)]
    responses: list[tuple[int, JsonValue] | BaseException] = [
        (200, _ref()),
        (200, _repository()),
        (200, _app()),
        (200, [_installation()]),
        (201, _minted_token()),
        (200, {"total_count": 1, "repositories": [_repository()]}),
        *[(200, full_page) for _ in range(10)],
    ]
    subject, transport = _subject(responses)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()
    assert len(transport.calls) == 16
    assert transport.calls[-1][1].endswith("rulesets?per_page=100&page=10")


def test_observation_contract_rejects_identity_forgery() -> None:
    subject, _ = _subject()
    result = subject.verify()
    forged = result.model_copy(update={"writer_app_id": APP_ID + 1})
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedConfigurationDiagnostic.model_validate(
            forged.model_dump(mode="json")
        )


def test_public_verifier_surface_is_read_only_and_non_authoritative() -> None:
    names = set(dir(MainPersonalExactCasGitHubHostedConfigurationVerifier))
    assert names.isdisjoint({"apply", "exchange", "write", "record", "authorize"})
    source = Path(
        "src/avo_correlate/adapters/hosted_git/main_personal_exact_cas_hosted_configuration.py"
    ).read_text(encoding="utf-8")
    assert "MainPersonalExactCasReceipt" not in source
    assert '"PATCH"' not in source and '"PUT"' not in source and '"DELETE"' not in source


def test_installation_token_is_not_a_constructor_input() -> None:
    assert "installation_token" not in inspect.signature(
        MainPersonalExactCasGitHubHostedConfigurationVerifier
    ).parameters


@pytest.mark.parametrize(
    "mutation", ["permissions", "missing-metadata", "selection", "repositories", "expiry"]
)
def test_minted_installation_token_scope_is_exact(mutation: str) -> None:
    responses = _responses()
    token = copy.deepcopy(_minted_token())
    if mutation == "permissions":
        token["permissions"] = {"contents": "write"}
    elif mutation == "missing-metadata":
        token["permissions"] = {"contents": "read"}
    elif mutation == "selection":
        token["repository_selection"] = "all"
    elif mutation == "repositories":
        token["repositories"] = [_repository(), _repository()]
    else:
        token["expires_at"] = "2026-09-02T13:30:01Z"
    responses[4] = (201, token)
    subject, _ = _subject(responses)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()


def test_minted_installation_token_status_or_shape_fails_closed() -> None:
    responses_to_test: tuple[tuple[int, JsonValue], ...] = (
        (200, _minted_token()),
        (201, {}),
        (201, {"token": "foreign"}),
    )
    for response in responses_to_test:
        responses = _responses()
        responses[4] = response
        subject, _ = _subject(responses)
        with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
            subject.verify()


@pytest.mark.parametrize(
    "expires_at",
    [
        "2026-09-02T12:30:00+00:00",
        "2026-09-02T12:30:00.000Z",
        "2026-09-02T12:30Z",
        "2026-09-02T12:30:00+01:00",
    ],
)
def test_minted_installation_token_requires_exact_utc_timestamp_format(
    expires_at: str,
) -> None:
    responses = _responses()
    token = copy.deepcopy(_minted_token())
    token["expires_at"] = expires_at
    responses[4] = (201, token)
    subject, _ = _subject(responses)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()
