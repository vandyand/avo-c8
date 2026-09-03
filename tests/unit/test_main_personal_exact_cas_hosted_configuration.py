"""Adversarial fixture tests for the personal exact-CAS hosted configuration."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import copy
import inspect
import re
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from avo_correlate.adapters.hosted_git import (
    main_personal_exact_cas_hosted_configuration as hosted_configuration_module,
)
from avo_correlate.adapters.hosted_git.github import JsonBody, JsonObject, JsonValue
from avo_correlate.adapters.hosted_git.github_read_provenance import (
    GitHubReadRequest,
    GitHubReadWithProvenance,
)
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_hosted_configuration import (
    MainPersonalExactCasGitHubHostedConfigurationVerifier,
    MainPersonalExactCasHostedConfigurationUnverified,
)
from avo_correlate.contracts.main_personal_exact_cas_hosted_configuration import (
    MainPersonalExactCasHostedConfigurationDiagnostic,
)
from avo_correlate.domain.canonical import canonical_digest

NOW = datetime(2026, 9, 2, 12, tzinfo=UTC)
SHA = "a" * 40
OWNER_ID = 77
APP_ID = 88
INSTALLATION_ID = 99
CANDIDATE_APP_ID = 100
CANDIDATE_INSTALLATION_ID = 111
REPOSITORY_ID = 1_354_880_741
OWNER_ADMIN_TOKEN = "owner-admin-token-secret"
APP_TOKEN = "app-jwt-secret"
CANDIDATE_APP_TOKEN = "candidate-app-jwt-secret"
MINTED_INSTALLATION_TOKEN = "minted-installation-token-secret"
CANDIDATE_MINTED_INSTALLATION_TOKEN = "candidate-minted-installation-token-secret"


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


def _candidate_app() -> dict[str, JsonValue]:
    value = _app()
    value.update(
        {
            "id": CANDIDATE_APP_ID,
            "slug": "avo-c8-candidate-publisher-vandyand",
            "name": "avo-c8-candidate-publisher-vandyand",
            "public": False,
            "webhook_active": False,
        }
    )
    return value


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


def _candidate_installation() -> dict[str, JsonValue]:
    value = _installation()
    value.update(
        {
            "id": CANDIDATE_INSTALLATION_ID,
            "app_id": CANDIDATE_APP_ID,
            "app_slug": "avo-c8-candidate-publisher-vandyand",
        }
    )
    return value


def _minted_token() -> dict[str, JsonValue]:
    return {
        "token": MINTED_INSTALLATION_TOKEN,
        "expires_at": "2026-09-02T12:30:00Z",
        "permissions": {"contents": "read", "metadata": "read"},
        "repository_selection": "selected",
        "repositories": [_repository()],
    }


def _candidate_minted_token() -> dict[str, JsonValue]:
    value = _minted_token()
    value["token"] = CANDIDATE_MINTED_INSTALLATION_TOKEN
    return value


def _summary(ident: int, name: str) -> dict[str, JsonValue]:
    return {
        "id": ident,
        "name": name,
        "source_type": "Repository",
        "source": "vandyand/avo-c8",
        "enforcement": "enabled",
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


def _candidate_creation() -> dict[str, JsonValue]:
    return _detail(
        404,
        "AVO C8 candidate creation",
        ["creation"],
        [{"actor_id": CANDIDATE_APP_ID, "actor_type": "Integration", "bypass_mode": "always"}],
        target_ref="refs/heads/avo/candidate/*",
    )


def _candidate_immutable() -> dict[str, JsonValue]:
    return _detail(
        505,
        "AVO C8 candidate immutable",
        ["update", "deletion", "non_fast_forward"],
        [],
        target_ref="refs/heads/avo/candidate/*",
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
        (200, _candidate_app()),
        (200, _candidate_installation()),
        (201, _candidate_minted_token()),
        (200, {"total_count": 1, "repositories": [_repository()]}),
        (
            200,
            [
                _summary(101, "AVO C8 main writer"),
                _summary(202, "AVO C8 main safety"),
                _summary(303, "AVO C8 rollback namespace"),
                _summary(404, "AVO C8 candidate creation"),
                _summary(505, "AVO C8 candidate immutable"),
            ],
        ),
        (200, _writer()),
        (200, _safety()),
        (200, _rollback()),
        (200, _candidate_creation()),
        (200, _candidate_immutable()),
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
    times = iter((NOW, NOW, NOW, NOW, NOW, finish or NOW + timedelta(seconds=1)))
    return (
        MainPersonalExactCasGitHubHostedConfigurationVerifier(
            owner_admin_token=OWNER_ADMIN_TOKEN,
            app_jwt=APP_TOKEN,
            candidate_publisher_app_jwt=CANDIDATE_APP_TOKEN,
            candidate_publisher_app_id=CANDIDATE_APP_ID,
            candidate_publisher_installation_id=CANDIDATE_INSTALLATION_ID,
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
            summary["enforcement"] = "disabled"
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
    elif kind == "candidate-private":
        obj["public"] = True
    elif kind == "candidate-webhook":
        obj["webhook_active"] = True
    elif kind == "candidate-optional-absent":
        obj.pop("public", None)
        obj.pop("webhook_active", None)
    elif kind == "candidate-install-wrong-app":
        obj["app_id"] = CANDIDATE_APP_ID + 1
    elif kind == "candidate-install-all-repositories":
        obj["repository_selection"] = "all"
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
    elif kind == "candidate-creation-wrong-bypass":
        actor = _as_object(_as_list(obj["bypass_actors"])[0])
        actor["actor_id"] = CANDIDATE_APP_ID + 1
    elif kind == "candidate-creation-missing-bypass":
        obj["bypass_actors"] = None
    elif kind == "candidate-immutable-bypass":
        obj["bypass_actors"] = [
            {"actor_id": CANDIDATE_APP_ID, "actor_type": "Integration", "bypass_mode": "always"}
        ]
    elif kind == "candidate-immutable-missing-bypass":
        obj.pop("bypass_actors", None)
    elif kind == "candidate-broad-ref-condition":
        conditions = _as_object(obj["conditions"])
        _as_object(conditions["ref_name"])["include"] = ["refs/heads/avo/*"]
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
    assert result.rollback_ruleset_id == 303
    assert result.rollback_ruleset_name == "AVO C8 rollback namespace"
    assert result.candidate_creation_ruleset_id == 404
    assert result.candidate_immutable_ruleset_id == 505
    assert result.candidate_publisher_app_id == CANDIDATE_APP_ID
    assert result.candidate_publisher_installation_id == CANDIDATE_INSTALLATION_ID
    assert result.rollback_ruleset_digest.startswith("sha256:")
    assert result.protection_ruleset_digest == canonical_digest(
        {
            "writer_ruleset": result.writer_ruleset_digest,
            "safety_ruleset": result.safety_ruleset_digest,
            "rollback_ruleset": result.rollback_ruleset_digest,
            "candidate_creation_ruleset": result.candidate_creation_ruleset_digest,
            "candidate_immutable_ruleset": result.candidate_immutable_ruleset_digest,
        }
    )
    assert result.selected_repository_ids == (REPOSITORY_ID,)
    assert result.first_pass_digest == result.second_pass_digest
    assert result.is_authoritative is False
    assert result.readiness_authorized is False
    assert result.deploy_performed is False
    assert len(transport.calls) == 34
    expected_pass = [
        "https://api.github.com/repos/vandyand/avo-c8",
        "https://api.github.com/app",
        "https://api.github.com/app/installations?per_page=100&page=1",
        "https://api.github.com/app/installations/99/access_tokens",
        "https://api.github.com/installation/repositories?per_page=100&page=1",
        "https://api.github.com/app",
        "https://api.github.com/app/installations/111",
        "https://api.github.com/app/installations/111/access_tokens",
        "https://api.github.com/installation/repositories?per_page=100&page=1",
        "https://api.github.com/repos/vandyand/avo-c8/rulesets?per_page=100&page=1",
        "https://api.github.com/repos/vandyand/avo-c8/rulesets/101",
        "https://api.github.com/repos/vandyand/avo-c8/rulesets/202",
        "https://api.github.com/repos/vandyand/avo-c8/rulesets/303",
        "https://api.github.com/repos/vandyand/avo-c8/rulesets/404",
        "https://api.github.com/repos/vandyand/avo-c8/rulesets/505",
        "https://api.github.com/repos/vandyand/avo-c8/branches/main/protection",
    ]
    assert [call[1] for call in transport.calls] == [
        "https://api.github.com/repos/vandyand/avo-c8/git/ref/heads/main",
        *expected_pass,
        *expected_pass,
        "https://api.github.com/repos/vandyand/avo-c8/git/ref/heads/main",
    ]
    for call_index, call in enumerate(transport.calls):
        if (
            call[1] == "https://api.github.com/app"
            or "/app/installations?" in call[1]
            or "/app/installations/" in call[1]
            or call[1].endswith("/access_tokens")
        ):
            expected_token = (
                CANDIDATE_APP_TOKEN
                    if 5 <= (call_index - 1) % 16 <= 7
                else APP_TOKEN
            )
        elif "/installation/repositories?" in call[1]:
            expected_token = (
                CANDIDATE_MINTED_INSTALLATION_TOKEN
                if (call_index - 1) % 16 == 8
                else MINTED_INSTALLATION_TOKEN
            )
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


def test_authenticated_configuration_provenance_is_canonical_and_secret_free() -> None:
    subject, _ = _subject()
    observed = subject.verify_with_provenance()
    provenance = observed.provenance
    assert observed.result.main_commit == SHA
    assert provenance.provenance_digest.startswith("sha256:")
    assert len(provenance.configuration_pass_digests) == 2
    assert provenance.configuration_pass_digests[0] == provenance.configuration_pass_digests[1]
    assert provenance.requests[0] == GitHubReadRequest(
        "GET", "/repos/vandyand/avo-c8/git/ref/heads/main", "owner_admin_token"
    )
    assert provenance.requests[4].method == "POST"
    assert provenance.requests[4].credential_role == "app_jwt"
    assert provenance.requests[-1].path.endswith("/git/ref/heads/main")
    text = repr(provenance)
    assert OWNER_ADMIN_TOKEN not in text
    assert APP_TOKEN not in text
    assert MINTED_INSTALLATION_TOKEN not in text

    rotated = _responses()
    for index, token in ((4, "rotated-first-secret"), (20, "rotated-second-secret")):
        token_response = rotated[index]
        assert not isinstance(token_response, BaseException)
        token_body = token_response[1]
        assert isinstance(token_body, dict)
        token_body["token"] = token
    rotated_subject, _ = _subject(rotated)
    rotated_observed = rotated_subject.verify_with_provenance()
    assert rotated_observed.provenance.provenance_digest == provenance.provenance_digest

    assert (
        replace(provenance, app_id=APP_ID + 1).provenance_digest
        != provenance.provenance_digest
    )


def test_same_verifier_concurrent_reads_keep_operation_local_complete_traces() -> None:
    class ConcurrentTransport:
        def __init__(self) -> None:
            self.local = threading.local()
            self.barrier = threading.Barrier(2)

        def __call__(
            self, method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
        ) -> tuple[int, JsonValue]:
            del method, url, body, headers
            responses = getattr(self.local, "responses", None)
            if responses is None:
                responses = _responses()
                self.local.responses = responses
            self.barrier.wait(timeout=5)
            response = responses.pop(0)
            assert not isinstance(response, BaseException)
            return copy.deepcopy(response)

    subject = MainPersonalExactCasGitHubHostedConfigurationVerifier(
        owner_admin_token=OWNER_ADMIN_TOKEN,
        app_jwt=APP_TOKEN,
        candidate_publisher_app_jwt=CANDIDATE_APP_TOKEN,
        candidate_publisher_app_id=CANDIDATE_APP_ID,
        candidate_publisher_installation_id=CANDIDATE_INSTALLATION_ID,
        trusted_clock=lambda: NOW,
        transport=ConcurrentTransport(),
    )

    def verify_once(
        _: int,
    ) -> GitHubReadWithProvenance[
        MainPersonalExactCasHostedConfigurationDiagnostic
    ]:
        return subject.verify_with_provenance()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(verify_once, (1, 2)))
    assert len(results) == 2
    first, second = results
    assert first.result == second.result
    assert first.provenance.provenance_digest == second.provenance.provenance_digest
    assert len(first.provenance.requests) == len(second.provenance.requests) == 34
    assert [item.credential_role for item in first.provenance.requests] == [
        item.credential_role for item in second.provenance.requests
    ]
    assert first.provenance.requests[0].path.endswith("/git/ref/heads/main")
    assert first.provenance.requests[-1].path.endswith("/git/ref/heads/main")


def test_documented_app_shape_without_optional_flags_is_accepted() -> None:
    app = _app()
    assert "public" not in app and "webhook_active" not in app
    subject, _ = _subject()
    assert subject.verify().verification_status == "matched"


def test_live_ruleset_summary_shape_with_branch_and_active_is_accepted() -> None:
    responses = _responses()
    for index in (10, 26):
        response = responses[index]
        assert not isinstance(response, BaseException)
        status, value = response
        summaries = _as_list(value)
        for item in summaries:
            summary = _as_object(item)
            summary["target"] = "branch"
            summary["enforcement"] = "active"
        responses[index] = (status, value)
    subject, _ = _subject(responses)
    assert subject.verify().verification_status == "matched"


def test_candidate_app_optional_privacy_fields_may_be_absent() -> None:
    subject, _ = _subject(_mutated((6, 22), "candidate-optional-absent"))
    assert subject.verify().verification_status == "matched"


@pytest.mark.parametrize(
    ("indexes", "mutation"),
    [
        ((1, 17), "private-repository"),
        ((1, 17), "fork-repository"),
        ((1, 17), "wrong-repository-id"),
        ((1, 17), "organization-owner"),
        ((2, 18), "extra-app-permission"),
        ((2, 18), "app-event"),
        ((2, 18), "wrong-app"),
        ((3, 19), "wrong-installation-app"),
        ((3, 19), "all-repositories"),
        ((3, 19), "suspended-installation"),
        ((5, 21), "wrong-selected-repository"),
        ((10, 26), "summary-target"),
        ((10, 26), "summary-active"),
        ((10, 26), "summary-name-mismatch"),
        ((10, 26), "summary-source-mismatch"),
        ((11, 27), "non-always-bypass"),
        ((11, 27), "missing-writer-bypass"),
        ((11, 27), "update-fetch-and-merge"),
        ((11, 27), "extra-update-parameter"),
        ((12, 28), "safety-bypass"),
        ((12, 28), "missing-safety-rule"),
        ((13, 29), "missing-rollback-rule"),
        ((13, 29), "rollback-broad-ref-condition"),
        ((13, 29), "rollback-wrong-bypass"),
        ((14, 30), "candidate-creation-wrong-bypass"),
        ((14, 30), "candidate-creation-missing-bypass"),
        ((15, 31), "candidate-immutable-bypass"),
        ((15, 31), "candidate-immutable-missing-bypass"),
        ((14, 30), "candidate-broad-ref-condition"),
        ((11, 27), "broad-ref-condition"),
        ((11, 27), "detail-tag-target"),
        ((11, 27), "detail-evaluate"),
        ((16, 32), "admins-not-enforced"),
        ((16, 32), "nonlinear-history"),
        ((16, 32), "force-push"),
        ((16, 32), "deletion"),
        ((16, 32), "required-status"),
        ((6, 22), "candidate-private"),
        ((6, 22), "candidate-webhook"),
        ((7, 23), "candidate-install-wrong-app"),
        ((7, 23), "candidate-install-all-repositories"),
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
        "candidate-creation-wrong-bypass",
        "candidate-creation-missing-bypass",
        "candidate-immutable-bypass",
        "candidate-immutable-missing-bypass",
        "candidate-broad-ref-condition",
        "broad-ref-condition",
        "detail-tag-target",
        "detail-evaluate",
        "admins-not-enforced",
        "nonlinear-history",
        "force-push",
        "deletion",
        "required-status",
        "candidate-private",
        "candidate-webhook",
        "candidate-install-wrong-app",
        "candidate-install-all-repositories",
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
    for index in (11, 13, 27, 29):
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
    absent[10] = (200, [])
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
            (200, _candidate_app()),
            (200, _candidate_installation()),
            (201, _candidate_minted_token()),
            (200, {"total_count": 1, "repositories": [_repository()]}),
        *[(200, full_page) for _ in range(10)],
    ]
    subject, transport = _subject(responses)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()
    assert len(transport.calls) == 20
    assert transport.calls[-1][1].endswith("rulesets?per_page=100&page=10")


def test_observation_contract_rejects_identity_forgery() -> None:
    subject, _ = _subject()
    result = subject.verify()
    forged = result.model_copy(update={"writer_app_id": APP_ID + 1})
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedConfigurationDiagnostic.model_validate(
            forged.model_dump(mode="json")
        )


@pytest.mark.parametrize(
    "field", [
        "candidate_publisher_app_slug",
        "candidate_publisher_app_name",
        "candidate_publisher_app_homepage",
    ],
)
def test_candidate_publisher_identity_literals_reject_dto_tampering(field: str) -> None:
    subject, _ = _subject()
    result = subject.verify()
    forged = result.model_copy(update={field: "foreign-candidate-publisher"})
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedConfigurationDiagnostic.model_validate(
            forged.model_dump(mode="json")
        )


def test_rollback_ruleset_id_is_strictly_positive_and_non_boolean() -> None:
    subject, _ = _subject()
    result = subject.verify()
    for value in (True, 0, -1):
        payload = result.model_dump(mode="json")
        payload["rollback_ruleset_id"] = value
        with pytest.raises(ValueError):
            MainPersonalExactCasHostedConfigurationDiagnostic.model_validate(payload)


def test_public_verifier_surface_is_read_only_and_non_authoritative() -> None:
    names = set(dir(MainPersonalExactCasGitHubHostedConfigurationVerifier))
    assert names.isdisjoint({"apply", "exchange", "write", "record", "authorize"})
    source = Path(
        "src/avo_correlate/adapters/hosted_git/main_personal_exact_cas_hosted_configuration.py"
    ).read_text(encoding="utf-8")
    assert "MainPersonalExactCasReceipt" not in source
    assert '"PATCH"' not in source and '"PUT"' not in source and '"DELETE"' not in source


def test_installation_token_is_not_a_constructor_input() -> None:
    parameters = inspect.signature(MainPersonalExactCasGitHubHostedConfigurationVerifier).parameters
    assert "installation_token" not in parameters
    assert "candidate_publisher_app_slug" not in parameters
    assert "candidate_publisher_app_name" not in parameters
    assert "candidate_publisher_app_homepage" not in parameters


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


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("owner_admin_token", ""),
        ("app_jwt", ""),
        ("candidate_publisher_app_jwt", ""),
        ("candidate_publisher_app_id", 0),
        ("candidate_publisher_installation_id", 0),
        ("trusted_clock", None),
    ],
)
def test_constructor_rejects_unusable_authentication_inputs(field: str, value: object) -> None:
    kwargs: dict[str, object] = {
        "owner_admin_token": OWNER_ADMIN_TOKEN,
        "app_jwt": APP_TOKEN,
        "candidate_publisher_app_jwt": CANDIDATE_APP_TOKEN,
        "candidate_publisher_app_id": CANDIDATE_APP_ID,
        "candidate_publisher_installation_id": CANDIDATE_INSTALLATION_ID,
        "trusted_clock": lambda: NOW,
        "transport": FakeTransport([]),
    }
    kwargs[field] = value
    with pytest.raises(ValueError):
        MainPersonalExactCasGitHubHostedConfigurationVerifier(**kwargs)  # type: ignore[arg-type]


def test_small_validation_helpers_reject_malformed_provider_values() -> None:
    subject, _ = _subject([])
    malformed_objects: tuple[object, ...] = (None, [], "not-an-object")
    for value in malformed_objects:
        with pytest.raises(ValueError, match="object"):
            subject._object(value)
    for value in (None, "", "bad\x00value", 4):
        with pytest.raises(ValueError, match="string"):
            subject._string({"x": value}, "x")
    for value in (None, True, 0, -1, "1"):
        with pytest.raises(ValueError, match="identity"):
            subject._positive_int({"x": value}, "x")
    for value in (None, True, -1, "0"):
        with pytest.raises(ValueError, match="count"):
            subject._nonnegative_int({"x": value}, "x")


def test_private_ref_and_transport_fences_reject_bad_shapes() -> None:
    subject, _ = _subject([(200, _ref("z" * 40))])
    with pytest.raises(ValueError, match="object"):
        subject._read_main_ref([])
    subject, _ = _subject(
        [(200, {"ref": "refs/heads/dev", "object": {"type": "commit", "sha": SHA}})]
    )
    with pytest.raises(ValueError, match="malformed"):
        subject._read_main_ref([])
    subject, _ = _subject([(201, {})])
    with pytest.raises(ValueError, match="read failed"):
        subject._get("/probe", "token", [])


def test_pagination_readers_reject_malformed_and_drifting_pages() -> None:
    subject, _ = _subject([(200, {})])
    with pytest.raises(ValueError, match="paginated"):
        subject._read_array_pages("/probe", "token", [])
    subject, _ = _subject([(200, {"total_count": 0, "repositories": [_repository()]})])
    with pytest.raises(ValueError, match="ambiguous"):
        subject._read_object_pages("/probe", "repositories", "token", [])
    responses: list[tuple[int, JsonValue] | BaseException] = [
        (200, cast(JsonValue, {"total_count": 101, "repositories": [_repository()] * 100})),
        (200, cast(JsonValue, {"total_count": 102, "repositories": []})),
    ]
    subject, _ = _subject(responses)
    with pytest.raises(ValueError, match="drifted"):
        subject._read_object_pages("/probe", "repositories", "token", [])


def test_ruleset_and_protection_helpers_cover_rejection_boundaries() -> None:
    subject, _ = _subject([])
    assert subject._update_rule_is_restrictive({"type": "update"})
    assert subject._update_rule_is_restrictive(
        {"type": "update", "parameters": {"update_allows_fetch_and_merge": False}}
    )
    assert not subject._update_rule_is_restrictive(
        {"type": "update", "parameters": {"update_allows_fetch_and_merge": True}}
    )
    assert not subject._update_rule_is_restrictive({"type": "update", "unexpected": False})
    with pytest.raises(ValueError, match="required rulesets"):
        subject._classify_rulesets([_writer()], APP_ID)
    duplicated = _writer()
    duplicated["id"] = 102
    with pytest.raises(ValueError, match="required rulesets"):
        subject._classify_rulesets([_writer(), duplicated], APP_ID)
    extra_protection: JsonObject = _protection()
    extra_protection["required_status_checks"] = {}
    protections: tuple[JsonObject, ...] = (
        {},
        cast(JsonObject, {"enforce_admins": {"enabled": "yes"}}),
        extra_protection,
    )
    for protection in protections:
        with pytest.raises(ValueError, match="branch protection"):
            subject._verify_branch_protection(protection)


@pytest.mark.parametrize(
    "mutation",
    [
        "naive-start",
        "backwards-time",
        "ruleset-overlap",
        "app-overlap",
        "installation-overlap",
        "selected-repository",
        "events",
        "publisher-identity-digest",
        "publisher-installation-digest",
        "pass-drift",
        "protection-digest",
        "configuration-digest",
        "source-digest",
        "observation-digest",
    ],
)
def test_hosted_configuration_contract_rejects_semantic_tampering(mutation: str) -> None:
    subject, _ = _subject()
    result = subject.verify()
    payload = result.model_dump(mode="json")
    if mutation == "naive-start":
        payload["started_at"] = "2026-09-02T12:00:00"
    elif mutation == "backwards-time":
        payload["finished_at"] = "2026-09-02T11:59:59Z"
    elif mutation == "ruleset-overlap":
        payload["safety_ruleset_id"] = payload["writer_ruleset_id"]
    elif mutation == "app-overlap":
        payload["candidate_publisher_app_id"] = payload["writer_app_id"]
    elif mutation == "installation-overlap":
        payload["candidate_publisher_installation_id"] = payload["writer_installation_id"]
    elif mutation == "selected-repository":
        payload["selected_repository_ids"] = [123]
    elif mutation == "events":
        payload["subscribed_events"] = ["push"]
    elif mutation == "publisher-identity-digest":
        payload["candidate_publisher_identity_digest"] = "sha256:" + "f" * 64
    elif mutation == "publisher-installation-digest":
        payload["candidate_publisher_installation_digest"] = "sha256:" + "f" * 64
    elif mutation == "pass-drift":
        payload["second_pass_digest"] = "sha256:" + "f" * 64
    elif mutation == "protection-digest":
        payload["protection_ruleset_digest"] = "sha256:" + "f" * 64
    elif mutation == "configuration-digest":
        payload["configuration_digest"] = "sha256:" + "f" * 64
    elif mutation == "source-digest":
        payload["source_digest"] = "sha256:" + "f" * 64
    else:
        payload["observation_digest"] = "sha256:" + "f" * 64
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedConfigurationDiagnostic.model_validate(payload)


def test_verifier_rejects_trace_mismatch_even_when_reads_are_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    subject, _ = _subject()
    def empty_trace(_first: object, _second: object) -> tuple[GitHubReadRequest, ...]:
        return ()

    monkeypatch.setattr(hosted_configuration_module, "_expected_trace", empty_trace)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()


def test_verifier_rejects_installation_and_selection_cardinality() -> None:
    for indexes, mutation in (
        ((3,), "wrong-installation-app"),
        ((5,), "wrong-selected-repository"),
    ):
        responses = _mutated(indexes, mutation)
        response = responses[indexes[0]]
        assert not isinstance(response, BaseException)
        status, value = response
        if mutation == "wrong-installation-app":
            responses[indexes[0]] = (status, [])
        else:
            payload = _as_object(value)
            payload["repositories"] = []
            payload["total_count"] = 0
            responses[indexes[0]] = (status, payload)
        subject, _ = _subject(responses)
        with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
            subject.verify()


def test_verifier_rejects_invalid_token_timestamp_and_rule_detail_shapes() -> None:
    responses = _responses()
    token = copy.deepcopy(_minted_token())
    token["expires_at"] = "2026-99-99T99:99:99Z"
    responses[4] = (201, token)
    subject, _ = _subject(responses)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()

    responses = _responses()
    detail = copy.deepcopy(_writer())
    detail["conditions"] = {
        "ref_name": {"include": ["refs/heads/main"], "exclude": [], "extra": []}
    }
    responses[11] = (200, detail)
    subject, _ = _subject(responses)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()


def test_verifier_rejects_classification_name_and_actor_cardinality_errors() -> None:
    cases: tuple[tuple[int, Callable[[], dict[str, JsonValue]], str, JsonValue], ...] = (
        (11, _writer, "name", "wrong"),
        (12, _safety, "name", "wrong"),
        (13, _rollback, "bypass_actors", []),
        (14, _candidate_creation, "bypass_actors", []),
        (15, _candidate_immutable, "name", "wrong"),
    )
    for index, detail_factory, field, value in cases:
        responses = _responses()
        detail = detail_factory()
        detail[field] = value
        responses[index] = (200, detail)
        subject, _ = _subject(responses)
        with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
            subject.verify()


def test_verifier_rejects_ambiguous_ruleset_page_bound() -> None:
    full_page: JsonValue = [_summary(900, "unclassified") for _ in range(100)]
    responses: list[tuple[int, JsonValue] | BaseException] = [
        (200, _ref()),
        (200, _repository()),
        (200, _app()),
        (200, [_installation()]),
        (201, _minted_token()),
        (200, {"total_count": 1, "repositories": [_repository()]}),
        (200, _candidate_app()),
        (200, _candidate_installation()),
        (201, _candidate_minted_token()),
        (200, {"total_count": 1, "repositories": [_repository()]}),
        *[(200, full_page) for _ in range(10)],
    ]
    subject, _ = _subject(responses)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()


def test_verifier_rejects_malformed_branch_protection_flag() -> None:
    responses = _responses()
    protection = copy.deepcopy(_protection())
    protection["enforce_admins"] = {"enabled": "yes"}
    responses[16] = (200, protection)
    subject, _ = _subject(responses)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()


def test_coverage_floor_uses_exact_two_decimal_precision() -> None:
    project = Path("pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r"(?m)^precision\s*=\s*(\d+)\s*$", project)
    assert match is not None and int(match.group(1)) >= 2


def test_remaining_policy_classifier_rejections_are_exercised_directly() -> None:
    subject, _ = _subject([])
    cases: tuple[dict[str, JsonValue], ...] = ()
    bad_rule = _writer()
    bad_rule["rules"] = [{"type": 4}]
    bad_safety_rule = _safety()
    bad_safety_rule["rules"] = [
        {"type": "deletion", "unexpected": False},
        {"type": "non_fast_forward"},
        {"type": "required_linear_history"},
    ]
    cases += (bad_rule, bad_safety_rule)
    for detail_factory, field in (
        (_writer, "name"),
        (_safety, "name"),
        (_rollback, "name"),
        (_candidate_creation, "name"),
        (_candidate_immutable, "name"),
    ):
        detail = detail_factory()
        detail[field] = "wrong"
        cases += (detail,)
    for detail in cases:
        with pytest.raises(ValueError):
            subject._classify_rulesets([detail], APP_ID)
    overlap = [
        _writer(),
        _safety(),
        _rollback(),
        _candidate_creation(),
        _candidate_immutable(),
    ]
    overlap[-1]["id"] = overlap[0]["id"]
    with pytest.raises(ValueError, match="overlap"):
        subject._classify_rulesets(overlap, APP_ID)


def test_candidate_identity_and_pagination_shape_guards_are_fail_closed() -> None:
    for index, value in ((6, {**_candidate_app(), "id": CANDIDATE_APP_ID + 1}),):
        responses = _responses()
        responses[index] = (200, value)
        subject, _ = _subject(responses)
        with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
            subject.verify()
    responses = _responses()
    responses[7] = (200, {**_candidate_installation(), "id": CANDIDATE_INSTALLATION_ID + 1})
    subject, _ = _subject(responses)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()
    responses = _responses()
    responses[9] = (200, {"total_count": 0, "repositories": []})
    subject, _ = _subject(responses)
    with pytest.raises(MainPersonalExactCasHostedConfigurationUnverified):
        subject.verify()


def test_object_page_reader_rejects_malformed_page_and_bound() -> None:
    subject, _ = _subject([(200, {"total_count": 1, "repositories": None})])
    with pytest.raises(ValueError, match="malformed"):
        subject._read_object_pages("/probe", "repositories", "token", [])
    page: JsonValue = cast(
        JsonValue, {"total_count": 1001, "repositories": [_repository()] * 100}
    )
    pages: list[tuple[int, JsonValue] | BaseException] = [(200, page) for _ in range(10)]
    subject, _ = _subject(pages)
    with pytest.raises(ValueError, match="bound"):
        subject._read_object_pages("/probe", "repositories", "token", [])


def test_summary_and_clock_guards_reject_untrusted_values() -> None:
    subject, _ = _subject([])
    detail = _writer()
    detail["conditions"] = {"ref_name": {"include": ["refs/heads/main"], "exclude": []}}
    detail["conditions"]["extra"] = []  # type: ignore[index]
    with pytest.raises(ValueError, match="conditions"):
        subject._verify_summary_detail(_summary(101, "AVO C8 main writer"), detail)
    invalid_clock = MainPersonalExactCasGitHubHostedConfigurationVerifier(
        owner_admin_token=OWNER_ADMIN_TOKEN,
        app_jwt=APP_TOKEN,
        candidate_publisher_app_jwt=CANDIDATE_APP_TOKEN,
        candidate_publisher_app_id=CANDIDATE_APP_ID,
        candidate_publisher_installation_id=CANDIDATE_INSTALLATION_ID,
        trusted_clock=lambda: "untrusted",  # type: ignore[return-value]
        transport=FakeTransport([]),
    )
    with pytest.raises(ValueError, match="trusted time"):
        invalid_clock._now()
