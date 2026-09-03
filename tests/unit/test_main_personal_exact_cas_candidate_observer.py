"""Adversarial tests for the non-authoritative candidate observer."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import pytest

from avo_correlate.adapters.hosted_git import (
    GitHubCandidateRefObserver,
    MainPersonalExactCasCandidateObservationError,
)
from avo_correlate.adapters.hosted_git import (
    main_personal_exact_cas_candidate_observer as module,
)
from avo_correlate.adapters.hosted_git.github import github_repository_digest
from avo_correlate.adapters.hosted_git.github_main_base_reader import (
    GitHubMainBaseReaderConfiguration,
    GitHubMainBaseReaderCredentials,
)
from avo_correlate.contracts.main_personal_exact_cas_candidate_observation import (
    MainPersonalExactCasCandidateObservationRequest,
    candidate_ref_for_operation,
)

OWNER = "alice"
REPOSITORY = "avo-c8"
OWNER_ID = 10
REPOSITORY_ID = 11
APP_ID = 12
INSTALLATION_ID = 13
OPERATION = "sha256:" + "a" * 64
COMMIT = "b" * 40
TREE = "c" * 40
PARENT = "d" * 40
REF = candidate_ref_for_operation(OPERATION)
NOW = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)


class FakeTransport:
    responses: ClassVar[list[tuple[int, object]]] = []
    instances: ClassVar[list[FakeTransport]] = []

    def __init__(self, **_: object) -> None:
        self.calls: list[tuple[str, str, object, dict[str, str]]] = []
        self.__class__.instances.append(self)

    def __call__(
        self, method: str, url: str, body: object, headers: dict[str, str]
    ) -> tuple[int, object]:
        self.calls.append((method, url, body, headers))
        if not self.responses:
            raise RuntimeError("fixture exhausted secret=jwt")
        return self.responses.pop(0)


def _configuration() -> GitHubMainBaseReaderConfiguration:
    return GitHubMainBaseReaderConfiguration(
        owner=OWNER,
        owner_id=OWNER_ID,
        repo=REPOSITORY,
        repository_id=REPOSITORY_ID,
        repository_digest=github_repository_digest(OWNER, REPOSITORY),
        observer_identity="observer-app",
        observer_app_name="Observer App",
        observer_app_id=APP_ID,
        observer_installation_id=INSTALLATION_ID,
        writer_app_id=14,
        writer_installation_id=15,
    )


def _responses(*, fence: str = COMMIT) -> list[tuple[int, object]]:
    return [
        (
            200,
            {
                "id": APP_ID,
                "slug": "observer-app",
                "name": "Observer App",
                "permissions": {"contents": "read", "metadata": "read"},
                "events": [],
                "owner": {"login": OWNER, "id": OWNER_ID, "type": "User"},
                "hostile": "jwt-secret",
            },
        ),
        (
            200,
            {
                "id": INSTALLATION_ID,
                "app_id": APP_ID,
                "app_slug": "observer-app",
                "repository_selection": "selected",
                "target_id": OWNER_ID,
                "target_type": "User",
                "suspended_at": None,
                "permissions": {"contents": "read", "metadata": "read"},
                "events": [],
                "account": {"login": OWNER, "id": OWNER_ID, "type": "User"},
                "hostile": "installation-secret",
            },
        ),
        (
            201,
            {
                "token": "installation-token-secret",
                "expires_at": (NOW + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "permissions": {"contents": "read", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [
                    {
                        "id": REPOSITORY_ID,
                        "name": REPOSITORY,
                        "full_name": f"{OWNER}/{REPOSITORY}",
                        "owner": {"login": OWNER, "id": OWNER_ID, "type": "User"},
                    }
                ],
            },
        ),
        (
            200,
            {
                "id": REPOSITORY_ID,
                "name": REPOSITORY,
                "full_name": f"{OWNER}/{REPOSITORY}",
                "owner": {"login": OWNER, "id": OWNER_ID, "type": "User"},
            },
        ),
        (200, {"ref": REF, "object": {"type": "commit", "sha": COMMIT}}),
        (
            200,
            {
                "sha": COMMIT,
                "tree": {"sha": TREE},
                "parents": [{"sha": PARENT}],
                "hostile": "commit-secret",
            },
        ),
        (200, {"ref": REF, "object": {"type": "commit", "sha": fence}}),
    ]


def _reader(monkeypatch: pytest.MonkeyPatch, responses: list[tuple[int, object]]) -> Any:
    monkeypatch.setattr(module, "GitHubJsonTransport", FakeTransport)
    monkeypatch.setattr(module, "_utc_now", lambda: NOW)
    FakeTransport.responses = responses
    FakeTransport.instances.clear()
    return GitHubCandidateRefObserver(
        _configuration(), GitHubMainBaseReaderCredentials("app-jwt-secret")
    )


def _request() -> MainPersonalExactCasCandidateObservationRequest:
    return MainPersonalExactCasCandidateObservationRequest(
        operation_id=OPERATION,
        repository_digest=github_repository_digest(OWNER, REPOSITORY),
        candidate_ref=REF,
    )


def test_candidate_observation_is_fenced_and_secret_free(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _reader(monkeypatch, _responses())
    observed = reader.observe_with_provenance(_request())
    assert observed.result.candidate_commit == COMMIT
    assert observed.result.candidate_tree == TREE
    assert observed.result.candidate_parents == (PARENT,)
    assert observed.result.policy.status == "unverifiable"
    assert observed.result.policy.missing_prerequisite == (
        "separate-owner-admin-ruleset-read-credential"
    )
    assert [item.method for item in observed.provenance.requests] == [
        "GET",
        "GET",
        "POST",
        "GET",
        "GET",
        "GET",
        "GET",
    ]
    assert [item.path for item in observed.provenance.requests] == [
        "/app",
        f"/app/installations/{INSTALLATION_ID}",
        f"/app/installations/{INSTALLATION_ID}/access_tokens",
        f"/repositories/{REPOSITORY_ID}",
        f"/repos/{OWNER}/{REPOSITORY}/git/ref/heads/avo/candidate/" + "a" * 64,
        f"/repos/{OWNER}/{REPOSITORY}/git/commits/{COMMIT}",
        f"/repos/{OWNER}/{REPOSITORY}/git/ref/heads/avo/candidate/" + "a" * 64,
    ]
    assert all(call[0] in {"GET", "POST"} for call in FakeTransport.instances[0].calls)
    assert FakeTransport.instances[0].calls[2][1].endswith("/access_tokens")
    assert FakeTransport.instances[0].calls[2][2] == {
        "repository_ids": [REPOSITORY_ID],
        "permissions": {"contents": "read"},
    }
    assert all(
        call[3]["Authorization"] == "Bearer app-jwt-secret"
        for call in FakeTransport.instances[0].calls[:3]
    )
    assert all(
        call[3]["Authorization"] == "Bearer installation-token-secret"
        for call in FakeTransport.instances[0].calls[3:]
    )
    assert all("policy" not in item.path for item in observed.provenance.requests)
    assert "jwt-secret" not in repr(observed)


def test_candidate_ref_drift_fails_closed_without_exception_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = _reader(monkeypatch, _responses(fence="e" * 40))
    with pytest.raises(MainPersonalExactCasCandidateObservationError) as raised:
        reader.observe(_request())
    assert str(raised.value) == "candidate_observation_unresolved"
    assert raised.value.__cause__ is None and raised.value.__context__ is None


@pytest.mark.parametrize(
    "bad_ref",
    ["refs/heads/main", "refs/heads/avo/main-rollback/" + "a" * 64, "refs/heads/avo/candidate/bad"],
)
def test_request_namespace_is_exact_and_rejected_before_network(
    monkeypatch: pytest.MonkeyPatch, bad_ref: str
) -> None:
    reader = _reader(monkeypatch, [])
    with pytest.raises(MainPersonalExactCasCandidateObservationError):
        reader.observe(
            MainPersonalExactCasCandidateObservationRequest.model_construct(
                operation_id=OPERATION,
                repository_digest=reader.repository_digest,
                candidate_ref=bad_ref,
            )
        )
    assert FakeTransport.instances[0].calls == []


def test_malformed_ordered_parent_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = _responses()
    body = responses[5][1]
    assert isinstance(body, dict)
    body["parents"] = [{"sha": "bad"}]
    reader = _reader(monkeypatch, responses)
    with pytest.raises(MainPersonalExactCasCandidateObservationError):
        reader.observe(_request())


def test_installation_token_scope_is_exact(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = _responses()
    token = responses[2][1]
    assert isinstance(token, dict)
    token["permissions"] = {"contents": "write", "metadata": "read"}
    reader = _reader(monkeypatch, responses)
    with pytest.raises(MainPersonalExactCasCandidateObservationError):
        reader.observe(_request())
    assert len(FakeTransport.instances[0].calls) == 3


def test_policy_requires_a_separate_owner_admin_read_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = _reader(monkeypatch, _responses())
    observed = reader.observe(_request())
    assert observed.policy.status == "unverifiable"
    assert observed.policy.missing_prerequisite == ("separate-owner-admin-ruleset-read-credential")


def test_observer_is_frozen_and_has_no_mutation_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _reader(monkeypatch, [])
    names = {name for name in dir(reader) if not name.startswith("_")}
    assert names == {
        "configuration_digest",
        "observe",
        "observe_with_provenance",
        "repository_digest",
    }
    for name in ("post", "put", "patch", "delete", "mutate", "publish", "dispatch"):
        assert not hasattr(reader, name)
    with pytest.raises(FrozenInstanceError):
        reader._configuration = _configuration()  # type: ignore[misc]
