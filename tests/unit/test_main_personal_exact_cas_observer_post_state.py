"""Adversarial coverage for the App-bound exact post-state observer."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from typing import Any

import pytest

from avo_correlate.adapters.hosted_git import github_main_base_reader as base_module
from avo_correlate.adapters.hosted_git.github_main_base_reader import (
    GitHubMainBaseReaderConfiguration,
    GitHubMainBaseReaderCredentials,
)
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_post_state import (
    GitHubMainBasePostStateReader,
    MainPersonalExactCasPostStateTransportError,
)
from tests.unit.test_github_main_base_reader import (
    APP_ID,
    APP_NAME,
    APP_SLUG,
    COMMIT,
    INSTALLATION_ID,
    NOW,
    OWNER,
    OWNER_ID,
    REPO,
    REPOSITORY_ID,
    TREE,
    FakeTransport,
    _responses,
)
from tests.unit.test_main_personal_exact_cas_post_state import REPO_DIGEST, _chain


def _reader(monkeypatch: pytest.MonkeyPatch, responses: list[tuple[int, object]]) -> Any:
    def fake_digest(_owner: str, _repo: str) -> str:
        return REPO_DIGEST

    monkeypatch.setattr(base_module, "github_repository_digest", fake_digest)
    monkeypatch.setattr(base_module, "GitHubJsonTransport", FakeTransport)
    monkeypatch.setattr(base_module, "_utc_now", lambda: NOW)
    FakeTransport.instances.clear()
    FakeTransport.responses = responses
    config = GitHubMainBaseReaderConfiguration(
        owner=OWNER,
        owner_id=OWNER_ID,
        repo=REPO,
        repository_id=REPOSITORY_ID,
        repository_digest=REPO_DIGEST,
        observer_identity=APP_SLUG,
        observer_app_name=APP_NAME,
        observer_app_id=APP_ID,
        observer_installation_id=INSTALLATION_ID,
        writer_app_id=1,
        writer_installation_id=2,
    )
    return GitHubMainBasePostStateReader(
        config, GitHubMainBaseReaderCredentials("observer-app-jwt"), lambda: NOW
    )


def test_exact_observer_routes_app_jwt_then_one_scoped_installation_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = _reader(monkeypatch, _responses())
    intent, _ = _chain()
    observed = reader.observe_with_provenance(intent)
    assert observed.result.observed_commit == COMMIT
    assert observed.result.observed_tree == TREE
    assert observed.result.observed_parents == ("c" * 40,)
    assert len(observed.provenance.requests) == 7
    assert observed.provenance.requests[2].method == "POST"
    assert observed.provenance.requests[2].credential_role == "app_jwt"
    assert all(
        request.credential_role == "app_jwt"
        for request in observed.provenance.requests[:3]
    )
    assert all(
        request.credential_role == "installation_token"
        for request in observed.provenance.requests[3:]
    )
    assert FakeTransport.instances[0].calls[0][3]["Authorization"] == "Bearer observer-app-jwt"
    assert all(
        call[3]["Authorization"] == "Bearer reader-minted-installation-token"
        for call in FakeTransport.instances[0].calls[3:]
    )


def test_intent_scope_and_configuration_identity_fail_before_or_after_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = _reader(monkeypatch, [])
    intent, _ = _chain()
    with pytest.raises(MainPersonalExactCasPostStateTransportError):
        reader.observe(intent.model_copy(update={"target_ref": "refs/heads/dev"}))
    assert FakeTransport.instances[0].calls == []


def test_hostile_extra_fields_do_not_change_provenance_or_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    intent, _ = _chain()
    baseline = _reader(monkeypatch, _responses()).observe_with_provenance(intent)
    responses = _responses()
    for index in (0, 1, 3, 4, 5, 6):
        body = responses[index][1]
        assert isinstance(body, dict)
        body["secret_canary"] = "writer-jwt-secret"
    changed = _reader(monkeypatch, responses).observe_with_provenance(intent)
    assert changed.result == baseline.result
    assert changed.provenance == baseline.provenance
    assert "writer-jwt-secret" not in repr(changed)


def test_observer_is_frozen_and_has_no_mutation_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _reader(monkeypatch, [])
    names = {name for name in dir(reader) if not name.startswith("_")}
    assert names == {
        "configuration_digest",
        "observe",
        "observe_with_provenance",
        "repository_digest",
    }
    for name in ("post", "put", "patch", "delete", "mutate", "exchange"):
        assert not hasattr(reader, name)
    with pytest.raises(FrozenInstanceError):
        reader._clock = lambda: datetime.now(UTC)  # type: ignore[misc]


def test_transport_error_has_no_exception_context_or_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = _reader(monkeypatch, [(200, RuntimeError("writer-jwt-secret"))])
    intent, _ = _chain()
    with pytest.raises(MainPersonalExactCasPostStateTransportError) as raised:
        reader.observe_with_provenance(intent)
    assert str(raised.value) == "post_state_unresolved"
    assert raised.value.__cause__ is None and raised.value.__context__ is None
    assert "writer-jwt-secret" not in repr(raised.value)
