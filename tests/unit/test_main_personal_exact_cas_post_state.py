"""Fast adversarial tests for the fixed read-only main observation leaf."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

import pytest

from avo_correlate.adapters.hosted_git import main_personal_exact_cas_post_state as module
from avo_correlate.adapters.hosted_git.github import GitHubRejected, GitHubTransportError
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_post_state import (
    MainPersonalExactCasGitHubPostStateReader,
    MainPersonalExactCasPostStateTransportError,
)
from avo_correlate.contracts.main_personal_exact_cas_post_state import (
    MainPersonalExactCasReadOnlyPostState,
)
from tests.unit.test_main_personal_exact_cas_response_evidence import _chain

NOW = datetime(2026, 1, 1, tzinfo=UTC)
REPO_DIGEST = "sha256:" + "a" * 64


class FakeTransport:
    responses: ClassVar[list[tuple[int, object]]] = []
    calls: ClassVar[list[tuple[str, str, object, dict[str, str]]]] = []

    def __init__(self, **_kwargs: object) -> None:
        self._responses = list(type(self).responses)
        type(self).calls = []

    def __call__(
        self, method: str, url: str, body: object, headers: dict[str, str]
    ) -> tuple[int, object]:
        type(self).calls.append((method, url, body, headers))
        if not self._responses:
            raise RuntimeError("unexpected call")
        response = self._responses.pop(0)
        if isinstance(response[1], BaseException):
            raise response[1]
        return response


def _fake_repo_digest(_owner: str, _repo: str) -> str:
    return REPO_DIGEST


def _reader(
    monkeypatch: pytest.MonkeyPatch,
    responses: list[tuple[int, object]],
    clock: Any = None,
):
    intent, _marker = _chain()
    monkeypatch.setattr(
        module,
        "github_repository_digest",
        _fake_repo_digest,
    )
    monkeypatch.setattr(module, "GitHubJsonTransport", FakeTransport)
    FakeTransport.responses = responses
    times = iter((NOW, NOW + timedelta(seconds=1))) if clock is None else clock
    reader = MainPersonalExactCasGitHubPostStateReader(
        owner="fixture",
        repo="repo",
        repository_digest=REPO_DIGEST,
        token="test-secret-token",
        trusted_clock=lambda: next(times),
    )
    return reader, intent


def _ref(sha: str, *, object_type: str = "commit") -> dict[str, object]:
    return {"ref": "refs/heads/main", "object": {"sha": sha, "type": object_type}}


def _commit(sha: str, *, parents: list[str] | None = None) -> dict[str, object]:
    return {
        "sha": sha,
        "tree": {"sha": "4" * 40},
        "parents": [{"sha": value} for value in (parents or ["1" * 40, "2" * 40])],
    }


BAD_RESPONSES: list[list[tuple[int, object]]] = [
    [
        (200, _ref("3" * 40, object_type="tree")),
        (200, _commit("3" * 40)),
        (200, _ref("3" * 40)),
    ],
    [
        (200, _ref("3" * 40)),
        (
            200,
            {
                "sha": "3" * 40,
                "tree": {"sha": "4" * 40},
                "parents": [{"sha": "bad"}],
            },
        ),
        (200, _ref("3" * 40)),
    ],
    [(200, _ref("3" * 40)), (500, {}), (200, _ref("3" * 40))],
]


def test_three_fixed_reads_return_nonterminal_topology(monkeypatch: pytest.MonkeyPatch):
    sha = "3" * 40
    reader, intent = _reader(
        monkeypatch,
        [(200, _ref(sha)), (200, _commit(sha)), (200, _ref(sha))],
    )
    result = reader.observe(intent)
    assert isinstance(result, MainPersonalExactCasReadOnlyPostState)
    assert result.observed_commit == sha
    assert result.observed_parents == ("1" * 40, "2" * 40)
    assert result.is_terminal is False and result.is_authoritative is False
    assert [call[0] for call in FakeTransport.calls] == ["GET", "GET", "GET"]
    assert [call[1] for call in FakeTransport.calls] == [
        "https://api.github.com/repos/fixture/repo/git/ref/heads/main",
        f"https://api.github.com/repos/fixture/repo/git/commits/{sha}",
        "https://api.github.com/repos/fixture/repo/git/ref/heads/main",
    ]
    assert all(call[2] is None for call in FakeTransport.calls)
    assert all(
        call[3]
        == {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer test-secret-token",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        for call in FakeTransport.calls
    )


def test_final_ref_drift_is_rejected_without_secret_context(monkeypatch: pytest.MonkeyPatch):
    sha = "3" * 40
    reader, intent = _reader(
        monkeypatch,
        [(200, _ref(sha)), (200, _commit(sha)), (200, _ref("5" * 40))],
    )
    with pytest.raises(MainPersonalExactCasPostStateTransportError) as raised:
        reader.observe(intent)
    assert str(raised.value) == "post_state_unresolved"
    assert "secret" not in repr(raised.value)
    assert raised.value.__cause__ is None and raised.value.__context__ is None


@pytest.mark.parametrize(
    "responses",
    BAD_RESPONSES,
)
def test_wrong_type_parent_or_status_fails_closed(
    monkeypatch: pytest.MonkeyPatch, responses: list[tuple[int, object]]
):
    reader, intent = _reader(monkeypatch, responses)
    with pytest.raises(MainPersonalExactCasPostStateTransportError):
        reader.observe(intent)


def test_noncanonical_intent_scope_rejected_before_network(monkeypatch: pytest.MonkeyPatch):
    reader, intent = _reader(monkeypatch, [])
    forged = intent.model_copy(update={"target_ref": "refs/heads/other"})
    with pytest.raises(MainPersonalExactCasPostStateTransportError):
        reader.observe(forged)
    assert FakeTransport.calls == []


@pytest.mark.parametrize(
    "failure",
    [
        GitHubTransportError("redirect https://evil.example token=secret"),
        GitHubRejected("malformed response token=secret", status=401),
        RuntimeError("cross-origin token=secret"),
    ],
)
def test_transport_failures_are_code_only_without_exception_context(
    monkeypatch: pytest.MonkeyPatch, failure: BaseException
):
    reader, intent = _reader(monkeypatch, [(200, failure)])
    with pytest.raises(MainPersonalExactCasPostStateTransportError) as raised:
        reader.observe(intent)
    assert str(raised.value) == "post_state_unresolved"
    assert "secret" not in repr(raised.value)
    assert raised.value.__cause__ is None and raised.value.__context__ is None


def test_contract_model_copy_cannot_change_observation_identity(monkeypatch: pytest.MonkeyPatch):
    sha = "3" * 40
    reader, intent = _reader(
        monkeypatch,
        [(200, _ref(sha)), (200, _commit(sha)), (200, _ref(sha))],
    )
    result = reader.observe(intent)
    forged = result.model_copy(update={"observed_commit": "5" * 40})
    with pytest.raises(ValueError):
        MainPersonalExactCasReadOnlyPostState.model_validate(forged.model_dump(mode="json"))


def test_public_surface_has_no_mutation_or_receipt_dto():
    names = set(dir(MainPersonalExactCasGitHubPostStateReader))
    assert "apply" not in names and "exchange" not in names
    source = Path(
        "src/avo_correlate/adapters/hosted_git/main_personal_exact_cas_post_state.py"
    ).read_text(encoding="utf-8")
    assert "MainPersonalExactCasReceipt" not in source
    assert "MainPersonalExactCasPostStateObservation" not in source
    assert "PATCH" not in source and "DELETE" not in source
