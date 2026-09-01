"""Security tests for the bounded GitHub JSON transport."""
# pyright: reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportPrivateUsage=false

import io
from datetime import UTC, datetime
from email.message import Message
from typing import Any, NoReturn, cast
from urllib.error import HTTPError
from urllib.request import Request

import pytest

from avo_correlate.adapters.hosted_git import github_transport
from avo_correlate.adapters.hosted_git.github import (
    GitHubIntegrationProvider,
    GitHubRejected,
    GitHubTransportError,
    github_repository_digest,
)
from avo_correlate.adapters.hosted_git.github_transport import GitHubJsonTransport


class _Response:
    status = 200

    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.payload[:limit]


def test_origin_is_pinned_before_opener_and_credentials_never_appear(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def opener(*args: object, **kwargs: object) -> _Response:
        nonlocal called
        called = True
        return _Response(b"{}")

    monkeypatch.setattr(github_transport._NO_REDIRECT_OPENER, "open", opener)
    transport = GitHubJsonTransport()
    for url in (
        "http://api.github.com/repos/x",
        "https://evil.example/repos/x",
        "https://user:secret@api.github.com/repos/x",
        "https://api.github.com:444/repos/x",
    ):
        with pytest.raises(ValueError):
            transport("GET", url, None, {"Authorization": "Bearer secret-token"})
    assert not called
    assert "secret-token" not in repr(transport)
    with pytest.raises(ValueError):
        GitHubJsonTransport(origin="https://api.github.com?evil=1")
    for method in ("get", "OPTIONS", "CUSTOM", "GET\x7f"):
        with pytest.raises(ValueError):
            transport(method, "https://api.github.com/repos/x", None, {})
    assert not called


def test_request_and_response_bounds_are_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = GitHubJsonTransport(max_request_bytes=5, max_response_bytes=3)
    with pytest.raises(ValueError, match="request body"):
        transport("POST", "https://api.github.com/x", {"value": "large"}, {})
    monkeypatch.setattr(
        github_transport._NO_REDIRECT_OPENER,
        "open",
        lambda *args, **kwargs: _Response(b"{}xx"),
    )
    with pytest.raises(GitHubTransportError, match="response exceeded"):
        transport("GET", "https://api.github.com/x", None, {})


def test_duplicate_keys_and_nonfinite_json_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = GitHubJsonTransport()
    for payload in (b'{"a":1,"a":2}', b"NaN"):
        monkeypatch.setattr(
            github_transport._NO_REDIRECT_OPENER,
            "open",
            lambda *args, payload=payload, **kwargs: _Response(payload),
        )
        with pytest.raises(GitHubTransportError, match="strict JSON"):
            transport("GET", "https://api.github.com/x", None, {})


def test_normal_objects_and_adapter_query_urls_are_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        github_transport._NO_REDIRECT_OPENER,
        "open",
        lambda *args, **kwargs: _Response(b'{"data":[1]}'),
    )
    transport = GitHubJsonTransport()
    assert transport("GET", "https://api.github.com/graphql?query=bound", None, {}) == (
        200,
        {"data": [1]},
    )
    with pytest.raises(ValueError):
        transport("GET", "https://api.github.com/graphql?x=1#fragment", None, {})
    with pytest.raises(ValueError, match="strict JSON"):
        transport("POST", "https://api.github.com/x", {1: "bad"}, {})  # type: ignore[dict-item]


def test_redirect_handler_rejects_before_following_another_origin() -> None:
    handler = github_transport._NoRedirectHandler()
    with pytest.raises(GitHubTransportError, match="redirect"):
        handler.redirect_request(None, 302, "", {}, "https://evil.example/")


def test_default_provider_rejects_cross_origin_redirect_without_forwarding_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The provider's live default must use the pinned, no-redirect transport."""

    provider = GitHubIntegrationProvider(
        owner="acme",
        repo="widget",
        repository_digest=github_repository_digest("acme", "widget"),
        target_ref="refs/heads/integration",
        trusted_checks=(("ci", 7),),
        protection_checks=(("ci", 7),),
        freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
        token="secret-token",
    )
    assert isinstance(provider.transport, GitHubJsonTransport)

    requests: list[Request] = []

    def open_with_cross_origin_redirect(request: Request, **_: object) -> NoReturn:
        requests.append(request)
        handler = next(
            item
            for item in cast(Any, github_transport._NO_REDIRECT_OPENER).handlers
            if isinstance(item, github_transport._NoRedirectHandler)
        )
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {"Location": "https://evil.example/collect"},
            "https://evil.example/collect",
        )
        raise AssertionError("the no-redirect handler must reject before this point")

    monkeypatch.setattr(
        github_transport._NO_REDIRECT_OPENER, "open", open_with_cross_origin_redirect
    )
    with pytest.raises(GitHubTransportError, match="redirect"):
        provider.observe_integration("refs/heads/integration")

    assert len(requests) == 1
    request = requests[0]
    assert request.full_url == "https://api.github.com/repos/acme/widget/git/ref/heads/integration"
    assert request.get_header("Authorization") == "Bearer secret-token"


def test_4xx_is_authoritative_but_5xx_and_timeout_are_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = GitHubJsonTransport()
    for status in (401, 429):
        monkeypatch.setattr(
            github_transport._NO_REDIRECT_OPENER,
            "open",
            lambda *args, status=status, **kwargs: (_ for _ in ()).throw(
                HTTPError(
                    "https://api.github.com/x", status, "secret-token", Message(), io.BytesIO()
                )
            ),
        )
        with pytest.raises(GitHubRejected) as exc_info:
            transport("GET", "https://api.github.com/x", None, {})
        assert exc_info.value.status == status
        assert "secret-token" not in str(exc_info.value)
        assert exc_info.value.__cause__ is None
    monkeypatch.setattr(
        github_transport._NO_REDIRECT_OPENER,
        "open",
        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("secret-token")),
    )
    with pytest.raises(GitHubTransportError) as exc_info:
        transport("GET", "https://api.github.com/x", None, {})
    assert "secret-token" not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


def test_callable_accepts_both_provider_transport_shapes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        github_transport._NO_REDIRECT_OPENER,
        "open",
        lambda *args, **kwargs: _Response(b"[1, true, null]"),
    )
    transport = GitHubJsonTransport()
    assert transport("GET", "https://api.github.com/x", None, {}) == (200, [1, True, None])
    monkeypatch.setattr(
        github_transport._NO_REDIRECT_OPENER,
        "open",
        lambda *args, **kwargs: _Response(b'"ok"'),
    )
    assert transport("POST", "https://api.github.com/x", {"x": 1}, {}) == (200, "ok")
