"""Security tests for the bounded GitHub JSON transport."""
# pyright: reportUnknownArgumentType=false, reportUnknownLambdaType=false

import io
from email.message import Message
from urllib.error import HTTPError

import pytest

from avo_correlate.adapters.hosted_git import github_transport
from avo_correlate.adapters.hosted_git.github import GitHubRejected, GitHubTransportError
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

    monkeypatch.setattr(github_transport, "urlopen", opener)
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


def test_request_and_response_bounds_are_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = GitHubJsonTransport(max_request_bytes=5, max_response_bytes=3)
    with pytest.raises(ValueError, match="request body"):
        transport("POST", "https://api.github.com/x", {"value": "large"}, {})
    monkeypatch.setattr(github_transport, "urlopen", lambda *args, **kwargs: _Response(b"{}xx"))
    with pytest.raises(GitHubTransportError, match="response exceeded"):
        transport("GET", "https://api.github.com/x", None, {})


def test_duplicate_keys_and_nonfinite_json_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = GitHubJsonTransport()
    for payload in (b'{"a":1,"a":2}', b"NaN"):
        monkeypatch.setattr(
            github_transport,
            "urlopen",
            lambda *args, payload=payload, **kwargs: _Response(payload),
        )
        with pytest.raises(GitHubTransportError, match="strict JSON"):
            transport("GET", "https://api.github.com/x", None, {})


def test_4xx_is_authoritative_but_5xx_and_timeout_are_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = GitHubJsonTransport()
    for status in (401, 429):
        monkeypatch.setattr(
            github_transport,
            "urlopen",
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
    monkeypatch.setattr(
        github_transport,
        "urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError("secret-token")),
    )
    with pytest.raises(GitHubTransportError) as exc_info:
        transport("GET", "https://api.github.com/x", None, {})
    assert "secret-token" not in str(exc_info.value)


def test_callable_accepts_both_provider_transport_shapes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        github_transport,
        "urlopen",
        lambda *args, **kwargs: _Response(b"[1, true, null]"),
    )
    transport = GitHubJsonTransport()
    assert transport("GET", "https://api.github.com/x", None, {}) == (200, [1, True, None])
    monkeypatch.setattr(github_transport, "urlopen", lambda *args, **kwargs: _Response(b'"ok"'))
    assert transport("POST", "https://api.github.com/x", {"x": 1}, {}) == (200, "ok")
