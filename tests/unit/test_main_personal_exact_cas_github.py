"""Serverless adversarial tests for the fixed personal exact-CAS transport."""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime
from http.client import HTTPMessage
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from avo_correlate.adapters.hosted_git.github import github_repository_digest
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_github import (
    MainPersonalExactCasGitHubTransport,
    MainPersonalExactCasTransportError,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_personal_exact_cas import (
    MainPersonalExactCasActivation,
    MainPersonalExactCasDispatchStarted,
    MainPersonalExactCasIntent,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_main_personal_exact_cas_journal import (
    _chain,  # pyright: ignore[reportPrivateUsage]
)

NOW = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)


class Response:
    def __init__(self, status: int, body: object, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.closed = False
        self.headers = headers or {"X-GitHub-Request-Id": "req-123"}
        self._raw = json.dumps(body, separators=(",", ":")).encode()

    def read(self, _limit: int = -1) -> bytes:
        return self._raw

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.closed = True
        return None

    def getcode(self) -> int:
        return self.status


class Opener:
    def __init__(self, response: Any) -> None:
        self.response = response
        self.requests: list[Any] = []

    def open(self, request: Any, *, timeout: float) -> Any:
        self.requests.append((request, timeout))
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


def _materials() -> tuple[MainPersonalExactCasIntent, MainPersonalExactCasDispatchStarted, str]:
    plan_digest = canonical_digest({"plan": "transport-fixture"})
    activation = MainPersonalExactCasActivation.build(
        repository_digest=github_repository_digest("vandyand", "avo-c8"),
        source_operation_id=canonical_digest({"source": "operation"}),
        source_plan_digest=plan_digest,
        source_plan_artifact=ArtifactRef(
            digest=plan_digest,
            size_bytes=1,
            media_type="application/vnd.avo.main-graduation-plan+json",
            role="main-graduation-plan",
            created_at=NOW,
        ),
        source_package_digest=canonical_digest({"source": "package"}),
        source_composition_digest=canonical_digest({"source": "composition"}),
        base_commit="a" * 40,
        base_tree="b" * 40,
        candidate_commit="c" * 40,
        candidate_tree="d" * 40,
        candidate_ref="refs/heads/avo/candidate/" + "e" * 64,
        candidate_parents=("a" * 40,),
        protection_ruleset_digest=canonical_digest({"rules": "fixture"}),
        writer_app_id=1,
        writer_installation_id=2,
        writer_identity="fixture-controller",
        activated_at=NOW,
    )
    _, intent, marker, *_ = _chain(activation)
    assert isinstance(intent, MainPersonalExactCasIntent)
    assert isinstance(marker, MainPersonalExactCasDispatchStarted)
    return intent, marker, activation.repository_digest


def _transport(opener: Opener, **kwargs: Any) -> MainPersonalExactCasGitHubTransport:
    trusted_clock = kwargs.pop("trusted_clock", lambda: NOW)
    return MainPersonalExactCasGitHubTransport(
        owner="vandyand",
        repo="avo-c8",
        repository_digest=kwargs.pop("repository_digest"),
        token="secret-token",
        writer_app_id=1,
        writer_installation_id=2,
        writer_identity="fixture-controller",
        opener=opener,
        trusted_clock=trusted_clock,
        **kwargs,
    )


def _success(intent: MainPersonalExactCasIntent) -> dict[str, object]:
    return {"ref": "refs/heads/main", "object": {"sha": intent.candidate_commit}}


def test_exact_patch_shape_and_frozen_sanitized_observation() -> None:
    intent, marker, repository_digest = _materials()
    opener = Opener(
        Response(
            200, _success(intent), {"X-GitHub-Request-Id": "req-123", "Authorization": "secret"}
        )
    )
    observation = _transport(opener, repository_digest=repository_digest).exchange(intent, marker)
    request, timeout = opener.requests[0]
    assert request.full_url == "https://api.github.com/repos/vandyand/avo-c8/git/refs/heads/main"
    assert request.get_method() == "PATCH"
    assert json.loads(request.data) == {"sha": intent.candidate_commit, "force": False}
    assert request.get_header("Authorization") == "Bearer secret-token"
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("X-github-api-version") == "2022-11-28"
    assert timeout == 30.0
    assert observation.status == 200
    assert observation.classification == "candidate_response"
    assert observation.request_id == "req-123"
    assert observation.sanitized_metadata == {"x-github-request-id": "req-123"}
    assert observation.operation_id == intent.operation_id
    assert observation.intent_digest == intent.intent_digest
    assert observation.dispatch_marker_digest == marker.dispatch_marker_digest
    assert observation.is_terminal is False and observation.is_authoritative is False
    assert isinstance(observation.body, MappingProxyType)
    assert opener.response.closed is True
    with pytest.raises(TypeError):
        observation.body["ref"] = "evil"  # type: ignore[index]
    with pytest.raises(TypeError):
        observation.metadata["x"] = "y"  # type: ignore[index]


def test_real_urllib_http_message_headers_are_sanitized() -> None:
    intent, marker, repository_digest = _materials()
    response = Response(200, _success(intent))
    headers = HTTPMessage()
    headers["X-GitHub-Request-Id"] = "req-real-123"
    headers["Authorization"] = "Bearer secret"
    response.headers = headers  # type: ignore[assignment]
    observation = _transport(Opener(response), repository_digest=repository_digest).exchange(
        intent, marker
    )
    assert observation.request_id == "req-real-123"
    assert observation.metadata == {"x-github-request-id": "req-real-123"}


@pytest.mark.parametrize("status", [409, 422, 401, 403, 429, 500, 502, 503])
def test_statuses_are_parsed_without_claiming_authority(
    status: int,
) -> None:
    intent, marker, repository_digest = _materials()
    observation = _transport(
        Opener(Response(status, {"message": "provider secret"})),
        repository_digest=repository_digest,
    ).exchange(intent, marker)
    assert observation.status == status
    expected = {
        409: "conflict_or_rejected",
        422: "configuration_or_validation_rejected",
        401: "authentication_or_authorization_rejected",
        403: "authentication_or_authorization_rejected",
        429: "rate_limited",
        500: "ambiguous",
        502: "ambiguous",
        503: "ambiguous",
    }[status]
    assert observation.classification == expected
    assert "secret" not in repr(observation)


def test_200_body_is_observation_even_when_ref_or_sha_mismatch() -> None:
    intent, marker, repository_digest = _materials()
    bodies: tuple[dict[str, object], ...] = (
        {"ref": "refs/heads/other", "object": {"sha": intent.candidate_commit}},
        {"ref": "refs/heads/main", "object": {"sha": "0" * 40}},
        {"ref": "refs/heads/main", "object": {}},
    )
    for body in bodies:
        observation = _transport(
            Opener(Response(200, body)), repository_digest=repository_digest
        ).exchange(intent, marker)
        assert observation.classification == "candidate_response"


def test_timeout_malformed_duplicate_and_oversize_are_code_only_errors() -> None:
    intent, marker, repository_digest = _materials()
    with pytest.raises(MainPersonalExactCasTransportError) as timeout:
        _transport(
            Opener(TimeoutError("token=secret")), repository_digest=repository_digest
        ).exchange(intent, marker)
    assert timeout.value.code == "transport_ambiguous"
    assert timeout.value.__cause__ is None and timeout.value.__context__ is None
    assert "secret" not in repr(timeout.value)

    class Malformed(Response):
        def __init__(self) -> None:
            self.status = 200
            self.headers = {"X-GitHub-Request-Id": "req-safe"}

        def read(self, _limit: int = -1) -> bytes:
            return b'{"ref":"main","ref":"secret"}'

    with pytest.raises(MainPersonalExactCasTransportError) as malformed:
        _transport(Opener(Malformed()), repository_digest=repository_digest).exchange(
            intent, marker
        )
    assert malformed.value.code == "malformed_response"
    with pytest.raises(MainPersonalExactCasTransportError) as large:
        _transport(
            Opener(Response(200, {})), repository_digest=repository_digest, max_response_bytes=1
        ).exchange(intent, marker)
    assert large.value.code == "response_too_large"

    def bad_clock() -> datetime:
        raise RuntimeError("token=secret")

    with pytest.raises(MainPersonalExactCasTransportError) as clock:
        _transport(
            Opener(Response(200, {})),
            repository_digest=repository_digest,
            trusted_clock=bad_clock,
        ).exchange(intent, marker)
    assert clock.value.code == "transport_ambiguous"
    assert clock.value.__cause__ is None and clock.value.__context__ is None
    assert "secret" not in repr(clock.value)


def test_wrong_scope_writer_and_marker_are_rejected_before_opener() -> None:
    intent, marker, repository_digest = _materials()
    opener = Opener(Response(200, _success(intent)))
    transport = _transport(opener, repository_digest=repository_digest)
    wrong = intent.model_copy(update={"writer_identity": "other"})
    with pytest.raises(MainPersonalExactCasTransportError):
        transport.exchange(wrong, marker)
    assert not opener.requests

    other_marker = marker.model_copy(update={"claim_nonce": "other"})
    with pytest.raises(MainPersonalExactCasTransportError):
        transport.exchange(intent, other_marker)
    assert not opener.requests

    with pytest.raises(TypeError):
        transport.exchange(intent, object())  # type: ignore[arg-type]
    assert not opener.requests

    malformed = intent.model_copy(update={"candidate_commit": "f" * 40})
    malformed_marker = marker.model_copy(update={"candidate_commit": "f" * 40})
    with pytest.raises(MainPersonalExactCasTransportError) as error:
        transport.exchange(malformed, malformed_marker)
    assert error.value.__cause__ is None and error.value.__context__ is None
    assert not opener.requests


def test_redirect_handler_rejects_without_following_or_forwarding_credentials() -> None:
    from avo_correlate.adapters.hosted_git import main_personal_exact_cas_github as module

    handler = module._NoRedirectHandler()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(MainPersonalExactCasTransportError) as error:
        handler.redirect_request(None, 302, "", {}, "https://evil.example/collect")
    assert error.value.code == "redirect_rejected"


def test_public_surface_and_module_are_not_generic_or_receipt_writers() -> None:
    path = Path("src/avo_correlate/adapters/hosted_git/main_personal_exact_cas_github.py")
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    transport = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "MainPersonalExactCasGitHubTransport"
    )
    public = {
        node.name
        for node in transport.body
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
    }
    assert public == {"exchange"}
    exchange = next(
        node
        for node in transport.body
        if isinstance(node, ast.FunctionDef) and node.name == "exchange"
    )
    assert {arg.arg for arg in exchange.args.args} == {"self", "intent", "marker"}
    assert "MainPersonalExactCasReceipt" not in source
    assert "DELETE" not in source
    assert "force=True" not in source
