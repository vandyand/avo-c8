"""Adversarial tests for the pure personal exact-CAS response boundary."""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.hosted_git.main_personal_exact_cas_response import (
    MainPersonalExactCasResponse,
    MainPersonalExactCasResponseError,
    parse_main_personal_exact_cas_response,
)


def parse(
    status: object = 200,
    body: object = {"ok": True},
    headers: object = None,
    max_body_bytes: int = 1024 * 1024,
    max_body_depth: int = 32,
    max_headers: int = 64,
    max_header_key_length: int = 128,
    max_header_value_length: int = 2048,
) -> MainPersonalExactCasResponse:
    return parse_main_personal_exact_cas_response(
        status,
        body,
        headers if headers is not None else {},
        max_body_bytes=max_body_bytes,
        max_body_depth=max_body_depth,
        max_headers=max_headers,
        max_header_key_length=max_header_key_length,
        max_header_value_length=max_header_value_length,
    )


def test_success_is_candidate_only_and_headers_are_case_folded() -> None:
    result = parse(
        headers={
            "X-GITHUB-REQUEST-ID": "req-1",
            "ETag": '"abc"',
            "X-RateLimit-Remaining": "9",
            "Authorization": "Bearer secret",
            "X-Arbitrary": "discarded",
        }
    )

    assert result.classification == "candidate_response"
    assert result.is_terminal is False
    assert result.headers == {
        "x-github-request-id": "req-1",
        "x-ratelimit-remaining": "9",
    }
    assert "secret" not in repr(result)
    with pytest.raises(FrozenInstanceError):
        attribute_name = "status"
        setattr(result, attribute_name, 201)


def test_status_classes_are_deterministic() -> None:
    expected = {
        200: "candidate_response",
        401: "authentication_or_authorization_rejected",
        403: "authentication_or_authorization_rejected",
        409: "conflict_or_rejected",
        422: "configuration_or_validation_rejected",
        429: "rate_limited",
        500: "ambiguous",
        599: "ambiguous",
        300: "unverifiable",
    }
    for status, classification in expected.items():
        assert parse(status).classification == classification


def test_body_is_bounded_strict_json_and_canonical_friendly() -> None:
    result = parse(body={"z": [1, None, False], "a": "é"})
    assert result.body == {"z": [1, None, False], "a": "é"}
    assert parse(body={"nested": {"ok": 1}}, max_body_depth=2).body
    with pytest.raises(MainPersonalExactCasResponseError):
        parse(body={"nested": {"too": {"deep": True}}}, max_body_depth=2)
    with pytest.raises(MainPersonalExactCasResponseError):
        parse(body=float("nan"))
    with pytest.raises(MainPersonalExactCasResponseError):
        parse(body={"x": "0123456789"}, max_body_bytes=5)
    with pytest.raises(MainPersonalExactCasResponseError):
        parse(body={1: "non-string-key"})


def test_lone_surrogate_body_is_a_redacted_domain_error() -> None:
    with pytest.raises(MainPersonalExactCasResponseError) as caught:
        parse(body="\ud800")
    assert str(caught.value) == "invalid exact-CAS response"
    assert repr(caught.value) == "MainPersonalExactCasResponseError()"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize("status", [True, False, 99, 600, "200", 200.0])
def test_status_must_be_a_strict_bounded_integer(status: object) -> None:
    with pytest.raises(MainPersonalExactCasResponseError):
        parse(status)


def test_secret_and_arbitrary_headers_are_never_retained() -> None:
    result = parse(
        headers={
            "Authorization": "Bearer very-secret",
            "Cookie": "session=secret",
            "Set-Cookie": "session=secret",
            "X-Not-Allowlisted": "secret",
            "Retry-After": "10",
        }
    )
    assert result.metadata == {"retry-after": "10"}
    assert all("secret" not in value for value in result.metadata.values())


@pytest.mark.parametrize(
    ("key", "value"),
    [("X-GitHub-Request-Id", "bad\nvalue"), ("bad\rkey", "value"), ("X", "x" * 20)],
)
def test_header_values_and_names_are_bounded_and_control_free(key: str, value: str) -> None:
    with pytest.raises(MainPersonalExactCasResponseError):
        parse(headers={key: value}, max_header_value_length=10)


def test_header_count_and_duplicate_allowlisted_names_fail_closed() -> None:
    with pytest.raises(MainPersonalExactCasResponseError):
        parse(headers={str(index): "x" for index in range(3)}, max_headers=2)
    with pytest.raises(MainPersonalExactCasResponseError):
        parse(headers={"X-GitHub-Request-ID": "one", "x-github-request-id": "two"})


@pytest.mark.parametrize("malformed_item", [("a", "b", "c"), "not-a-pair"])
def test_malformed_header_item_is_a_redacted_domain_error(malformed_item: object) -> None:
    class MalformedMapping(dict[object, object]):
        def items(self) -> Any:
            return iter((malformed_item,))

    with pytest.raises(MainPersonalExactCasResponseError) as caught:
        parse(headers=MalformedMapping())
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_header_iterator_is_consumed_only_through_max_plus_one() -> None:
    consumed: list[int] = []

    class BoundedProbeMapping(dict[object, object]):
        def items(self) -> Any:
            index = 0
            while True:
                consumed.append(index)
                if index > 2:
                    raise AssertionError("secret iterator over-consumption")
                yield (f"arbitrary-{index}", "discard")
                index += 1

    with pytest.raises(MainPersonalExactCasResponseError) as caught:
        parse(headers=BoundedProbeMapping(), max_headers=2)
    assert consumed == [0, 1, 2]
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_allowlisted_metadata_uses_conservative_value_grammars() -> None:
    result = parse(
        headers={
            "X-GitHub-Request-Id": "Bearer TOP-SECRET",
            "Retry-After": "Bearer TOP-SECRET",
            "X-RateLimit-Limit": "1e9",
            "X-RateLimit-Remaining": "-1",
            "X-RateLimit-Reset": "1700000000",
            "X-RateLimit-Resource": "core",
            "ETag": "Bearer TOP-SECRET",
        }
    )
    assert result.metadata == {
        "x-ratelimit-reset": "1700000000",
        "x-ratelimit-resource": "core",
    }
    assert "TOP-SECRET" not in result.metadata.values()
    assert "TOP-SECRET" not in repr(result)


def test_invalid_input_exception_is_redacted_and_context_free() -> None:
    hostile = "Bearer TOP-SECRET\n<do-not-print>"
    with pytest.raises(MainPersonalExactCasResponseError) as caught:
        parse(body={"hostile": hostile}, headers={"X": hostile}, max_header_value_length=10)
    error = caught.value
    assert str(error) == "invalid exact-CAS response"
    assert repr(error) == "MainPersonalExactCasResponseError()"
    assert hostile not in str(error)
    assert error.__cause__ is None
    assert error.__context__ is None


def test_failing_header_mapping_does_not_leak_underlying_exception() -> None:
    class BrokenMapping(dict[object, object]):
        def items(self):
            raise RuntimeError("secret mapping failure")

    with pytest.raises(MainPersonalExactCasResponseError) as caught:
        parse(headers=BrokenMapping())
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "secret" not in repr(caught.value)


def test_public_module_has_no_network_or_mutation_capability() -> None:
    source_path = Path("src/avo_correlate/adapters/hosted_git/main_personal_exact_cas_response.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    )
    assert imported.isdisjoint({"httpx", "urllib", "requests", "socket"})
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"open", "urlopen"}
        for node in ast.walk(tree)
    )
