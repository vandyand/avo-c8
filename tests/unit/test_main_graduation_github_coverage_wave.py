"""High-yield, transport-only branch coverage for the protected-main adapter."""
# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportArgumentType=false, reportCallIssue=false, reportUnknownLambdaType=false, reportMissingImports=false, reportOptionalSubscript=false, reportIndexIssue=false

from __future__ import annotations

from typing import Any

import pytest

from avo_correlate.adapters.hosted_git.github import GitHubRejected, GitHubTransportError
from avo_correlate.adapters.hosted_git.main_graduation_github import (
    GitHubMainGraduationAdapter,
    GitHubMainGraduationAmbiguous,
    GitHubMainGraduationError,
    GitHubMainGraduationRejected,
)
from avo_correlate.application.c4_capabilities import CandidatePublicationResult
from tests.unit.test_main_graduation_github import adapter, candidate_request


def _payload(*, run_id: int = 1, nonce: str = "n", name: str = "other") -> dict[str, Any]:
    return {"id": run_id, "external_id": nonce, "name": name}


def test_invoke_classifies_rejection_ambiguity_and_parser_failures() -> None:
    request = candidate_request()

    class Transport:
        def __init__(self, value: Any) -> None:
            self.value = value

        def __call__(self, *_args: object) -> tuple[Any, Any]:
            if isinstance(self.value, BaseException):
                raise self.value
            return self.value

    cases = [
        (Transport((400, {"error": "no"})), "rejected", False),
        (Transport((500, {"error": "retry"})), "ambiguous", True),
        (Transport((True, {})), "ambiguous", True),
        (Transport(GitHubRejected("bad", status=422)), "rejected", False),
        (Transport(GitHubRejected("bad", status=503)), "ambiguous", True),
        (Transport(GitHubTransportError("lost")), "ambiguous", True),
        (Transport((200, {})), "ambiguous", True),
    ]
    for transport, outcome, dispatch in cases:
        value, _ = adapter()
        value._transports["source"] = transport  # pyright: ignore[reportPrivateUsage]
        result = value._invoke(  # pyright: ignore[reportPrivateUsage]
            "source",
            "POST",
            "/candidate",
            {},
            request,
            CandidatePublicationResult,
            lambda payload: payload["missing"],
        )
        assert result.outcome == outcome
        assert result.dispatch_started is dispatch


def test_invoke_applied_result_fields_and_headers_are_bound() -> None:
    value, transports = adapter()
    request = candidate_request()
    result = value._invoke(  # pyright: ignore[reportPrivateUsage]
        "source",
        "POST",
        "/candidate",
        {"x": "y"},
        request,
        CandidatePublicationResult,
        lambda payload: payload,
        lambda parsed: {"candidate_commit": "a" * 40},
    )
    assert result.outcome == "applied"
    assert result.candidate_commit == "a" * 40
    method, url, body = transports[0].calls[-1]
    assert (method, url, body) == ("POST", "https://api.github.com/candidate", {"x": "y"})


def test_enumerate_checks_rejects_pagination_drift_and_duplicate_identity() -> None:
    run_a = _payload(run_id=1, nonce="a")
    run_b = _payload(run_id=2, nonce="b")

    class Pages:
        def __init__(self, pages: list[tuple[int, Any]]) -> None:
            self.pages = pages
            self.calls = 0

        def __call__(self, *_args: object) -> tuple[int, Any]:
            page = self.pages[min(self.calls, len(self.pages) - 1)]
            self.calls += 1
            return page

    value, _ = adapter(
        observer=Pages(
            [
                (200, {"total_count": 2, "check_runs": [run_a]}),
                (200, {"total_count": 3, "check_runs": [run_b]}),
            ]
        )
    )
    with pytest.raises(GitHubMainGraduationError, match="total_count changed"):
        value._enumerate_checks("observer", "a" * 40)  # pyright: ignore[reportPrivateUsage]

    value, _ = adapter(observer=Pages([(200, {"total_count": 2, "check_runs": [run_a, run_a]})]))
    with pytest.raises(GitHubMainGraduationRejected, match="duplicate"):
        value._enumerate_checks("observer", "a" * 40)  # pyright: ignore[reportPrivateUsage]


def test_enumerate_checks_rejects_malformed_and_unbounded_pages() -> None:
    class Transport:
        def __init__(self, payload: Any) -> None:
            self.payload = payload

        def __call__(self, *_args: object) -> tuple[int, Any]:
            return 200, self.payload

    value, _ = adapter(observer=Transport({"total_count": "1", "check_runs": []}))
    with pytest.raises(GitHubMainGraduationError, match="total_count"):
        value._enumerate_checks("observer", "a" * 40)  # pyright: ignore[reportPrivateUsage]

    value, _ = adapter(observer=Transport({"total_count": 1001, "check_runs": [{"id": 1}]}))
    with pytest.raises(GitHubMainGraduationError, match="pagination"):
        value._enumerate_checks("observer", "a" * 40)  # pyright: ignore[reportPrivateUsage]


def test_constructor_rejects_identity_and_capability_collisions() -> None:
    value, transports = adapter()
    principals = value._principals  # pyright: ignore[reportPrivateUsage]
    assert value.repository_name == "owner/repo"
    assert value.repository_url == "https://github.com/owner/repo"
    assert value.repository_path == "/repos/owner/repo"
    assert value._headers(principals["source"]).get("Authorization") == "Bearer token"  # pyright: ignore[reportPrivateUsage]
    assert transports

    with pytest.raises(ValueError, match="distinct transport"):
        GitHubMainGraduationAdapter(
            "owner",
            "repo",
            value.repository_digest,
            source_publisher_transport=transports[0],
            source_publisher_principal=principals["source"],
            preparation_transport=transports[0],
            preparation_principal=principals["preparation"],
            admission_issuer_transport=transports[2],
            admission_issuer_principal=principals["admission"],
            group_hold_issuer_transport=transports[3],
            group_hold_issuer_principal=principals["hold"],
            release_issuer_transport=transports[4],
            release_issuer_principal=principals["release"],
            observer_transport=transports[5],
            observer_principal=principals["observer"],
            mutation_authorize=lambda _: None,
            trusted_clock=lambda: __import__("datetime").datetime.now(__import__("datetime").UTC),
            release_freshness_cutoff=lambda _: __import__("datetime").datetime.now(
                __import__("datetime").UTC
            ),
            admission_request=lambda _: None,  # type: ignore[return-value]
            admission_freshness_cutoff=lambda _: __import__("datetime").datetime.now(
                __import__("datetime").UTC
            ),
            trusted_check_contexts=("validation",),
        )


def test_read_translates_transport_and_non_404_provider_errors() -> None:
    value, _ = adapter()

    class Broken:
        def __call__(self, *_args: object) -> tuple[int, Any]:
            raise GitHubTransportError("offline")

    value._read_only_transports["observer"] = Broken()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(GitHubMainGraduationAmbiguous, match="transport"):
        value._read("observer", "GET", "/x")  # pyright: ignore[reportPrivateUsage]

    class Rejected:
        def __call__(self, *_args: object) -> tuple[int, Any]:
            raise GitHubRejected("forbidden", status=403)

    value._read_only_transports["observer"] = Rejected()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(GitHubMainGraduationRejected, match="forbidden"):
        value._read("observer", "GET", "/x")  # pyright: ignore[reportPrivateUsage]
