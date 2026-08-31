"""No-live-request tests for the capability-separated GitHub adapter."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from avo_correlate.adapters.hosted_git.github import github_repository_digest
from avo_correlate.adapters.hosted_git.main_graduation_github import (
    GitHubMainGraduationAdapter,
    GitHubPrincipalBinding,
)
from avo_correlate.application.c4_capabilities import CandidatePublicationRequest

DIGEST = "sha256:" + "a" * 64
OBJECT = "a" * 40


class FakeTransport:
    def __init__(
        self, response: tuple[int, Any], *, get_response: tuple[int, Any] | None = None
    ) -> None:
        self.response = response
        self.get_response = get_response
        self.calls: list[tuple[str, str, Mapping[str, Any] | None]] = []

    def __call__(
        self, method: str, url: str, body: Any, _headers: Mapping[str, str]
    ) -> tuple[int, Any]:
        self.calls.append((method, url, body))
        return (
            self.get_response
            if method == "GET" and self.get_response is not None
            else self.response
        )


def adapter(
    *, source: FakeTransport | None = None
) -> tuple[GitHubMainGraduationAdapter, list[FakeTransport]]:
    transports = [FakeTransport((200, {})) for _ in range(6)]
    if source is not None:
        transports[0] = source
    principals = [
        GitHubPrincipalBinding(f"principal-{n}", n + 1, DIGEST, "token") for n in range(6)
    ]
    issuer = GitHubPrincipalBinding("isolated-issuer", 99, DIGEST, "token")
    principals[2:] = [
        issuer,
        GitHubPrincipalBinding("hold", 99, DIGEST, "token"),
        GitHubPrincipalBinding("release", 99, DIGEST, "token"),
        principals[5],
    ]
    # Issuer bindings intentionally share the same identity values but remain
    # distinct objects and transports.
    for index in (3, 4):
        principals[index] = GitHubPrincipalBinding("isolated-issuer", 99, DIGEST, "token")
    value = GitHubMainGraduationAdapter(
        "owner",
        "repo",
        github_repository_digest("owner", "repo"),
        source_publisher_transport=transports[0],
        source_publisher_principal=principals[0],
        preparation_transport=transports[1],
        preparation_principal=principals[1],
        admission_issuer_transport=transports[2],
        admission_issuer_principal=principals[2],
        group_hold_issuer_transport=transports[3],
        group_hold_issuer_principal=principals[3],
        release_issuer_transport=transports[4],
        release_issuer_principal=principals[4],
        observer_transport=transports[5],
        observer_principal=principals[5],
    )
    return value, transports


def candidate_request() -> CandidatePublicationRequest:
    operation = DIGEST
    return CandidatePublicationRequest.build(
        operation_id=operation,
        repository_digest=github_repository_digest("owner", "repo"),
        lease_epoch_digest=DIGEST,
        candidate_ref="refs/heads/avo/candidate/" + operation.removeprefix("sha256:"),
        candidate_commit=OBJECT,
        preparation_authorization_digest=DIGEST,
    )


def test_candidate_publication_uses_exact_ref_endpoint_and_body() -> None:
    transport = FakeTransport(
        (
            201,
            {
                "ref": "refs/heads/avo/candidate/" + "a" * 64,
                "object": {"type": "commit", "sha": OBJECT},
            },
        ),
        get_response=(404, {}),
    )
    value, _ = adapter(source=transport)
    result = value.publish_candidate(candidate_request())
    assert result.outcome == "applied"
    post = transport.calls[1]
    assert transport.calls[0][0] == "GET"
    assert post[0] == "POST"
    assert post[1].endswith("/repos/owner/repo/git/refs")
    assert post[2] == {
        "ref": "refs/heads/avo/candidate/" + "a" * 64,
        "sha": OBJECT,
    }


def test_candidate_4xx_is_authoritative_rejection_without_dispatch() -> None:
    transport = FakeTransport(
        (422, {"message": "Reference already exists"}), get_response=(404, {})
    )
    value, _ = adapter(source=transport)
    result = value.publish_candidate(candidate_request())
    assert result.outcome == "rejected"
    assert result.dispatch_started is False


def test_reused_transport_binding_is_rejected_before_requests() -> None:
    transport = FakeTransport((201, {}))
    principals = [GitHubPrincipalBinding(f"p-{n}", n + 1, DIGEST, "token") for n in range(6)]
    with pytest.raises(ValueError, match="distinct transport"):
        GitHubMainGraduationAdapter(
            "owner",
            "repo",
            github_repository_digest("owner", "repo"),
            source_publisher_transport=transport,
            source_publisher_principal=principals[0],
            preparation_transport=transport,
            preparation_principal=principals[1],
            admission_issuer_transport=FakeTransport((200, {})),
            admission_issuer_principal=principals[2],
            group_hold_issuer_transport=FakeTransport((200, {})),
            group_hold_issuer_principal=principals[3],
            release_issuer_transport=FakeTransport((200, {})),
            release_issuer_principal=principals[4],
            observer_transport=FakeTransport((200, {})),
            observer_principal=principals[5],
        )
