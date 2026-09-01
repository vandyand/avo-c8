"""Security and replay tests for the read-only C8 GitHub snapshot adapter."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from typing import Any

import pytest

from avo_correlate.adapters.hosted_git import (
    C8GitHubSnapshotAdapter,
    C8SnapshotUnverifiable,
    GitHubJsonTransport,
)
from avo_correlate.application.c8_hosted_preflight import C8HostedPreflightService

NOW = datetime(2026, 1, 1, tzinfo=UTC)
COMMIT = "a" * 40
TREE = "b" * 40
PARENT = "c" * 40
CONTENT = (
    b"name: validation\non:\n  pull_request:\n  merge_group:\n"
    b"jobs:\n  check:\n    steps:\n      - uses: actions/checkout@v4\n"
    b"        with:\n          ref: ${{ github.sha }}\n"
)


def responses(
    *,
    full_name: str = "avo-org/avo",
    ref: str = "refs/heads/main",
    commit: str = COMMIT,
    tree: str = TREE,
    parents: list[str] | None = None,
    content: str | None = None,
    content_sha: str = PARENT,
) -> dict[str, Any]:
    raw_content = CONTENT if content is None else content.encode()
    encoded = base64.b64encode(raw_content).decode()
    blob_sha = hashlib.sha1(f"blob {len(raw_content)}\0".encode() + raw_content).hexdigest()
    return {
        "/repos/avo-org/avo": {"full_name": full_name, "owner": {"type": "Organization"}},
        "/repos/avo-org/avo/git/ref/heads/main": {
            "ref": ref,
            "object": {"sha": commit, "type": "commit"},
        },
        f"/repos/avo-org/avo/git/commits/{COMMIT}": {
            "sha": commit,
            "tree": {"sha": tree},
            "parents": [{"sha": value} for value in (parents if parents is not None else [PARENT])],
        },
        f"/repos/avo-org/avo/contents/.github/workflows/validation.yml?ref={COMMIT}": {
            "path": ".github/workflows/validation.yml",
            "type": "file",
            "sha": blob_sha if content_sha == PARENT else content_sha,
            "content": encoded,
            "encoding": "base64",
            "size": len(raw_content),
        },
    }


class FakeTransport:
    def __init__(self, payloads: dict[str, Any] | None = None) -> None:
        self.payloads = payloads or responses()
        self.calls: list[tuple[str, str, Any, dict[str, str]]] = []

    def __call__(
        self, method: str, url: str, body: Any, headers: dict[str, str]
    ) -> tuple[int, Any]:
        from urllib.parse import urlsplit

        path = urlsplit(url).path
        if urlsplit(url).query:
            path += "?" + urlsplit(url).query
        self.calls.append((method, path, body, headers))
        return 200, self.payloads[path]


def adapter(transport: Any, **kwargs: Any) -> C8GitHubSnapshotAdapter:
    return C8GitHubSnapshotAdapter(
        owner="avo-org",
        repo="avo",
        workflow_path=".github/workflows/validation.yml",
        token="injected-secret",
        transport=transport,
        clock=lambda: NOW,
        **kwargs,
    )


def test_capture_uses_exact_four_gets_and_replays_without_network() -> None:
    fake = FakeTransport()
    subject = adapter(fake)
    repository, workflow = subject.capture()
    assert [(method, path, body) for method, path, body, _ in fake.calls] == [
        ("GET", "/repos/avo-org/avo", None),
        ("GET", "/repos/avo-org/avo/git/ref/heads/main", None),
        ("GET", f"/repos/avo-org/avo/git/commits/{COMMIT}", None),
        ("GET", f"/repos/avo-org/avo/contents/.github/workflows/validation.yml?ref={COMMIT}", None),
        ("GET", "/repos/avo-org/avo/git/ref/heads/main", None),
    ]
    assert all(call[3]["Authorization"] == "Bearer injected-secret" for call in fake.calls)
    first = (repository.model_dump(mode="json"), workflow.model_dump(mode="json"))
    fake.payloads.clear()
    assert (
        subject.observe_repository().model_dump(mode="json"),
        subject.observe_workflow().model_dump(mode="json"),
    ) == first
    assert len(fake.calls) == 5


def test_snapshot_binding_is_common_fresh_and_deterministic() -> None:
    first = adapter(FakeTransport()).capture()
    second = adapter(FakeTransport()).capture()
    assert first[0].binding == first[1].binding
    assert first[0].binding is not None
    assert first[0].binding.observed_at == NOW
    assert first[0].model_dump(mode="json") == second[0].model_dump(mode="json")
    assert first[1].workflow_digest is not None


@pytest.mark.parametrize("field", ["full_name", "ref", "commit", "tree", "parents"])
def test_identity_mismatch_is_sanitized(field: str) -> None:
    payloads = responses()
    if field == "full_name":
        payloads["/repos/avo-org/avo"]["full_name"] = "evil/avo"
    elif field == "ref":
        payloads["/repos/avo-org/avo/git/ref/heads/main"]["ref"] = "refs/heads/dev"
    elif field == "commit":
        payloads["/repos/avo-org/avo/git/ref/heads/main"]["object"]["sha"] = "d" * 40
    elif field == "tree":
        payloads[f"/repos/avo-org/avo/git/commits/{COMMIT}"]["tree"]["sha"] = "bad"
    else:
        payloads[f"/repos/avo-org/avo/git/commits/{COMMIT}"]["parents"] = [{"sha": "bad"}]
    with pytest.raises(C8SnapshotUnverifiable) as error:
        adapter(FakeTransport(payloads)).capture()
    assert str(error.value) == "C8 hosted snapshot is unverifiable"
    assert "injected-secret" not in repr(error.value)


@pytest.mark.parametrize("value", ["../x", "x/../y", "\\x", "x?bad", "x#bad"])
def test_path_traversal_and_invalid_workflow_are_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        C8GitHubSnapshotAdapter(owner="avo-org", repo="avo", workflow_path=value, token="secret")


@pytest.mark.parametrize(
    "owner,repo", [("../org", "avo"), ("org/x", "avo"), ("org", "../avo"), ("org", "avo/x")]
)
def test_owner_and_repo_path_injection_is_rejected(owner: str, repo: str) -> None:
    with pytest.raises(ValueError):
        C8GitHubSnapshotAdapter(
            owner=owner, repo=repo, workflow_path=".github/workflows/x.yml", token="secret"
        )


def test_workflow_content_is_strictly_base64_and_identity_checked() -> None:
    payloads = responses()
    payloads[f"/repos/avo-org/avo/contents/.github/workflows/validation.yml?ref={COMMIT}"][
        "content"
    ] = "%%%"
    with pytest.raises(C8SnapshotUnverifiable):
        adapter(FakeTransport(payloads)).capture()
    payloads = responses()
    payloads[f"/repos/avo-org/avo/contents/.github/workflows/validation.yml?ref={COMMIT}"][
        "path"
    ] = ".github/workflows/other.yml"
    with pytest.raises(C8SnapshotUnverifiable):
        adapter(FakeTransport(payloads)).capture()


@pytest.mark.parametrize(
    "failure", [PermissionError("token leaked"), RuntimeError("transport secret")]
)
def test_transport_and_permission_errors_are_generic(failure: Exception) -> None:
    def failing(*args: Any, **kwargs: Any) -> tuple[int, Any]:
        raise failure

    with pytest.raises(C8SnapshotUnverifiable) as error:
        adapter(failing).capture()
    assert str(error.value) == "C8 hosted snapshot is unverifiable"
    assert "secret" not in str(error.value)


def test_unsupported_reads_are_unverifiable_and_preflight_stays_unverifiable() -> None:
    subject = adapter(FakeTransport())
    subject.capture()
    with pytest.raises(C8SnapshotUnverifiable):
        subject.observe_protection()
    report = C8HostedPreflightService(subject).run()
    assert report.result == "unverifiable"
    assert "protection_observer_unavailable" not in report.unverifiable_codes
    assert "protection_read_unverifiable" in report.unverifiable_codes


def test_adapter_exposes_no_mutation_or_capability_surface() -> None:
    names = set(dir(C8GitHubSnapshotAdapter))
    assert not any(
        token in name.casefold()
        for name in names
        if not name.startswith("observe_")
        for token in ("write", "mutat", "activate", "rollback")
    )


def test_default_transport_is_bounded_and_origin_pinned() -> None:
    subject = C8GitHubSnapshotAdapter(
        owner="avo-org", repo="avo", workflow_path=".github/workflows/x.yml", token="secret"
    )
    assert isinstance(subject._transport, GitHubJsonTransport)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError):
        C8GitHubSnapshotAdapter(
            owner="avo-org",
            repo="avo",
            workflow_path=".github/workflows/x.yml",
            token="secret",
            api_origin="https://evil.example",
        )
