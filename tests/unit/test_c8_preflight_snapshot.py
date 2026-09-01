from __future__ import annotations

import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import pytest

from avo_correlate.adapters.hosted_git import (
    C8PreflightSnapshotUnverifiable,
    GitHubC8PreflightSnapshot,
)
from avo_correlate.application.c8_hosted_preflight import C8HostedPreflightService

A = "a" * 40
B = "b" * 40
C = "c" * 40
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def payloads(owner_type: str = "Organization", *, no_queue: bool = False) -> dict[str, Any]:
    base = "/repos/avo-org/avo"
    content = b"name: validation\n"
    blob = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
    return {
        base: {"full_name": "avo-org/avo", "owner": {"type": owner_type}},
        base + "/git/ref/heads/main": {
            "ref": "refs/heads/main",
            "object": {"sha": A, "type": "commit"},
        },
        base + "/git/commits/" + A: {
            "sha": A,
            "tree": {"sha": B},
            "parents": [{"sha": C}],
        },
        base + "/contents/.github/workflows/validation.yml?ref=" + A: {
            "path": ".github/workflows/validation.yml",
            "type": "file",
            "sha": blob,
            "content": base64.b64encode(content).decode(),
            "encoding": "base64",
            "size": len(content),
        },
        base + "/rules/branches/main?per_page=100&page=1": [
            {
                "type": "merge_queue",
                "ruleset_source_type": "Repository",
                "ruleset_source": "avo-org/avo",
                "ruleset_id": 1,
                "parameters": {
                    "max_entries_to_merge": 1,
                    "max_entries_to_build": 1,
                    "merge_method": "SQUASH",
                    "grouping_strategy": "ALLGREEN",
                },
            }
        ],
        base + "/rulesets/1": {
            "id": 1,
            "source_type": "Repository",
            "source": "avo-org/avo",
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
            "rules": [
                {
                    "type": "merge_queue",
                    "parameters": {
                        "max_entries_to_merge": 1,
                        "max_entries_to_build": 1,
                        "merge_method": "SQUASH",
                        "grouping_strategy": "ALLGREEN",
                    },
                }
            ],
        },
        base + "/branches/main/protection": {
            "required_status_checks": {
                "strict": True,
                "contexts": [
                    "validate (ubuntu-latest)",
                    "validate (windows-latest)",
                    "avo-main-release",
                ],
                "checks": [
                    {"context": "validate (ubuntu-latest)", "app_id": 15368},
                    {"context": "validate (windows-latest)", "app_id": 15368},
                    {"context": "avo-main-release", "app_id": 42},
                ],
            }
        },
        "__queue__": no_queue,
    }


class FakeTransport:
    def __init__(self, values: dict[str, Any] | None = None) -> None:
        self.values = values or payloads()
        self.calls: list[tuple[str, str, Any]] = []

    def __call__(
        self, method: str, url: str, body: Any, headers: dict[str, str]
    ) -> tuple[int, Any]:
        parsed = urlsplit(url)
        path = parsed.path + (("?" + parsed.query) if parsed.query else "")
        self.calls.append((method, path, body))
        if parsed.path == "/graphql":
            if self.values["__queue__"]:
                queue = None
            else:
                queue = {
                    "configuration": {
                        "maximumEntriesToBuild": 1,
                        "maximumEntriesToMerge": 1,
                        "mergeMethod": "SQUASH",
                        "mergingStrategy": "ALLGREEN",
                    },
                    "entries": {
                        "totalCount": 0,
                        "nodes": [],
                        "pageInfo": {"hasNextPage": False},
                    },
                }
            return 200, {"data": {"repository": {"mergeQueue": queue}}}
        return 200, self.values[path]


def subject(fake: FakeTransport) -> GitHubC8PreflightSnapshot:
    return GitHubC8PreflightSnapshot(
        owner="avo-org",
        repo="avo",
        workflow_path=".github/workflows/validation.yml",
        token="secret",
        transport=fake,
        clock=lambda: NOW,
    )


def test_phase2_transaction_and_replay_are_single_flight() -> None:
    fake = FakeTransport()
    observer = subject(fake)
    assert observer.capture() is observer
    assert [item[0] for item in fake.calls] == (
        ["GET"] * 7 + ["POST"] + ["GET"] * 3 + ["POST", "GET"]
    )
    assert fake.calls[4][1] == "/repos/avo-org/avo/rules/branches/main?per_page=100&page=1"
    assert "secret" not in repr(observer.observe_repository())
    count = len(fake.calls)
    assert observer.observe_protection().binding == observer.observe_queue_configuration().binding
    assert len(fake.calls) == count


def test_common_binding_and_facts() -> None:
    observer = subject(FakeTransport()).capture()
    values = [
        observer.observe_repository(),
        observer.observe_protection(),
        observer.observe_queue_configuration(),
        observer.observe_workflow(),
    ]
    assert len({item.binding for item in values}) == 1
    assert observer.observe_workflow().validation_check_identity_digest is None
    with pytest.raises(C8PreflightSnapshotUnverifiable):
        observer.observe_validation_identity()
    assert observer.observe_queue_configuration().available


def test_concurrent_capture_is_single_flight() -> None:
    fake = FakeTransport()
    observer = subject(fake)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: observer.capture(), range(8)))
    assert all(item is observer for item in results)
    assert len(fake.calls) == 13


def test_absent_queue_maps_through_service_and_unsupported_reads_stay_unverifiable() -> None:
    fake = FakeTransport(payloads(no_queue=True))
    observer = subject(fake)
    with pytest.raises(C8PreflightSnapshotUnverifiable):
        observer.capture()
    failed_calls = len(fake.calls)
    with pytest.raises(C8PreflightSnapshotUnverifiable):
        observer.capture()
    assert len(fake.calls) == failed_calls
    with pytest.raises(C8PreflightSnapshotUnverifiable):
        observer.observe_isolated_issuer()
    with pytest.raises(C8PreflightSnapshotUnverifiable):
        observer.observe_rollback_namespace()
    report = C8HostedPreflightService(observer).run()
    assert "merge_queue_unavailable" not in report.blocker_codes
    assert "queue_configuration_read_unverifiable" in report.unverifiable_codes
    assert "isolated_issuer_read_unverifiable" in report.unverifiable_codes


def test_user_owned_repository_is_blocked() -> None:
    observer = subject(FakeTransport(payloads("User"))).capture()
    report = C8HostedPreflightService(observer).run()
    assert "organization_hosting_required" in report.blocker_codes


def test_final_ref_drift_and_malformed_rules_are_redacted() -> None:
    values = payloads()
    fake = FakeTransport(values)
    original = fake.__call__
    calls = 0

    def drift(method: str, url: str, body: Any, headers: dict[str, str]) -> tuple[int, Any]:
        nonlocal calls
        calls += 1
        if calls == 13:
            values["/repos/avo-org/avo/git/ref/heads/main"]["object"]["sha"] = "d" * 40
        return original(method, url, body, headers)

    with pytest.raises(C8PreflightSnapshotUnverifiable) as error:
        GitHubC8PreflightSnapshot(
            owner="avo-org",
            repo="avo",
            workflow_path=".github/workflows/validation.yml",
            token="secret",
            transport=drift,
            clock=lambda: NOW,
        ).capture()
    assert str(error.value) == "C8 hosted snapshot is unverifiable"


def test_full_effective_rules_page_is_ambiguous_and_failure_is_cached() -> None:
    values = payloads()
    values["/repos/avo-org/avo/rules/branches/main?per_page=100&page=1"] = [
        values["/repos/avo-org/avo/rules/branches/main?per_page=100&page=1"][0]
    ] * 100
    fake = FakeTransport(values)
    observer = subject(fake)
    with pytest.raises(C8PreflightSnapshotUnverifiable):
        observer.capture()
    count = len(fake.calls)
    with pytest.raises(C8PreflightSnapshotUnverifiable):
        observer.observe_repository()
    assert len(fake.calls) == count


def test_sha256_git_blob_oid_is_supported() -> None:
    values = payloads()
    content = b"name: validation\n"
    values["/repos/avo-org/avo/contents/.github/workflows/validation.yml?ref=" + A]["sha"] = (
        hashlib.sha256(f"blob {len(content)}\0".encode() + content).hexdigest()
    )
    observer = subject(FakeTransport(values)).capture()
    assert observer.observe_workflow().workflow_digest is not None


@pytest.mark.parametrize("field", ["effective", "protection", "queue"])
def test_configuration_drift_between_passes_is_rejected(field: str) -> None:
    values = payloads()
    fake = FakeTransport(values)
    original = fake.__call__
    calls = 0

    def drift(method: str, url: str, body: Any, headers: dict[str, str]) -> tuple[int, Any]:
        nonlocal calls
        calls += 1
        if calls == 8 and field == "effective":
            values["/repos/avo-org/avo/rules/branches/main?per_page=100&page=1"][0][
                "parameters"
            ]["max_entries_to_merge"] = 2
            values["/repos/avo-org/avo/rulesets/1"]["rules"][0]["parameters"][
                "max_entries_to_merge"
            ] = 2
        if calls == 10 and field == "protection":
            values["/repos/avo-org/avo/branches/main/protection"]["required_status_checks"][
                "checks"
            ][0]["app_id"] = 42
        result = original(method, url, body, headers)
        if calls == 12 and field == "queue":
            result = (
                result[0],
                {"data": {"repository": {"mergeQueue": {"configuration": {
                    "maximumEntriesToBuild": 2,
                    "maximumEntriesToMerge": 1,
                    "mergeMethod": "SQUASH",
                    "mergingStrategy": "ALLGREEN",
                }, "entries": {
                    "totalCount": 0,
                    "nodes": [],
                    "pageInfo": {"hasNextPage": False},
                }}}}},
            )
        return result

    with pytest.raises(C8PreflightSnapshotUnverifiable):
        GitHubC8PreflightSnapshot(
            owner="avo-org",
            repo="avo",
            workflow_path=".github/workflows/validation.yml",
            token="secret",
            transport=drift,
            clock=lambda: NOW,
        ).capture()
