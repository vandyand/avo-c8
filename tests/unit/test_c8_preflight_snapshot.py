from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import urlsplit

import pytest

from avo_correlate.adapters.hosted_git import (
    C8PreflightSnapshotUnverifiable,
    GitHubC8PreflightSnapshot,
)
from avo_correlate.adapters.hosted_git.github import JsonBody, JsonValue
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
        base + "/check-runs": [
            {
                "id": 101,
                "name": "validate (ubuntu-latest)",
                "head_sha": A,
                "status": "completed",
                "conclusion": "success",
                "completed_at": "2026-01-01T00:00:00+00:00",
                "app": {"id": 15368, "slug": "github-actions", "name": "GitHub Actions"},
            },
            {
                "id": 102,
                "name": "validate (windows-latest)",
                "head_sha": A,
                "status": "completed",
                "conclusion": "success",
                "completed_at": "2026-01-01T00:00:00+00:00",
                "app": {"id": 15368, "slug": "github-actions", "name": "GitHub Actions"},
            },
        ],
        "__queue__": no_queue,
    }


class FakeTransport:
    def __init__(self, values: dict[str, Any] | None = None) -> None:
        self.values = values or payloads()
        self.calls: list[tuple[str, str, Any]] = []

    def __call__(
        self, method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        parsed = urlsplit(url)
        path = parsed.path + (("?" + parsed.query) if parsed.query else "")
        self.calls.append((method, path, body))
        if parsed.path == "/graphql":
            queue: dict[str, JsonValue] | None
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
        if parsed.path.endswith("/check-runs"):
            runs = self.values["/repos/avo-org/avo/check-runs"]
            page = int(dict([part.split("=") for part in parsed.query.split("&")])["page"])
            start = (page - 1) * 100
            return 200, {"total_count": len(runs), "check_runs": runs[start : start + 100]}
        return 200, self.values[path]


class SecretFailingTransport:
    def __init__(self) -> None:
        self.authorization: str | None = None

    def __call__(
        self, method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        self.authorization = headers["Authorization"]
        raise RuntimeError(f"transport-secret-canary {self.authorization}")


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
        ["GET"] * 7 + ["POST"] + ["GET"] * 4 + ["POST", "GET", "GET"]
    )
    assert fake.calls[4][1] == "/repos/avo-org/avo/rules/branches/main?per_page=100&page=1"
    expected_checks_path = (
        "/repos/avo-org/avo/commits/"
        + A
        + "/check-runs?filter=all&per_page=100&page=1"
    )
    assert fake.calls[8][1] == expected_checks_path
    assert fake.calls[8][2] is None
    assert "secret" not in repr(observer.observe_repository())
    count = len(fake.calls)
    assert observer.observe_protection().binding == observer.observe_queue_configuration().binding
    assert len(fake.calls) == count


def test_transport_failure_does_not_retain_secret_exception_context() -> None:
    token = "observer-token-canary"
    transport = SecretFailingTransport()
    observer = GitHubC8PreflightSnapshot(
        owner="avo-org",
        repo="avo",
        workflow_path=".github/workflows/validation.yml",
        token=token,
        transport=transport,
        clock=lambda: NOW,
    )
    with pytest.raises(C8PreflightSnapshotUnverifiable) as error:
        observer.capture()
    assert str(error.value) == "C8 hosted snapshot is unverifiable"
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert transport.authorization == "Bearer " + token
    assert token not in repr(error.value)


def test_common_binding_and_facts() -> None:
    observer = subject(FakeTransport()).capture()
    values = [
        observer.observe_repository(),
        observer.observe_protection(),
        observer.observe_queue_configuration(),
        observer.observe_workflow(),
    ]
    assert values
    assert all(item.binding == values[0].binding for item in values)
    workflow = observer.observe_workflow()
    assert workflow.validation_check_identity_digest is not None
    assert workflow.pull_request_event is None
    assert workflow.merge_group_event is None
    assert workflow.exact_sha_checkout is None
    assert workflow.checkout_persist_credentials_false is None
    validation = observer.observe_validation_identity()
    assert validation.app_id == 15368
    assert validation.identity == "github-actions"
    assert observer.observe_queue_configuration().available


def test_valid_authenticated_workflow_fills_static_facts_without_identity_claim() -> None:
    values = payloads()
    content = (
        b"name: validation\n"
        b"on:\n  pull_request:\n  merge_group:\n    types: [checks_requested]\n"
        b"jobs:\n  validate:\n    steps:\n      - uses: actions/checkout@"
        + b"11d5960a326750d5838078e36cf38b85af677262\n"
        b"        with:\n          ref: ${{ github.sha }}\n"
        b"          persist-credentials: false\n"
    )
    blob = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
    workflow = values["/repos/avo-org/avo/contents/.github/workflows/validation.yml?ref=" + A]
    workflow["content"] = base64.b64encode(content).decode()
    workflow["size"] = len(content)
    workflow["sha"] = blob
    observer = subject(FakeTransport(values)).capture()
    read = observer.observe_workflow()
    assert read.pull_request_event is True
    assert read.merge_group_event is True
    assert read.exact_sha_checkout is True
    assert read.checkout_persist_credentials_false is True
    assert read.validation_check_identity_digest is not None
    assert observer.observe_validation_identity().app_id == 15368


def test_concurrent_capture_is_single_flight() -> None:
    fake = FakeTransport()
    observer = subject(fake)
    with ThreadPoolExecutor(max_workers=8) as pool:
        def capture(_index: int) -> GitHubC8PreflightSnapshot:
            return observer.capture()

        results = list(pool.map(capture, range(8)))
    assert all(item is observer for item in results)
    assert len(fake.calls) == 15


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

    def drift(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        nonlocal calls
        calls += 1
        if calls == 15:
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


def test_validation_success_must_remain_fresh_at_final_snapshot_time() -> None:
    values = payloads()
    for item in values["/repos/avo-org/avo/check-runs"]:
        item["completed_at"] = "2025-12-31T23:57:00+00:00"
    times = iter((NOW, NOW + timedelta(minutes=4)))
    observer = GitHubC8PreflightSnapshot(
        owner="avo-org",
        repo="avo",
        workflow_path=".github/workflows/validation.yml",
        token="secret",
        transport=FakeTransport(values),
        clock=lambda: next(times),
    )
    with pytest.raises(C8PreflightSnapshotUnverifiable):
        observer.capture()


@pytest.mark.parametrize("blocker", ["wrong_app", "terminal_failure"])
def test_validation_blocker_must_remain_fresh_at_final_snapshot_time(blocker: str) -> None:
    values = payloads()
    for item in values["/repos/avo-org/avo/check-runs"]:
        item["completed_at"] = "2025-12-31T23:57:00+00:00"
    if blocker == "wrong_app":
        values["/repos/avo-org/avo/check-runs"][0]["app"] = {
            "id": 42,
            "slug": "other",
            "name": "Other",
        }
    else:
        values["/repos/avo-org/avo/check-runs"][0]["conclusion"] = "failure"
    times = iter((NOW, NOW + timedelta(minutes=4)))
    observer = GitHubC8PreflightSnapshot(
        owner="avo-org",
        repo="avo",
        workflow_path=".github/workflows/validation.yml",
        token="secret",
        transport=FakeTransport(values),
        clock=lambda: next(times),
    )
    with pytest.raises(C8PreflightSnapshotUnverifiable):
        observer.capture()


@pytest.mark.parametrize("blocker", ["wrong_app", "terminal_failure"])
def test_fresh_validation_blocker_remains_conclusive(blocker: str) -> None:
    values = payloads()
    if blocker == "wrong_app":
        values["/repos/avo-org/avo/check-runs"][0]["app"] = {
            "id": 42,
            "slug": "other",
            "name": "Other",
        }
    else:
        values["/repos/avo-org/avo/check-runs"][0]["conclusion"] = "failure"
    observer = GitHubC8PreflightSnapshot(
        owner="avo-org",
        repo="avo",
        workflow_path=".github/workflows/validation.yml",
        token="secret",
        transport=FakeTransport(values),
        clock=lambda: NOW,
    ).capture()
    assert observer.observe_validation_identity().app_id is None
    report = C8HostedPreflightService(observer).run()
    assert "validation_app15368_identity_unverified" in report.blocker_codes


def _with_duplicate_validation_run(values: dict[str, Any]) -> None:
    checks = values["/repos/avo-org/avo/check-runs"]
    duplicate = checks[0].copy()
    duplicate["id"] = 103
    checks.append(duplicate)


def test_duplicate_validation_context_must_remain_fresh_at_final_snapshot_time() -> None:
    values = payloads()
    _with_duplicate_validation_run(values)
    for item in values["/repos/avo-org/avo/check-runs"]:
        item["completed_at"] = "2025-12-31T23:57:00+00:00"
    times = iter((NOW, NOW + timedelta(minutes=4)))
    observer = GitHubC8PreflightSnapshot(
        owner="avo-org",
        repo="avo",
        workflow_path=".github/workflows/validation.yml",
        token="secret",
        transport=FakeTransport(values),
        clock=lambda: next(times),
    )
    with pytest.raises(C8PreflightSnapshotUnverifiable):
        observer.capture()


def test_duplicate_validation_context_page_drift_is_rejected() -> None:
    values = payloads()
    _with_duplicate_validation_run(values)
    fake = FakeTransport(values)
    original = fake.__call__
    calls = 0

    def drift(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        nonlocal calls
        calls += 1
        if calls == 14:
            values["/repos/avo-org/avo/check-runs"][2]["details_url"] = "https://drift.invalid"
        return original(method, url, body, headers)

    observer = GitHubC8PreflightSnapshot(
        owner="avo-org",
        repo="avo",
        workflow_path=".github/workflows/validation.yml",
        token="secret",
        transport=drift,
        clock=lambda: NOW,
    )
    with pytest.raises(C8PreflightSnapshotUnverifiable):
        observer.capture()


def test_fresh_duplicate_validation_context_remains_conclusive() -> None:
    values = payloads()
    _with_duplicate_validation_run(values)
    observer = GitHubC8PreflightSnapshot(
        owner="avo-org",
        repo="avo",
        workflow_path=".github/workflows/validation.yml",
        token="secret",
        transport=FakeTransport(values),
        clock=lambda: NOW,
    ).capture()
    assert observer.observe_validation_identity().app_id is None


def test_unrelated_check_run_page_drift_is_bound_between_configuration_passes() -> None:
    values = payloads()
    values["/repos/avo-org/avo/check-runs"].append(
        {"id": 103, "name": "unrelated", "head_sha": A}
    )
    fake = FakeTransport(values)
    original = fake.__call__
    calls = 0

    def drift(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        nonlocal calls
        calls += 1
        if calls == 14:
            values["/repos/avo-org/avo/check-runs"][2]["name"] = "unrelated-drift"
        return original(method, url, body, headers)

    observer = GitHubC8PreflightSnapshot(
        owner="avo-org",
        repo="avo",
        workflow_path=".github/workflows/validation.yml",
        token="secret",
        transport=drift,
        clock=lambda: NOW,
    )
    with pytest.raises(C8PreflightSnapshotUnverifiable):
        observer.capture()


@pytest.mark.parametrize("kind", ["base64", "utf8"])
def test_bad_workflow_bytes_do_not_retain_exception_context(kind: str) -> None:
    values = payloads()
    token = "workflow-token-canary"
    key = "/repos/avo-org/avo/contents/.github/workflows/validation.yml?ref=" + A
    workflow = values[key]
    if kind == "base64":
        workflow["content"] = "%%%workflow-content-canary%%%"
    else:
        content = b"\xffworkflow-content-canary"
        workflow["content"] = base64.b64encode(content).decode()
        workflow["size"] = len(content)
        workflow["sha"] = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
    observer = GitHubC8PreflightSnapshot(
        owner="avo-org",
        repo="avo",
        workflow_path=".github/workflows/validation.yml",
        token=token,
        transport=FakeTransport(values),
        clock=lambda: NOW,
    )
    with pytest.raises(C8PreflightSnapshotUnverifiable) as error:
        observer.capture()
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert token not in repr(error.value)


@pytest.mark.parametrize("field", ["effective", "protection", "queue"])
def test_configuration_drift_between_passes_is_rejected(field: str) -> None:
    values = payloads()
    fake = FakeTransport(values)
    original = fake.__call__
    calls = 0

    def drift(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        nonlocal calls
        calls += 1
        if calls == 10 and field == "effective":
            values["/repos/avo-org/avo/rules/branches/main?per_page=100&page=1"][0][
                "parameters"
            ]["max_entries_to_merge"] = 2
            values["/repos/avo-org/avo/rulesets/1"]["rules"][0]["parameters"][
                "max_entries_to_merge"
            ] = 2
        if calls == 12 and field == "protection":
            values["/repos/avo-org/avo/branches/main/protection"]["required_status_checks"][
                "checks"
            ][0]["app_id"] = 42
        result = original(method, url, body, headers)
        if calls == 13 and field == "queue":
            result = (
                result[0],
                cast(JsonValue, {"data": {"repository": {"mergeQueue": {"configuration": {
                    "maximumEntriesToBuild": 2,
                    "maximumEntriesToMerge": 1,
                    "mergeMethod": "SQUASH",
                    "mergingStrategy": "ALLGREEN",
                }, "entries": {
                    "totalCount": 0,
                    "nodes": [],
                    "pageInfo": {"hasNextPage": False},
                }}}}}),
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
