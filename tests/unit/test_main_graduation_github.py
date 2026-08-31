"""No-live-request tests for the capability-separated GitHub adapter."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import pytest

from avo_correlate.adapters.hosted_git.github import github_repository_digest
from avo_correlate.adapters.hosted_git.main_graduation_github import (
    GitHubMainGraduationAdapter,
    GitHubMainGraduationRejected,
    GitHubPrincipalBinding,
)
from avo_correlate.adapters.hosted_git.protected_main import ProtectedMainProvider
from avo_correlate.application.c4_capabilities import (
    AdmissionIssueRequest,
    CandidatePublicationRequest,
    PullRequestLookupRequest,
    PullRequestReconcileRequest,
    QueueEnqueueRequest,
)
from avo_correlate.domain.canonical import canonical_digest

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


class RoutingTransport(FakeTransport):
    def __init__(self, responses: Mapping[str, tuple[int, Any]]) -> None:
        super().__init__((500, {}))
        self.responses = responses

    def __call__(
        self, method: str, url: str, body: Any, _headers: Mapping[str, str]
    ) -> tuple[int, Any]:
        self.calls.append((method, url, body))
        for suffix, response in self.responses.items():
            if url.endswith(suffix):
                return response
        return 500, {}


def _permit_release(_request: Any) -> None:
    pass


def adapter(
    *,
    source: FakeTransport | None = None,
    preparation: FakeTransport | None = None,
    observer: FakeTransport | None = None,
    admission_request: Any = lambda _digest: None,
    mutation_authorize: Any = _permit_release,
) -> tuple[GitHubMainGraduationAdapter, list[FakeTransport]]:
    transports = [FakeTransport((200, {})) for _ in range(6)]
    if source is not None:
        transports[0] = source
    if preparation is not None:
        transports[1] = preparation
    if observer is not None:
        transports[5] = observer
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
        mutation_authorize=mutation_authorize,
        trusted_clock=lambda: datetime.now(UTC),
        release_freshness_cutoff=lambda _request: datetime(2026, 1, 1, tzinfo=UTC),
        admission_request=admission_request,
        admission_freshness_cutoff=lambda _request: datetime(2026, 1, 1, tzinfo=UTC),
        trusted_check_contexts=("validation",),
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


def queue_request(admission_digest: str = DIGEST) -> QueueEnqueueRequest:
    base, head, base_tree, head_tree = "b" * 40, OBJECT, "c" * 40, "d" * 40
    return QueueEnqueueRequest.build(
        operation_id=DIGEST,
        repository_digest=github_repository_digest("owner", "repo"),
        lease_epoch_digest=DIGEST,
        queue_configuration_digest=DIGEST,
        pull_request_number=1,
        pull_request_url="https://github.com/owner/repo/pull/1",
        pull_request_identity=canonical_digest(
            {
                "operation_id": DIGEST,
                "repository_digest": github_repository_digest("owner", "repo"),
                "pull_request_number": 1,
                "pull_request_url": "https://github.com/owner/repo/pull/1",
            }
        ),
        pull_request_head=head,
        pull_request_tree=head_tree,
        base_commit=base,
        base_tree=base_tree,
        preparation_authorization_digest=DIGEST,
        admission_observation_digest=admission_digest,
    )


def admission_for(request: QueueEnqueueRequest) -> AdmissionIssueRequest:
    return AdmissionIssueRequest.build(
        operation_id=request.operation_id,
        repository_digest=request.repository_digest,
        lease_epoch_digest=request.lease_epoch_digest,
        queue_configuration_digest=request.queue_configuration_digest,
        preparation_authorization_digest=request.preparation_authorization_digest,
        pull_request_number=request.pull_request_number,
        pull_request_head=request.pull_request_head,
        pull_request_tree=request.pull_request_tree,
        base_commit=request.base_commit,
        base_tree=request.base_tree,
        admission_run_id="admission-run",
        admission_nonce="admission-nonce",
        issuer_identity="isolated-issuer",
        issuer_app_id=99,
        issuer_isolation_digest=DIGEST,
    )


def preparation_reads(
    request: QueueEnqueueRequest, check_response: tuple[int, Any]
) -> RoutingTransport:
    branch = request.operation_id.removeprefix("sha256:")
    pr = {
        "number": 1,
        "html_url": request.pull_request_url,
        "state": "open",
        "draft": False,
        "merged": False,
        "node_id": "PR_node",
        "base": {
            "ref": "main",
            "sha": request.base_commit,
            "repo": {"full_name": "owner/repo"},
        },
        "head": {
            "ref": f"avo/candidate/{branch}",
            "sha": request.pull_request_head,
            "repo": {"full_name": "owner/repo"},
        },
    }
    return RoutingTransport(
        {
            "/graphql": (
                200,
                {
                    "data": {
                        "repository": {
                            "mergeQueue": {
                                "id": "queue-id",
                                "configuration": {
                                    "maximumEntriesToBuild": 1,
                                    "maximumEntriesToMerge": 1,
                                    "mergeMethod": "SQUASH",
                                    "mergingStrategy": "ALLGREEN",
                                },
                                "entries": {"totalCount": 0, "nodes": []},
                            }
                        }
                    }
                },
            ),
            "/branches/main/protection": (
                200,
                {
                    "required_status_checks": {
                        "contexts": ["validation", "avo-main-release"],
                        "checks": [
                            {"context": "validation", "app_id": 15368},
                            {"context": "avo-main-release", "app_id": 99},
                        ],
                    },
                    "allow_force_pushes": False,
                    "allow_deletions": False,
                },
            ),
            "/rules/branches/main": (
                200,
                [
                    {
                        "ruleset_source_type": "Repository",
                        "ruleset_source": "owner/repo",
                        "ruleset_id": 1,
                        "type": "merge_queue",
                        "parameters": {
                            "max_entries_to_merge": 1,
                            "merge_method": "SQUASH",
                            "grouping_strategy": "ALLGREEN",
                        },
                    }
                ],
            ),
            "/rulesets/1": (
                200,
                {
                    "id": 1,
                    "name": "main queue",
                    "source_type": "Repository",
                    "source": "owner/repo",
                    "target": "branch",
                    "enforcement": "active",
                    "bypass_actors": [],
                    "rules": [
                        {
                            "type": "merge_queue",
                            "parameters": {
                                "max_entries_to_merge": 1,
                                "merge_method": "SQUASH",
                                "grouping_strategy": "ALLGREEN",
                            },
                        }
                    ],
                },
            ),
            "/git/ref/heads/main": (
                200,
                {
                    "ref": "refs/heads/main",
                    "object": {"type": "commit", "sha": request.base_commit},
                },
            ),
            "/pulls/1": (200, pr),
            f"/git/commits/{request.pull_request_head}": (
                200,
                {
                    "sha": request.pull_request_head,
                    "tree": {"sha": request.pull_request_tree},
                    "parents": [],
                },
            ),
            f"/git/commits/{request.base_commit}": (
                200,
                {"sha": request.base_commit, "tree": {"sha": request.base_tree}, "parents": [
                    {"sha": "e" * 40}
                ]},
            ),
            "/check-runs?per_page=100&page=1": check_response,
        }
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
            mutation_authorize=lambda _request: None,
            trusted_clock=lambda: datetime.now(UTC),
            release_freshness_cutoff=lambda _request: datetime(2026, 1, 1, tzinfo=UTC),
            admission_request=lambda _digest: None,
            admission_freshness_cutoff=lambda _request: datetime(2026, 1, 1, tzinfo=UTC),
            trusted_check_contexts=("validation",),
        )


def test_release_authorization_callback_is_mandatory() -> None:
    with pytest.raises(ValueError, match="authorization callback"):
        adapter(mutation_authorize=None)


def test_observer_transport_uses_request_bound_issuer_not_observer_app() -> None:
    value, transports = adapter()
    transports[5].response = (
        200,
        {
            "total_count": 1,
            "check_runs": [
                {
                    "id": "run",
                    "external_id": "nonce",
                    "name": "avo-main-release",
                    "head_sha": OBJECT,
                    "status": "completed",
                    "conclusion": "success",
                    "app": {"id": 99, "slug": "isolated-issuer"},
                }
            ],
        },
    )
    assert value._check(
        "observer",
        OBJECT,
        "run",
        "nonce",
        status="completed",
        conclusion="success",
        issuer=("isolated-issuer", 99, DIGEST),
    )["name"] == "avo-main-release"


@pytest.mark.parametrize(
    "runs",
    [
        [],
        [
            {
                "id": "wrong-run",
                "external_id": "wrong-nonce",
                "name": "avo-main-release",
                "head_sha": OBJECT,
                "status": "completed",
                "conclusion": "success",
                "completed_at": "2026-08-31T12:00:00Z",
                "app": {"id": 99, "slug": "isolated-issuer"},
            }
        ],
        [
            {
                "id": "admission-run",
                "external_id": "admission-nonce",
                "name": "avo-main-release",
                "head_sha": OBJECT,
                "status": "completed",
                "conclusion": "success",
                "completed_at": "2025-01-01T00:00:00Z",
                "app": {"id": 99, "slug": "isolated-issuer"},
            }
        ],
        [
            {
                "id": "admission-run",
                "external_id": "admission-nonce",
                "name": "avo-main-release",
                "head_sha": OBJECT,
                "status": "completed",
                "conclusion": "success",
                "completed_at": "2026-08-31T12:00:00Z",
                "app": {"id": 99, "slug": "isolated-issuer"},
            },
            {
                "id": "other-run",
                "external_id": "other-nonce",
                "name": "avo-main-release",
                "head_sha": OBJECT,
                "status": "completed",
                "conclusion": "success",
                "completed_at": "2026-08-31T12:00:00Z",
                "app": {"id": 99, "slug": "isolated-issuer"},
            },
        ],
    ],
)
def test_enqueue_rejects_unresolved_admission_without_enqueue_write(
    runs: list[dict[str, Any]],
) -> None:
    request = queue_request()
    transport = preparation_reads(
        request, (200, {"total_count": len(runs), "check_runs": runs})
    )
    value, _ = adapter(
        preparation=transport, admission_request=lambda _digest: admission_for(request)
    )
    with pytest.raises(GitHubMainGraduationRejected):
        value.enqueue(request)
    assert not any(
        method == "POST"
        and isinstance(body, Mapping)
        and "enqueuePullRequest" in str(body.get("query", ""))
        for method, _url, body in transport.calls
    )


def test_queue_generation_projection_matches_protected_main_provider() -> None:
    request = queue_request()
    queue = {
        "id": "queue-id",
        "configuration": {
            "maximumEntriesToBuild": 1,
            "maximumEntriesToMerge": 1,
            "mergeMethod": "SQUASH",
            "mergingStrategy": "ALLGREEN",
        },
        "entries": {
            "totalCount": 1,
            "nodes": [
                {
                    "id": "entry-id",
                    "position": 1,
                    "state": "QUEUED",
                    "solo": True,
                    "pullRequest": {"number": request.pull_request_number},
                    "baseCommit": {"oid": request.base_commit},
                    "headCommit": {"oid": request.pull_request_head},
                }
            ],
        },
    }
    protection = {
        "required_status_checks": {
            "contexts": ["validation", "avo-main-release"],
            "checks": [
                {"context": "validation", "app_id": 15368},
                {"context": "avo-main-release", "app_id": 99},
            ],
        },
        "allow_force_pushes": False,
        "allow_deletions": False,
    }
    effective = [
        {
            "ruleset_source_type": "Repository",
            "ruleset_source": "owner/repo",
            "ruleset_id": 1,
            "type": "merge_queue",
            "parameters": {
                "max_entries_to_merge": 1,
                "merge_method": "SQUASH",
                "grouping_strategy": "ALLGREEN",
            },
        }
    ]
    ruleset = {
        "id": 1,
        "name": "main queue",
        "source_type": "Repository",
        "source": "owner/repo",
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "rules": [{"type": "merge_queue", "parameters": effective[0]["parameters"]}],
    }
    transport = RoutingTransport(
        {
            "/graphql": (200, {"data": {"repository": {"mergeQueue": queue}}}),
            "/branches/main/protection": (200, protection),
            "/rules/branches/main": (200, effective),
            "/rulesets/1": (200, ruleset),
            "/git/ref/heads/main": (
                200,
                {
                    "ref": "refs/heads/main",
                    "object": {"type": "commit", "sha": request.base_commit},
                },
            ),
            f"/git/commits/{request.base_commit}": (
                200,
                {
                    "sha": request.base_commit,
                    "tree": {"sha": request.base_tree},
                    "parents": [{"sha": "e" * 40}],
                },
            ),
        }
    )
    value, _ = adapter(observer=transport)
    adapter_state = value._queue_state(
        "observer",
        request.pull_request_number,
        request.pull_request_head,
        request.base_commit,
        request.base_tree,
    )
    protected_provider = ProtectedMainProvider(
        "owner",
        "repo",
        request.repository_digest,
        release_issuer_identity="isolated-issuer",
        release_issuer_app_id=99,
        issuer_isolation_digest=DIGEST,
        trusted_check_contexts=("validation",),
        token="token",
        transport=transport,
    )
    entries = queue["entries"]
    queue["entries"] = {"totalCount": 0, "nodes": []}
    configuration = protected_provider.observe_queue_configuration()
    queue["entries"] = entries
    protected = protected_provider.observe_queue(
        operation_id=configuration.operation_id,
        queue_configuration_digest=configuration.queue_configuration_digest,
        admission_observation_digest=DIGEST,
    )
    assert adapter_state["queue_manifest_digest"] == protected.queue_manifest_digest
    assert adapter_state["queue_generation_digest"] == protected.queue_generation_digest


@pytest.mark.parametrize("field, value", [("merged", True), ("head_sha", "b" * 40)])
def test_authoritative_pr_rejects_merged_or_equal_head_base(field: str, value: Any) -> None:
    request = queue_request()
    transport = preparation_reads(request, (200, {"total_count": 0, "check_runs": []}))
    pr = transport.responses["/pulls/1"][1]
    assert isinstance(pr, dict)
    if field == "merged":
        pr["merged"] = value
    else:
        head = pr["head"]
        assert isinstance(head, dict)
        head["sha"] = value
    value_adapter, _ = adapter(preparation=transport)
    with pytest.raises(GitHubMainGraduationRejected):
        value_adapter._authoritative_pr(
            "preparation",
            1,
            candidate_ref=f"refs/heads/avo/candidate/{request.operation_id.removeprefix('sha256:')}",
            head_commit=value if field == "head_sha" else request.pull_request_head,
            head_tree=request.base_tree if field == "head_sha" else request.pull_request_tree,
            base_commit=request.base_commit,
            base_tree=request.base_tree,
        )


def test_production_binding_is_canonical_and_pr_lookup_reconcile_is_same_repository() -> None:
    request = queue_request()
    candidate_ref = "refs/heads/avo/candidate/" + request.operation_id.removeprefix("sha256:")
    pr: dict[str, Any] = {
        "number": 1,
        "html_url": "https://github.com/owner/repo/pull/1",
        "state": "open",
        "draft": False,
        "merged": False,
        "base": {
            "ref": "main",
            "sha": request.base_commit,
            "repo": {"full_name": "owner/repo"},
        },
        "head": {
            "ref": candidate_ref,
            "sha": request.pull_request_head,
            "repo": {"full_name": "owner/repo"},
        },
    }

    def transport(
        method: str, url: str, body: Any, headers: Mapping[str, Any]
    ) -> tuple[int, Any]:
        del body, headers
        if method == "GET" and "/pulls?state=all" in url:
            return 200, [pr]
        if method == "GET" and url.endswith("/pulls/1"):
            return 200, pr
        if method == "GET" and url.endswith("/git/commits/" + request.pull_request_head):
            return 200, {
                "sha": request.pull_request_head,
                "tree": {"sha": request.pull_request_tree},
                "parents": [],
            }
        if method == "GET" and url.endswith("/git/commits/" + request.base_commit):
            return 200, {
                "sha": request.base_commit,
                "tree": {"sha": request.base_tree},
                "parents": [],
            }
        raise AssertionError((method, url))

    value, _ = adapter(observer=RoutingTransport({}))
    # Use the public binding exposed to the coordinator and verify it cannot
    # be replaced by a caller after construction.
    assert value.repository_name == "owner/repo"
    assert value.repository_url == "https://github.com/owner/repo"
    with pytest.raises(AttributeError):
        value.repository_name = "other/repo"  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(AttributeError):
        value.repository_url = "https://github.com/other/repo"  # pyright: ignore[reportAttributeAccessIssue]

    value, _ = adapter(observer=RoutingTransport({}))
    value._read_only_transports["observer"] = transport
    lookup = PullRequestLookupRequest.build(
        operation_id=request.operation_id,
        repository_digest=request.repository_digest,
        lease_epoch_digest=request.lease_epoch_digest,
        candidate_ref=candidate_ref,
        candidate_commit=request.pull_request_head,
        candidate_tree=request.pull_request_tree,
        base_commit=request.base_commit,
        base_tree=request.base_tree,
    )
    observed = value.lookup_pull_request(lookup)
    assert observed.object_id == "https://github.com/owner/repo/pull/1"

    reconcile = PullRequestReconcileRequest.build(
        operation_id=request.operation_id,
        repository_digest=request.repository_digest,
        lease_epoch_digest=request.lease_epoch_digest,
        pull_request_number=1,
        candidate_ref=candidate_ref,
        head_commit=request.pull_request_head,
        head_tree=request.pull_request_tree,
        base_commit=request.base_commit,
        base_tree=request.base_tree,
        repository_name=value.repository_name,
    )
    reconciled = value.reconcile_pull_request(reconcile)
    assert reconciled.object_id == "owner/repo:pull/1"

    foreign_url = {**pr, "html_url": "https://github.com/other/repo/pull/1"}
    foreign_name = {
        **pr,
        "base": {**pr["base"], "repo": {"full_name": "other/repo"}},
    }
    for foreign in (foreign_url, foreign_name):
        value._read_only_transports["observer"] = (
            lambda *_args, foreign=foreign, **_kwargs: (200, [foreign])
        )
        with pytest.raises(GitHubMainGraduationRejected):
            value.lookup_pull_request(lookup)

    foreign_reconcile = PullRequestReconcileRequest.build(
        operation_id=request.operation_id,
        repository_digest=request.repository_digest,
        lease_epoch_digest=request.lease_epoch_digest,
        pull_request_number=1,
        candidate_ref=candidate_ref,
        head_commit=request.pull_request_head,
        head_tree=request.pull_request_tree,
        base_commit=request.base_commit,
        base_tree=request.base_tree,
        repository_name="other/repo",
    )
    with pytest.raises(ValueError, match="repository binding"):
        value.reconcile_pull_request(foreign_reconcile)
