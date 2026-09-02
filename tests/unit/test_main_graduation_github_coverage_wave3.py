"""Third adversarial coverage wave for the protected-main GitHub adapter."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportUnknownMemberType=false, reportArgumentType=false, reportCallIssue=false, reportUnknownLambdaType=false, reportMissingImports=false, reportOptionalSubscript=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportOptionalMemberAccess=false, reportUnusedImport=false, reportUntypedFunctionDecorator=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from avo_correlate.adapters.hosted_git import main_graduation_github as module
from avo_correlate.adapters.hosted_git.github import GitHubRejected, GitHubTransportError
from avo_correlate.adapters.hosted_git.main_graduation_github import (
    GitHubMainGraduationAmbiguous,
    GitHubMainGraduationError,
)
from avo_correlate.application.c4_capabilities import (
    GroupHoldObservationRequest,
    PullRequestCreateRequest,
    PullRequestLookupRequest,
    PullRequestObservationRequest,
    QueueEnqueueRequest,
    QueueObservationRequest,
    ReleaseObservationRequest,
)
from tests.unit.test_main_graduation_github import (
    DIGEST,
    OBJECT,
    FakeTransport,
    adapter,
    admission_for,
)


def _pr(
    *,
    number: int = 1,
    head_ref: str | None = None,
    head_sha: str = OBJECT,
    base_sha: str = "b" * 40,
    base_ref: str = "main",
    state: str = "open",
    draft: bool = False,
    merged: bool = False,
    node_id: str | None = "PR_node",
) -> dict[str, Any]:
    return {
        "number": number,
        "html_url": f"https://github.com/owner/repo/pull/{number}",
        "state": state,
        "draft": draft,
        "merged": merged,
        "node_id": node_id,
        "base": {
            "ref": base_ref,
            "sha": base_sha,
            "repo": {"full_name": "owner/repo"},
        },
        "head": {
            "ref": head_ref or "avo/candidate/" + "a" * 64,
            "sha": head_sha,
            "repo": {"full_name": "owner/repo"},
        },
    }


def _commit(
    sha: str = OBJECT, tree: str = "c" * 40, parents: list[str] | None = None
) -> dict[str, Any]:
    return {
        "sha": sha,
        "tree": {"sha": tree},
        "parents": [{"sha": item} for item in (parents or [])],
    }


def _protection() -> dict[str, Any]:
    return {
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


def _ruleset() -> dict[str, Any]:
    return {
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
    }


def _queue_payload(
    *, nodes: list[dict[str, Any]] | None = None, total: int | None = None
) -> dict[str, Any]:
    nodes = nodes or []
    return {
        "repository": {
            "mergeQueue": {
                "id": "queue-id",
                "configuration": {
                    "maximumEntriesToBuild": 1,
                    "maximumEntriesToMerge": 1,
                    "mergeMethod": "SQUASH",
                    "mergingStrategy": "ALLGREEN",
                },
                "entries": {"totalCount": len(nodes) if total is None else total, "nodes": nodes},
            }
        }
    }


def _create_request() -> PullRequestCreateRequest:
    return PullRequestCreateRequest.build(
        operation_id=DIGEST,
        repository_digest=module.github_repository_digest("owner", "repo"),
        lease_epoch_digest=DIGEST,
        candidate_ref="refs/heads/avo/candidate/" + "a" * 64,
        candidate_commit=OBJECT,
        candidate_tree="d" * 40,
        base_commit="b" * 40,
        base_tree="c" * 40,
        preparation_authorization_digest=DIGEST,
    )


def _lookup_request() -> PullRequestLookupRequest:
    request = _create_request()
    return PullRequestLookupRequest.build(
        operation_id=request.operation_id,
        repository_digest=request.repository_digest,
        target_ref=request.target_ref,
        lease_epoch_digest=request.lease_epoch_digest,
        candidate_ref=request.candidate_ref,
        candidate_commit=request.candidate_commit,
        candidate_tree=request.candidate_tree,
        base_commit=request.base_commit,
        base_tree=request.base_tree,
    )


@pytest.mark.parametrize(
    "owner,repo",
    [("", "repo"), ("owner/evil", "repo"), ("owner", "repo/evil"), ("owner", "repo!")],
)
def test_repository_binding_rejects_ambiguous_components(owner: str, repo: str) -> None:
    with pytest.raises(ValueError, match="repository binding"):
        module._repository_binding(owner, repo)


@pytest.mark.parametrize("value", [None, 1, "", "not-a-sha"])
def test_json_parser_primitives_fail_closed(value: Any) -> None:
    with pytest.raises(GitHubMainGraduationError):
        module._obj(value, "payload")
    with pytest.raises(GitHubMainGraduationError):
        module._git("bad", "object")

    with pytest.raises(GitHubMainGraduationError):
        module._nested({"nested": value}, "nested", "payload")


def test_json_parser_rejects_empty_and_bool_scalars() -> None:
    with pytest.raises(GitHubMainGraduationError):
        module._str({"key": ""}, "key", "payload")
    with pytest.raises(GitHubMainGraduationError):
        module._str({"key": "a\x00b"}, "key", "payload")
    with pytest.raises(GitHubMainGraduationError):
        module._int({"key": True}, "key", "payload")
    assert module._stable_observation(
        {"updated_at": "volatile", "value": [1, {"created_at": 2}]}
    ) == {"value": [1, {}]}


def test_read_handles_missing_transport_malformed_status_and_server_status() -> None:
    value, _transports = adapter()
    value._read_only_transports.clear()  # pyright: ignore[reportPrivateUsage]
    value._transports.pop("source")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(GitHubMainGraduationError, match="unavailable"):
        value._read("source", "GET", "/x")  # pyright: ignore[reportPrivateUsage]

    for response, expected in [
        ((True, {}), "status was malformed"),
        ((302, {}), "not authoritative"),
    ]:
        value, _ = adapter()
        value._read_only_transports["observer"] = FakeTransport(response)  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(GitHubMainGraduationAmbiguous, match=expected):
            value._read("observer", "GET", "/x")  # pyright: ignore[reportPrivateUsage]

    value, _ = adapter()
    value._read_only_transports["observer"] = FakeTransport((200, []))  # pyright: ignore[reportPrivateUsage]
    assert value._read("observer", "GET", "/x") == []  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "payload",
    [
        {"sha": "bad", "tree": {"sha": "c" * 40}, "parents": []},
        {"sha": OBJECT, "tree": {"sha": "bad"}, "parents": []},
        {"sha": OBJECT, "tree": {"sha": "c" * 40}, "parents": ["bad"]},
        {"sha": OBJECT, "tree": {"sha": "c" * 40}, "parents": [True]},
    ],
)
def test_read_commit_rejects_malformed_identity_and_parent_shape(payload: dict[str, Any]) -> None:
    value, _ = adapter()
    value._read = lambda *_args, **_kwargs: payload  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(GitHubMainGraduationError):
        value._read_commit("observer", OBJECT)  # pyright: ignore[reportPrivateUsage]


def test_read_commit_checks_expected_tree_and_parents() -> None:
    value, _ = adapter()
    value._read = lambda *_args, **_kwargs: _commit(parents=["e" * 40])  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match="authoritative commit differs"):
        value._read_commit("observer", OBJECT, expected_tree="d" * 40)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match="parents differ"):
        value._read_commit("observer", OBJECT, expected_parents=[])  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "changes",
    [
        {"html_url": "https://github.com/other/repo/pull/1"},
        {"base": {"ref": "main", "sha": "b" * 40, "repo": {"full_name": "other/repo"}}},
        {"base": {"ref": "develop", "sha": "b" * 40, "repo": {"full_name": "owner/repo"}}},
        {"head": {"ref": "feature", "sha": OBJECT, "repo": {"full_name": "owner/repo"}}},
        {"draft": "false"},
        {"merged": None},
    ],
)
def test_parse_pr_rejects_foreign_refs_repositories_and_flag_shapes(
    changes: dict[str, Any],
) -> None:
    value, _ = adapter()
    payload = _pr()
    payload.update(changes)
    with pytest.raises(GitHubMainGraduationError):
        value._parse_pr(payload, 1)  # pyright: ignore[reportPrivateUsage]


def test_parse_pr_normalizes_refs_and_preserves_node_identity() -> None:
    value, _ = adapter()
    parsed = value._parse_pr(_pr(head_ref="avo/candidate/" + "a" * 64), 1)  # pyright: ignore[reportPrivateUsage]
    assert parsed["base_ref"] == "refs/heads/main"
    assert parsed["head_ref"].startswith("refs/heads/avo/candidate/")
    assert parsed["node_id"] == "PR_node"


def _protection_reader(
    value: Any, protection: dict[str, Any], effective: list[Any], ruleset: dict[str, Any]
) -> None:
    def read(_role: str, _method: str, path: str, _body: Any = None) -> Any:
        if path.endswith("/branches/main/protection"):
            return protection
        if path.endswith("/rules/branches/main"):
            return effective
        if path.endswith("/rulesets/1") or path.endswith("/orgs/owner/rulesets/1"):
            return ruleset
        raise AssertionError(path)

    value._read = read  # pyright: ignore[reportPrivateUsage]


def test_authoritative_protection_builds_manifest_for_repository_and_organization_rules() -> None:
    value, _ = adapter()
    protection, effective, ruleset = (
        _protection(),
        [
            {
                "ruleset_source_type": "Repository",
                "ruleset_source": "owner/repo",
                "ruleset_id": 1,
            }
        ],
        _ruleset(),
    )
    queue_config = {
        "maximumEntriesToMerge": 1,
        "mergeMethod": "SQUASH",
        "mergingStrategy": "ALLGREEN",
    }
    _protection_reader(value, protection, effective, ruleset)
    manifest, epoch = value._authoritative_protection(  # pyright: ignore[reportPrivateUsage]
        "observer", queue_configuration=queue_config
    )
    assert manifest.startswith("sha256:")
    assert epoch.startswith("sha256:")

    effective[0]["ruleset_source_type"] = "Organization"
    effective[0]["ruleset_source"] = "owner"
    ruleset["source_type"] = "Organization"
    ruleset["source"] = "owner"
    _protection_reader(value, protection, effective, ruleset)
    manifest_org, epoch_org = value._authoritative_protection(  # pyright: ignore[reportPrivateUsage]
        "observer", queue_configuration=queue_config
    )
    assert manifest_org != manifest
    assert epoch_org != epoch


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p, _e, _r: p["required_status_checks"].update(contexts="bad"),
        lambda p, _e, _r: p["required_status_checks"].update(checks="bad"),
        lambda p, _e, _r: p["required_status_checks"]["checks"].append(
            {"context": "validation", "app_id": 15368}
        ),
        lambda p, _e, _r: p["required_status_checks"].update(contexts=["validation"]),
        lambda p, _e, _r: p.update(allow_force_pushes=True),
        lambda p, _e, _r: p.update(allow_deletions=True),
        lambda _p, e, _r: e.clear(),
        lambda _p, e, _r: e[0].update(ruleset_id=0),
        lambda _p, e, _r: e[0].update(ruleset_source_type="user"),
        lambda _p, e, _r: e[0].update(ruleset_source="other/repo"),
        lambda _p, _e, r: r.update(bypass_actors=[{"actor_id": 1}]),
        lambda _p, _e, r: r.update(target="tag"),
        lambda _p, _e, r: r.update(enforcement="disabled"),
        lambda _p, _e, r: r.update(rules=["bad"]),
    ],
)
def test_authoritative_protection_rejects_malformed_or_unsafe_facts(
    mutation: Any,
) -> None:
    value, _ = adapter()
    protection, effective, ruleset = (
        _protection(),
        [
            {
                "ruleset_source_type": "Repository",
                "ruleset_source": "owner/repo",
                "ruleset_id": 1,
            }
        ],
        _ruleset(),
    )
    mutation(protection, effective, ruleset)
    _protection_reader(value, protection, effective, ruleset)
    with pytest.raises((GitHubMainGraduationError, module._Precondition)):
        value._authoritative_protection(  # pyright: ignore[reportPrivateUsage]
            "observer",
            queue_configuration={
                "maximumEntriesToMerge": 1,
                "mergeMethod": "SQUASH",
                "mergingStrategy": "ALLGREEN",
            },
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda _p, _e, r: r.update(id=2),
        lambda _p, _e, r: r.update(source_type="Organization"),
        lambda _p, _e, r: r.update(name=""),
        lambda _p, _e, r: r.update(rules=[{"type": "required_signatures", "parameters": {}}]),
        lambda _p, _e, r: r.update(rules=r["rules"] + [{"type": "merge_queue", "parameters": {}}]),
    ],
)
def test_authoritative_protection_rejects_duplicate_or_missing_merge_queue_rule(
    mutation: Any,
) -> None:
    value, _ = adapter()
    protection, effective, ruleset = (
        _protection(),
        [
            {
                "ruleset_source_type": "Repository",
                "ruleset_source": "owner/repo",
                "ruleset_id": 1,
            }
        ],
        _ruleset(),
    )
    mutation(protection, effective, ruleset)
    _protection_reader(value, protection, effective, ruleset)
    with pytest.raises((GitHubMainGraduationError, module._Precondition)):
        value._authoritative_protection(  # pyright: ignore[reportPrivateUsage]
            "observer",
            queue_configuration={
                "maximumEntriesToMerge": 1,
                "mergeMethod": "SQUASH",
                "mergingStrategy": "ALLGREEN",
            },
        )


def test_authoritative_protection_deduplicates_repeated_effective_rule() -> None:
    value, _ = adapter()
    protection, effective, ruleset = (
        _protection(),
        [
            {
                "ruleset_source_type": "Repository",
                "ruleset_source": "owner/repo",
                "ruleset_id": 1,
            }
        ],
        _ruleset(),
    )
    effective.append(dict(effective[0]))
    _protection_reader(value, protection, effective, ruleset)
    manifest, epoch = value._authoritative_protection(  # pyright: ignore[reportPrivateUsage]
        "observer",
        queue_configuration={
            "maximumEntriesToMerge": 1,
            "mergeMethod": "SQUASH",
            "mergingStrategy": "ALLGREEN",
        },
    )
    assert manifest.startswith("sha256:") and epoch.startswith("sha256:")


def _install_queue_probe(value: Any, payload: dict[str, Any], *, base: str = "b" * 40) -> None:
    value._graphql = lambda *_args, **_kwargs: payload  # pyright: ignore[reportPrivateUsage]
    value._authoritative_protection = lambda *_args, **_kwargs: (DIGEST, DIGEST)  # pyright: ignore[reportPrivateUsage]
    value._read = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "ref": "refs/heads/main",
        "object": {"type": "commit", "sha": base},
    }
    value._read_commit = lambda *_args, **_kwargs: (base, "c" * 40, ())  # pyright: ignore[reportPrivateUsage]


def test_queue_state_reconstructs_empty_and_singleton_generation() -> None:
    value, _ = adapter()
    base, head, tree = "b" * 40, OBJECT, "c" * 40
    _install_queue_probe(value, _queue_payload())
    empty = value._queue_state(  # pyright: ignore[reportPrivateUsage]
        "observer", 1, head, base, tree, require_entry=False
    )
    assert empty["state"] == "empty"
    assert empty["entry_id"] == "empty"
    entry = {
        "id": "entry-id",
        "position": 1,
        "state": "QUEUED",
        "solo": True,
        "pullRequest": {"number": 1},
        "baseCommit": {"oid": base},
        "headCommit": {"oid": head},
    }
    _install_queue_probe(value, _queue_payload(nodes=[entry]))
    singleton = value._queue_state(  # pyright: ignore[reportPrivateUsage]
        "observer", 1, head, base, tree
    )
    assert singleton["state"] == "queued"
    assert singleton["group_topology_digest"].startswith("sha256:")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p["repository"]["mergeQueue"]["configuration"].update(maximumEntriesToMerge=True),
        lambda p: p["repository"]["mergeQueue"]["configuration"].update(maximumEntriesToBuild=0),
        lambda p: p["repository"]["mergeQueue"]["configuration"].update(mergeMethod="MERGE"),
        lambda p: p["repository"]["mergeQueue"]["configuration"].update(mergingStrategy="ANY"),
        lambda p: p["repository"]["mergeQueue"].update(id=""),
        lambda p: p["repository"]["mergeQueue"].update(entries="bad"),
    ],
)
def test_queue_state_rejects_malformed_configuration_and_queue_identity(
    mutation: Any,
) -> None:
    value, _ = adapter()
    payload = _queue_payload()
    mutation(payload)
    _install_queue_probe(value, payload)
    with pytest.raises((GitHubMainGraduationError, module._Precondition)):
        value._queue_state(  # pyright: ignore[reportPrivateUsage]
            "observer", 1, OBJECT, "b" * 40, "c" * 40, require_entry=False
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p["repository"]["mergeQueue"]["entries"].update(totalCount=1),
        lambda p: p["repository"]["mergeQueue"]["entries"].update(nodes="bad"),
        lambda p: p["repository"]["mergeQueue"].update(
            entries={"totalCount": 2, "nodes": [{"id": "one"}]}
        ),
    ],
)
def test_queue_state_rejects_entry_count_and_node_shape_drift(mutation: Any) -> None:
    value, _ = adapter()
    payload = _queue_payload()
    mutation(payload)
    _install_queue_probe(value, payload)
    with pytest.raises((module._Precondition, GitHubMainGraduationError)):
        value._queue_state(  # pyright: ignore[reportPrivateUsage]
            "observer", 1, OBJECT, "b" * 40, "c" * 40, require_entry=False
        )


@pytest.mark.parametrize("state", ("MERGED", "", "CANCELLED"))
def test_queue_state_rejects_non_pending_singleton_states(state: str) -> None:
    value, _ = adapter()
    entry = {
        "id": "entry-id",
        "state": state,
        "solo": True,
        "pullRequest": {"number": 1},
        "baseCommit": {"oid": "b" * 40},
        "headCommit": {"oid": OBJECT},
    }
    payload = _queue_payload(nodes=[entry])
    _install_queue_probe(value, payload)
    with pytest.raises((module._Precondition, GitHubMainGraduationError)):
        value._queue_state("observer", 1, OBJECT, "b" * 40, "c" * 40)  # pyright: ignore[reportPrivateUsage]


def test_create_pull_request_reconciles_existing_exact_pr() -> None:
    value, _ = adapter()
    request = _create_request()
    existing = _pr(head_sha=request.candidate_commit, base_sha=request.base_commit)
    value._read = lambda *_args, **_kwargs: [existing]  # pyright: ignore[reportPrivateUsage]
    value._authoritative_pr = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "number": 1,
        "url": existing["html_url"],
        "base_commit": request.base_commit,
        "head_commit": request.candidate_commit,
        "base_ref": "refs/heads/main",
        "head_ref": request.candidate_ref,
        "state": "open",
        "draft": False,
        "merged": False,
        "node_id": "PR_node",
    }
    result = value.create_pull_request(request)
    assert result.outcome == "already_applied"
    assert result.pull_request_number == 1


def test_create_pull_request_posts_and_revalidates_created_identity() -> None:
    value, _ = adapter(preparation=FakeTransport((201, _pr())))
    request = _create_request()
    value._read = lambda *_args, **_kwargs: []  # pyright: ignore[reportPrivateUsage]
    parsed = {
        "number": 1,
        "url": "https://github.com/owner/repo/pull/1",
        "base_commit": request.base_commit,
        "head_commit": request.candidate_commit,
        "base_ref": "refs/heads/main",
        "head_ref": request.candidate_ref,
        "state": "open",
        "draft": False,
        "merged": False,
        "node_id": "PR_node",
    }
    value._authoritative_pr = lambda *_args, **_kwargs: parsed  # pyright: ignore[reportPrivateUsage]
    result = value.create_pull_request(request)
    assert result.outcome == "applied"
    assert result.pull_request_url == parsed["url"]


def test_create_pull_request_rejects_conflicting_search_and_bounded_pagination() -> None:
    request = _create_request()
    conflicting = _pr(
        head_ref=request.candidate_ref, head_sha="f" * 40, base_sha=request.base_commit
    )
    value, _ = adapter()
    value._read = lambda *_args, **_kwargs: [conflicting]  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match="conflicting"):
        value.create_pull_request(request)

    value, _ = adapter()
    value._read = lambda *_args, **_kwargs: [object()] * 100  # pyright: ignore[reportPrivateUsage]
    value._parse_pr = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "number": 1,
        "url": "https://github.com/owner/repo/pull/1",
        "base_commit": request.base_commit,
        "head_commit": request.candidate_commit,
        "base_ref": "refs/heads/main",
        "head_ref": request.candidate_ref,
        "state": "open",
        "draft": False,
        "merged": False,
        "node_id": "PR_node",
    }
    with pytest.raises(GitHubMainGraduationAmbiguous, match="exceeded bounds"):
        value.create_pull_request(request)


def test_lookup_pull_request_finds_exact_identity_and_rejects_missing_or_conflicting() -> None:
    request = _lookup_request()
    exact = _pr(
        head_ref=request.candidate_ref,
        head_sha=request.candidate_commit,
        base_sha=request.base_commit,
    )
    value, _ = adapter()
    value._read = lambda *_args, **_kwargs: [exact]  # pyright: ignore[reportPrivateUsage]
    value._authoritative_pr = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "number": 1,
        "url": exact["html_url"],
        "base_commit": request.base_commit,
        "head_commit": request.candidate_commit,
        "base_ref": "refs/heads/main",
        "head_ref": request.candidate_ref,
        "state": "open",
        "draft": False,
        "merged": False,
        "node_id": "PR_node",
    }
    result = value.lookup_pull_request(request)
    assert result.outcome == "observed"

    value, _ = adapter()
    value._read = lambda *_args, **_kwargs: []  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match="missing or ambiguous"):
        value.lookup_pull_request(request)

    value, _ = adapter()
    foreign = _pr(
        head_ref="refs/heads/avo/candidate/" + "b" * 64,
        head_sha=request.candidate_commit,
        base_sha=request.base_commit,
    )
    value._read = lambda *_args, **_kwargs: [foreign]  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match="foreign head"):
        value.lookup_pull_request(request)


class _RaisingTransport:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def __call__(self, *_args: Any, **_kwargs: Any) -> Any:
        raise self.error


@pytest.mark.parametrize(
    "response, expected",
    [
        ((True, {}), "ambiguous"),
        ((302, {}), "ambiguous"),
        ((404, {}), "rejected"),
        ((500, {}), "ambiguous"),
    ],
)
def test_invoke_classifies_malformed_and_provider_statuses(
    response: tuple[Any, Any], expected: str
) -> None:
    request = module.CandidatePublicationRequest.build(
        operation_id=DIGEST,
        repository_digest=module.github_repository_digest("owner", "repo"),
        lease_epoch_digest=DIGEST,
        candidate_ref="refs/heads/avo/candidate/" + "a" * 64,
        candidate_commit=OBJECT,
        preparation_authorization_digest=DIGEST,
    )
    value, transports = adapter(source=FakeTransport(response))
    result = value._invoke(  # pyright: ignore[reportPrivateUsage]
        "source",
        "POST",
        "/refs",
        {"ref": request.candidate_ref, "sha": request.candidate_commit},
        request,
        module.CandidatePublicationResult,
        lambda payload: payload,
    )
    assert result.outcome == expected
    assert result.dispatch_started is (expected != "rejected")
    assert transports[0].calls


@pytest.mark.parametrize(
    "error, expected",
    [
        (GitHubRejected("bad", status=422), "rejected"),
        (GitHubRejected("unknown", status=503), "ambiguous"),
        (GitHubTransportError("socket"), "ambiguous"),
        (RuntimeError("bug"), "ambiguous"),
    ],
)
def test_invoke_classifies_transport_exceptions_and_parser_failure(
    error: Exception, expected: str
) -> None:
    request = module.CandidatePublicationRequest.build(
        operation_id=DIGEST,
        repository_digest=module.github_repository_digest("owner", "repo"),
        lease_epoch_digest=DIGEST,
        candidate_ref="refs/heads/avo/candidate/" + "a" * 64,
        candidate_commit=OBJECT,
        preparation_authorization_digest=DIGEST,
    )
    value, _ = adapter(source=_RaisingTransport(error))
    result = value._invoke(  # pyright: ignore[reportPrivateUsage]
        "source", "POST", "/refs", None, request, module.CandidatePublicationResult, lambda x: x
    )
    assert result.outcome == expected

    value, _ = adapter(source=FakeTransport((200, {})))
    parser_result = value._invoke(  # pyright: ignore[reportPrivateUsage]
        "source",
        "POST",
        "/refs",
        None,
        request,
        module.CandidatePublicationResult,
        lambda _payload: (_ for _ in ()).throw(ValueError("malformed")),
    )
    assert parser_result.outcome == "ambiguous"


@pytest.mark.parametrize(
    "error, expected",
    [
        (GitHubRejected("missing", status=404), module._Precondition),
        (GitHubRejected("bad", status=401), module._Precondition),
        (GitHubRejected("malformed", status=None), GitHubMainGraduationAmbiguous),
        (GitHubTransportError("socket"), GitHubMainGraduationAmbiguous),
        (RuntimeError("bug"), GitHubMainGraduationAmbiguous),
    ],
)
def test_read_classifies_rejection_transport_and_unknown_failures(
    error: Exception, expected: type[Exception]
) -> None:
    value, _ = adapter(observer=_RaisingTransport(error))
    with pytest.raises(expected):
        value._read("observer", "GET", "/x")  # pyright: ignore[reportPrivateUsage]


def test_graphql_rejects_errors_and_requires_object_data() -> None:
    value, _ = adapter()
    value._read = lambda *_args, **_kwargs: {"errors": [], "data": {"ok": True}}  # pyright: ignore[reportPrivateUsage]
    assert value._graphql("observer", "query", {}) == {"ok": True}  # pyright: ignore[reportPrivateUsage]
    for payload in ({"errors": [{}], "data": {}}, {"errors": "bad", "data": {}}, {"data": []}):
        value._read = lambda *_args, payload=payload, **_kwargs: payload  # pyright: ignore[reportPrivateUsage]
        with pytest.raises((module._Precondition, GitHubMainGraduationError)):
            value._graphql("observer", "query", {})  # pyright: ignore[reportPrivateUsage]


def _queue_request() -> QueueEnqueueRequest:
    from tests.unit.test_main_graduation_github import queue_request

    return queue_request()


def test_enqueue_applies_mutation_only_after_exact_preflight_and_post_observation() -> None:
    value, _ = adapter()
    request = _queue_request()
    parsed = {
        "number": request.pull_request_number,
        "url": request.pull_request_url,
        "base_commit": request.base_commit,
        "head_commit": request.pull_request_head,
        "base_ref": "refs/heads/main",
        "head_ref": request.candidate_ref
        if hasattr(request, "candidate_ref")
        else module._operation_candidate(request),
        "state": "open",
        "draft": False,
        "merged": False,
        "node_id": "PR_node",
    }
    calls: list[str] = []
    value._authoritative_pr = lambda *_args, **_kwargs: parsed  # pyright: ignore[reportPrivateUsage]
    value._authoritative_queue = lambda *_args, **kwargs: (
        calls.append(  # pyright: ignore[reportPrivateUsage]
            "pre" if kwargs.get("require_entry") is False else "queue"
        )
        or {"state": "empty"}
    )
    value._authoritative_admission = lambda *_args, **_kwargs: calls.append("admission")  # pyright: ignore[reportPrivateUsage]
    value._graphql = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "enqueuePullRequest": {"mergeQueueEntry": {"id": "entry-id"}}
    }
    value._queue_state = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "state": "queued",
        "entry_id": "entry-id",
    }
    result = value.enqueue(request)
    assert result.outcome == "applied"
    assert result.dispatch_started is True
    assert calls == ["pre", "admission"]


@pytest.mark.parametrize(
    "failure, expected",
    [("precondition", "rejected"), ("transport", "ambiguous"), ("malformed", "ambiguous")],
)
def test_enqueue_fails_closed_after_graphql_boundary(failure: str, expected: str) -> None:
    value, _ = adapter()
    request = _queue_request()
    parsed = {
        "number": request.pull_request_number,
        "url": request.pull_request_url,
        "base_commit": request.base_commit,
        "head_commit": request.pull_request_head,
        "base_ref": "refs/heads/main",
        "head_ref": module._operation_candidate(request),
        "state": "open",
        "draft": False,
        "merged": False,
        "node_id": "PR_node",
    }
    value._authoritative_pr = lambda *_args, **_kwargs: parsed  # pyright: ignore[reportPrivateUsage]
    value._authoritative_queue = lambda *_args, **_kwargs: {"state": "empty"}  # pyright: ignore[reportPrivateUsage]
    value._authoritative_admission = lambda *_args, **_kwargs: None  # pyright: ignore[reportPrivateUsage]
    if failure == "precondition":
        value._graphql = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            module._Precondition("stale")
        )  # pyright: ignore[reportPrivateUsage]
    elif failure == "transport":
        value._graphql = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("lost"))  # pyright: ignore[reportPrivateUsage]
    else:
        value._graphql = lambda *_args, **_kwargs: {"enqueuePullRequest": {}}  # pyright: ignore[reportPrivateUsage]
    result = value.enqueue(request)
    assert result.outcome == expected
    assert result.dispatch_started is (expected == "ambiguous")


def _adapter_kwargs() -> dict[str, Any]:
    transports = [FakeTransport((200, {})) for _ in range(7)]
    principals = [
        module.GitHubPrincipalBinding(f"principal-{n}", n + 1, DIGEST, "token") for n in range(7)
    ]
    issuer = module.GitHubPrincipalBinding("isolated-issuer", 99, DIGEST, "token")
    principals[2] = issuer
    principals[3] = module.GitHubPrincipalBinding("isolated-issuer", 99, DIGEST, "token")
    principals[4] = module.GitHubPrincipalBinding("isolated-issuer", 99, DIGEST, "token")
    return {
        "owner": "owner",
        "repo": "repo",
        "repository_digest": module.github_repository_digest("owner", "repo"),
        "source_publisher_transport": transports[0],
        "source_publisher_principal": principals[0],
        "preparation_transport": transports[1],
        "preparation_principal": principals[1],
        "admission_issuer_transport": transports[2],
        "admission_issuer_principal": principals[2],
        "group_hold_issuer_transport": transports[3],
        "group_hold_issuer_principal": principals[3],
        "release_issuer_transport": transports[4],
        "release_issuer_principal": principals[4],
        "observer_transport": transports[5],
        "observer_principal": principals[5],
        "mutation_authorize": lambda _request: None,
        "trusted_clock": lambda: datetime.now(UTC),
        "release_freshness_cutoff": lambda _request: datetime(2026, 1, 1, tzinfo=UTC),
        "admission_request": lambda _digest: (_ for _ in ()).throw(AssertionError()),
        "admission_freshness_cutoff": lambda _request: datetime(2026, 1, 1, tzinfo=UTC),
        "trusted_check_contexts": ("validation",),
    }


@pytest.mark.parametrize(
    "override, message",
    [
        ({"api_base": "http://github.invalid"}, "API base"),
        ({"source_publisher_transport": "prep"}, "distinct transport"),
        ({"preparation_transport": "SAME"}, "distinct transport"),
        ({"observer_transport": None}, "observer transport"),
        ({"observer_principal": None}, "observer transport"),
        ({"read_only_observer": object()}, "injected observer"),
        ({"mutation_authorize": None}, "authorization callback"),
        ({"trusted_clock": None}, "callbacks"),
        ({"trusted_check_contexts": ()}, "check configuration"),
        ({"trusted_check_contexts": ("avo-main-release",)}, "check configuration"),
        ({"provider_identity": ""}, "check configuration"),
        ({"validation_app_id": 42}, "check configuration"),
    ],
)
def test_constructor_rejects_invalid_capability_configuration(
    override: dict[str, Any], message: str
) -> None:
    kwargs = _adapter_kwargs()
    if override.get("source_publisher_transport") == "prep":
        override = {"source_publisher_transport": kwargs["preparation_transport"]}
    elif override.get("preparation_transport") == "SAME":
        override = {"preparation_transport": kwargs["source_publisher_transport"]}
    kwargs.update(override)
    with pytest.raises(ValueError, match=message):
        module.GitHubMainGraduationAdapter(**kwargs)


@pytest.mark.parametrize(
    "override, message",
    [
        ({"preparation_principal": "source"}, "distinct principal"),
        ({"group_hold_issuer_principal": "mismatch"}, "issuer identity"),
        ({"group_hold_issuer_principal": "validation"}, "validation App"),
        ({"observer_principal": "source"}, "distinct principal"),
        ({"rollback_cleanup_transport": "prep"}, "distinct transport"),
        ({"rollback_cleanup_principal": "source"}, "distinct principal"),
        ({"rollback_cleanup_transport": "cleanup", "cleanup_transport": "other"}, "twice"),
        ({"rollback_cleanup_principal": "cleanup", "cleanup_principal": "other"}, "twice"),
        ({"rollback_cleanup_transport": "missing_transport"}, "paired"),
        ({"rollback_cleanup_principal": "missing_principal"}, "paired"),
    ],
)
def test_constructor_rejects_identity_and_cleanup_collisions(
    override: dict[str, Any], message: str
) -> None:
    kwargs = _adapter_kwargs()
    source_principal = kwargs["source_publisher_principal"]
    if override.get("preparation_principal") == "source":
        override = {"preparation_principal": source_principal}
    elif override.get("group_hold_issuer_principal") == "mismatch":
        override = {
            "group_hold_issuer_principal": module.GitHubPrincipalBinding(
                "other", 99, DIGEST, "token"
            )
        }
    elif override.get("group_hold_issuer_principal") == "validation":
        override = {
            "admission_issuer_principal": module.GitHubPrincipalBinding(
                "isolated-issuer", 15368, DIGEST, "token"
            ),
            "group_hold_issuer_principal": module.GitHubPrincipalBinding(
                "isolated-issuer", 15368, DIGEST, "token"
            ),
            "release_issuer_principal": module.GitHubPrincipalBinding(
                "isolated-issuer", 15368, DIGEST, "token"
            ),
        }
    elif override.get("observer_principal") == "source":
        override = {"observer_principal": source_principal}
    elif override.get("rollback_cleanup_transport") == "prep":
        override = {
            "rollback_cleanup_transport": kwargs["preparation_transport"],
            "rollback_cleanup_principal": module.GitHubPrincipalBinding(
                "cleanup", 101, DIGEST, "token"
            ),
        }
    elif override.get("rollback_cleanup_principal") == "source":
        override = {
            "rollback_cleanup_principal": source_principal,
            "rollback_cleanup_transport": FakeTransport((200, {})),
        }
    elif override.get("rollback_cleanup_transport") == "missing_transport":
        override = {"rollback_cleanup_transport": FakeTransport((200, {}))}
    elif override.get("rollback_cleanup_principal") == "missing_principal":
        override = {
            "rollback_cleanup_principal": module.GitHubPrincipalBinding(
                "cleanup", 101, DIGEST, "token"
            )
        }
    kwargs.update(override)
    with pytest.raises(ValueError, match=message):
        module.GitHubMainGraduationAdapter(**kwargs)


def test_enumerate_checks_accepts_complete_pages_and_rejects_pagination_drift() -> None:
    value, _ = adapter()
    runs = [
        {"id": 1, "external_id": "one"},
        {"id": "2", "external_id": "two"},
    ]
    value._read = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "check_runs": runs,
        "total_count": 2,
    }
    assert value._enumerate_checks("observer", OBJECT) == runs  # pyright: ignore[reportPrivateUsage]

    cases: list[Any] = [
        {"check_runs": "bad", "total_count": 0},
        {"check_runs": [{}], "total_count": True},
        {"check_runs": [{}], "total_count": 2},
        {"check_runs": [{"id": True, "external_id": "one"}], "total_count": 1},
        {"check_runs": [{"id": 1, "external_id": ""}], "total_count": 1},
    ]
    for payload in cases:
        value._read = lambda *_args, payload=payload, **_kwargs: payload  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(GitHubMainGraduationError):
            value._enumerate_checks("observer", OBJECT)  # pyright: ignore[reportPrivateUsage]

    value._read = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "check_runs": [
            {"id": 1, "external_id": "one"},
            {"id": 1, "external_id": "two"},
        ],
        "total_count": 2,
    }
    with pytest.raises(module._Precondition, match="duplicate"):
        value._enumerate_checks("observer", OBJECT)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "mutation, expected",
    [
        (lambda run: run.update(name="wrong"), "context is missing"),
        (lambda run: run.update(head_sha="b" * 40), "identity or state"),
        (lambda run: run.update(app={"id": 1, "slug": "other"}), "identity or state"),
        (lambda run: run.update(id="other"), "identity or state"),
        (lambda run: run.update(external_id="other"), "identity or state"),
    ],
)
def test_check_rejects_lookalike_contexts_and_run_identity(mutation: Any, expected: str) -> None:
    value, _ = adapter()
    run = {
        "id": "7",
        "external_id": "nonce",
        "name": "avo-main-release",
        "head_sha": OBJECT,
        "status": "completed",
        "conclusion": "success",
        "app": {"id": 1, "slug": "principal-0"},
    }
    mutation(run)
    value._enumerate_checks = lambda *_args: [run]  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match=expected):
        value._check("source", OBJECT, "7", "nonce", status="completed", conclusion="success")  # pyright: ignore[reportPrivateUsage]


def test_issue_admission_requires_isolated_issuer_and_revalidates_before_check_write() -> None:
    from tests.unit.test_main_graduation_github import admission_for, queue_request

    value, _ = adapter()
    request = admission_for(queue_request())
    value._authoritative_pr = lambda *_args, **_kwargs: {}  # pyright: ignore[reportPrivateUsage]
    value._authoritative_queue = lambda *_args, **_kwargs: {"state": "empty"}  # pyright: ignore[reportPrivateUsage]
    value._issue_check = lambda *_args, **_kwargs: {"created": True}  # pyright: ignore[reportPrivateUsage]
    result = value.issue_admission(request)
    assert result == {"created": True}

    bad_values = request.model_dump()
    bad_values["issuer_identity"] = "lookalike"
    bad = module.AdmissionIssueRequest.build(**bad_values)
    with pytest.raises(ValueError, match="issuer binding"):
        value.issue_admission(bad)


def test_read_only_observation_methods_bind_each_c4_request_to_fresh_evidence() -> None:
    value, _ = adapter()
    create = _create_request()
    parsed = {
        "number": 1,
        "url": "https://github.com/owner/repo/pull/1",
        "base_commit": create.base_commit,
        "head_commit": create.candidate_commit,
        "base_ref": "refs/heads/main",
        "head_ref": create.candidate_ref,
        "state": "open",
        "draft": False,
        "merged": False,
        "node_id": "PR_node",
    }
    pull = PullRequestObservationRequest.build(
        operation_id=create.operation_id,
        repository_digest=create.repository_digest,
        lease_epoch_digest=create.lease_epoch_digest,
        object_id="pull-observation",
        pull_request_number=1,
        candidate_ref=create.candidate_ref,
        head_commit=create.candidate_commit,
        head_tree=create.candidate_tree,
        base_commit=create.base_commit,
        base_tree=create.base_tree,
    )
    value._authoritative_pr = lambda *_args, **_kwargs: parsed  # pyright: ignore[reportPrivateUsage]
    assert value.observe_pull_request(pull).outcome == "observed"

    queue = _queue_request()
    admission = module.AdmissionObservationRequest.build(
        **admission_for(queue).model_dump(exclude={"stage"}), object_id="admission-observation"
    )
    run = {
        "id": admission.admission_run_id,
        "external_id": admission.admission_nonce,
        "name": "avo-main-release",
        "head_sha": admission.pull_request_head,
        "status": "completed",
        "conclusion": "success",
        "app": {"id": 99, "slug": "isolated-issuer"},
    }
    value._check = lambda *_args, **_kwargs: run  # pyright: ignore[reportPrivateUsage]
    assert value.observe_admission(admission).outcome == "observed"

    queue_observation = QueueObservationRequest.build(
        **queue.model_dump(exclude={"stage", "queue_generation_digest"}),
        queue_generation_digest=DIGEST,
        object_id="queue-observation",
    )
    value._authoritative_queue = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "state": "queued",
        "entry_id": "entry-id",
        "queue_generation_digest": "sha256:" + "b" * 64,
    }
    assert value.observe_queue(queue_observation).outcome == "observed"

    group_values: dict[str, Any] = {
        "operation_id": DIGEST,
        "repository_digest": module.github_repository_digest("owner", "repo"),
        "lease_epoch_digest": DIGEST,
        "queue_generation_digest": DIGEST,
        "admission_observation_digest": DIGEST,
        "pull_request_number": 1,
        "pull_request_head": OBJECT,
        "pull_request_tree": "d" * 40,
        "group_sha": "e" * 40,
        "group_tree": "d" * 40,
        "expected_group_tree": "d" * 40,
        "group_parents": ["b" * 40, OBJECT],
        "expected_group_parents": ["b" * 40, OBJECT],
        "group_topology_digest": DIGEST,
        "base_commit": "b" * 40,
        "base_tree": "c" * 40,
        "queue_members": [1],
        "hold_run_id": "hold-run",
        "hold_nonce": "hold-nonce",
        "issuer_identity": "isolated-issuer",
        "issuer_app_id": 99,
        "issuer_isolation_digest": DIGEST,
        "object_id": "group-observation",
    }
    hold = GroupHoldObservationRequest.build(**group_values)
    value._authoritative_group = lambda *_args, **_kwargs: {}  # pyright: ignore[reportPrivateUsage]
    pending = dict(
        run,
        id="hold-run",
        external_id="hold-nonce",
        head_sha="e" * 40,
        status="in_progress",
        conclusion="pending",
    )
    value._check = lambda *_args, **_kwargs: pending  # pyright: ignore[reportPrivateUsage]
    assert value.observe_group_hold(hold).outcome == "observed"

    release_values = dict(group_values)
    release_values.update(
        hold_observation_digest=DIGEST,
        release_authorization_digest=DIGEST,
        release_claim_digest=DIGEST,
        authorization_expires_at=datetime(2026, 9, 3, tzinfo=UTC),
        object_id="release-observation",
    )
    release = ReleaseObservationRequest.build(**release_values)
    success = dict(pending, status="completed", conclusion="success")
    value._check = lambda *_args, **_kwargs: success  # pyright: ignore[reportPrivateUsage]
    assert value.observe_release(release).outcome == "observed"


def test_publish_candidate_reconciles_exact_ref_and_validates_creation_response() -> None:
    request = module.CandidatePublicationRequest.build(
        operation_id=DIGEST,
        repository_digest=module.github_repository_digest("owner", "repo"),
        lease_epoch_digest=DIGEST,
        candidate_ref="refs/heads/avo/candidate/" + "a" * 64,
        candidate_commit=OBJECT,
        preparation_authorization_digest=DIGEST,
    )
    raw = {"ref": request.candidate_ref, "object": {"type": "commit", "sha": OBJECT}}
    value, _ = adapter(source=FakeTransport((201, raw), get_response=(404, {})))
    result = value.publish_candidate(request)
    assert result.outcome == "applied"

    value, _ = adapter(source=FakeTransport((201, raw), get_response=(200, raw)))
    assert value.publish_candidate(request).outcome == "already_applied"

    value, _ = adapter(source=FakeTransport((201, {"ref": "wrong"}), get_response=(404, {})))
    assert value.publish_candidate(request).outcome == "ambiguous"

    value, _ = adapter(source=FakeTransport((201, raw), get_response=(403, {})))
    assert value.publish_candidate(request).outcome == "rejected"


def test_authoritative_pr_rechecks_commit_topology_and_exact_open_state() -> None:
    value, _ = adapter()
    ref = "refs/heads/avo/candidate/" + "a" * 64
    payload = _pr(head_ref=ref, head_sha=OBJECT, base_sha="b" * 40)
    value._read = lambda *_args, **_kwargs: payload  # pyright: ignore[reportPrivateUsage]
    value._read_commit = lambda *_args, **kwargs: (  # pyright: ignore[reportPrivateUsage]
        OBJECT,
        "d" * 40 if kwargs.get("expected_tree") == "d" * 40 else "c" * 40,
        (),
    )
    assert (
        value._authoritative_pr(  # pyright: ignore[reportPrivateUsage]
            "observer",
            1,
            candidate_ref=ref,
            head_commit=OBJECT,
            head_tree="d" * 40,
            base_commit="b" * 40,
            base_tree="c" * 40,
        )["number"]
        == 1
    )
    for mutation in (
        {"state": "closed"},
        {"draft": True},
        {"merged": True},
        {"head": {"ref": ref, "sha": "b" * 40, "repo": {"full_name": "owner/repo"}}},
    ):
        changed = dict(payload)
        changed.update(mutation)
        value._read = lambda *_args, changed=changed, **_kwargs: changed  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(module._Precondition, match="exact open"):
            value._authoritative_pr(  # pyright: ignore[reportPrivateUsage]
                "observer",
                1,
                candidate_ref=ref,
                head_commit=OBJECT,
                head_tree="d" * 40,
                base_commit="b" * 40,
                base_tree="c" * 40,
            )


def test_authoritative_queue_enforces_generation_configuration_and_topology_fences() -> None:
    value, _ = adapter()
    request = _queue_request()
    state = {
        "state": "queued",
        "queue_generation_digest": "sha256:" + "b" * 64,
        "queue_configuration_digest": DIGEST,
        "group_topology_digest": DIGEST,
    }
    value._queue_state = lambda *_args, **_kwargs: state  # pyright: ignore[reportPrivateUsage]
    fenced = request.model_copy(update={"queue_generation_digest": DIGEST})
    with pytest.raises(module._Precondition, match="generation"):
        value._authoritative_queue("observer", fenced)  # pyright: ignore[reportPrivateUsage]
    state["queue_generation_digest"] = DIGEST
    with pytest.raises(module._Precondition, match="configuration"):
        value._authoritative_queue(
            "observer",
            fenced.model_copy(update={"queue_configuration_digest": "sha256:" + "b" * 64}),
        )  # pyright: ignore[reportPrivateUsage]
    state["queue_configuration_digest"] = request.queue_configuration_digest
    with_topology = fenced.model_copy(update={"group_topology_digest": "sha256:" + "b" * 64})
    with pytest.raises(module._Precondition, match="topology"):
        value._authoritative_queue("observer", with_topology)  # pyright: ignore[reportPrivateUsage]


def test_rollback_post_state_and_result_verifiers_reauthenticate_exact_topology() -> None:
    from tests.unit.test_main_rollback_lifecycle_contracts import _rollback_fixture, _signed
    from tests.unit.test_main_rollback_terminal_contracts import _attempt

    _source, inverse, intent, auth, _lease, result = _rollback_fixture()
    attempt = _attempt(_source, inverse, intent, auth)
    result_values = result.model_dump()
    result_values["operation_id"] = attempt.operation_id
    result_for_attempt = _signed(module.MainRollbackResultReceipt, result_values, "receipt_digest")
    value, _ = adapter()
    value._read = lambda _role, _method, path, _body=None: (  # pyright: ignore[reportPrivateUsage]
        {
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": result_for_attempt.result_commit},
        }
        if path.endswith("/git/ref/heads/main")
        else {
            "sha": result_for_attempt.result_commit,
            "tree": {"sha": result_for_attempt.result_tree},
            "parents": [{"sha": attempt.current_main_commit}],
        }
    )
    observation = value.observe_rollback_post_state(result_for_attempt, attempt)
    assert observation.result_commit == result_for_attempt.result_commit
    value._verify_exact_rollback_main(  # pyright: ignore[reportPrivateUsage]
        result_commit=result_for_attempt.result_commit,
        result_tree=result_for_attempt.result_tree,
        current_main_commit=attempt.current_main_commit,
    )

    value.provider_identity = result.provider_identity  # pyright: ignore[reportPrivateUsage]
    value.provider_api_version = result.provider_api_version  # pyright: ignore[reportPrivateUsage]
    value.verify_rollback_result(result, intent, auth)
    with pytest.raises(module._Precondition, match="differs"):
        value._read = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": "a" * 40},
        }
        value._verify_exact_rollback_main(  # pyright: ignore[reportPrivateUsage]
            result_commit=result_for_attempt.result_commit,
            result_tree=result_for_attempt.result_tree,
            current_main_commit=attempt.current_main_commit,
        )


def _group_observation_values() -> dict[str, Any]:
    return {
        "operation_id": DIGEST,
        "repository_digest": module.github_repository_digest("owner", "repo"),
        "lease_epoch_digest": DIGEST,
        "queue_generation_digest": DIGEST,
        "admission_observation_digest": DIGEST,
        "pull_request_number": 1,
        "pull_request_head": OBJECT,
        "pull_request_tree": "d" * 40,
        "group_sha": "e" * 40,
        "group_tree": "d" * 40,
        "expected_group_tree": "d" * 40,
        "group_parents": ["b" * 40, OBJECT],
        "expected_group_parents": ["b" * 40, OBJECT],
        "group_topology_digest": DIGEST,
        "base_commit": "b" * 40,
        "base_tree": "c" * 40,
        "queue_members": [1],
        "hold_run_id": "hold-run",
        "hold_nonce": "hold-nonce",
        "issuer_identity": "isolated-issuer",
        "issuer_app_id": 99,
        "issuer_isolation_digest": DIGEST,
    }


def test_issue_group_hold_and_release_use_isolated_check_mutations() -> None:
    value, _ = adapter()
    values = _group_observation_values()
    hold = module.GroupHoldIssueRequest.build(**values)
    value._authoritative_group = lambda *_args, **_kwargs: {}  # pyright: ignore[reportPrivateUsage]
    value._authoritative_admission = lambda *_args, **_kwargs: {}  # pyright: ignore[reportPrivateUsage]
    value._issue_check = lambda *_args, **_kwargs: {"hold": True}  # pyright: ignore[reportPrivateUsage]
    assert value.issue_group_hold(hold) == {"hold": True}

    release_values = dict(values)
    release_values.update(
        hold_observation_digest=DIGEST,
        release_authorization_digest=DIGEST,
        release_claim_digest=DIGEST,
        authorization_expires_at=datetime(2026, 9, 3, tzinfo=UTC),
    )
    release = module.ReleaseIssueRequest.build(**release_values)
    value._final_revalidate_release = lambda *_args, **_kwargs: None  # pyright: ignore[reportPrivateUsage]
    run = {
        "id": release.hold_run_id,
        "external_id": release.hold_nonce,
        "name": release.check_context,
        "head_sha": release.group_sha,
        "status": "completed",
        "conclusion": "success",
        "app": {"id": 99, "slug": "isolated-issuer"},
    }
    value._transports["release"] = FakeTransport((200, run))  # pyright: ignore[reportPrivateUsage]
    result = value.issue_release(release)
    assert result.outcome == "applied"
    assert result.dispatch_started is True

    bad_values = dict(release_values)
    bad_values["issuer_identity"] = "lookalike"
    bad_values["issuer_app_id"] = 99
    bad_values["issuer_isolation_digest"] = DIGEST
    with pytest.raises(ValueError, match="issuer binding"):
        value.issue_release(module.ReleaseIssueRequest.build(**bad_values))


def test_cleanup_parsers_reject_namespace_topology_and_state_drift() -> None:
    value, _ = adapter()
    intent = module.MainRollbackCleanupIntent.model_construct(
        candidate_ref="refs/heads/avo/main-rollback/" + "a" * 64,
        candidate_commit=OBJECT,
        pull_request_number=3,
        pull_request_url="https://github.com/owner/repo/pull/3",
    )
    base_pr = {
        "number": 3,
        "html_url": intent.pull_request_url,
        "state": "closed",
        "merged": True,
        "base": {"ref": "main", "repo": {"full_name": "owner/repo"}},
        "head": {
            "ref": intent.candidate_ref,
            "sha": OBJECT,
            "repo": {"full_name": "owner/repo"},
        },
    }
    mutations = [
        {"number": 4},
        {"html_url": "https://github.com/owner/repo/pull/4"},
        {"base": {"ref": "main", "repo": {"full_name": "other/repo"}}},
        {"head": {"ref": intent.candidate_ref, "sha": OBJECT, "repo": {"full_name": "other/repo"}}},
        {"base": {"ref": "develop", "repo": {"full_name": "owner/repo"}}},
        {"head": {"ref": "wrong", "sha": OBJECT, "repo": {"full_name": "owner/repo"}}},
        {"state": "pending"},
        {"merged": "true"},
    ]
    for mutation in mutations:
        payload = dict(base_pr)
        payload.update(mutation)
        value._read = lambda *_args, payload=payload, **_kwargs: payload  # pyright: ignore[reportPrivateUsage]
        with pytest.raises((module._Precondition, GitHubMainGraduationError)):
            value._cleanup_pr(intent)  # pyright: ignore[reportPrivateUsage]

    value._read = lambda *_args, **_kwargs: (_ for _ in ()).throw(  # pyright: ignore[reportPrivateUsage]
        module._Precondition("provider rejected", status=409)
    )
    with pytest.raises(module._Precondition, match="provider rejected"):
        value._cleanup_ref(intent)  # pyright: ignore[reportPrivateUsage]


def test_queue_configuration_observation_rejects_drift_and_malformed_evidence() -> None:
    value, _ = adapter()
    value._read_commit = lambda *_args, **_kwargs: (OBJECT, "b" * 40, ())  # pyright: ignore[reportPrivateUsage]
    value._queue_state = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "state": "empty",
        "queue_configuration_digest": DIGEST,
        "protection_manifest_digest": DIGEST,
        "protection_epoch": DIGEST,
    }
    value._read = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "ref": "refs/heads/main",
        "object": {"type": "commit", "sha": OBJECT},
    }
    observation = value.observe_queue_configuration()
    assert observation.queue_configuration_digest == DIGEST

    for ref in (
        {"ref": "refs/heads/develop", "object": {"type": "commit", "sha": OBJECT}},
        {"ref": "refs/heads/main", "object": {"type": "tree", "sha": OBJECT}},
    ):
        value._read = lambda *_args, ref=ref, **_kwargs: ref  # pyright: ignore[reportPrivateUsage]
        with pytest.raises(module._Precondition, match="main ref"):
            value.observe_queue_configuration()

    value._read = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "ref": "refs/heads/main",
        "object": {"type": "commit", "sha": OBJECT},
    }
    value._queue_state = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "state": "queued",
        "queue_configuration_digest": DIGEST,
        "protection_manifest_digest": DIGEST,
        "protection_epoch": DIGEST,
    }
    with pytest.raises(module._Precondition, match="pre-enqueue"):
        value.observe_queue_configuration()

    value._queue_state = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "state": "empty",
        "queue_configuration_digest": "bad",
        "protection_manifest_digest": DIGEST,
        "protection_epoch": DIGEST,
    }
    with pytest.raises(GitHubMainGraduationError, match="evidence"):
        value.observe_queue_configuration()


def test_authoritative_queue_and_group_return_only_after_all_fences_match() -> None:
    value, _ = adapter()
    request = _queue_request().model_copy(
        update={"queue_generation_digest": DIGEST, "group_topology_digest": DIGEST}
    )
    state = {
        "state": "queued",
        "queue_generation_digest": DIGEST,
        "queue_configuration_digest": DIGEST,
        "group_topology_digest": DIGEST,
    }
    value._queue_state = lambda *_args, **_kwargs: state  # pyright: ignore[reportPrivateUsage]
    assert value._authoritative_queue("observer", request) == state  # pyright: ignore[reportPrivateUsage]

    group = module.GroupHoldIssueRequest.build(**_group_observation_values())
    value._authoritative_pr = lambda *_args, **_kwargs: {}  # pyright: ignore[reportPrivateUsage]
    value._read_commit = lambda *_args, **_kwargs: (OBJECT, "d" * 40, ("b" * 40, OBJECT))  # pyright: ignore[reportPrivateUsage]
    assert value._authoritative_group("hold", group) == state  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "kind", ("identity", "preparation", "issuer", "clock", "missing", "date", "stale", "digest")
)
def test_authoritative_admission_rejects_each_stale_or_mismatched_authority(kind: str) -> None:
    value, _ = adapter()
    queue = _queue_request()
    admission = admission_for(queue)
    run = {
        "id": admission.admission_run_id,
        "external_id": admission.admission_nonce,
        "name": "avo-main-release",
        "head_sha": admission.pull_request_head,
        "status": "completed",
        "conclusion": "success",
        "completed_at": "2026-09-02T11:30:00+00:00",
        "app": {"id": 99, "slug": "isolated-issuer"},
    }
    observed_digest = module.canonical_digest(run)
    request = SimpleNamespace(
        operation_id=admission.operation_id,
        lease_epoch_digest=admission.lease_epoch_digest,
        pull_request_number=admission.pull_request_number,
        pull_request_head=admission.pull_request_head,
        pull_request_tree=admission.pull_request_tree,
        base_commit=admission.base_commit,
        base_tree=admission.base_tree,
        queue_configuration_digest=admission.queue_configuration_digest,
        preparation_authorization_digest=admission.preparation_authorization_digest,
        admission_observation_digest=observed_digest,
    )
    if kind == "identity":
        request.pull_request_number = 99
    elif kind == "preparation":
        request.preparation_authorization_digest = "sha256:" + "b" * 64
    elif kind == "issuer":
        admission = module.AdmissionIssueRequest.build(
            **admission.model_dump(exclude={"stage", "issuer_identity"}), issuer_identity="other"
        )
    elif kind == "clock":
        value._trusted_clock = lambda: datetime(2026, 9, 2, 11, tzinfo=UTC)  # pyright: ignore[reportPrivateUsage]
    elif kind == "missing":
        run.pop("completed_at")
    elif kind == "date":
        run["completed_at"] = "not-a-date"
    elif kind == "stale":
        run["completed_at"] = "2025-01-01T00:00:00+00:00"
    else:
        request.admission_observation_digest = "sha256:" + "b" * 64
    value._admission_request = lambda _digest: admission  # pyright: ignore[reportPrivateUsage]
    value._check = lambda *_args, **_kwargs: run  # pyright: ignore[reportPrivateUsage]
    with pytest.raises((module._Precondition, GitHubMainGraduationError)):
        value._authoritative_admission("observer", request)  # pyright: ignore[reportPrivateUsage]


def test_cleanup_intent_and_verifiers_bind_fresh_terminal_evidence() -> None:
    from tests.unit.test_main_rollback_hosted_terminal import _intent

    value, _ = adapter()
    intent = _intent()
    value._principals["cleanup"] = module.GitHubPrincipalBinding("cleanup", 5, DIGEST, "token")  # pyright: ignore[reportPrivateUsage]
    value._principals["observer"] = module.GitHubPrincipalBinding("observer", 4, DIGEST, "token")  # pyright: ignore[reportPrivateUsage]
    value._transports["cleanup"] = FakeTransport((204, {}))  # pyright: ignore[reportPrivateUsage]
    checked = value._cleanup_intent(intent)  # pyright: ignore[reportPrivateUsage]
    assert checked.intent_digest == intent.intent_digest

    state = {
        "candidate_ref_absent": True,
        "pull_request_state": "closed",
        "pull_request_merged": True,
    }
    value._cleanup_pre_state = lambda _intent: state  # pyright: ignore[reportPrivateUsage]
    value._cleanup_state = lambda _intent: state  # pyright: ignore[reportPrivateUsage]
    rollback_intent = SimpleNamespace(
        candidate_ref=intent.candidate_ref, candidate_commit=intent.candidate_commit
    )
    result = SimpleNamespace(receipt_digest=intent.result_receipt_digest)
    authorization = SimpleNamespace(authorization_digest=intent.authorization_digest)
    value.verify_rollback_cleanup_intent(intent, rollback_intent, result, authorization)

    record = SimpleNamespace(
        intent_digest=intent.intent_digest,
        receipt_digest=intent.result_receipt_digest,
        cleanup_intent_digest=intent.intent_digest,
        cleanup_receipt_digest=intent.result_receipt_digest,
        outcome="already_absent",
        pull_request_state="closed",
        pull_request_merged=True,
    )
    value._cleanup_record_binding = lambda *_args: True  # pyright: ignore[reportPrivateUsage]
    value.verify_rollback_cleanup_receipt(record, intent, result)
    observation = SimpleNamespace(
        receipt_digest=intent.result_receipt_digest,
        outcome="absent",
        candidate_ref_absent=True,
        pull_request_state="closed",
        pull_request_merged=True,
    )
    value.verify_rollback_cleanup_observation(observation, intent, record)
    evidence = SimpleNamespace(
        cleanup_receipt_digest=intent.result_receipt_digest,
        cleanup_intent_digest=intent.intent_digest,
        pull_request_state="closed",
        pull_request_merged=True,
    )
    value.verify_rollback_cleanup_terminal(evidence, intent, record)

    with pytest.raises(module.GitHubMainGraduationRejected, match="ancestry"):
        value.verify_rollback_cleanup_intent(
            intent,
            SimpleNamespace(candidate_ref="wrong", candidate_commit=intent.candidate_commit),
            result,
            authorization,
        )


@pytest.mark.parametrize("mode", ("naive_clock", "future_cutoff", "expired"))
def test_final_release_fence_rejects_invalid_clock_cutoff_and_expiry(mode: str) -> None:
    value, _ = adapter()
    now = datetime(2026, 9, 2, 12, tzinfo=UTC)
    request = SimpleNamespace(
        authorization_expires_at=now + timedelta(minutes=1),
        check_context="avo-main-release",
    )
    if mode == "naive_clock":
        value._trusted_clock = lambda: datetime(2026, 9, 2, 12)  # pyright: ignore[reportPrivateUsage]
        value._release_freshness_cutoff = lambda _request: now  # pyright: ignore[reportPrivateUsage]
    elif mode == "future_cutoff":
        value._trusted_clock = lambda: now  # pyright: ignore[reportPrivateUsage]
        value._release_freshness_cutoff = lambda _request: now + timedelta(minutes=1)  # pyright: ignore[reportPrivateUsage]
    else:
        value._trusted_clock = lambda: now  # pyright: ignore[reportPrivateUsage]
        value._release_freshness_cutoff = lambda _request: now  # pyright: ignore[reportPrivateUsage]
        request.authorization_expires_at = now
    with pytest.raises((module._Precondition, GitHubMainGraduationError)):
        value._final_revalidate_release(request)  # pyright: ignore[reportPrivateUsage]


def test_check_rejects_missing_run_and_malformed_issuer_isolation() -> None:
    value, _ = adapter()
    value._enumerate_checks = lambda *_args: [  # pyright: ignore[reportPrivateUsage]
        {"id": "other", "external_id": "other", "name": "avo-main-release"}
    ]
    with pytest.raises(module._Precondition, match="missing or ambiguous"):
        value._check("source", OBJECT, "run", "nonce", status="completed", conclusion="success")  # pyright: ignore[reportPrivateUsage]
    run = {
        "id": "run",
        "external_id": "nonce",
        "name": "avo-main-release",
        "head_sha": OBJECT,
        "status": "completed",
        "conclusion": "success",
        "app": {"id": 1, "slug": "principal-0"},
    }
    value._enumerate_checks = lambda *_args: [run]  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(GitHubMainGraduationError, match="isolation"):
        value._check(  # pyright: ignore[reportPrivateUsage]
            "source",
            OBJECT,
            "run",
            "nonce",
            status="completed",
            conclusion="success",
            issuer=("principal-0", 1, "bad"),
        )


def test_remaining_identity_fences_reject_wrong_numbers_refs_nodes_and_queue_topology() -> None:
    value, _ = adapter()
    with pytest.raises(module._Precondition, match="number"):
        value._parse_pr(_pr(), 2)  # pyright: ignore[reportPrivateUsage]
    publication = module.CandidatePublicationRequest.build(
        operation_id=DIGEST,
        repository_digest=module.github_repository_digest("owner", "repo"),
        lease_epoch_digest=DIGEST,
        candidate_ref="refs/heads/avo/candidate/" + "a" * 64,
        candidate_commit=OBJECT,
        preparation_authorization_digest=DIGEST,
    )
    bad_ref = publication.model_dump()
    bad_ref["candidate_ref"] = "refs/heads/other/" + "a" * 64
    value._validate_request = lambda request, *_args: request  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError, match="operation ref"):
        value.publish_candidate(module.CandidatePublicationRequest.model_construct(**bad_ref))

    queue = _queue_request()
    value._queue_state = lambda *_args, **_kwargs: {"state": "queued"}  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match="pre-enqueue"):
        value._authoritative_queue("observer", queue, require_entry=False)  # pyright: ignore[reportPrivateUsage]
    value._authoritative_pr = lambda *_args, **_kwargs: {"url": "wrong"}  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match="identity"):
        value.enqueue(queue)

    value, _ = adapter()
    payload = _queue_payload()
    _install_queue_probe(value, payload)
    value._read = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "ref": "refs/heads/main",
        "object": {"type": "commit", "sha": OBJECT},
    }
    with pytest.raises(module._Precondition, match="base"):
        value._queue_state("observer", 1, OBJECT, "b" * 40, "c" * 40, require_entry=False)  # pyright: ignore[reportPrivateUsage]

    entry = {
        "id": "entry-id",
        "state": "QUEUED",
        "solo": False,
        "pullRequest": {"number": 1},
        "baseCommit": {"oid": "b" * 40},
        "headCommit": {"oid": OBJECT},
    }
    _install_queue_probe(value, _queue_payload(nodes=[entry]))
    with pytest.raises(module._Precondition, match="singleton"):
        value._queue_state("observer", 1, OBJECT, "b" * 40, "c" * 40)  # pyright: ignore[reportPrivateUsage]


def test_invoke_non_integer_status_and_existing_candidate_conflict_are_ambiguous() -> None:
    request = module.CandidatePublicationRequest.build(
        operation_id=DIGEST,
        repository_digest=module.github_repository_digest("owner", "repo"),
        lease_epoch_digest=DIGEST,
        candidate_ref="refs/heads/avo/candidate/" + "a" * 64,
        candidate_commit=OBJECT,
        preparation_authorization_digest=DIGEST,
    )
    value, _ = adapter(source=FakeTransport(("200", {})))
    result = value._invoke(  # pyright: ignore[reportPrivateUsage]
        "source", "POST", "/refs", None, request, module.CandidatePublicationResult, lambda x: x
    )
    assert result.outcome == "ambiguous"

    wrong = {"ref": request.candidate_ref, "object": {"type": "commit", "sha": "b" * 40}}
    value, _ = adapter(source=FakeTransport((200, wrong), get_response=(200, wrong)))
    with pytest.raises(module._Precondition, match="existing candidate"):
        value.publish_candidate(request)

    bad_response = {"ref": request.candidate_ref, "object": {"type": "commit", "sha": "b" * 40}}
    value, _ = adapter(source=FakeTransport((201, bad_response), get_response=(404, {})))
    assert value.publish_candidate(request).outcome == "ambiguous"


def test_protection_requires_queue_binding_and_enqueue_requires_node_identity() -> None:
    value, _ = adapter()
    protection, effective, ruleset = (
        _protection(),
        [{"ruleset_source_type": "Repository", "ruleset_source": "owner/repo", "ruleset_id": 1}],
        _ruleset(),
    )
    _protection_reader(value, protection, effective, ruleset)
    with pytest.raises(GitHubMainGraduationError, match="configuration is required"):
        value._authoritative_protection("observer")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match="merge_queue rule differs"):
        value._authoritative_protection(  # pyright: ignore[reportPrivateUsage]
            "observer",
            queue_configuration={
                "maximumEntriesToMerge": 2,
                "mergeMethod": "SQUASH",
                "mergingStrategy": "ALLGREEN",
            },
        )

    request = _queue_request()
    parsed = {
        "number": request.pull_request_number,
        "url": request.pull_request_url,
        "base_commit": request.base_commit,
        "head_commit": request.pull_request_head,
        "base_ref": "refs/heads/main",
        "head_ref": module._operation_candidate(request),
        "state": "open",
        "draft": False,
        "merged": False,
        "node_id": None,
    }
    value._authoritative_pr = lambda *_args, **_kwargs: parsed  # pyright: ignore[reportPrivateUsage]
    value._authoritative_queue = lambda *_args, **_kwargs: {}  # pyright: ignore[reportPrivateUsage]
    value._authoritative_admission = lambda *_args, **_kwargs: None  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match="node identity"):
        value.enqueue(request)
