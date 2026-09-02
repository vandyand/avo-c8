"""Second, lower-half branch wave for the capability-separated GitHub adapter.

These tests stay entirely on fake transports and intentionally exercise the
provider's fail-closed parsing, observation, and rollback-cleanup seams.
"""
# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportArgumentType=false, reportCallIssue=false, reportUnknownLambdaType=false, reportMissingImports=false, reportOptionalSubscript=false, reportIndexIssue=false, reportAttributeAccessIssue=false, reportUnusedImport=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from avo_correlate.adapters.hosted_git import main_graduation_github as module
from avo_correlate.adapters.hosted_git.github import GitHubTransportError
from avo_correlate.adapters.hosted_git.main_graduation_github import (
    GitHubMainGraduationAmbiguous,
    GitHubMainGraduationError,
)
from avo_correlate.application.c4_capabilities import (
    CandidateObservationRequest,
    CandidateObservationResult,
    CandidatePublicationResult,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_main_graduation_github import (
    DIGEST,
    OBJECT,
    FakeTransport,
    adapter,
    admission_for,
    candidate_request,
    queue_request,
)


def _run(*, run_id: str = "7", nonce: str = "n", sha: str = OBJECT) -> dict[str, Any]:
    return {
        "id": run_id,
        "external_id": nonce,
        "name": "avo-main-release",
        "head_sha": sha,
        "status": "completed",
        "conclusion": "success",
        "completed_at": "2026-09-02T12:00:00+00:00",
        "app": {"id": 1, "slug": "principal-0", "owner": {"login": "owner"}},
    }


def test_issue_check_creates_and_replays_only_exact_identity() -> None:
    value, transports = adapter()
    request = candidate_request()
    nonce = value._expected_nonce(request.external_identity)  # pyright: ignore[reportPrivateUsage]
    run = _run(nonce=nonce)
    value._enumerate_checks = lambda *_args: []  # pyright: ignore[reportPrivateUsage]
    transports[0].response = (201, run)
    result = value._issue_check(  # pyright: ignore[reportPrivateUsage]
        "source", request, CandidatePublicationResult, OBJECT, "7", nonce, "completed", "success"
    )
    assert result.outcome == "applied"
    assert transports[0].calls[-1][2]["conclusion"] == "success"

    value._enumerate_checks = lambda *_args: [run]  # pyright: ignore[reportPrivateUsage]
    replay = value._issue_check(  # pyright: ignore[reportPrivateUsage]
        "source", request, CandidatePublicationResult, OBJECT, "7", nonce, "completed", "success"
    )
    assert replay.outcome == "already_applied"
    bad = dict(run, head_sha="b" * 40)
    value._enumerate_checks = lambda *_args: [bad]  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match="identity or state differs"):
        value._issue_check(  # pyright: ignore[reportPrivateUsage]
            "source",
            request,
            CandidatePublicationResult,
            OBJECT,
            "7",
            nonce,
            "completed",
            "success",
        )


def test_authoritative_admission_revalidates_fresh_digest_and_staleness() -> None:
    value, _ = adapter()
    queue = queue_request()
    admission = admission_for(queue)
    run = _run(run_id=admission.admission_run_id, nonce=admission.admission_nonce, sha=OBJECT)
    observed_digest = canonical_digest(run)
    value._admission_request = lambda _digest: admission  # pyright: ignore[reportPrivateUsage]
    value._check = lambda *_args, **_kwargs: run  # pyright: ignore[reportPrivateUsage]
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
    assert value._authoritative_admission("admission", request) == run  # pyright: ignore[reportPrivateUsage]
    value._trusted_clock = lambda: datetime(2026, 9, 2, 11, tzinfo=UTC)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match="stale"):
        value._authoritative_admission("admission", request)  # pyright: ignore[reportPrivateUsage]
    request.admission_observation_digest = "bad"
    with pytest.raises(module._Precondition, match="missing or malformed"):
        value._authoritative_admission("admission", request)  # pyright: ignore[reportPrivateUsage]


def test_final_release_revalidation_reads_protection_and_group_checks() -> None:
    value, _ = adapter()
    base, tree, group = "a" * 40, "b" * 40, "c" * 40
    now = datetime(2026, 9, 2, 12, tzinfo=UTC)
    request = SimpleNamespace(
        authorization_expires_at=now + timedelta(minutes=10),
        check_context="avo-main-release",
        hold_run_id="hold",
        hold_nonce="hold-nonce",
        group_sha=group,
        base_commit=base,
        base_tree=tree,
    )
    value._trusted_clock = lambda: now  # pyright: ignore[reportPrivateUsage]
    value._release_freshness_cutoff = lambda _request: now - timedelta(hours=1)  # pyright: ignore[reportPrivateUsage]
    value._authoritative_group = lambda *_args: {}  # pyright: ignore[reportPrivateUsage]
    value._authoritative_admission = lambda *_args: {}  # pyright: ignore[reportPrivateUsage]
    value._read_commit = lambda *_args, **_kwargs: (base, tree, ("d" * 40,))  # pyright: ignore[reportPrivateUsage]
    release = {
        "id": "hold",
        "external_id": "hold-nonce",
        "name": "avo-main-release",
        "head_sha": group,
        "status": "in_progress",
        "conclusion": "pending",
        "app": {"id": 99, "slug": "isolated-issuer"},
    }
    validation = {
        "id": "validation",
        "external_id": "validation-nonce",
        "name": "validation",
        "head_sha": group,
        "status": "completed",
        "conclusion": "success",
        "completed_at": "2026-09-02T11:30:00+00:00",
        "app": {"id": 15368, "slug": "validation"},
    }
    value._enumerate_checks = lambda *_args: [release, validation]  # pyright: ignore[reportPrivateUsage]

    def read(_role: str, _method: str, path: str, _body: Any = None) -> Any:
        if path.endswith("/git/ref/heads/main"):
            return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": base}}
        return {
            "required_status_checks": {
                "contexts": ["validation", "avo-main-release"],
                "checks": [
                    {"context": "validation", "app_id": 15368},
                    {"context": "avo-main-release", "app_id": 99},
                ],
            }
        }

    value._read = read  # pyright: ignore[reportPrivateUsage]
    value._check = lambda *_args, **_kwargs: release  # pyright: ignore[reportPrivateUsage]
    value._final_revalidate_release(request)  # pyright: ignore[reportPrivateUsage]
    value._read = lambda *_args, **_kwargs: {
        "required_status_checks": {"contexts": [], "checks": []}
    }  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(GitHubMainGraduationError, match="malformed main ref"):
        value._final_revalidate_release(request)  # pyright: ignore[reportPrivateUsage]


def test_check_response_and_request_issuer_reject_lookalikes() -> None:
    value, _ = adapter()
    request = SimpleNamespace(
        hold_run_id="7",
        hold_nonce="nonce",
        check_context="avo-main-release",
        group_sha=OBJECT,
        issuer_identity="isolated-issuer",
        issuer_app_id=99,
        issuer_isolation_digest=DIGEST,
    )
    run = dict(
        _run(run_id="7", nonce="nonce", sha=OBJECT), app={"id": 99, "slug": "isolated-issuer"}
    )
    assert value._check_response(run, request) == run  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match="differs"):
        value._check_response(dict(run, conclusion="failure"), request)  # pyright: ignore[reportPrivateUsage]
    assert value._request_issuer(request) == ("isolated-issuer", 99, DIGEST)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(GitHubMainGraduationError, match="issuer"):
        value._request_issuer(
            SimpleNamespace(issuer_identity="x", issuer_app_id=True, issuer_isolation_digest=DIGEST)
        )  # pyright: ignore[reportPrivateUsage]


def test_candidate_observation_is_fresh_and_bound_to_observer_reads() -> None:
    value, _ = adapter()
    publication = candidate_request()
    request = CandidateObservationRequest.build(
        operation_id=publication.operation_id,
        repository_digest=publication.repository_digest,
        lease_epoch_digest=publication.lease_epoch_digest,
        candidate_ref=publication.candidate_ref,
        candidate_commit=publication.candidate_commit,
        preparation_authorization_digest=publication.preparation_authorization_digest,
        object_id="candidate-observation",
    )
    value._read = lambda *_args, **_kwargs: {
        "ref": request.candidate_ref,
        "object": {"type": "commit", "sha": request.candidate_commit},
    }  # pyright: ignore[reportPrivateUsage]
    value._read_commit = lambda *_args, **_kwargs: (request.candidate_commit, "b" * 40, ())  # pyright: ignore[reportPrivateUsage]
    result = value.observe_candidate(request)
    assert isinstance(result, CandidateObservationResult)
    assert result.evidence_digest
    value._read = lambda *_args, **_kwargs: {
        "ref": request.candidate_ref,
        "object": {"type": "blob", "sha": request.candidate_commit},
    }  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match="differs"):
        value.observe_candidate(request)


def test_observation_delegate_rejects_missing_method_and_wrong_binding() -> None:
    value, _ = adapter()
    request = candidate_request()
    value._observer = object()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(GitHubMainGraduationError, match="does not implement"):
        value._delegate_observer("observe_candidate", request, CandidateObservationResult)  # pyright: ignore[reportPrivateUsage]

    class Wrong:
        def observe_candidate(self, _request: Any) -> Any:
            return object()

    value._observer = Wrong()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(GitHubMainGraduationError, match="wrong result"):
        value._delegate_observer("observe_candidate", request, CandidateObservationResult)  # pyright: ignore[reportPrivateUsage]


def test_cleanup_ref_and_pr_authenticate_namespace_and_merged_state() -> None:
    value, _ = adapter()
    intent = SimpleNamespace(
        candidate_ref="refs/heads/avo/main-rollback/" + "a" * 64,
        candidate_commit=OBJECT,
        pull_request_number=3,
        pull_request_url="https://github.com/owner/repo/pull/3",
    )
    pr = {
        "number": 3,
        "html_url": intent.pull_request_url,
        "state": "closed",
        "merged": True,
        "base": {"ref": "main", "repo": {"full_name": "owner/repo"}},
        "head": {"ref": intent.candidate_ref, "sha": OBJECT, "repo": {"full_name": "owner/repo"}},
    }
    value._read = lambda _role, _method, path, _body=None: (
        {"ref": intent.candidate_ref, "object": {"type": "commit", "sha": OBJECT}}
        if "/git/ref/heads/" in path
        else pr
    )  # pyright: ignore[reportPrivateUsage]
    assert value._cleanup_ref(intent)  # pyright: ignore[reportPrivateUsage]
    assert value._cleanup_pr(intent) == ("closed", True)  # pyright: ignore[reportPrivateUsage]

    value._read = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        module._Precondition("gone", status=404)
    )  # pyright: ignore[reportPrivateUsage]
    assert value._cleanup_ref(intent) is False  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(module._Precondition, match="must exist"):
        value._cleanup_pr(intent)  # pyright: ignore[reportPrivateUsage]


def test_cleanup_dispatch_and_cleanup_state_paths_are_fail_closed() -> None:
    value, _ = adapter()
    cleanup = FakeTransport((204, {}))
    value._transports["cleanup"] = cleanup  # pyright: ignore[reportPrivateUsage]
    value._principals["cleanup"] = module.GitHubPrincipalBinding("cleanup", 101, DIGEST, "token")  # pyright: ignore[reportPrivateUsage]
    assert value._cleanup_dispatch("DELETE", "/x", None) == (204, {})  # pyright: ignore[reportPrivateUsage]
    value._transports["cleanup"] = lambda *_args: (_ for _ in ()).throw(
        GitHubTransportError("offline")
    )  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(GitHubMainGraduationAmbiguous, match="ambiguous"):
        value._cleanup_dispatch("DELETE", "/x", None)  # pyright: ignore[reportPrivateUsage]

    intent = SimpleNamespace(candidate_ref="refs/heads/avo/main-rollback/" + "a" * 64)
    value._cleanup_ref = lambda _intent: True  # pyright: ignore[reportPrivateUsage]
    value._cleanup_pr = lambda _intent: ("closed", True)  # pyright: ignore[reportPrivateUsage]
    assert value._cleanup_state(intent) == {
        "candidate_ref_absent": False,
        "pull_request_state": "closed",
        "pull_request_merged": True,
    }  # pyright: ignore[reportPrivateUsage]
    value._cleanup_state = lambda _intent: {
        "candidate_ref_absent": False,
        "pull_request_state": "open",
        "pull_request_merged": False,
    }  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(GitHubMainGraduationAmbiguous, match="post-state"):
        value._cleanup_post_state(intent)  # pyright: ignore[reportPrivateUsage]


def test_cleanup_rollback_classifies_preexisting_dispatch_and_post_errors() -> None:
    value, _ = adapter()
    intent = SimpleNamespace(candidate_ref="refs/heads/avo/main-rollback/" + "a" * 64)
    value._transports["cleanup"] = FakeTransport((204, {}))  # pyright: ignore[reportPrivateUsage]
    value._principals["cleanup"] = module.GitHubPrincipalBinding("cleanup", 101, DIGEST, "token")  # pyright: ignore[reportPrivateUsage]
    value._cleanup_intent = lambda item: item  # pyright: ignore[reportPrivateUsage]
    value._cleanup_receipt = lambda _intent, **kwargs: kwargs  # pyright: ignore[reportPrivateUsage]
    value._cleanup_pre_state = lambda _intent: {
        "candidate_ref_absent": True,
        "pull_request_state": "closed",
        "pull_request_merged": True,
    }  # pyright: ignore[reportPrivateUsage]
    assert value.cleanup_rollback(intent)["outcome"] == "already_absent"
    value._cleanup_pre_state = lambda _intent: {
        "candidate_ref_absent": False,
        "pull_request_state": "closed",
        "pull_request_merged": True,
    }  # pyright: ignore[reportPrivateUsage]
    value._cleanup_dispatch = lambda *_args: (200, {"unexpected": True})  # pyright: ignore[reportPrivateUsage]
    assert value.cleanup_rollback(intent)["outcome"] == "ambiguous"
    value._cleanup_dispatch = lambda *_args: (204, {})  # pyright: ignore[reportPrivateUsage]
    value._cleanup_post_state = lambda _intent: (_ for _ in ()).throw(
        GitHubMainGraduationAmbiguous("uncertain")
    )  # pyright: ignore[reportPrivateUsage]
    assert value.cleanup_rollback(intent)["outcome"] == "ambiguous"


def test_queue_configuration_observation_binds_stable_empty_state() -> None:
    value, _ = adapter()
    base, tree = OBJECT, "b" * 40
    value._read = lambda *_args, **_kwargs: {
        "ref": "refs/heads/main",
        "object": {"type": "commit", "sha": base},
    }  # pyright: ignore[reportPrivateUsage]
    value._read_commit = lambda *_args, **_kwargs: (base, tree, ())  # pyright: ignore[reportPrivateUsage]
    value._queue_state = lambda *_args, **_kwargs: {  # pyright: ignore[reportPrivateUsage]
        "state": "empty",
        "queue_configuration_digest": DIGEST,
        "protection_manifest_digest": DIGEST,
        "protection_epoch": DIGEST,
    }
    observation = value.observe_queue_configuration()
    assert observation.expected_base_commit == base
    assert observation.merge_method == "squash"


def test_helpers_and_record_binding_cover_malformed_transport_and_exact_fields() -> None:
    value, _ = adapter()
    record = SimpleNamespace(
        provider_identity="github-protected-main", provider_api_version="2022-11-28"
    )
    intent = SimpleNamespace(
        provider_identity="github-protected-main", provider_api_version="2022-11-28"
    )
    assert value._cleanup_record_binding(record, intent) is True  # pyright: ignore[reportPrivateUsage]
    record.provider_api_version = "other"
    assert value._cleanup_record_binding(record, intent) is False  # pyright: ignore[reportPrivateUsage]
    value._trusted_clock = lambda: datetime(2026, 9, 2, 12, tzinfo=UTC)  # pyright: ignore[reportPrivateUsage]
    assert value._rollback_now().tzinfo is not None  # pyright: ignore[reportPrivateUsage]
    value._trusted_clock = lambda: datetime(2026, 9, 2, 12)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(GitHubMainGraduationError, match="naive"):
        value._rollback_now()  # pyright: ignore[reportPrivateUsage]
