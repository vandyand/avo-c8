"""Adversarial fake-transport coverage for hosted rollback terminal cleanup."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainRollbackAuthorityVerifier,
)
from avo_correlate.adapters.hosted_git.github import github_repository_digest
from avo_correlate.adapters.hosted_git.main_graduation_github import (
    GitHubMainGraduationAdapter,
    GitHubMainGraduationRejected,
    GitHubPrincipalBinding,
)
from avo_correlate.contracts.main_graduation import (
    MainRollbackCleanupIntent,
    rollback_cleanup_authority_digest,
)
from avo_correlate.domain.canonical import canonical_digest

D = "sha256:" + "a" * 64
SOURCE = "sha256:" + "b" * 64
COMMIT = "c" * 40
REPOSITORY = github_repository_digest("owner", "repo")
REF = "refs/heads/avo/main-rollback/" + "b" * 64
NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)


def _intent() -> MainRollbackCleanupIntent:
    values: dict[str, Any] = {
        "operation_id": SOURCE,
        "source_operation_id": D,
        "repository_digest": REPOSITORY,
        "target_ref": "refs/heads/main",
        "completion_package_digest": D,
        "result_receipt_digest": D,
        "authorization_digest": D,
        "candidate_ref": REF,
        "candidate_commit": COMMIT,
        "pull_request_number": 17,
        "pull_request_url": "https://github.com/owner/repo/pull/17",
        "provider_identity": "github-protected-main",
        "provider_api_version": "2022-11-28",
        "cleanup_principal_identity": "cleanup",
        "cleanup_principal_app_id": 5,
        "cleanup_principal_isolation_digest": D,
        "observer_identity": "observer",
        "observer_app_id": 4,
        "observer_isolation_digest": D,
        "observer_provider_identity": "github-protected-main",
        "observer_provider_api_version": "2022-11-28",
        "cleanup_authority_digest": rollback_cleanup_authority_digest(REPOSITORY),
        "recorded_at": NOW,
    }
    probe = MainRollbackCleanupIntent.model_construct(**values, intent_digest=D)
    values["intent_digest"] = canonical_digest(
        probe.model_dump(exclude={"intent_digest"}, mode="json")
    )
    return MainRollbackCleanupIntent.model_validate(values)


class _Observer:
    def __init__(self, *, ref_present: bool, pr_state: str, merged: bool) -> None:
        self.ref_present = ref_present
        self.pr_state = pr_state
        self.merged = merged
        self.calls: list[tuple[str, str, Any, str | None]] = []

    def __call__(self, method: str, url: str, body: Any, headers: Any) -> tuple[int, Any]:
        self.calls.append((method, url, body, headers.get("Authorization")))
        if "/git/ref/heads/" in url:
            if not self.ref_present:
                return 404, {}
            return 200, {"ref": REF, "object": {"type": "commit", "sha": COMMIT}}
        if url.endswith("/pulls/17"):
            if self.pr_state == "absent":
                return 404, {}
            return 200, {
                "number": 17,
                "html_url": "https://github.com/owner/repo/pull/17",
                "state": self.pr_state,
                "merged": self.merged,
                "base": {"ref": "main", "repo": {"full_name": "owner/repo"}},
                "head": {
                    "ref": REF,
                    "sha": COMMIT,
                    "repo": {"full_name": "owner/repo"},
                },
            }
        raise AssertionError((method, url))


class _Cleanup:
    def __init__(
        self,
        observer: _Observer,
        *,
        ambiguous: bool = False,
        status: object = 204,
        payload: Any = None,
        post_pr_state: str | None = None,
        post_merged: bool | None = None,
    ) -> None:
        self.observer = observer
        self.ambiguous = ambiguous
        self.status = status
        self.payload = payload
        self.post_pr_state = post_pr_state
        self.post_merged = post_merged
        self.calls: list[tuple[str, str, Any, str | None]] = []

    def __call__(self, method: str, url: str, body: Any, headers: Any) -> tuple[int, Any]:
        self.calls.append((method, url, body, headers.get("Authorization")))
        assert method == "DELETE"
        assert "/git/refs/heads/" in url
        assert body is None
        if self.ambiguous:
            raise TimeoutError("lost response")
        self.observer.ref_present = False
        if self.post_pr_state is not None:
            self.observer.pr_state = self.post_pr_state
        if self.post_merged is not None:
            self.observer.merged = self.post_merged
        return self.status, self.payload


def _adapter(observer: _Observer, cleanup: _Cleanup) -> GitHubMainGraduationAdapter:
    def principal(identity: str, app_id: int) -> GitHubPrincipalBinding:
        return GitHubPrincipalBinding(identity, app_id, D, "token-" + identity)

    issuer = principal("issuer", 9000)
    return GitHubMainGraduationAdapter(
        "owner",
        "repo",
        REPOSITORY,
        source_publisher_transport=lambda *args: (200, {}),
        source_publisher_principal=principal("source", 1),
        preparation_transport=lambda *args: (200, {}),
        preparation_principal=principal("preparation", 2),
        admission_issuer_transport=lambda *args: (200, {}),
        admission_issuer_principal=issuer,
        group_hold_issuer_transport=lambda *args: (200, {}),
        group_hold_issuer_principal=principal("issuer", 9000),
        release_issuer_transport=lambda *args: (200, {}),
        release_issuer_principal=principal("issuer", 9000),
        observer_transport=observer,
        observer_principal=principal("observer", 4),
        cleanup_transport=cleanup,
        cleanup_principal=principal("cleanup", 5),
        mutation_authorize=lambda _request: None,
        trusted_clock=lambda: NOW,
        release_freshness_cutoff=lambda _request: NOW,
        admission_request=lambda _digest: None,
        admission_freshness_cutoff=lambda _request: NOW,
        trusted_check_contexts=("validation",),
    )


def test_cleanup_deletes_only_exact_ref_after_merged_closed_and_reads_absence() -> None:
    observer = _Observer(ref_present=True, pr_state="closed", merged=True)
    cleanup = _Cleanup(observer)
    receipt = _adapter(observer, cleanup).cleanup_rollback(_intent())

    assert receipt.outcome == "applied"
    assert receipt.dispatch_started is True
    assert [call[0] for call in cleanup.calls] == ["DELETE"]
    assert all(call[3] == "Bearer token-cleanup" for call in cleanup.calls)
    assert len(observer.calls) == 4  # ref/PR before and ref/PR after DELETE
    assert observer.calls[0][1].endswith("/pulls/17")
    assert "/git/ref/heads/" in observer.calls[1][1]
    assert "/git/ref/heads/" in observer.calls[2][1]
    assert observer.calls[3][1].endswith("/pulls/17")
    assert receipt.observed_at == NOW


def test_cleanup_replay_is_truthful_and_non_dispatching() -> None:
    observer = _Observer(ref_present=False, pr_state="closed", merged=True)
    cleanup = _Cleanup(observer)
    receipt = _adapter(observer, cleanup).cleanup_rollback(_intent())

    assert receipt.outcome == "already_absent"
    assert receipt.dispatch_started is False
    assert cleanup.calls == []


def test_concrete_cleanup_verifier_is_read_only_and_binds_authority() -> None:
    observer = _Observer(ref_present=False, pr_state="closed", merged=True)
    cleanup = _Cleanup(observer)
    adapter = _adapter(observer, cleanup)
    verifier: MainRollbackAuthorityVerifier = adapter
    journal = MainGraduationJournal(Path("."), rollback_authority_verifier=verifier)
    assert journal._rollback_authority_verifier is verifier  # type: ignore[attr-defined]
    intent = _intent()
    receipt = adapter.cleanup_rollback(intent)
    result = type("Result", (), {"receipt_digest": intent.result_receipt_digest})()

    verifier.verify_rollback_cleanup_receipt(receipt, intent, result)  # type: ignore[arg-type]
    assert cleanup.calls == []

    forged = receipt.model_copy(
        update={"cleanup_authority_digest": "sha256:" + "f" * 64}
    )
    with pytest.raises(GitHubMainGraduationRejected, match="authority"):
        adapter.verify_rollback_cleanup_receipt(forged, intent, result)
    assert cleanup.calls == []


@pytest.mark.parametrize(
    "pr_state,merged", [("open", False), ("closed", False), ("open", True)]
)
def test_cleanup_rejects_open_or_unmerged_pr_before_delete(pr_state: str, merged: bool) -> None:
    observer = _Observer(ref_present=True, pr_state=pr_state, merged=merged)
    cleanup = _Cleanup(observer)
    receipt = _adapter(observer, cleanup).cleanup_rollback(_intent())

    assert receipt.outcome == "invalid"
    assert receipt.dispatch_started is False
    assert cleanup.calls == []


def test_cleanup_rejects_missing_exact_pr_before_delete() -> None:
    observer = _Observer(ref_present=True, pr_state="absent", merged=False)
    cleanup = _Cleanup(observer)
    receipt = _adapter(observer, cleanup).cleanup_rollback(_intent())

    assert receipt.outcome == "invalid"
    assert receipt.dispatch_started is False
    assert cleanup.calls == []


@pytest.mark.parametrize("status,payload", [(200, {}), (404, {}), ("204", None)])
def test_delete_non_success_or_malformed_status_is_ambiguous(
    status: object, payload: Any
) -> None:
    observer = _Observer(ref_present=True, pr_state="closed", merged=True)
    cleanup = _Cleanup(observer, status=status, payload=payload)
    receipt = _adapter(observer, cleanup).cleanup_rollback(_intent())

    assert receipt.outcome == "ambiguous"
    assert receipt.dispatch_started is True
    assert len(cleanup.calls) == 1


def test_delete_toctou_post_state_drift_cannot_claim_applied() -> None:
    observer = _Observer(ref_present=True, pr_state="closed", merged=True)
    cleanup = _Cleanup(observer, post_pr_state="open", post_merged=False)
    receipt = _adapter(observer, cleanup).cleanup_rollback(_intent())

    assert receipt.outcome == "ambiguous"
    assert receipt.dispatch_started is True


def test_reconciliation_rejects_missing_exact_pr_without_mutation() -> None:
    observer = _Observer(ref_present=False, pr_state="absent", merged=False)
    cleanup = _Cleanup(observer)
    adapter = _adapter(observer, cleanup)
    successful_observer = _Observer(ref_present=True, pr_state="closed", merged=True)
    successful_cleanup = _Cleanup(successful_observer)
    receipt = _adapter(successful_observer, successful_cleanup).cleanup_rollback(_intent())

    with pytest.raises(GitHubMainGraduationRejected):
        adapter.reconcile_rollback_cleanup(_intent(), receipt)
    assert cleanup.calls == []


def test_ambiguous_delete_is_reconciled_read_only_with_observer_identity() -> None:
    observer = _Observer(ref_present=True, pr_state="closed", merged=True)
    cleanup = _Cleanup(observer, ambiguous=True)
    adapter = _adapter(observer, cleanup)
    receipt = adapter.cleanup_rollback(_intent())
    assert receipt.outcome == "ambiguous"
    assert receipt.dispatch_started is True

    observer.ref_present = False
    observation = adapter.reconcile_rollback_cleanup(_intent(), receipt)
    assert observation.outcome == "absent"
    assert observation.observer_identity == "observer"
    assert observation.provider_identity == "github-protected-main"
    assert cleanup.calls == [("DELETE", cleanup.calls[0][1], None, "Bearer token-cleanup")]


def test_principal_binding_tuples_must_be_distinct() -> None:
    observer = _Observer(ref_present=False, pr_state="closed", merged=True)
    cleanup = _Cleanup(observer)
    with pytest.raises(ValueError, match="observer requires a distinct principal"):
        # Reusing the source principal tuple must be rejected even with a new
        # object, proving separation is identity/app/isolation based.
        GitHubMainGraduationAdapter(
            "owner",
            "repo",
            REPOSITORY,
            source_publisher_transport=lambda *args: (200, {}),
            source_publisher_principal=GitHubPrincipalBinding("same", 1, D, "source"),
            preparation_transport=lambda *args: (200, {}),
            preparation_principal=GitHubPrincipalBinding("prep", 2, D, "prep"),
            admission_issuer_transport=lambda *args: (200, {}),
            admission_issuer_principal=GitHubPrincipalBinding("issuer", 9, D, "issuer"),
            group_hold_issuer_transport=lambda *args: (200, {}),
            group_hold_issuer_principal=GitHubPrincipalBinding("issuer", 9, D, "hold"),
            release_issuer_transport=lambda *args: (200, {}),
            release_issuer_principal=GitHubPrincipalBinding("issuer", 9, D, "release"),
            observer_transport=observer,
            observer_principal=GitHubPrincipalBinding("same", 1, D, "observer"),
            cleanup_transport=cleanup,
            cleanup_principal=GitHubPrincipalBinding("cleanup", 5, D, "cleanup"),
            mutation_authorize=lambda _request: None,
            trusted_clock=lambda: NOW,
            release_freshness_cutoff=lambda _request: NOW,
            admission_request=lambda _digest: None,
            admission_freshness_cutoff=lambda _request: NOW,
            trusted_check_contexts=("validation",),
        )
