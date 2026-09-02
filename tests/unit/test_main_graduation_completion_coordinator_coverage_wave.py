# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportIndexIssue=false, reportUnnecessaryCast=false, reportPrivateUsage=false, reportMissingImports=false

"""Adversarial branch coverage for the C4 completion coordinator."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from avo_correlate.application.c4_capabilities import QueueObservationResult
from avo_correlate.application.main_graduation_completion_coordinator import (
    MainGraduationCompletionCoordinator,
    MainGraduationCompletionError,
)
from avo_correlate.contracts.main_graduation import MainCheckObservation, MainQueueObservation
from tests.unit.test_main_graduation_completion_filesystem import (
    CompletionProvider,
    MutableClock,
    _attestation,
    _completion_coordinator,
    _completion_fixture,
    _make_group,
)
from tests.unit.test_main_graduation_coordinator_preparation import (
    MAIN_OPERATION,
    NOW,
    Authority,
    Fence,
    _coordinator,
    _fixture,
)


def _queued(root: Path) -> tuple[Any, CompletionProvider]:
    journal, provider = _completion_fixture(root)
    result = _coordinator(journal, provider).prepare(MAIN_OPERATION)
    assert result.state == "queued", result
    return journal, provider


def test_completion_constructor_rejects_nonpositive_ttl(tmp_path: Path) -> None:
    journal, provider = _completion_fixture(tmp_path)
    with pytest.raises(ValueError, match="authorization_ttl must be positive"):
        MainGraduationCompletionCoordinator(
            journal=journal,
            clock=provider.clock,
            lease_fence=Fence(),
            provider=provider,
            hold_capability=provider.hold_capability,
            release_capability=provider.release_capability,
            observation_capability=provider.observation_capability,
            authority_verifier=Authority(),
            authorization_ttl=provider.clock.current - provider.clock.current,
        )


def test_complete_quarantines_without_durable_preparation(tmp_path: Path) -> None:
    journal, provider = _completion_fixture(tmp_path)
    result = _completion_coordinator(journal, provider, provider.clock).complete(MAIN_OPERATION)
    assert result.state == "quarantined"
    assert result.reason == "durable queue is missing"


class _NoReceiptProvider(CompletionProvider):
    def observe_merge_group(self, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        return SimpleNamespace(
            group_sha="g",
            group_tree="t",
            group_parents=(),
            pull_request_numbers=(),
            queue_generation_digest="q",
        )


class _RejectedQueueProvider(CompletionProvider):
    def observe_queue(self, request: Any | None = None) -> Any:
        if request is None:
            return super().observe_queue(request)
        observed = cast(QueueObservationResult, super().observe_queue(request))
        return observed.model_copy(update={"outcome": "rejected"})


def test_group_observation_requires_sha_and_authenticated_receipt(tmp_path: Path) -> None:
    journal, provider = _queued(tmp_path)
    coordinator = _completion_coordinator(journal, provider, provider.clock)
    queue = journal.read_queue_observation(MAIN_OPERATION)
    assert queue is not None
    with pytest.raises(MainGraduationCompletionError, match="SHA is required"):
        coordinator._group_observation(
            None,
            group_sha=None,
            webhook_body=None,
            webhook_headers=None,
            queue=cast(MainQueueObservation, queue[0]),
            pull_request_number=provider.pr_number,
        )

    journal2, provider2 = _fixture(tmp_path / "receipt", _NoReceiptProvider)
    provider2 = cast(_NoReceiptProvider, provider2)
    _coordinator(journal2, provider2).prepare(MAIN_OPERATION)
    queue2 = journal2.read_queue_observation(MAIN_OPERATION)
    assert queue2 is not None
    with pytest.raises(MainGraduationCompletionError, match="authenticated receipt"):
        _completion_coordinator(journal2, provider2, provider2.clock)._group_observation(
            None,
            group_sha="g",
            webhook_body=b"{}",
            webhook_headers={"x": "y"},
            queue=cast(MainQueueObservation, queue2[0]),
            pull_request_number=provider2.pr_number,
        )


def test_queue_observation_rejection_and_queued_chain_identity_fail_closed(tmp_path: Path) -> None:
    journal, provider = _fixture(tmp_path, _RejectedQueueProvider)
    provider = cast(_RejectedQueueProvider, provider)
    result = _coordinator(journal, provider).prepare(MAIN_OPERATION)
    assert result.state == "queued"
    coordinator = _completion_coordinator(journal, provider, provider.clock)
    plan, prep, lease, config, queue, admission, protection = coordinator._load(MAIN_OPERATION)
    with pytest.raises(MainGraduationCompletionError, match="rejected queued preparation"):
        coordinator._observe_queue(plan, prep, queue, admission)
    with pytest.raises(MainGraduationCompletionError, match="configuration differs"):
        coordinator._assert_queued_chain(
            plan,
            prep,
            lease,
            config.model_copy(update={"queue_configuration_digest": "sha256:" + "f" * 64}),
            queue,
            admission,
            protection,
            revalidate_provider=False,
        )


class _ReleaseContextChecksProvider(CompletionProvider):
    def observe_merge_group_checks(self, group_sha: str, *, freshness_cutoff: Any) -> list[Any]:
        return [
            MainCheckObservation(
                name="release",
                context="avo-main-release",
                app_id=15368,
                sha=group_sha,
                status="completed",
                conclusion="success",
                run_id="run",
                nonce="nonce",
                observed_at=freshness_cutoff,
            )
        ]


def test_group_checks_reject_release_context_and_authorization_expiry(tmp_path: Path) -> None:
    journal, provider = _fixture(tmp_path, _ReleaseContextChecksProvider)
    provider = cast(_ReleaseContextChecksProvider, provider)
    assert _coordinator(journal, provider).prepare(MAIN_OPERATION).state == "queued"
    coordinator = _completion_coordinator(journal, provider, provider.clock)
    plan, prep, lease, _config, queue, admission, _protection = coordinator._load(MAIN_OPERATION)
    _attestation(journal)
    attestation = coordinator._attestation(MAIN_OPERATION)
    with pytest.raises(MainGraduationCompletionError, match="release hold context"):
        coordinator._group_checks("a" * 40, plan, attestation, queue)
    expired_clock = MutableClock(lease.expires_at)
    expired = _completion_coordinator(journal, provider, expired_clock)
    with pytest.raises(MainGraduationCompletionError, match="after lease expiry"):
        expired._issue_authorization(plan, prep, lease, admission, cast(Any, None))


def test_hold_observation_must_match_queued_topology(tmp_path: Path) -> None:
    journal, provider = _queued(tmp_path)
    _make_group(provider, tmp_path / "checkout")
    _attestation(journal)
    group = provider.observe_merge_group(
        provider.group_sha,
        webhook_body=b'{"action":"checks_requested"}',
        webhook_headers={},
        queue=journal.read_queue_observation(MAIN_OPERATION)[0],
        pull_request_number=provider.pr_number,
    )
    bad_group = SimpleNamespace(
        group_sha="foreign",
        group_tree=group.group_tree,
        group_parents=group.group_parents,
        pull_request_numbers=group.pull_request_numbers,
        queue_generation_digest=group.queue_generation_digest,
        webhook_receipt=group.webhook_receipt,
    )
    coordinator = _completion_coordinator(journal, provider, provider.clock)
    plan, prep, lease, config, queue, admission, protection = coordinator._load(MAIN_OPERATION)
    with pytest.raises(MainGraduationCompletionError, match="differs from queued preparation"):
        coordinator._issue_hold(
            plan,
            prep,
            lease,
            config,
            queue,
            admission,
            protection,
            coordinator._attestation(MAIN_OPERATION),
            bad_group,
        )


def test_parent_proof_and_post_state_are_fail_closed(tmp_path: Path) -> None:
    journal, provider = _queued(tmp_path)
    coordinator = _completion_coordinator(journal, provider, provider.clock)
    with pytest.raises(MainGraduationCompletionError, match="receipt is missing"):
        coordinator._parent_proof(
            cast(
                Any,
                SimpleNamespace(stage="queue_enqueue", intent_digest="sha256:" + "e" * 64),
            )
        )

    plan, _prep, _lease, _config, _queue, _admission, _protection = coordinator._load(
        MAIN_OPERATION
    )
    provider.observe_main = cast(Any, lambda: SimpleNamespace(commit="c", tree="t", parents=[]))
    with pytest.raises(MainGraduationCompletionError, match="post-state is incomplete"):
        coordinator._post_state(plan, cast(Any, None), cast(Any, None), cast(Any, None))


def test_completion_result_is_replayable_after_authoritative_recovery(tmp_path: Path) -> None:
    journal, provider = _completion_fixture(tmp_path)
    _make_group(provider, tmp_path / "checkout")
    assert _coordinator(journal, provider).prepare(MAIN_OPERATION).state == "queued"
    _attestation(journal)
    first = _completion_coordinator(journal, provider, provider.clock).complete(
        MAIN_OPERATION, group_sha=provider.group_sha, pull_request_number=provider.pr_number
    )
    assert first.state == "reconciliation_required"
    provider.clock.current = NOW.replace(minute=NOW.minute + 10)
    # The existing durable transition remains the sole release intent; this
    # retry only observes the provider's applied result.
    from tests.unit.test_main_graduation_coordinator_preparation import _fresh_journal

    fresh = _fresh_journal(journal)
    provider.journal = fresh
    recovered = _completion_coordinator(fresh, provider, provider.clock).complete(MAIN_OPERATION)
    assert recovered.state == "completed"
    replay = _completion_coordinator(fresh, provider, provider.clock).complete(MAIN_OPERATION)
    assert replay.state == "completed"
    assert replay.package == recovered.package
    assert provider.release_calls == 1
