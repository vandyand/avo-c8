"""Completion-level C4 gates for races, crash boundaries, and chronology.

These tests deliberately use the filesystem-backed preparation fixture.  The
provider remains a deterministic fake, but every mutation crosses the same
durable journal and stage executor boundary as the C4 coordinator.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import Any, cast

import pytest

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.application.c4_capabilities import ReleaseIssueResult
from avo_correlate.contracts.main_graduation import MainQueueObservation
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.c4_coordinator_test_support import MAIN_OPERATION
from tests.unit.test_main_graduation_completion_filesystem import (
    CompletionProvider,
    MutableClock,
    _attestation,
    _completion_coordinator,
    _fresh_journal,
    _make_group,
)
from tests.unit.test_main_graduation_coordinator_preparation import (
    CONFIG,
    NOW,
    _coordinator,
    _fixture,
)


class SuccessfulCompletionProvider(CompletionProvider):
    """Complete the release synchronously and reject a second release call."""

    def issue_group_hold(self, request: Any) -> Any:
        if self.hold_calls:
            raise AssertionError("group hold was dispatched more than once")
        return super().issue_group_hold(request)

    def issue_release(self, request: Any) -> Any:
        self.release_calls += 1
        if self.release_calls != 1:
            raise AssertionError("release transition was dispatched more than once")
        self.applied = True
        self.main_commit = self.candidate
        self.main_tree = self.candidate_tree
        return ReleaseIssueResult.build(
            **request.model_dump(
                exclude={"request_digest", "external_key", "external_identity"}
            ),
            outcome="applied",
            response_digest=CONFIG,
            observed_at=self.clock.now(),
            dispatch_started=True,
        )


def _prepared_completion_fixture(
    root: Path,
) -> tuple[MainGraduationJournal, SuccessfulCompletionProvider, MutableClock]:
    journal, provider = _fixture(root, SuccessfulCompletionProvider)
    provider = cast(SuccessfulCompletionProvider, provider)
    clock = MutableClock(NOW)
    provider.clock = clock
    _make_group(provider, root / "checkout")
    prepared = _coordinator(journal, provider).prepare(MAIN_OPERATION)
    assert prepared.state == "queued", prepared
    _attestation(journal)
    return journal, provider, clock


def test_independent_coordinators_race_then_restart_with_one_hold_and_release(
    tmp_path: Path,
) -> None:
    journal, provider, clock = _prepared_completion_fixture(tmp_path)
    barrier = Barrier(2)

    def run(index: int) -> object:
        target = journal if index == 0 else _fresh_journal(journal)
        barrier.wait()
        return _completion_coordinator(target, provider, clock).complete(
            MAIN_OPERATION,
            group_sha=provider.group_sha,
            pull_request_number=provider.pr_number,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, (0, 1)))

    states = [(result.state, result.reason) for result in results]
    assert sum(state == "completed" for state, _ in states) >= 1
    assert all(
        state == "completed"
        or (state == "quarantined" and reason and "terminal receipt" in reason)
        for state, reason in states
    )
    assert provider.hold_calls == 1
    assert provider.release_calls == 1
    assert journal.read_release_hold(MAIN_OPERATION) is not None
    assert journal.read_release_authorization(MAIN_OPERATION) is not None
    assert journal.read_release_transition(MAIN_OPERATION) is not None
    assert journal.read_completion(MAIN_OPERATION) is not None

    restarted = _fresh_journal(journal)
    provider.journal = restarted
    replay = _completion_coordinator(restarted, provider, clock).complete(MAIN_OPERATION)
    assert replay.state == "completed"
    assert provider.hold_calls == 1
    assert provider.release_calls == 1


class _CrashAfterJournalWrite:
    """Install one crash after a selected durable write has committed."""

    def __init__(self, journal: MainGraduationJournal, monkeypatch: pytest.MonkeyPatch) -> None:
        self.journal = journal
        self.monkeypatch = monkeypatch
        self.crashed = False

    def after(
        self,
        method_name: str,
        predicate: Callable[[Any], bool] | None = None,
    ) -> None:
        original = getattr(self.journal, method_name)

        def wrapped(record: Any) -> Any:
            result = original(record)
            if not self.crashed and (predicate is None or predicate(record)):
                self.crashed = True
                raise MainGraduationJournalError("simulated process crash after durable write")
            return result

        self.monkeypatch.setattr(self.journal, method_name, wrapped)


@pytest.mark.parametrize(
    ("boundary", "method_name", "predicate", "release_before_restart"),
    [
        (
            "hold-receipt",
            "record_mutation_receipt",
            lambda record: record.stage == "merge_group_hold",
            False,
        ),
        ("durable-hold", "record_release_hold", None, False),
        ("authorization", "record_release_authorization", None, False),
        ("claim", "record_release_claim", None, False),
        (
            "transition-intent",
            "record_mutation_intent",
            lambda record: record.stage == "release_transition",
            False,
        ),
        ("claimed-transition", "record_claimed_release_transition", None, True),
    ],
)
def test_restart_matrix_never_repeats_irreversible_release_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
    method_name: str,
    predicate: Callable[[Any], bool] | None,
    release_before_restart: bool,
) -> None:
    del boundary
    journal, provider, clock = _prepared_completion_fixture(tmp_path)
    crash = _CrashAfterJournalWrite(journal, monkeypatch)
    crash.after(method_name, predicate)

    first = _completion_coordinator(journal, provider, clock).complete(
        MAIN_OPERATION,
        group_sha=provider.group_sha,
        pull_request_number=provider.pr_number,
    )
    assert first.state == "quarantined"
    assert crash.crashed
    assert provider.hold_calls == 1
    assert provider.release_calls == int(release_before_restart)

    restarted = _fresh_journal(journal)
    provider.journal = restarted
    second = _completion_coordinator(restarted, provider, clock).complete(MAIN_OPERATION)
    assert second.state == "completed", second.reason
    assert provider.hold_calls == 1
    assert provider.release_calls == 1
    assert restarted.read_completion(MAIN_OPERATION) is not None


def test_regenerated_queue_generation_cannot_reuse_durable_hold_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal, provider, clock = _prepared_completion_fixture(tmp_path)
    crash = _CrashAfterJournalWrite(journal, monkeypatch)
    crash.after("record_release_claim")

    first = _completion_coordinator(journal, provider, clock).complete(
        MAIN_OPERATION,
        group_sha=provider.group_sha,
        pull_request_number=provider.pr_number,
    )
    assert first.state == "quarantined"
    assert provider.hold_calls == 1
    assert provider.release_calls == 0
    authorization = journal.read_release_authorization(MAIN_OPERATION)
    assert authorization is not None
    claim = journal.read_release_claim_for_authorization(MAIN_OPERATION, authorization[0])
    assert claim is not None

    original_observe_queue = provider.observe_queue

    def regenerated_queue(
        *, operation_id: str, queue_configuration_digest: str, admission_observation_digest: str
    ) -> MainQueueObservation:
        del operation_id, queue_configuration_digest, admission_observation_digest
        observed = original_observe_queue()
        assert isinstance(observed, MainQueueObservation)
        return observed.model_copy(
            update={"queue_generation_digest": canonical_digest({"generation": "regenerated"})}
        )

    monkeypatch.setattr(provider, "observe_queue", regenerated_queue)
    restarted = _fresh_journal(journal)
    provider.journal = restarted
    result = _completion_coordinator(restarted, provider, clock).complete(MAIN_OPERATION)
    assert result.state == "quarantined"
    assert result.reason is not None and "queued preparation differs" in result.reason
    assert provider.release_calls == 0
    assert restarted.read_release_authorization(MAIN_OPERATION) is not None
    assert restarted.read_completion(MAIN_OPERATION) is None


class ChronologyProvider(SuccessfulCompletionProvider):
    def __init__(self, *args: Any) -> None:
        super().__init__(*args)
        self.events: list[str] = []

    def enqueue(self, request: Any) -> Any:
        self.events.append("enqueue")
        return super().enqueue(request)

    def issue_group_hold(self, request: Any) -> Any:
        self.events.append("merge_group_hold")
        return super().issue_group_hold(request)

    def issue_release(self, request: Any) -> Any:
        self.events.append("release_transition")
        return super().issue_release(request)


def test_provider_chronology_has_no_queue_or_merge_mutation_after_release_authorization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal, provider = _fixture(tmp_path, ChronologyProvider)
    provider = cast(ChronologyProvider, provider)
    provider.clock = MutableClock(NOW)
    _make_group(provider, tmp_path / "checkout")
    assert _coordinator(journal, provider).prepare(MAIN_OPERATION).state == "queued"
    _attestation(journal)

    original = journal.record_release_authorization

    def record_authorization(record: Any) -> Any:
        result = original(record)
        provider.events.append("release_authorization")
        return result

    monkeypatch.setattr(journal, "record_release_authorization", record_authorization)
    result = _completion_coordinator(journal, provider, provider.clock).complete(
        MAIN_OPERATION,
        group_sha=provider.group_sha,
        pull_request_number=provider.pr_number,
    )
    assert result.state == "completed", result.reason
    assert provider.events.index("enqueue") < provider.events.index("merge_group_hold")
    authorization_index = provider.events.index("release_authorization")
    assert provider.events[authorization_index + 1 :] == ["release_transition"]
    assert not set(provider.events[authorization_index + 1 :]) & {
        "enqueue",
        "merge_group_hold",
    }
