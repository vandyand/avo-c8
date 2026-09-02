"""Adversarial tests for the offline personal exact-CAS state machine."""

# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportArgumentType=false, reportMissingImports=false

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest

from avo_correlate.application.main_personal_exact_cas_controller import (
    MainPersonalExactCasController,
    MainPersonalExactCasControllerResult,
)
from avo_correlate.contracts.main_personal_exact_cas import (
    MainPersonalExactCasDispatchStarted,
    MainPersonalExactCasIntent,
    MainPersonalExactCasPostStateObservation,
    MainPersonalExactCasReceipt,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_main_personal_exact_cas_journal import (
    NOW,
    _activation,
    _chain,
    _journal,
)


class Clock:
    def __init__(self, value: datetime) -> None:
        self.value = value
        self.calls = 0

    def now(self) -> datetime:
        self.calls += 1
        return self.value


class SequenceClock(Clock):
    def __init__(self, values: list[datetime]) -> None:
        super().__init__(values[0])
        self.values = values

    def now(self) -> datetime:
        self.calls += 1
        return self.values[min(self.calls - 1, len(self.values) - 1)]


class Lease:
    def __init__(self, events: list[str], fail: bool = False) -> None:
        self.events, self.fail = events, fail

    def assert_current(self, **_kwargs: Any) -> None:
        self.events.append("lease")
        if self.fail:
            raise RuntimeError("secret lease token")


class Dispatch:
    def __init__(
        self,
        events: list[str],
        *,
        timeout: bool = False,
        outcome: str = "applied",
        forged: bool = False,
    ) -> None:
        self.events, self.timeout, self.outcome, self.forged, self.calls = (
            events,
            timeout,
            outcome,
            forged,
            0,
        )

    def apply(
        self, intent: MainPersonalExactCasIntent, marker: MainPersonalExactCasDispatchStarted
    ) -> MainPersonalExactCasReceipt:
        self.events.append("dispatch")
        self.calls += 1
        if self.timeout:
            raise TimeoutError("secret transport detail")
        receipt = MainPersonalExactCasReceipt.build(
            **_scope(intent),
            authorization_digest=intent.authorization_digest,
            intent_digest=intent.intent_digest,
            dispatch_marker_digest=marker.dispatch_marker_digest,
            response_digest=canonical_digest({"response": "ok"}),
            outcome=self.outcome,
            dispatch_started=True,
            error_code="transport_ambiguous" if self.outcome == "ambiguous" else None,
            observed_at=NOW + timedelta(minutes=4),
        )
        if self.forged:
            return receipt.model_copy(
                update={"intent_digest": "sha256:" + "0" * 64}
            )
        return receipt


class PostState:
    def __init__(self, events: list[str]) -> None:
        self.events, self.calls = events, 0

    def observe(self, intent: Any, receipt: Any) -> MainPersonalExactCasPostStateObservation:
        self.events.append("observe")
        self.calls += 1
        return MainPersonalExactCasPostStateObservation.build(
            **_scope(intent),
            authorization_digest=intent.authorization_digest,
            intent_digest=intent.intent_digest,
            receipt_digest=receipt.receipt_digest,
            receipt_outcome=receipt.outcome,
            observed_ref="refs/heads/main",
            observed_commit=intent.candidate_commit,
            observed_tree=intent.candidate_tree,
            observed_parents=(intent.base_commit,),
            observed_at=NOW + timedelta(minutes=5),
        )


class CrashBeforeCompletion:
    def __init__(self, journal: Any) -> None:
        self.journal, self.crashed = journal, False

    def __getattr__(self, name: str) -> Any:
        return getattr(self.journal, name)

    def record_completion(self, _completion: Any) -> None:
        if not self.crashed:
            self.crashed = True
            raise RuntimeError("simulated crash")
        self.journal.record_completion(_completion)


class ClaimBarrierJournal:
    def __init__(self, journal: Any) -> None:
        self.journal, self.barrier = journal, Barrier(2)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.journal, name)

    def claim_dispatch_started(self, marker: Any) -> Any:
        self.barrier.wait()
        return self.journal.claim_dispatch_started(marker)


class AdvancingClaimJournal:
    def __init__(self, journal: Any, clock: Clock, expiry: datetime) -> None:
        self.journal, self.clock, self.expiry = journal, clock, expiry

    def __getattr__(self, name: str) -> Any:
        return getattr(self.journal, name)

    def claim_dispatch_started(self, marker: Any) -> Any:
        result = self.journal.claim_dispatch_started(marker)
        self.clock.value = self.expiry
        return result


class RegressingClaimJournal:
    def __init__(self, journal: Any, clock: SequenceClock, value: datetime) -> None:
        self.journal, self.clock, self.value = journal, clock, value

    def __getattr__(self, name: str) -> Any:
        return getattr(self.journal, name)

    def claim_dispatch_started(self, marker: Any) -> Any:
        result = self.journal.claim_dispatch_started(marker)
        self.clock.values.append(self.value)
        return result


def _scope(value: Any) -> dict[str, Any]:
    return {name: getattr(value, name) for name in (
        "activation_digest", "operation_id", "repository_digest", "target_ref",
        "source_operation_id", "source_plan_digest", "source_package_digest",
        "source_composition_digest", "base_commit", "base_tree", "candidate_commit",
        "candidate_tree", "candidate_ref", "candidate_parents", "protection_ruleset_digest",
        "writer_app_id", "writer_installation_id", "writer_identity", "lease_identity",
        "lease_digest", "lease_expires_at", "claim_nonce", "claim_digest",
    )}


def _setup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Any, Any, Any, Any]:
    source_journal, source, journal = _journal(monkeypatch, tmp_path)
    activation = _activation(source_journal, source)
    journal.record_activation(activation, source)
    authorization, *_ = _chain(activation)
    return journal, activation, authorization, source_journal


def test_applied_order_and_completion_replay_are_single_dispatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    journal, _activation_value, authorization, _ = _setup(monkeypatch, tmp_path)
    events: list[str] = []
    clock = Clock(NOW + timedelta(minutes=1))
    dispatch = Dispatch(events)
    controller = MainPersonalExactCasController(
        journal, dispatch, PostState(events), Lease(events), clock
    )
    result = controller.execute(authorization)
    assert result.state == "completed" and result.dispatch_count == 1
    assert events.index("dispatch") < events.index("observe")
    replay = controller.execute(authorization)
    assert replay.completion_replayed and replay.dispatch_count == 0
    assert dispatch.calls == 1


def test_timeout_leaves_marker_without_receipt_and_retry_never_dispatches(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    journal, _activation_value, authorization, _ = _setup(monkeypatch, tmp_path)
    events: list[str] = []
    controller = MainPersonalExactCasController(
        journal,
        Dispatch(events, timeout=True),
        PostState(events),
        Lease(events),
        Clock(NOW + timedelta(minutes=1)),
    )
    result = controller.execute(authorization)
    assert result.state == "reconciliation_required" and result.outcome == "ambiguous"
    assert events.count("dispatch") == 1
    replay = controller.execute(authorization)
    assert replay.state == "reconciliation_required" and replay.dispatch_count == 0
    assert events.count("dispatch") == 1


def test_explicit_ambiguous_receipt_is_reconciled_by_authoritative_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    journal, _activation_value, authorization, _ = _setup(monkeypatch, tmp_path)
    events: list[str] = []
    dispatch = Dispatch(events, outcome="ambiguous")
    result = MainPersonalExactCasController(
        journal,
        dispatch,
        PostState(events),
        Lease(events),
        Clock(NOW + timedelta(minutes=1)),
    ).execute(authorization)
    assert result.state == "completed" and result.outcome == "applied"
    assert dispatch.calls == 1


def test_rejected_receipt_replay_stays_rejected_without_post_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    journal, _activation_value, authorization, _ = _setup(monkeypatch, tmp_path)
    events: list[str] = []
    dispatch = Dispatch(events, outcome="rejected")
    controller = MainPersonalExactCasController(
        journal,
        dispatch,
        PostState(events),
        Lease(events),
        Clock(NOW + timedelta(minutes=1)),
    )
    first = controller.execute(authorization)
    second = controller.execute(authorization)
    assert first.state == second.state == "rejected"
    assert first.dispatch_count == 1 and second.dispatch_count == 0
    assert events.count("observe") == 0 and dispatch.calls == 1


def test_forged_receipt_is_not_repaired_or_completed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    journal, _activation_value, authorization, _ = _setup(monkeypatch, tmp_path)
    events: list[str] = []
    dispatch = Dispatch(events, forged=True)
    controller = MainPersonalExactCasController(
        journal,
        dispatch,
        PostState(events),
        Lease(events),
        Clock(NOW + timedelta(minutes=1)),
    )
    result = controller.execute(authorization)
    assert result.state == "reconciliation_required" and dispatch.calls == 1
    assert journal.read_receipt(authorization.operation_id) is None
    retry = controller.execute(authorization)
    assert retry.dispatch_count == 0 and dispatch.calls == 1


def test_final_lease_expiry_blocks_marker_and_dispatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    journal, _activation_value, authorization, _ = _setup(monkeypatch, tmp_path)
    events: list[str] = []
    dispatch = Dispatch(events)
    clock = SequenceClock([NOW + timedelta(minutes=1), authorization.lease_expires_at])
    result = MainPersonalExactCasController(
        journal, dispatch, PostState(events), Lease(events), clock
    ).execute(authorization)
    assert result.state == "rejected" and result.dispatch_count == 0
    assert dispatch.calls == 0


def test_existing_intent_is_adopted_without_rebuilding_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    journal, activation, authorization, _ = _setup(monkeypatch, tmp_path)
    _, intent, _, *_ = _chain(activation)
    journal.record_authorization(authorization)
    journal.record_intent(intent)
    events: list[str] = []
    dispatch = Dispatch(events)
    result = MainPersonalExactCasController(
        journal,
        dispatch,
        PostState(events),
        Lease(events),
        SequenceClock([NOW + timedelta(minutes=2), NOW + timedelta(minutes=4)]),
    ).execute(authorization)
    assert result.state == "completed" and dispatch.calls == 1


def test_recovery_adopts_durable_post_state_and_reconciliation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    journal, _activation_value, authorization, _ = _setup(monkeypatch, tmp_path)
    events: list[str] = []
    dispatch = Dispatch(events, outcome="ambiguous")
    crashed = CrashBeforeCompletion(journal)
    controller = MainPersonalExactCasController(
        crashed,
        dispatch,
        PostState(events),
        Lease(events),
        Clock(NOW + timedelta(minutes=1)),
    )
    first = controller.execute(authorization)
    assert first.state == "reconciliation_required" and dispatch.calls == 1
    observed = events.count("observe")
    second = MainPersonalExactCasController(
        crashed,
        dispatch,
        PostState(events),
        Lease(events),
        Clock(NOW + timedelta(minutes=1)),
    ).execute(authorization)
    assert second.state == "completed" and second.dispatch_count == 0, second
    assert dispatch.calls == 1 and events.count("observe") == observed


def test_expired_lease_before_intent_has_zero_dispatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    journal, _activation_value, authorization, _ = _setup(monkeypatch, tmp_path)
    events: list[str] = []
    dispatch = Dispatch(events)
    result = MainPersonalExactCasController(
        journal,
        dispatch,
        PostState(events),
        Lease(events),
        Clock(authorization.lease_expires_at),
    ).execute(authorization)
    assert result.state == "rejected" and result.dispatch_count == 0
    assert dispatch.calls == 0


def test_marker_without_receipt_is_reconciliation_required_without_dispatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    journal, _activation_value, authorization, _ = _setup(monkeypatch, tmp_path)
    # A real marker is deliberately left without a receipt; recovery must stop.
    _, intent, marker, *_ = _chain(_activation_value)
    journal.record_authorization(authorization)
    journal.record_intent(intent)
    journal.record_dispatch_started(marker)
    events: list[str] = []
    dispatch = Dispatch(events)
    result = MainPersonalExactCasController(
        journal,
        dispatch,
        PostState(events),
        Lease(events),
        Clock(NOW + timedelta(minutes=1)),
    ).execute(authorization)
    assert result.state == "reconciliation_required" and result.dispatch_count == 0
    assert dispatch.calls == 0


def test_lease_failure_is_secret_safe_and_pre_dispatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    journal, _activation_value, authorization, _ = _setup(monkeypatch, tmp_path)
    events: list[str] = []
    result = MainPersonalExactCasController(
        journal,
        Dispatch(events),
        PostState(events),
        Lease(events, fail=True),
        Clock(NOW + timedelta(minutes=1)),
    ).execute(authorization)
    assert result.state == "rejected"
    assert "secret" not in result.reason


def test_controller_source_has_no_live_or_generic_ref_capability() -> None:
    source = Path(
        "src/avo_correlate/application/main_personal_exact_cas_controller.py"
    ).read_text(encoding="utf-8").lower()
    tree = ast.parse(source)
    forbidden_imports = {"requests", "urllib", "http", "subprocess"}
    assert not any(
        isinstance(node, (ast.Import, ast.ImportFrom))
        and any(
            (alias.name.split(".", 1)[0] in forbidden_imports)
            for alias in getattr(node, "names", ())
        )
        for node in ast.walk(tree)
    )
    forbidden_surface = {"force", "force_update", "delete", "generic_ref"}
    surface_names = {
        node.id if isinstance(node, ast.Name) else node.attr
        for node in ast.walk(tree)
        if isinstance(node, (ast.Name, ast.Attribute))
    }
    assert not forbidden_surface & surface_names


def test_concurrent_controllers_have_one_dispatch_owner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    journal, _activation_value, authorization, _ = _setup(monkeypatch, tmp_path)
    shared_journal = ClaimBarrierJournal(journal)
    events: list[str] = []
    dispatch = Dispatch(events)
    controllers = [
        MainPersonalExactCasController(
            shared_journal,
            dispatch,
            PostState(events),
            Lease(events),
            Clock(NOW + timedelta(minutes=1)),
        )
        for _ in range(2)
    ]

    def execute(
        controller: MainPersonalExactCasController,
    ) -> MainPersonalExactCasControllerResult:
        return controller.execute(authorization)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(execute, controllers))
    assert dispatch.calls == 1
    assert {result.state for result in results} == {"completed", "reconciliation_required"}


def test_marker_claim_expiry_is_checked_before_dispatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    journal, _activation_value, authorization, _ = _setup(monkeypatch, tmp_path)
    events: list[str] = []
    clock = Clock(NOW + timedelta(minutes=1))
    delayed_journal = AdvancingClaimJournal(journal, clock, authorization.lease_expires_at)
    dispatch = Dispatch(events)
    result = MainPersonalExactCasController(
        delayed_journal,
        dispatch,
        PostState(events),
        Lease(events),
        clock,
    ).execute(authorization)
    assert result.state == "reconciliation_required" and result.dispatch_count == 0
    assert dispatch.calls == 0


def test_marker_claim_clock_regression_is_checked_before_dispatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    journal, _activation_value, authorization, _ = _setup(monkeypatch, tmp_path)
    events: list[str] = []
    clock = SequenceClock(
        [
            NOW + timedelta(minutes=1),
            NOW + timedelta(minutes=2),
            NOW + timedelta(minutes=1, seconds=30),
        ]
    )
    delayed_journal = RegressingClaimJournal(journal, clock, NOW + timedelta(minutes=1, seconds=30))
    dispatch = Dispatch(events)
    result = MainPersonalExactCasController(
        delayed_journal, dispatch, PostState(events), Lease(events), clock
    ).execute(authorization)
    assert result.state == "reconciliation_required" and result.dispatch_count == 0
    assert dispatch.calls == 0
