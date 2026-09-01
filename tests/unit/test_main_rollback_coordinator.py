"""Crash-cutpoint coverage for the rollback aggregate boundary."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from avo_correlate.application.main_rollback_coordinator import MainRollbackCoordinator
from avo_correlate.contracts.main_graduation import MainRollbackCleanupObservation
from tests.unit.test_main_rollback_lifecycle_contracts import (
    RB,
    D,
    _journal_with_records,
    _lifecycle_records,
)


class _Principal:
    identity = "cleanup"
    app_id = 5
    isolation_digest = D


class _Clock:
    def now(self) -> datetime:
        return datetime(2026, 1, 1, 0, 10, tzinfo=UTC)


class _AuthorityVerifier:
    def verify_rollback_cleanup_receipt(self, *_values: object) -> None:
        return None

    def verify_rollback_cleanup_observation(self, *_values: object) -> None:
        return None


class _Cleanup:
    cleanup_principal = _Principal()
    observer_principal = SimpleNamespace(identity="observer", app_id=4, isolation_digest=D)

    def __init__(self, observation: MainRollbackCleanupObservation) -> None:
        self.observation = observation
        self.calls = 0

    def cleanup_rollback(self, _intent: object) -> object:
        self.calls += 1
        raise RuntimeError("crash after durable cleanup owner")

    def reconcile_rollback_cleanup(self, _intent: object, _receipt: object) -> object:
        return self.observation


def test_restart_after_cleanup_owner_reconciles_without_second_delete(tmp_path) -> None:
    source, intent, auth, _inverse, result, cleanup, _receipt, observation = _lifecycle_records()
    dependencies = {
        "completion": source,
        "rollback-intent": intent,
        "rollback-authorization": auth,
        "rollback-result": result,
        "rollback-cleanup-intent": cleanup,
    }
    journal = _journal_with_records(tmp_path, dependencies)
    receipt_box: dict[str, object] = {}
    journal.read_rollback_cleanup_receipt = lambda _operation_id: (
        (receipt_box["value"], None) if "value" in receipt_box else None
    )  # type: ignore[method-assign]
    journal.record_rollback_cleanup_receipt = lambda value: (
        receipt_box.__setitem__("value", value) or None
    )  # type: ignore[method-assign]
    journal.record_rollback_cleanup_terminal = lambda _value: None  # type: ignore[method-assign]
    capability = _Cleanup(observation)
    coordinator = object.__new__(MainRollbackCoordinator)
    coordinator.journal = journal
    coordinator.clock = _Clock()
    coordinator.cleanup_capability = capability
    coordinator.observation_capability = capability
    coordinator.authority_verifier = _AuthorityVerifier()

    authority = SimpleNamespace(operation_id=RB)
    with pytest.raises(RuntimeError, match="durable cleanup owner"):
        coordinator._cleanup(authority, result, cleanup)
    assert capability.calls == 1
    assert journal.read_rollback_cleanup_dispatch_owner(cleanup.intent_digest) is not None

    cleanup_receipt, cleanup_observation, terminal = coordinator._cleanup(
        authority, result, cleanup
    )
    assert capability.calls == 1
    assert cleanup_receipt.outcome == "already_absent"
    assert cleanup_observation is None
    assert terminal is not None
