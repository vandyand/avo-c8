"""Narrow hosted capability protocols for C5 terminal rollback evidence.

These protocols intentionally expose only authenticated observation and the
single exact rollback-candidate cleanup mutation.  They do not include a main-ref writer, force
update, reset, merge, or any other protected-main mutation.
"""

from __future__ import annotations

from typing import Protocol

from avo_correlate.contracts.main_graduation import (
    MainRollbackAttemptAuthority,
    MainRollbackCleanupIntent,
    MainRollbackCleanupObservation,
    MainRollbackCleanupReceipt,
    MainRollbackPostStateObservation,
    MainRollbackResultReceipt,
)


class MainRollbackFinalObserver(Protocol):
    """Authenticated read-only final-main observer."""

    def observe_rollback_post_state(
        self,
        result: MainRollbackResultReceipt,
        attempt: MainRollbackAttemptAuthority,
    ) -> MainRollbackPostStateObservation: ...


class MainRollbackCleanupCapability(Protocol):
    """Exact rollback candidate-ref/PR cleanup capability."""

    def cleanup_rollback(
        self, intent: MainRollbackCleanupIntent
    ) -> MainRollbackCleanupReceipt: ...

    def reconcile_rollback_cleanup(
        self,
        intent: MainRollbackCleanupIntent,
        receipt: MainRollbackCleanupReceipt,
    ) -> MainRollbackCleanupObservation: ...


class HostedMainRollbackTerminalCapability(
    MainRollbackFinalObserver, MainRollbackCleanupCapability, Protocol
):
    """Combined terminal capability accepted by a C5 coordinator."""


__all__ = [
    "HostedMainRollbackTerminalCapability",
    "MainRollbackCleanupCapability",
    "MainRollbackFinalObserver",
]
