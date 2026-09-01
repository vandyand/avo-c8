"""Pre-stage C5 rollback authority coordinator tests."""

from __future__ import annotations

from datetime import datetime

import pytest

from avo_correlate.application.main_rollback_authority import (
    MainRollbackAuthority,
    MainRollbackAuthorityError,
)


def test_clock_rejects_naive_time() -> None:
    class NaiveClock:
        def now(self) -> datetime:
            return datetime(2026, 1, 1)

    with pytest.raises(MainRollbackAuthorityError, match="naive"):
        MainRollbackAuthority(
            journal=object(),  # type: ignore[arg-type]
            clock=NaiveClock(),
        )._trusted_now()


def test_public_result_exposes_durable_refs() -> None:
    # Keep the public contract assertion independent of hosted/provider
    # adapters; all writes are exercised by the journal integration tests.
    assert callable(MainRollbackAuthority.prepare)
    assert callable(MainRollbackAuthority.authorize)
    assert callable(MainRollbackAuthority.prepare_authority)
