"""Focused fail-closed checks for the authority-owned C7 service.

These tests cover framework safety only.  They do not claim C4--C6 boundary
coverage or acceptance of a synthetic executor.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from avo_correlate.application.main_graduation_offline_drill_service import (
    MainGraduationOfflineDrillError,
    MainGraduationOfflineDrillService,
    PinnedC7AuthorityVerifier,
    _DeterministicOfflineDrillHarness,
)


def test_synthetic_harness_cannot_be_constructed() -> None:
    with pytest.raises(
        MainGraduationOfflineDrillError,
        match="c7_authority_executor_unavailable",
    ):
        _DeterministicOfflineDrillHarness()


def test_public_service_requires_controller_authority() -> None:
    class Executor:
        def execute(self, *_args: object) -> object:
            return object()

    with pytest.raises(
        MainGraduationOfflineDrillError,
        match="c7_authority_executor_unavailable",
    ):
        MainGraduationOfflineDrillService(Path("."), Executor())


def test_pinned_verifier_requires_digest() -> None:
    with pytest.raises(ValueError, match="authority digest is required"):
        PinnedC7AuthorityVerifier("not-a-digest")
