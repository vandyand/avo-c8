"""Focused fail-closed checks for the authority-owned C7 service.

These tests cover framework safety only.  They do not claim C4--C6 boundary
coverage or acceptance of a synthetic executor.
"""

# pyright: reportPrivateUsage=false, reportArgumentType=false

from __future__ import annotations

from pathlib import Path
from typing import NoReturn

import pytest

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.main_graduation_offline_drill_journal import (
    MainGraduationOfflineDrillJournal,
)
from avo_correlate.application.main_graduation_offline_drill_service import (
    MainGraduationOfflineDrillError,
    MainGraduationOfflineDrillService,
    PinnedC7AuthorityVerifier,
    _DeterministicOfflineDrillHarness,
)
from avo_correlate.application.main_graduation_offline_pytest_executor import (
    HermeticPytestExecutor,
)
from avo_correlate.domain.canonical import canonical_bytes
from tests.unit.test_main_graduation_offline_drill_journal import (
    _all_cases,
    _bound_result,
    _setup,
    _Verifier,
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


def test_fresh_service_replay_is_root_only_and_byte_identical(tmp_path: Path) -> None:
    journal, plan, authority, authority_ref, report, report_ref, _store = _setup(tmp_path)
    journal.record_plan(plan)
    cases = _all_cases(
        journal, plan, authority_ref, report_ref, report.junit_xml_artifact.digest
    )
    result = _bound_result(plan, cases, authority, report)
    journal.record_result(result)

    fresh_store = FilesystemArtifactStore(tmp_path / "artifacts")
    fresh_journal = MainGraduationOfflineDrillJournal(
        tmp_path, _Verifier(), artifact_store=fresh_store
    )

    class ExplodingClock:
        def now(self) -> NoReturn:
            pytest.fail("replay consulted the clock")

    clock = ExplodingClock()
    executor = HermeticPytestExecutor(
        tmp_path / "workspace-that-must-not-be-read",
        fresh_store,
        clock=clock.now,
        identity_checker=lambda _authority: pytest.fail(
            "replay consulted the workspace identity"
        ),
    )
    replayed = MainGraduationOfflineDrillService(
        fresh_journal,
        executor,
        authority=authority,
        clock=clock,
    ).replay()

    assert canonical_bytes(replayed) == canonical_bytes(result)
