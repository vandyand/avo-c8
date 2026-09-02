# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportArgumentType=false, reportIncompatibleMethodOverride=false, reportUnusedImport=false, reportUnusedVariable=false
"""Additional service/verifier coverage for C7 offline drill lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.application.main_graduation_offline_drill_service import (
    MainGraduationOfflineDrillError,
    MainGraduationOfflineDrillService,
    PinnedC7AuthorityVerifier,
)
from avo_correlate.application.main_graduation_offline_pytest_executor import HermeticPytestExecutor
from tests.unit.test_main_graduation_offline_drill_journal import (
    _authority_and_report,
    _bound_plan,
    _setup,
)

D = "sha256:" + "a" * 64


class _Executor(HermeticPytestExecutor):
    def __init__(self, report: Any) -> None:
        self.report = report
        self.validated = 0
        self.calls = 0

    def validate_authority(self, _authority: Any) -> None:
        self.validated += 1

    def execute(self, _authority: Any, _authority_ref: Any) -> Any:
        self.calls += 1
        return self.report


def test_service_operation_id_requires_digest() -> None:
    with pytest.raises(MainGraduationOfflineDrillError, match="operation"):
        MainGraduationOfflineDrillService.operation_id({})
    with pytest.raises(MainGraduationOfflineDrillError, match="operation"):
        MainGraduationOfflineDrillService.operation_id({"operation_id": "bad"})
    assert MainGraduationOfflineDrillService.operation_id({"operation_id": D}) == D


def test_service_rejects_manifest_and_binding_mismatches(tmp_path: Path) -> None:
    executor = _Executor(object())
    with pytest.raises(MainGraduationOfflineDrillError, match="invalid execution authority"):
        MainGraduationOfflineDrillService(
            tmp_path,
            executor,
            authority_manifest={"operation_id": D},
            authority_verifier=object(),
            clock=lambda: datetime.now(UTC),
        )
    journal, _plan_value, authority, _auth_ref, _report, _report_ref, _store = _setup(
        tmp_path / "second"
    )
    with pytest.raises(MainGraduationOfflineDrillError, match="operation mismatch"):
        MainGraduationOfflineDrillService(
            journal,
            executor,
            authority=authority,
            authority_verifier=journal._verifier,
            operation_id="sha256:" + "b" * 64,
            clock=lambda: datetime.now(UTC),
        )
    with pytest.raises(MainGraduationOfflineDrillError, match="repository mismatch"):
        MainGraduationOfflineDrillService(
            journal,
            executor,
            authority=authority,
            authority_verifier=journal._verifier,
            repository_digest="sha256:" + "b" * 64,
            clock=lambda: datetime.now(UTC),
        )


def test_pinned_verifier_rejects_wrong_authority_and_report_bindings(tmp_path: Path) -> None:
    store = _setup(tmp_path)[-1]
    authority, auth_ref, report, report_ref = _authority_and_report(store)
    verifier = PinnedC7AuthorityVerifier(
        authority.authority_digest,
        auth_ref.digest,
        controller_authority_digest=authority.controller_authority_digest,
        controller_authority_ref=authority.controller_authority_ref,
    )
    assert verifier.verify_execution_authority(authority, auth_ref)
    assert not verifier.verify_execution_authority(
        authority.model_copy(update={"authority_digest": "sha256:" + "b" * 64}), auth_ref
    )
    evidence = report.observations[0].evidence_refs
    assert verifier.verify_execution_report(authority, report, report_ref, evidence)
    stale_report = report.model_copy(update={"operation_id": "sha256:" + "b" * 64})
    assert not verifier.verify_execution_report(authority, stale_report, auth_ref, evidence)


def test_service_run_reuses_durable_report_without_executor_dispatch(tmp_path: Path) -> None:
    journal, plan, authority, auth_ref, report, _report_ref, _store = _setup(tmp_path)
    bound_plan = _bound_plan(plan, auth_ref, authority.authority_digest)
    journal.record_plan(bound_plan)
    executor = _Executor(report)
    service = MainGraduationOfflineDrillService(
        journal,
        executor,
        authority=authority,
        authority_verifier=journal._verifier,
        clock=lambda: datetime(2026, 1, 1, tzinfo=UTC),
    )
    # A durable report means this retry must not execute pytest again.
    result = service.run()
    assert result.status == "complete"
    assert executor.validated == 1
    assert executor.calls == 0
    assert service.replay().result_digest == result.result.result_digest  # type: ignore[union-attr]


def test_pinned_verifier_rejects_duplicate_or_wrong_evidence_roles(tmp_path: Path) -> None:
    store = _setup(tmp_path)[-1]
    authority, auth_ref, report, report_ref = _authority_and_report(store)
    verifier = PinnedC7AuthorityVerifier(
        authority.authority_digest,
        auth_ref.digest,
        controller_authority_digest=authority.controller_authority_digest,
        controller_authority_ref=authority.controller_authority_ref,
    )
    assert not verifier.verify_execution_report(authority, report, report_ref, ())
    assert MainGraduationOfflineDrillService is not None
