# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownLambdaType=false, reportArgumentType=false, reportUnknownMemberType=false, reportIncompatibleMethodOverride=false
"""Positive and recovery coverage for the authority-owned C7 drill service."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path

import pytest

from avo_correlate.adapters.artifacts.main_graduation_offline_drill_journal import (
    MainGraduationOfflineDrillJournal,
)
from avo_correlate.application.main_graduation_offline_drill_service import (
    MainGraduationOfflineDrillError,
    MainGraduationOfflineDrillRun,
    MainGraduationOfflineDrillService,
    PinnedC7AuthorityVerifier,
)
from avo_correlate.application.main_graduation_offline_pytest_executor import (
    HermeticPytestExecutor,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation_offline_drill import (
    MainGraduationOfflineExecutionAuthority,
    MainGraduationOfflineExecutionReport,
)
from tests.unit.test_main_graduation_offline_drill_journal import (
    _authority_and_report,
    _setup,
    _Verifier,
)


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 1, 1, tzinfo=UTC)

    def now(self) -> datetime:
        return self.value


class _FixtureExecutor(HermeticPytestExecutor):
    def __init__(self, report: MainGraduationOfflineExecutionReport) -> None:
        self.report = report
        self.calls = 0

    def validate_authority(self, _authority: MainGraduationOfflineExecutionAuthority) -> None:
        return None

    def execute(
        self,
        _authority: MainGraduationOfflineExecutionAuthority,
        _authority_ref: ArtifactRef,
    ) -> MainGraduationOfflineExecutionReport:
        self.calls += 1
        return self.report


def test_service_runs_complete_report_then_replays_durable_cases(tmp_path: Path) -> None:
    store_root = tmp_path / "artifacts"
    from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore

    store = FilesystemArtifactStore(store_root)
    authority, _auth_ref, report, _report_ref = _authority_and_report(store)
    journal = MainGraduationOfflineDrillJournal(
        tmp_path, _Verifier(), artifact_store=store
    )
    executor = _FixtureExecutor(report)
    service = MainGraduationOfflineDrillService(
        journal,
        executor,
        authority=authority,
        clock=_Clock(),
    )
    first = service.run()
    assert first.status == "complete"
    assert first.result is not None
    assert len(first.cases) == 47
    assert executor.calls == 1
    second = service.run()
    assert second.status == "complete"
    assert second.result is not None
    assert executor.calls == 1
    assert service.replay().result_digest == first.result.result_digest
    assert service.journal is journal
    assert service.executor is executor
    assert service.authority is authority


def test_service_returns_incomplete_when_report_omits_one_observation(tmp_path: Path) -> None:
    from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore

    store = FilesystemArtifactStore(tmp_path / "artifacts")
    authority, _auth_ref, report, _report_ref = _authority_and_report(store)
    journal = MainGraduationOfflineDrillJournal(
        tmp_path, _Verifier(), artifact_store=store
    )
    journal.record_execution_authority(authority)
    report_ref = journal.record_execution_report(report)
    incomplete_report = copy.copy(report)
    object.__setattr__(incomplete_report, "observations", report.observations[:-1])
    # The production journal only returns validated reports.  This narrow
    # proxy models a crash/recovery seam after durable report publication so
    # the service's explicit pending-vector behavior is exercised directly.
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        journal,
        "read_execution_report",
        lambda *_args, **_kwargs: (incomplete_report, report_ref),
    )
    monkeypatch.setattr(journal, "record_case_result", lambda _result: None)
    executor = _FixtureExecutor(report)
    run = MainGraduationOfflineDrillService(
        journal,
        executor,
        authority=authority,
        clock=_Clock(),
    ).run()
    monkeypatch.undo()
    assert run.status == "incomplete"
    assert run.result is None
    assert len(run.cases) == 46
    assert len(run.pending_case_vectors) == 1
    assert run.pending_case_ids


def test_service_accepts_authority_manifest_and_rejects_binding_mismatch(tmp_path: Path) -> None:
    from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore

    store = FilesystemArtifactStore(tmp_path / "artifacts")
    authority, _auth_ref, report, _report_ref = _authority_and_report(store)
    journal = MainGraduationOfflineDrillJournal(tmp_path, _Verifier(), artifact_store=store)
    executor = _FixtureExecutor(report)
    service = MainGraduationOfflineDrillService(
        journal,
        executor,
        authority_manifest=authority.model_dump(mode="json"),
        clock=_Clock(),
        operation_id=authority.operation_id,
        repository_digest=authority.repository_digest,
    )
    assert service.authority.operation_id == authority.operation_id
    with pytest.raises(MainGraduationOfflineDrillError, match="operation mismatch"):
        MainGraduationOfflineDrillService(
            journal,
            executor,
            authority=authority,
            clock=_Clock(),
            operation_id="sha256:" + "f" * 64,
        )


def test_pinned_verifier_positive_authority_report_plan_and_case_checks(tmp_path: Path) -> None:
    journal, plan, authority, authority_ref, _report, _report_ref, _store = _setup(tmp_path)
    verifier = PinnedC7AuthorityVerifier(
        authority.authority_digest,
        authority_ref.digest,
        controller_authority_digest=authority.controller_authority_digest,
        controller_authority_ref=authority.controller_authority_ref,
    )
    assert verifier.verify_execution_authority(authority, authority_ref)
    loaded_report = journal.read_execution_report(
        authority.operation_id, authority.authority_digest
    )
    assert loaded_report is not None
    loaded_report_model, loaded_report_ref = loaded_report
    assert verifier.verify_execution_report(
        authority,
        loaded_report_model,
        loaded_report_ref,
        loaded_report_model.observations[0].evidence_refs,
    )
    assert verifier.verify_plan(plan, authority, authority_ref)


def test_run_value_and_attribute_error_are_explicit() -> None:
    run = MainGraduationOfflineDrillRun(None, ())  # type: ignore[arg-type]
    with pytest.raises(AttributeError):
        run.__getattr__("result_digest")
