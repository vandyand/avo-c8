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
    MainGraduationOfflineDrillJournalError,
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
from avo_correlate.contracts.main_graduation_offline_drill import (
    MainGraduationOfflineEvidenceKind,
)
from avo_correlate.domain.canonical import canonical_bytes
from tests.unit.test_main_graduation_offline_drill_journal import (
    _all_cases,
    _authority_and_report,
    _bound_case,
    _bound_plan,
    _bound_result,
    _plan,
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


def test_pinned_verifier_closes_cases_with_semantic_and_artifact_report_digests(
    tmp_path: Path,
) -> None:
    store = FilesystemArtifactStore(tmp_path / "artifacts")
    authority, authority_ref, report, _ = _authority_and_report(store)
    verifier = PinnedC7AuthorityVerifier(
        authority.authority_digest,
        authority_ref.digest,
        controller_authority_digest=authority.controller_authority_digest,
        controller_authority_ref=authority.controller_authority_ref,
    )
    journal = MainGraduationOfflineDrillJournal(tmp_path, verifier, artifact_store=store)
    authority_ref = journal.record_execution_authority(authority)
    report_ref = journal.record_execution_report(report)
    plan = _bound_plan(_plan(), authority_ref, authority.authority_digest)
    journal.record_plan(plan)
    cases = _all_cases(
        journal, plan, authority_ref, report_ref, report.junit_xml_artifact.digest
    )
    result = _bound_result(plan, cases, authority, report)

    assert report.report_digest != report_ref.digest
    result_ref = journal.record_result(result)
    assert journal.read_result(plan.operation_id) == (result, result_ref)


def test_pinned_verifier_rejects_tampered_execution_report_artifact_ref(
    tmp_path: Path,
) -> None:
    store = FilesystemArtifactStore(tmp_path / "artifacts")
    authority, authority_ref, report, _ = _authority_and_report(store)
    verifier = PinnedC7AuthorityVerifier(
        authority.authority_digest,
        authority_ref.digest,
        controller_authority_digest=authority.controller_authority_digest,
        controller_authority_ref=authority.controller_authority_ref,
    )
    journal = MainGraduationOfflineDrillJournal(tmp_path, verifier, artifact_store=store)
    authority_ref = journal.record_execution_authority(authority)
    report_ref = journal.record_execution_report(report)
    plan = _bound_plan(_plan(), authority_ref, authority.authority_digest)
    journal.record_plan(plan)
    case_id, vector_id = plan.cases[0].case_id, plan.cases[0].vectors[0].vector_id
    case = _bound_case(
        plan,
        authority_ref,
        report_ref,
        case_id,
        vector_id,
        1,
        report.junit_xml_artifact.digest,
    )
    report_evidence = next(
        item
        for item in case.native_evidence_refs
        if item.kind is MainGraduationOfflineEvidenceKind.EXECUTION_REPORT
    )
    tampered_evidence = report_evidence.model_copy(
        update={
            "artifact": report_evidence.artifact.model_copy(
                update={
                    "role": "c7-execution-authority",
                    "media_type": "application/vnd.avo.c7.execution-authority+json",
                }
            )
        }
    )
    tampered_case = case.model_copy(
        update={
            "native_evidence_refs": tuple(
                tampered_evidence if item is report_evidence else item
                for item in case.native_evidence_refs
            )
        }
    )

    assert (
        verifier.verify_case_result(
            tampered_case,
            plan,
            authority,
            report,
            tampered_case.native_evidence_refs,
        )
        is False
    )
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.record_case_result(tampered_case)
