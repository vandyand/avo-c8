"""Additional branch coverage for the durable C7 offline-drill journal."""

# Fixture helpers intentionally come from the existing real-filesystem tests.
# pyright: reportPrivateUsage=false, reportUnknownParameterType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false

from __future__ import annotations

import json
from pathlib import Path

import pytest

from avo_correlate.adapters.artifacts.main_graduation_offline_drill_journal import (
    MainGraduationOfflineDrillJournal,
    MainGraduationOfflineDrillJournalError,
)
from tests.unit.test_main_graduation_offline_drill_journal import (
    _all_cases,
    _bound_result,
    _NoneVerifier,
    _setup,
    _Verifier,
    _WrongSignatureVerifier,
)

# Fixture helpers intentionally come from the existing real-filesystem tests.
# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportArgumentType=false


def test_constructor_rejects_ambiguous_verifier_and_nonpositive_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="only one C7 verifier"):
        MainGraduationOfflineDrillJournal(
            tmp_path, _NoneVerifier(), verifier=_WrongSignatureVerifier()
        )
    with pytest.raises(ValueError, match="max_record_bytes"):
        MainGraduationOfflineDrillJournal(tmp_path, max_record_bytes=0)


def test_empty_journal_reads_are_discoverable_and_read_only(tmp_path: Path) -> None:
    journal = MainGraduationOfflineDrillJournal(tmp_path)
    operation_id = "sha256:" + "a" * 64
    assert journal.read_execution_authority(operation_id) is None
    assert journal.read_execution_report(operation_id) is None
    assert journal.read_plan(operation_id) is None
    assert journal.read_result(operation_id) is None
    assert journal.read_completed_result(operation_id) is None
    assert journal.delete_artifact("sha256:" + "b" * 64) is False


def test_all_durable_records_replay_create_once_and_reload_after_cache_clear(
    tmp_path: Path,
) -> None:
    journal, plan, authority, authority_ref, report, report_ref, _store = _setup(tmp_path)
    assert journal.record_execution_authority(authority) == authority_ref
    assert journal.record_execution_report(report) == report_ref
    plan_ref = journal.record_plan(plan)
    assert journal.record_plan_once(plan) == plan_ref
    cases = _all_cases(
        journal, plan, authority_ref, report_ref, report.junit_xml_artifact.digest
    )
    result = _bound_result(plan, cases, authority, report)
    result_ref = journal.record_result(result)
    assert journal.record_result_once(result) == result_ref

    # A fresh object must rediscover every identity from durable indexes.
    fresh = MainGraduationOfflineDrillJournal(tmp_path, _Verifier())
    assert fresh.read_execution_authority(plan.operation_id) is not None
    assert fresh.read_execution_report(plan.operation_id) is not None
    assert fresh.read_plan(plan.operation_id) == (plan, plan_ref)
    assert fresh.read_case_result(
        plan.operation_id, cases[0].case_id, cases[0].vector_id
    ) is not None
    assert fresh.read_result(plan.operation_id) == (result, result_ref)
    assert fresh.read_completed_result(plan.operation_id) == (result, result_ref)


def test_missing_native_artifact_is_detected_on_report_reload(tmp_path: Path) -> None:
    journal, _plan, _authority, _authority_ref, report, report_ref, _store = _setup(tmp_path)
    assert journal.delete_artifact(report.junit_xml_artifact.digest)
    with pytest.raises(MainGraduationOfflineDrillJournalError, match="JUnit artifact"):
        journal.read_execution_report(report.operation_id)
    # The indexed report still exists, but the content-addressed evidence does
    # not; the journal must never silently reconstruct or accept it.
    assert report_ref.digest != report.junit_xml_artifact.digest


def test_malformed_duplicate_key_index_is_rejected(tmp_path: Path) -> None:
    journal, _plan, authority, _authority_ref, _report, _report_ref, _store = _setup(tmp_path)
    index = journal._authority_index(authority.operation_id, authority.authority_digest)
    index.write_bytes(b'{"digest":"x","digest":"y"}')
    with pytest.raises(MainGraduationOfflineDrillJournalError, match="malformed C7 authority"):
        journal.read_execution_authority(authority.operation_id, authority.authority_digest)


@pytest.mark.parametrize("verifier", [_NoneVerifier(), _WrongSignatureVerifier()])
def test_verifier_contract_is_exact_and_literal_true(tmp_path: Path, verifier: object) -> None:
    with pytest.raises(MainGraduationOfflineDrillJournalError, match="verifier"):
        _setup(tmp_path, verifier)


def test_report_index_noncanonical_json_is_rejected(tmp_path: Path) -> None:
    journal, _plan, authority, _authority_ref, report, _report_ref, _store = _setup(tmp_path)
    index = journal._report_index(
        report.operation_id, authority.authority_digest, report.report_digest
    )
    value = json.loads(index.read_text(encoding="utf-8"))
    index.write_text(json.dumps(value, indent=2), encoding="utf-8")
    with pytest.raises(MainGraduationOfflineDrillJournalError, match="malformed C7 report"):
        journal.read_execution_report(report.operation_id, authority.authority_digest)
