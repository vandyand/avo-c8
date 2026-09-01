"""Durability and authority-boundary tests for the C7 journal."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.main_graduation_offline_drill_journal import (
    MainGraduationOfflineDrillJournal,
    MainGraduationOfflineDrillJournalError,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation import MainReconciliation
from avo_correlate.contracts.main_graduation_offline_drill import (
    OFFLINE_EVIDENCE_ROLE_MEDIA,
    MainGraduationOfflineDrillCaseResult,
    MainGraduationOfflineDrillCrashFacts,
    MainGraduationOfflineDrillPlan,
    MainGraduationOfflineDrillReplayFacts,
    MainGraduationOfflineDrillResult,
    MainGraduationOfflineEvidenceKind,
    MainGraduationOfflineEvidenceRef,
    MainGraduationOfflineExecutionAuthority,
    MainGraduationOfflineExecutionReport,
    offline_drill_operation_id,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_main_graduation_offline_drill_contracts import (
    _authority,
    _execution_report,
    _expected,
    _plan,
)

# The journal tests intentionally use compact fixture helpers and protocol
# doubles; their runtime checks are stricter than static fixture typing.
# pyright: reportPrivateUsage=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportArgumentType=false, reportUnusedImport=false, reportUnusedVariable=false, reportIncompatibleMethodOverride=false


class _Verifier:
    def __init__(self, answer: object = True) -> None:
        self.answer = answer
        self.calls: list[str] = []

    def verify_execution_authority(
        self, _authority: MainGraduationOfflineExecutionAuthority, _ref: object
    ) -> object:
        self.calls.append("authority")
        return self.answer

    def verify_execution_report(
        self,
        _authority: MainGraduationOfflineExecutionAuthority,
        _report: MainGraduationOfflineExecutionReport,
        _ref: object,
        _evidence: object,
    ) -> object:
        self.calls.append("report")
        return self.answer

    def verify_plan(
        self,
        _plan: MainGraduationOfflineDrillPlan,
        _authority: MainGraduationOfflineExecutionAuthority,
        _ref: object,
    ) -> object:
        self.calls.append("plan")
        return self.answer

    def verify_case_result(
        self,
        _case: MainGraduationOfflineDrillCaseResult,
        _plan: MainGraduationOfflineDrillPlan,
        _authority: MainGraduationOfflineExecutionAuthority,
        _report: MainGraduationOfflineExecutionReport,
        _evidence: object,
    ) -> object:
        self.calls.append("case")
        return self.answer

    def verify_result(
        self,
        _result: MainGraduationOfflineDrillResult,
        _plan: MainGraduationOfflineDrillPlan,
        _authority: MainGraduationOfflineExecutionAuthority,
        _report: MainGraduationOfflineExecutionReport,
        _cases: object,
    ) -> object:
        self.calls.append("result")
        return self.answer


class _NoneVerifier(_Verifier):
    def verify_execution_authority(
        self, _authority: MainGraduationOfflineExecutionAuthority, _ref: object
    ) -> None:
        return None


class _WrongSignatureVerifier(_Verifier):
    def verify_execution_authority(
        self, _authority: MainGraduationOfflineExecutionAuthority, _ref: object, _extra: object
    ) -> object:
        return True


def _authority_and_report(
    store: FilesystemArtifactStore,
) -> tuple[
    MainGraduationOfflineExecutionAuthority,
    ArtifactRef,
    MainGraduationOfflineExecutionReport,
    ArtifactRef,
]:
    authority = _authority()
    auth_role, auth_media = OFFLINE_EVIDENCE_ROLE_MEDIA[
        MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY
    ]
    auth_ref = store.put_bytes(
        canonical_bytes(authority), role=auth_role, media_type=auth_media, max_bytes=8 * 1024 * 1024
    )
    report = _execution_report(authority)
    obs = tuple(
        observation.model_copy(
            update={
                "evidence_refs": (
                    MainGraduationOfflineEvidenceRef(
                        kind=MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY,
                        artifact=auth_ref,
                    ),
                )
            }
        )
        for observation in report.observations
    )
    values = report.model_dump(mode="json")
    values["observations"] = [item.model_dump(mode="json") for item in obs]
    values["report_digest"] = canonical_digest(
        {
            "domain": "avo-004.7-c7/offline-execution-report/v1",
            "value": {key: value for key, value in values.items() if key != "report_digest"},
        }
    )
    report = MainGraduationOfflineExecutionReport.model_validate(values)
    report_role, report_media = OFFLINE_EVIDENCE_ROLE_MEDIA[
        MainGraduationOfflineEvidenceKind.EXECUTION_REPORT
    ]
    report_ref = store.put_bytes(
        canonical_bytes(report),
        role=report_role,
        media_type=report_media,
        max_bytes=8 * 1024 * 1024,
    )
    return authority, auth_ref, report, report_ref


def _bound_plan(
    plan: MainGraduationOfflineDrillPlan, authority_ref: ArtifactRef, authority_digest: str
) -> MainGraduationOfflineDrillPlan:
    values = plan.model_dump(mode="json")
    values["execution_authority_ref"] = authority_ref.digest  # type: ignore[attr-defined]
    values["execution_authority_digest"] = authority_digest
    values["plan_digest"] = canonical_digest(
        {
            "domain": "avo-004.7-c7/offline-drill-plan/v1",
            "value": {key: value for key, value in values.items() if key != "plan_digest"},
        }
    )
    return MainGraduationOfflineDrillPlan.model_validate(values)


def _bound_case(
    plan: MainGraduationOfflineDrillPlan,
    authority_ref: ArtifactRef,
    report_ref: ArtifactRef,
    case_id: str,
    vector_id: str,
    index: int,
) -> MainGraduationOfflineDrillCaseResult:
    expected_outcome, expected_state = _expected(case_id, vector_id)
    values = {
        "root_operation_id": plan.operation_id,
        "plan_digest": plan.plan_digest,
        "case_id": case_id,
        "vector_id": vector_id,
        "operation_id": offline_drill_operation_id(plan.operation_id, case_id, vector_id),
        "expected_outcome": expected_outcome,
        "observed_outcome": expected_outcome,
        "expected_state": expected_state,
        "observed_state": expected_state,
        "main_before_commit": "b" * 40,
        "main_before_tree": "c" * 40,
        "main_before_parents": ("d" * 40,),
        "main_after_commit": "b" * 40,
        "main_after_tree": "c" * 40,
        "main_after_parents": ("d" * 40,),
        "provider_mutation_count": 0,
        "reconciliation_mutation_count": 0,
        "release_mutation_count": 0,
        "crash_facts": MainGraduationOfflineDrillCrashFacts(
            crash_injected=False, crash_boundary="none", restart_count=0
        ),
        "replay_facts": MainGraduationOfflineDrillReplayFacts(
            replayed=case_id == "replay-idempotence",
            byte_identical=case_id == "replay-idempotence",
            read_only=case_id == "replay-idempotence",
            mutation_delta=0,
        ),
        "injected_fault_digest": "sha256:" + "a" * 64,
        "reason_code": "expected-rejection",
        "execution_authority_digest": authority_ref.digest,  # type: ignore[attr-defined]
        "execution_report_digest": report_ref.digest,  # type: ignore[attr-defined]
        "native_evidence_refs": [
            MainGraduationOfflineEvidenceRef(
                kind=MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY, artifact=authority_ref
            ).model_dump(mode="json"),  # type: ignore[arg-type]
            MainGraduationOfflineEvidenceRef(
                kind=MainGraduationOfflineEvidenceKind.EXECUTION_REPORT, artifact=report_ref
            ).model_dump(mode="json"),  # type: ignore[arg-type]
        ],
        "deploy_performed": False,
    }
    stub = MainGraduationOfflineDrillCaseResult.model_construct(
        **values, result_digest="sha256:" + "a" * 64
    )
    values["result_digest"] = canonical_digest(
        {
            "domain": "avo-004.7-c7/offline-drill-case-result/v1",
            "value": stub.model_dump(exclude={"result_digest"}, mode="json"),
        }
    )
    return MainGraduationOfflineDrillCaseResult.model_validate(values)


def _bound_result(
    plan: MainGraduationOfflineDrillPlan,
    cases: tuple[MainGraduationOfflineDrillCaseResult, ...],
    authority: MainGraduationOfflineExecutionAuthority,
    report: MainGraduationOfflineExecutionReport,
) -> MainGraduationOfflineDrillResult:
    values = {
        "operation_id": plan.operation_id,
        "plan_digest": plan.plan_digest,
        "repository_digest": plan.repository_digest,
        "main_before_commit": plan.main_before_commit,
        "main_before_tree": plan.main_before_tree,
        "main_before_parents": plan.main_before_parents,
        "main_after_commit": plan.main_before_commit,
        "main_after_tree": plan.main_before_tree,
        "main_after_parents": plan.main_before_parents,
        "cases": cases,
        "execution_authority_digest": cases[0].execution_authority_digest,
        "execution_report_digest": cases[0].execution_report_digest,
    }
    stub = MainGraduationOfflineDrillResult.model_construct(
        **values, result_digest="sha256:" + "0" * 64
    )
    values["result_digest"] = canonical_digest(
        {
            "domain": "avo-004.7-c7/offline-drill-aggregate-result/v1",
            "value": stub.model_dump(exclude={"result_digest"}, mode="json"),
        }
    )
    return MainGraduationOfflineDrillResult.model_validate(values)


def _setup(
    tmp_path: Path, verifier: object | None = None
) -> tuple[
    MainGraduationOfflineDrillJournal,
    MainGraduationOfflineDrillPlan,
    MainGraduationOfflineExecutionAuthority,
    ArtifactRef,
    MainGraduationOfflineExecutionReport,
    ArtifactRef,
    FilesystemArtifactStore,
]:
    store = FilesystemArtifactStore(tmp_path / "artifacts")
    authority, authority_ref, report, report_ref = _authority_and_report(store)
    selected = verifier or _Verifier()
    journal = MainGraduationOfflineDrillJournal(tmp_path, selected, artifact_store=store)  # type: ignore[arg-type]
    authority_ref = journal.record_execution_authority(authority)
    report_ref = journal.record_execution_report(report)
    plan = _bound_plan(_plan(), authority_ref, authority.authority_digest)
    return journal, plan, authority, authority_ref, report, report_ref, store


def _all_cases(
    journal: MainGraduationOfflineDrillJournal,
    plan: MainGraduationOfflineDrillPlan,
    authority_ref: ArtifactRef,
    report_ref: ArtifactRef,
) -> tuple[MainGraduationOfflineDrillCaseResult, ...]:
    cases = []
    index = 1
    for spec in plan.cases:
        for vector in spec.vectors:
            case = _bound_case(
                plan, authority_ref, report_ref, spec.case_id, vector.vector_id, index
            )
            journal.record_case_result(case)
            cases.append(case)
            index += 1
    return tuple(cases)


def test_authority_report_plan_and_full_result_reload_exactly(tmp_path: Path) -> None:
    verifier = _Verifier()
    journal, plan, authority, authority_ref, report, report_ref, _store = _setup(tmp_path, verifier)
    plan_ref = journal.record_plan(plan)
    cases = _all_cases(journal, plan, authority_ref, report_ref)
    result = _bound_result(plan, cases, authority, report)
    result_ref = journal.record_result(result)
    restarted = MainGraduationOfflineDrillJournal(
        tmp_path, _Verifier(), artifact_store=FilesystemArtifactStore(tmp_path / "artifacts")
    )
    assert restarted.read_execution_authority(
        authority.operation_id, authority.authority_digest
    ) == (authority, authority_ref)
    assert restarted.read_execution_report(
        report.operation_id, report.authority_digest, report.report_digest
    ) == (report, report_ref)
    assert restarted.read_plan(plan.operation_id, authority.authority_digest) == (plan, plan_ref)
    first_case = cases[0]
    assert restarted.read_case_result(
        plan.operation_id, first_case.case_id, first_case.vector_id
    ) == restarted.read_case_result(
        plan.operation_id,
        first_case.case_id,
        first_case.vector_id,
        authority.authority_digest,
        report.report_digest,
    )
    assert restarted.read_result(plan.operation_id) == (result, result_ref)
    assert restarted.read_result(
        plan.operation_id, authority.authority_digest, report.report_digest
    ) == (result, result_ref)


def test_authority_and_report_are_required_before_plan_or_report(tmp_path: Path) -> None:
    store = FilesystemArtifactStore(tmp_path / "artifacts")
    authority = _authority()
    journal = MainGraduationOfflineDrillJournal(tmp_path, _Verifier(), artifact_store=store)
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.record_plan(_plan())
    report = _execution_report(authority)
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.record_execution_report(report)


def test_result_before_cases_and_case_omission_fail_closed(tmp_path: Path) -> None:
    journal, plan, authority, authority_ref, report, report_ref, _store = _setup(tmp_path)
    journal.record_plan(plan)
    cases = tuple(
        _bound_case(plan, authority_ref, report_ref, spec.case_id, vector.vector_id, i)
        for i, (spec, vector) in enumerate(
            (item for spec in plan.cases for item in [(spec, vector) for vector in spec.vectors]), 1
        )
    )
    result = _bound_result(plan, cases, authority, report)
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.record_result(result)
    journal.record_case_result(cases[0])
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.record_result(result)


def test_native_generic_wrong_kind_role_media_and_missing_fail(tmp_path: Path) -> None:
    journal, plan, authority, authority_ref, _report, report_ref, store = _setup(tmp_path)
    journal.record_plan(plan)
    case_id, vector_id = plan.cases[0].case_id, plan.cases[0].vectors[0].vector_id
    base = _bound_case(plan, authority_ref, report_ref, case_id, vector_id, 1)
    generic = store.put_bytes(
        canonical_bytes({"schema_version": 1, "c7_binding": {"operation_id": plan.operation_id}}),
        role="c7-controller-verifier",
        media_type="application/vnd.avo.c7.controller-verifier+json",
        max_bytes=1024,
    )
    values = base.model_dump(mode="json")
    values["native_evidence_refs"] = [
        MainGraduationOfflineEvidenceRef(
            kind=MainGraduationOfflineEvidenceKind.CONTROLLER_VERIFIER, artifact=generic
        ).model_dump(mode="json"),
        *values["native_evidence_refs"],
    ]
    values["result_digest"] = canonical_digest(
        {
            "domain": "avo-004.7-c7/offline-drill-case-result/v1",
            "value": {key: value for key, value in values.items() if key != "result_digest"},
        }
    )
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.record_case_result(MainGraduationOfflineDrillCaseResult.model_validate(values))
    store.delete(authority_ref.digest)
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.read_execution_authority(authority.operation_id, authority.authority_digest)


def test_native_c4_recovery_is_typed_and_case_operation_bound(tmp_path: Path) -> None:
    journal, plan, authority, authority_ref, report, report_ref, _store = _setup(tmp_path)
    case_id, vector_id = plan.cases[0].case_id, plan.cases[0].vectors[0].vector_id
    case = _bound_case(plan, authority_ref, report_ref, case_id, vector_id, 1)
    recovery = MainReconciliation(
        operation_id=case.operation_id,
        repository_digest=authority.repository_digest,
        target_ref=authority.target_ref,
        state="reconciliation_required",
        main_commit=case.main_after_commit,
        main_tree=case.main_after_tree,
        main_parents=list(case.main_after_parents),
        expected_tree=case.main_after_tree,
        expected_base_commit=case.main_after_parents[0],
        queue_generation_digest="sha256:" + "b" * 64,
    )
    parsed = journal._parse_native(  # type: ignore[reportPrivateUsage]
        MainGraduationOfflineEvidenceKind.C4_RECOVERY,
        json.loads(canonical_bytes(recovery)),
        authority,
        report,
        case=case,
    )
    assert parsed == recovery
    with pytest.raises(ValueError):
        journal._parse_native(  # type: ignore[reportPrivateUsage]
            MainGraduationOfflineEvidenceKind.C4_RECOVERY,
            {
                **json.loads(canonical_bytes(recovery)),
                "operation_id": authority.operation_id,
            },
            authority,
            report,
            case=case,
        )


@pytest.mark.parametrize(
    "verifier", [None, _NoneVerifier(), _Verifier(False), _WrongSignatureVerifier()]
)
def test_verifier_failures_on_authority_write(verifier: object | None, tmp_path: Path) -> None:
    store = FilesystemArtifactStore(tmp_path / "artifacts")
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        MainGraduationOfflineDrillJournal(
            tmp_path, verifier, artifact_store=store
        ).record_execution_authority(_authority())  # type: ignore[arg-type]


def test_create_once_conflict_and_index_cas_tamper(tmp_path: Path) -> None:
    journal, plan, authority, authority_ref, _report, _report_ref, store = _setup(tmp_path)
    ref = journal.record_plan(plan)
    calls = 0
    original_put = journal.artifact_store.put_bytes

    def counted_put(*args: Any, **kwargs: Any) -> ArtifactRef:
        nonlocal calls
        calls += 1
        return original_put(*args, **kwargs)

    journal.artifact_store.put_bytes = counted_put  # type: ignore[method-assign]
    assert journal.record_plan(plan) == ref
    assert calls == 0
    altered = _bound_plan(
        plan.model_copy(update={"configuration_digest": "sha256:" + "f" * 64}),
        authority_ref,
        authority.authority_digest,
    )
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.record_plan(altered)
    index = journal._plan_index(plan.operation_id, authority.authority_digest)  # type: ignore[reportPrivateUsage]
    index.write_bytes(canonical_bytes({**json.loads(index.read_text()), "role": "tampered"}))
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        MainGraduationOfflineDrillJournal(tmp_path, _Verifier(), artifact_store=store).read_plan(
            plan.operation_id, authority.authority_digest
        )
    index.write_bytes(canonical_bytes(json.loads(canonical_bytes(ref).decode())))
    store.path_for_digest(ref.digest).write_bytes(b"tampered")
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        MainGraduationOfflineDrillJournal(tmp_path, _Verifier(), artifact_store=store).read_plan(
            plan.operation_id, authority.authority_digest
        )
