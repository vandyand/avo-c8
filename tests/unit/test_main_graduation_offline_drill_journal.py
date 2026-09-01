"""Durability and authority-boundary tests for the C7 journal."""

from __future__ import annotations

import json
from datetime import UTC, datetime
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
from avo_correlate.contracts.main_graduation_ledger import MainLedgerAccumulatorState
from avo_correlate.contracts.main_graduation_offline_drill import (
    FROZEN_OFFLINE_DRILL_CASE_IDS,
    FROZEN_OFFLINE_DRILL_VECTOR_IDS,
    FROZEN_OFFLINE_EXECUTION_NODE_IDS,
    FROZEN_OFFLINE_NODE_ID_BY_VECTOR,
    OFFLINE_EVIDENCE_ROLE_MEDIA,
    MainGraduationOfflineDrillCaseResult,
    MainGraduationOfflineDrillCaseSpec,
    MainGraduationOfflineDrillPlan,
    MainGraduationOfflineDrillResult,
    MainGraduationOfflineDrillVectorSpec,
    MainGraduationOfflineEvidenceKind,
    MainGraduationOfflineEvidenceRef,
    MainGraduationOfflineExecutionAuthority,
    MainGraduationOfflineExecutionNodeSpec,
    MainGraduationOfflineExecutionReport,
    MainGraduationOfflineNodeObservation,
    MainGraduationOfflineWorkspaceIdentity,
    offline_drill_case_id,
    offline_drill_operation_id,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

D = "sha256:" + "a" * 64
BASE = "b" * 40
TREE = "c" * 40
PARENT = "d" * 40
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _digest(domain: str, value: object) -> str:
    return canonical_digest({"domain": domain, "value": value})


def _expected(case_id: str, vector_id: str) -> tuple[str, str]:
    if case_id == "replay-idempotence":
        return "replayed", "replayed_read_only"
    if (case_id, vector_id) in {
        ("crash-boundary-matrix", "after-hold-success"),
        ("admission-group-identity", "admission-success"),
    }:
        return "passed", "completed"
    return "reconciliation_required", "failed_closed"

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


def _authority() -> MainGraduationOfflineExecutionAuthority:
    nodes = tuple(
        MainGraduationOfflineExecutionNodeSpec(
            node_id=FROZEN_OFFLINE_NODE_ID_BY_VECTOR[(case_id, vector_id)],
            parameter_id=vector_id,
            case_id=case_id,
            vector_id=vector_id,
            oracle_expected_outcome=_expected(case_id, vector_id)[0],
            oracle_expected_state=_expected(case_id, vector_id)[1],
        )
        for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS
        for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]
    )
    values = {
        "operation_id": D,
        "controller_authority_digest": D,
        "controller_authority_ref": "refs/avo/c7-controller",
        "issuer_identity": "c7-harness",
        "repository_digest": D,
        "target_ref": "refs/heads/main",
        "source_commit": BASE,
        "source_tree": TREE,
        "source_tree_digest": D,
        "protocol_digest": D,
        "configuration_digest": D,
        "policy_digest": D,
        "activation_digest": D,
        "lockfile_digest": D,
        "interpreter_digest": D,
        "pytest_digest": D,
        "plugin_set_digest": D,
        "toolchain_digest": D,
        "environment_identity_digest": D,
        "uv_digest": D,
        "argv": (
            "pytest",
            "-q",
            "tests/unit/test_main_graduation_offline_drill_journal.py",
        ),
        "normalized_report_schema_digest": D,
        "authorized_at": NOW,
        "expires_at": datetime(2026, 1, 2, tzinfo=UTC),
        "nodes": nodes,
    }
    stub = MainGraduationOfflineExecutionAuthority.model_construct(**values, authority_digest=D)
    values["authority_digest"] = _digest(
        "avo-004.7-c7/offline-execution-authority/v1",
        stub.model_dump(exclude={"authority_digest"}, mode="json"),
    )
    return MainGraduationOfflineExecutionAuthority.model_validate(values)


def _workspace(
    authority: MainGraduationOfflineExecutionAuthority,
) -> MainGraduationOfflineWorkspaceIdentity:
    return MainGraduationOfflineWorkspaceIdentity(
        source_commit=authority.source_commit,
        source_tree=authority.source_tree,
        source_tree_digest=authority.source_tree_digest,
        lockfile_digest=authority.lockfile_digest,
        interpreter_digest=authority.interpreter_digest,
        pytest_digest=authority.pytest_digest,
        plugin_set_digest=authority.plugin_set_digest,
        toolchain_digest=authority.toolchain_digest,
        environment_identity_digest=authority.environment_identity_digest,
        uv_digest=authority.uv_digest,
    )


def _junit_xml(authority: MainGraduationOfflineExecutionAuthority) -> bytes:
    cases = []
    for node in authority.nodes:
        path, _, name = node.node_id.partition("::")
        classname = f"tests.unit.{path[:-3].replace('/', '.')}"
        cases.append(f'<testcase classname="{classname}" name="{name}" status="passed"/>')
    return ("<testsuite>" + "".join(cases) + "</testsuite>").encode()


def _execution_report(
    authority: MainGraduationOfflineExecutionAuthority,
    auth_ref: ArtifactRef | None = None,
    store: FilesystemArtifactStore | None = None,
) -> MainGraduationOfflineExecutionReport:
    if auth_ref is None:
        auth_role, auth_media = OFFLINE_EVIDENCE_ROLE_MEDIA[
            MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY
        ]
        auth_ref = ArtifactRef(
            digest=authority.authority_digest,
            size_bytes=1,
            media_type=auth_media,
            role=auth_role,
            created_at=NOW,
        )
    refs = (
        MainGraduationOfflineEvidenceRef(
            kind=MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY, artifact=auth_ref
        ),
    )
    observations = tuple(
        MainGraduationOfflineNodeObservation(
            node_id=node.node_id,
            parameter_id=node.parameter_id,
            case_id=node.case_id,
            vector_id=node.vector_id,
            verification_status="pass",
            reason_code="oracle-verified",
            evidence_refs=refs,
        )
        for node in authority.nodes
    )
    if store is None:
        junit_ref = ArtifactRef(
            digest=D,
            size_bytes=1,
            media_type="application/vnd.avo.c7.junit+xml",
            role="c7-junit-xml",
            created_at=NOW,
        )
    else:
        junit_ref = store.put_bytes(
            _junit_xml(authority),
            role="c7-junit-xml",
            media_type="application/vnd.avo.c7.junit+xml",
            max_bytes=8 * 1024 * 1024,
        )
    values = {
        "operation_id": authority.operation_id,
        "authority_digest": authority.authority_digest,
        "repository_digest": authority.repository_digest,
        "target_ref": authority.target_ref,
        "source_commit": authority.source_commit,
        "source_tree": authority.source_tree,
        "source_tree_digest": authority.source_tree_digest,
        "protocol_digest": authority.protocol_digest,
        "configuration_digest": authority.configuration_digest,
        "policy_digest": authority.policy_digest,
        "activation_digest": authority.activation_digest,
        "lockfile_digest": authority.lockfile_digest,
        "interpreter_digest": authority.interpreter_digest,
        "pytest_digest": authority.pytest_digest,
        "plugin_set_digest": authority.plugin_set_digest,
        "toolchain_digest": authority.toolchain_digest,
        "environment_identity_digest": authority.environment_identity_digest,
        "uv_digest": authority.uv_digest,
        "argv": authority.argv,
        "collection_count": len(observations),
        "collected_node_ids": FROZEN_OFFLINE_EXECUTION_NODE_IDS,
        "observations": observations,
        "workspace_before_identity": _workspace(authority),
        "workspace_after_identity": _workspace(authority),
        "junit_xml_artifact": junit_ref,
        "executed_at": datetime(2026, 1, 1, 12, tzinfo=UTC),
        "authority_expires_at": authority.expires_at,
    }
    stub = MainGraduationOfflineExecutionReport.model_construct(**values, report_digest=D)
    values["report_digest"] = _digest(
        "avo-004.7-c7/offline-execution-report/v1",
        stub.model_dump(exclude={"report_digest"}, mode="json"),
    )
    return MainGraduationOfflineExecutionReport.model_validate(values)


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
        canonical_bytes(authority),
        role=auth_role,
        media_type=auth_media,
        max_bytes=8 * 1024 * 1024,
    )
    report = _execution_report(authority, auth_ref, store)
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


def _plan() -> MainGraduationOfflineDrillPlan:
    cases = []
    for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS:
        vectors = []
        for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]:
            values = {
                "vector_id": vector_id,
                "oracle_expected_outcome": _expected(case_id, vector_id)[0],
                "oracle_expected_state": _expected(case_id, vector_id)[1],
                "fault_digest": D,
            }
            vector_stub = MainGraduationOfflineDrillVectorSpec.model_construct(
                **values, vector_digest=D
            )
            values["vector_digest"] = _digest(
                "avo-004.7-c7/offline-drill-vector/v1",
                vector_stub.model_dump(exclude={"vector_digest"}, mode="json"),
            )
            vectors.append(MainGraduationOfflineDrillVectorSpec.model_validate(values))
        case_values = {
            "case_id": case_id,
            "vectors": tuple(vectors),
            "plan_operation_id": D,
            "case_digest": D,
        }
        case_values["case_digest"] = offline_drill_case_id(
            D, case_id, [item.model_dump(mode="json") for item in vectors]
        )
        cases.append(MainGraduationOfflineDrillCaseSpec.model_validate(case_values))
    values = {
        "operation_id": D,
        "repository_digest": D,
        "target_ref": "refs/heads/main",
        "protocol_digest": D,
        "configuration_digest": D,
        "policy_digest": D,
        "policy_epoch_digest": D,
        "activation_digest": D,
        "controller_authority_digest": D,
        "controller_authority_ref": "refs/avo/c7-controller",
        "cases": tuple(cases),
        "execution_authority_digest": D,
        "execution_authority_ref": "refs/avo/test-execution-authority",
    }
    stub = MainGraduationOfflineDrillPlan.model_construct(**values, plan_digest=D)
    values["plan_digest"] = _digest(
        "avo-004.7-c7/offline-drill-plan/v1",
        stub.model_dump(exclude={"plan_digest"}, mode="json"),
    )
    return MainGraduationOfflineDrillPlan.model_validate(values)


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
    junit_xml_digest: str,
) -> MainGraduationOfflineDrillCaseResult:
    expected_outcome, expected_state = _expected(case_id, vector_id)
    values = {
        "root_operation_id": plan.operation_id,
        "plan_digest": plan.plan_digest,
        "case_id": case_id,
        "vector_id": vector_id,
        "operation_id": offline_drill_operation_id(plan.operation_id, case_id, vector_id),
        "oracle_expected_outcome": expected_outcome,
        "oracle_expected_state": expected_state,
        "verification_status": "pass",
        "fault_digest": D,
        "reason_code": "oracle-verified",
        "execution_authority_digest": authority_ref.digest,  # type: ignore[attr-defined]
        "execution_report_digest": report_ref.digest,  # type: ignore[attr-defined]
        "junit_xml_digest": junit_xml_digest,
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
        "target_ref": plan.target_ref,
        "workspace_before_identity": report.workspace_before_identity,
        "workspace_after_identity": report.workspace_after_identity,
        "cases": cases,
        "execution_authority_digest": cases[0].execution_authority_digest,
        "execution_report_digest": cases[0].execution_report_digest,
        "junit_xml_digest": report.junit_xml_artifact.digest,
        "proof_class": "deterministic-offline-proof",
        "deploy_performed": False,
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
    junit_xml_digest: str,
) -> tuple[MainGraduationOfflineDrillCaseResult, ...]:
    cases = []
    index = 1
    for spec in plan.cases:
        for vector in spec.vectors:
            case = _bound_case(
                plan,
                authority_ref,
                report_ref,
                spec.case_id,
                vector.vector_id,
                index,
                junit_xml_digest,
            )
            journal.record_case_result(case)
            cases.append(case)
            index += 1
    return tuple(cases)


def test_authority_report_plan_and_full_result_reload_exactly(tmp_path: Path) -> None:
    verifier = _Verifier()
    journal, plan, authority, authority_ref, report, report_ref, _store = _setup(tmp_path, verifier)
    plan_ref = journal.record_plan(plan)
    cases = _all_cases(
        journal, plan, authority_ref, report_ref, report.junit_xml_artifact.digest
    )
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


def test_report_rereads_raw_junit_and_rejects_tamper(tmp_path: Path) -> None:
    journal, _plan_value, authority, _authority_ref, report, _report_ref, store = _setup(tmp_path)
    assert journal.read_execution_report(
        authority.operation_id, authority.authority_digest, report.report_digest
    ) == (report, _report_ref)
    store.path_for_digest(report.junit_xml_artifact.digest).write_bytes(
        _junit_xml(authority).replace(b"status=\"passed\"", b"status=\"failed\"", 1)
    )
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.read_execution_report(
            authority.operation_id, authority.authority_digest, report.report_digest
        )


def test_authority_and_report_are_required_before_plan_or_report(tmp_path: Path) -> None:
    store = FilesystemArtifactStore(tmp_path / "artifacts")
    authority = _authority()
    journal = MainGraduationOfflineDrillJournal(tmp_path, _Verifier(), artifact_store=store)
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.record_plan(_plan())
    report = _execution_report(authority)
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.record_execution_report(report)


def test_workspace_identity_drift_is_rejected_at_journal_boundary(tmp_path: Path) -> None:
    store = FilesystemArtifactStore(tmp_path / "artifacts")
    authority = _authority()
    journal = MainGraduationOfflineDrillJournal(tmp_path, _Verifier(), artifact_store=store)
    authority_ref = journal.record_execution_authority(authority)
    report = _execution_report(authority, authority_ref, store)
    altered_identity = report.workspace_before_identity.model_copy(
        update={"environment_identity_digest": "sha256:" + "f" * 64}
    )
    values = report.model_dump(mode="json")
    values["environment_identity_digest"] = "sha256:" + "f" * 64
    values["workspace_before_identity"] = altered_identity.model_dump(mode="json")
    values["workspace_after_identity"] = altered_identity.model_dump(mode="json")
    values["report_digest"] = _digest(
        "avo-004.7-c7/offline-execution-report/v1",
        {key: value for key, value in values.items() if key != "report_digest"},
    )
    altered = MainGraduationOfflineExecutionReport.model_validate(values)
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.record_execution_report(altered)


def test_result_before_cases_and_case_omission_fail_closed(tmp_path: Path) -> None:
    journal, plan, authority, authority_ref, report, report_ref, _store = _setup(tmp_path)
    journal.record_plan(plan)
    cases = tuple(
        _bound_case(
            plan, authority_ref, report_ref, spec.case_id, vector.vector_id, i,
            report.junit_xml_artifact.digest,
        )
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
    base = _bound_case(
        plan, authority_ref, report_ref, case_id, vector_id, 1,
        _report.junit_xml_artifact.digest,
    )
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
    case = _bound_case(
        plan, authority_ref, report_ref, case_id, vector_id, 1,
        report.junit_xml_artifact.digest,
    )
    recovery = MainReconciliation(
        operation_id=case.operation_id,
        repository_digest=authority.repository_digest,
        target_ref=authority.target_ref,
        state="reconciliation_required",
        main_commit=authority.source_commit,
        main_tree=authority.source_tree,
        main_parents=[PARENT],
        expected_tree=authority.source_tree,
        expected_base_commit=PARENT,
        queue_generation_digest=D,
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


def test_native_c6_threshold_is_bound_to_exact_activation(tmp_path: Path) -> None:
    _journal, _plan, authority, _authority_ref, report, _report_ref, _store = _setup(tmp_path)
    values = {
        "schema_version": 2,
        "activation_digest": "sha256:" + "f" * 64,
        "last_scheduler_sequence": 0,
        "streak": 0,
        "successes": 0,
        "failures": 0,
        "boundary_violations": 0,
        "threshold_complete": False,
    }
    state = MainLedgerAccumulatorState.model_validate(
        {**values, "state_digest": canonical_digest(values)}
    )
    with pytest.raises(ValueError, match="activation differs"):
        MainGraduationOfflineDrillJournal._bind_native_identity(  # type: ignore[reportPrivateUsage]
            MainGraduationOfflineEvidenceKind.C6_THRESHOLD,
            state,
            authority,
            report,
            None,
            None,
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
