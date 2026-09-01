"""Immutable, controller-verified persistence for the C7 offline drill."""

# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false

from __future__ import annotations

import errno
import inspect
import json
import os
from pathlib import Path
from typing import Any, Protocol

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation_offline_drill import (
    OFFLINE_EVIDENCE_ROLE_MEDIA,
    MainGraduationOfflineDrillCaseResult,
    MainGraduationOfflineDrillPlan,
    MainGraduationOfflineDrillResult,
    MainGraduationOfflineEvidenceKind,
    MainGraduationOfflineEvidenceRef,
    MainGraduationOfflineExecutionAuthority,
    MainGraduationOfflineExecutionReport,
    offline_drill_operation_id,
)
from avo_correlate.domain.canonical import canonical_bytes


class MainGraduationOfflineDrillJournalError(RuntimeError):
    """A C7 record is missing, malformed, unverifiable, or conflicting."""


class MainGraduationOfflineDrillRecordConflictError(MainGraduationOfflineDrillJournalError):
    """A create-once identity is already bound to different canonical bytes."""


class MainGraduationOfflineDrillAuthorityVerifier(Protocol):
    """Controller-owned checks. Every method must return literal ``True``."""

    def verify_execution_authority(
        self, authority: MainGraduationOfflineExecutionAuthority, ref: ArtifactRef
    ) -> object: ...

    def verify_execution_report(
        self,
        authority: MainGraduationOfflineExecutionAuthority,
        report: MainGraduationOfflineExecutionReport,
        ref: ArtifactRef,
        reloaded_native_evidence: tuple[MainGraduationOfflineEvidenceRef, ...],
    ) -> object: ...

    def verify_plan(
        self,
        plan: MainGraduationOfflineDrillPlan,
        authority: MainGraduationOfflineExecutionAuthority,
        authority_ref: ArtifactRef,
    ) -> object: ...

    def verify_case_result(
        self,
        case_result: MainGraduationOfflineDrillCaseResult,
        plan: MainGraduationOfflineDrillPlan,
        authority: MainGraduationOfflineExecutionAuthority,
        report: MainGraduationOfflineExecutionReport,
        reloaded_native_evidence: tuple[MainGraduationOfflineEvidenceRef, ...],
    ) -> object: ...

    def verify_result(
        self,
        result: MainGraduationOfflineDrillResult,
        plan: MainGraduationOfflineDrillPlan,
        authority: MainGraduationOfflineExecutionAuthority,
        report: MainGraduationOfflineExecutionReport,
        cases: tuple[MainGraduationOfflineDrillCaseResult, ...],
    ) -> object: ...


MainGraduationOfflineDrillVerifier = MainGraduationOfflineDrillAuthorityVerifier
OfflineDrillAuthorityVerifier = MainGraduationOfflineDrillAuthorityVerifier

_MAX_INDEX_BYTES = 1024 * 1024
_MAX_RECORD_BYTES = 8 * 1024 * 1024
_KIND_ROLE_MEDIA = {
    kind: OFFLINE_EVIDENCE_ROLE_MEDIA[kind] for kind in MainGraduationOfflineEvidenceKind
}
_JOURNAL_ROLE = {
    "authority": "c7-execution-authority-record",
    "report": "c7-execution-report-record",
    "plan": "c7-offline-drill-plan-record",
    "case": "c7-offline-drill-case-record",
    "result": "c7-offline-drill-result-record",
}
_JOURNAL_MEDIA = {key: f"application/vnd.avo.c7.{key}-record+json" for key in _JOURNAL_ROLE}
_MODELS = {
    "authority": MainGraduationOfflineExecutionAuthority,
    "report": MainGraduationOfflineExecutionReport,
    "plan": MainGraduationOfflineDrillPlan,
    "case": MainGraduationOfflineDrillCaseResult,
    "result": MainGraduationOfflineDrillResult,
}


class MainGraduationOfflineDrillJournal:
    """Create-once filesystem journal for one exact C7 execution run."""

    def __init__(
        self,
        root: Path,
        authority_verifier: MainGraduationOfflineDrillAuthorityVerifier | None = None,
        *,
        verifier: MainGraduationOfflineDrillAuthorityVerifier | None = None,
        artifact_store: FilesystemArtifactStore | None = None,
        max_record_bytes: int = _MAX_RECORD_BYTES,
    ) -> None:
        if max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        if authority_verifier is not None and verifier is not None:
            raise ValueError("supply only one C7 verifier")
        self._root = root.resolve()
        self._indexes = self._root / "main-graduation-offline-drill-v1"
        self._store = artifact_store or FilesystemArtifactStore(self._root / "artifacts")
        self._verifier = authority_verifier if authority_verifier is not None else verifier
        self._max = max_record_bytes
        # These cache only a discovered index identity.  Every use still
        # reloads and validates the index and its content-addressed record.
        self._authority_digests: dict[str, str] = {}
        self._report_digests: dict[tuple[str, str], str] = {}

    @property
    def root(self) -> Path:
        return self._root

    @property
    def artifact_store(self) -> FilesystemArtifactStore:
        return self._store

    def delete_artifact(self, digest: str) -> bool:
        return self._store.delete(digest)

    def record_execution_authority(
        self, authority: MainGraduationOfflineExecutionAuthority
    ) -> ArtifactRef:
        checked = self._parse(MainGraduationOfflineExecutionAuthority, authority, "authority")
        data = canonical_bytes(checked)
        index = self._authority_index(checked.operation_id, checked.authority_digest)
        existing = self._replay_if_existing("authority", index, data)
        if existing is not None:
            self._verify("execution_authority", checked, existing)
            self._authority_digests[checked.operation_id] = checked.authority_digest
            return existing
        ref = self._put("authority", data, MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY)
        self._verify("execution_authority", checked, ref)
        recorded = self._create_once(index, ref, data, "authority")
        self._authority_digests[checked.operation_id] = checked.authority_digest
        return recorded

    record_execution_authority_once = record_execution_authority

    def read_execution_authority(
        self, operation_id: str, authority_digest: str | None = None
    ) -> tuple[MainGraduationOfflineExecutionAuthority, ArtifactRef] | None:
        if authority_digest is None:
            authority_digest = self._authority_digests.get(operation_id)
            if authority_digest is None:
                authority_digest = self._find_authority_digest(operation_id)
            if authority_digest is None:
                return None
        loaded = self._read_indexed(
            "authority",
            self._authority_index(operation_id, authority_digest),
            MainGraduationOfflineExecutionAuthority,
        )
        if loaded is None:
            return None
        authority, ref = loaded
        if authority.operation_id != operation_id or authority.authority_digest != authority_digest:
            raise MainGraduationOfflineDrillJournalError("authority identity mismatch")
        self._verify("execution_authority", authority, ref)
        self._authority_digests[operation_id] = authority_digest
        return authority, ref

    def record_execution_report(self, report: MainGraduationOfflineExecutionReport) -> ArtifactRef:
        checked = self._parse(MainGraduationOfflineExecutionReport, report, "report")
        authority_loaded = self.read_execution_authority(
            checked.operation_id, checked.authority_digest
        )
        if authority_loaded is None:
            raise MainGraduationOfflineDrillJournalError("report requires durable authority")
        authority, _ = authority_loaded
        self._bind_report_to_authority(checked, authority)
        evidence = self._read_report_evidence(checked, authority)
        data = canonical_bytes(checked)
        index = self._report_index(
            checked.operation_id, checked.authority_digest, checked.report_digest
        )
        existing = self._replay_if_existing("report", index, data)
        if existing is not None:
            self._verify("execution_report", authority, checked, existing, evidence)
            self._report_digests[(checked.operation_id, checked.authority_digest)] = (
                checked.report_digest
            )
            return existing
        ref = self._put("report", data, MainGraduationOfflineEvidenceKind.EXECUTION_REPORT)
        self._verify("execution_report", authority, checked, ref, evidence)
        recorded = self._create_once(index, ref, data, "report")
        self._report_digests[(checked.operation_id, checked.authority_digest)] = (
            checked.report_digest
        )
        return recorded

    record_execution_report_once = record_execution_report

    def read_execution_report(
        self,
        operation_id: str,
        authority_digest: str | None = None,
        report_digest: str | None = None,
    ) -> tuple[MainGraduationOfflineExecutionReport, ArtifactRef] | None:
        if authority_digest is None:
            authority_loaded = self.read_execution_authority(operation_id)
            if authority_loaded is None:
                return None
            authority_digest = authority_loaded[0].authority_digest
        if report_digest is None:
            report_digest = self._report_digests.get((operation_id, authority_digest))
            if report_digest is None:
                report_digest = self._find_report_digest(operation_id, authority_digest)
            if report_digest is None:
                return None
        loaded = self._read_indexed(
            "report",
            self._report_index(operation_id, authority_digest, report_digest),
            MainGraduationOfflineExecutionReport,
        )
        if loaded is None:
            return None
        report, ref = loaded
        authority_loaded = self.read_execution_authority(operation_id, authority_digest)
        if authority_loaded is None:
            raise MainGraduationOfflineDrillJournalError("report has no durable authority")
        authority = authority_loaded[0]
        self._bind_report_to_authority(report, authority)
        evidence = self._read_report_evidence(report, authority)
        self._verify("execution_report", authority, report, ref, evidence)
        self._report_digests[(operation_id, authority_digest)] = report_digest
        return report, ref

    def record_plan(self, plan: MainGraduationOfflineDrillPlan) -> ArtifactRef:
        checked = self._parse(MainGraduationOfflineDrillPlan, plan, "plan")
        authority_loaded = self.read_execution_authority(
            checked.operation_id, checked.execution_authority_digest
        )
        if authority_loaded is None:
            raise MainGraduationOfflineDrillJournalError("plan requires durable authority")
        authority, authority_ref = authority_loaded
        self._bind_plan_to_authority(checked, authority, authority_ref)
        data = canonical_bytes(checked)
        index = self._plan_index(checked.operation_id, checked.execution_authority_digest)
        existing = self._replay_if_existing("plan", index, data)
        self._verify("plan", checked, authority, authority_ref)
        if existing is not None:
            return existing
        return self._create_once(index, self._put("plan", data), data, "plan")

    record_plan_once = record_plan

    def record_case_result(self, case_result: MainGraduationOfflineDrillCaseResult) -> ArtifactRef:
        checked = self._parse(MainGraduationOfflineDrillCaseResult, case_result, "case")
        authority_loaded = self.read_execution_authority(checked.root_operation_id)
        if authority_loaded is None:
            raise MainGraduationOfflineDrillJournalError(
                "case requires durable plan, authority, and report"
            )
        authority, authority_ref = authority_loaded
        plan_loaded = self.read_plan(checked.root_operation_id, authority.authority_digest)
        report_loaded = self.read_execution_report(
            checked.root_operation_id, authority.authority_digest
        )
        if plan_loaded is None or report_loaded is None:
            raise MainGraduationOfflineDrillJournalError(
                "case requires durable plan, authority, and report"
            )
        plan, _ = plan_loaded
        report, report_ref = report_loaded
        if checked.execution_authority_digest != authority_ref.digest:
            raise MainGraduationOfflineDrillJournalError(
                "case authority ref is not durable authority"
            )
        if checked.execution_report_digest != report_ref.digest:
            raise MainGraduationOfflineDrillJournalError("case report ref is not durable report")
        self._bind_case_to_dependencies(checked, plan, authority, report, authority_ref, report_ref)
        evidence = self._read_case_evidence(checked, authority, report)
        data = canonical_bytes(checked)
        index = self._case_index(
            checked.root_operation_id,
            authority.authority_digest,
            report.report_digest,
            checked.case_id,
            checked.vector_id,
        )
        existing = self._replay_if_existing("case", index, data)
        self._verify("case", checked, plan, authority, report, evidence)
        if existing is not None:
            return existing
        return self._create_once(index, self._put("case", data), data, "case")

    record_case = record_case_result
    record_case_result_once = record_case_result

    def record_result(self, result: MainGraduationOfflineDrillResult) -> ArtifactRef:
        checked = self._parse(MainGraduationOfflineDrillResult, result, "result")
        authority_loaded = self.read_execution_authority(checked.operation_id)
        if authority_loaded is None:
            raise MainGraduationOfflineDrillJournalError(
                "result requires durable plan, authority, and report"
            )
        authority, authority_ref = authority_loaded
        plan_loaded = self.read_plan(checked.operation_id, authority.authority_digest)
        report_loaded = self.read_execution_report(
            checked.operation_id, authority.authority_digest
        )
        if plan_loaded is None or report_loaded is None:
            raise MainGraduationOfflineDrillJournalError(
                "result requires durable plan, authority, and report"
            )
        plan, _ = plan_loaded
        report, report_ref = report_loaded
        if checked.execution_authority_digest != authority_ref.digest:
            raise MainGraduationOfflineDrillJournalError(
                "result authority ref is not durable authority"
            )
        self._bind_result_to_dependencies(
            checked, plan, authority, report, authority_ref, report_ref
        )
        durable = self._load_complete_cases(plan, authority, authority_ref, report, report_ref)
        if tuple(item[0] for item in durable) != checked.cases:
            raise MainGraduationOfflineDrillJournalError(
                "result case closure differs from durable matrix"
            )
        data = canonical_bytes(checked)
        index = self._result_index(
            checked.operation_id,
            authority.authority_digest,
            report.report_digest,
        )
        existing = self._replay_if_existing("result", index, data)
        self._verify("result", checked, plan, authority, report, tuple(item[0] for item in durable))
        if existing is not None:
            return existing
        return self._create_once(index, self._put("result", data), data, "result")

    record_aggregate_result = record_result
    record_result_once = record_result

    def read_plan(
        self, operation_id: str, authority_digest: str | None = None
    ) -> tuple[MainGraduationOfflineDrillPlan, ArtifactRef] | None:
        if authority_digest is None:
            authority_loaded = self.read_execution_authority(operation_id)
            if authority_loaded is None:
                return None
            authority_digest = authority_loaded[0].authority_digest
        loaded = self._read_indexed(
            "plan", self._plan_index(operation_id, authority_digest), MainGraduationOfflineDrillPlan
        )
        if loaded is None:
            return None
        plan, ref = loaded
        authority_loaded = self.read_execution_authority(operation_id, authority_digest)
        if authority_loaded is None:
            raise MainGraduationOfflineDrillJournalError("plan has no authority")
        authority, authority_ref = authority_loaded
        self._bind_plan_to_authority(plan, authority, authority_ref)
        self._verify("plan", plan, authority, authority_ref)
        return plan, ref

    def read_case_result(
        self,
        root_operation_id: str,
        case_id: str,
        vector_id: str,
        authority_digest: str | None = None,
        report_digest: str | None = None,
    ) -> tuple[MainGraduationOfflineDrillCaseResult, ArtifactRef] | None:
        if authority_digest is None:
            authority_loaded = self.read_execution_authority(root_operation_id)
            if authority_loaded is None:
                return None
            authority_digest = authority_loaded[0].authority_digest
        if report_digest is None:
            report_loaded = self.read_execution_report(root_operation_id, authority_digest)
            if report_loaded is None:
                return None
            report_digest = report_loaded[0].report_digest
        plan_loaded = self.read_plan(root_operation_id, authority_digest)
        authority_loaded = self.read_execution_authority(root_operation_id, authority_digest)
        report_loaded = self.read_execution_report(root_operation_id, authority_digest)
        if plan_loaded is None or authority_loaded is None or report_loaded is None:
            raise MainGraduationOfflineDrillJournalError("case dependency closure is incomplete")
        plan, _ = plan_loaded
        authority, authority_ref = authority_loaded
        report, report_ref = report_loaded
        if report_digest != report.report_digest:
            raise MainGraduationOfflineDrillJournalError("case report identity mismatch")
        return self._read_case_with_dependencies(
            root_operation_id,
            case_id,
            vector_id,
            plan,
            authority,
            authority_ref,
            report,
            report_ref,
        )

    def _read_case_with_dependencies(
        self,
        root_operation_id: str,
        case_id: str,
        vector_id: str,
        plan: MainGraduationOfflineDrillPlan,
        authority: MainGraduationOfflineExecutionAuthority,
        authority_ref: ArtifactRef,
        report: MainGraduationOfflineExecutionReport,
        report_ref: ArtifactRef,
    ) -> tuple[MainGraduationOfflineDrillCaseResult, ArtifactRef] | None:
        loaded = self._read_indexed(
            "case",
            self._case_index(
                root_operation_id,
                authority.authority_digest,
                report.report_digest,
                case_id,
                vector_id,
            ),
            MainGraduationOfflineDrillCaseResult,
        )
        if loaded is None:
            return None
        case, ref = loaded
        if (case.root_operation_id, case.case_id, case.vector_id) != (
            root_operation_id,
            case_id,
            vector_id,
        ):
            raise MainGraduationOfflineDrillJournalError("case identity mismatch")
        self._bind_case_to_dependencies(case, plan, authority, report, authority_ref, report_ref)
        evidence = self._read_case_evidence(case, authority, report)
        self._verify("case", case, plan, authority, report, evidence)
        return case, ref

    read_case = read_case_result

    def read_result(
        self,
        operation_id: str,
        authority_digest: str | None = None,
        report_digest: str | None = None,
    ) -> tuple[MainGraduationOfflineDrillResult, ArtifactRef] | None:
        if authority_digest is None:
            authority_loaded = self.read_execution_authority(operation_id)
            if authority_loaded is None:
                return None
            authority_digest = authority_loaded[0].authority_digest
        if report_digest is None:
            report_loaded = self.read_execution_report(operation_id, authority_digest)
            if report_loaded is None:
                return None
            report_digest = report_loaded[0].report_digest
        loaded = self._read_indexed(
            "result",
            self._result_index(operation_id, authority_digest, report_digest),
            MainGraduationOfflineDrillResult,
        )
        if loaded is None:
            return None
        result, ref = loaded
        plan_loaded = self.read_plan(operation_id, authority_digest)
        authority_loaded = self.read_execution_authority(operation_id, authority_digest)
        report_loaded = self.read_execution_report(operation_id, authority_digest)
        if plan_loaded is None or authority_loaded is None or report_loaded is None:
            raise MainGraduationOfflineDrillJournalError("result dependency closure is incomplete")
        plan, _ = plan_loaded
        authority, authority_ref = authority_loaded
        report, report_ref = report_loaded
        self._bind_result_to_dependencies(
            result, plan, authority, report, authority_ref, report_ref
        )
        if report_digest != report.report_digest:
            raise MainGraduationOfflineDrillJournalError("result report identity mismatch")
        durable = self._load_complete_cases(plan, authority, authority_ref, report, report_ref)
        if tuple(item[0] for item in durable) != result.cases:
            raise MainGraduationOfflineDrillJournalError("result durable case closure mismatch")
        self._verify("result", result, plan, authority, report, tuple(item[0] for item in durable))
        return result, ref

    read_aggregate_result = read_result

    def _load_complete_cases(
        self,
        plan: MainGraduationOfflineDrillPlan,
        authority: MainGraduationOfflineExecutionAuthority,
        authority_ref: ArtifactRef,
        report: MainGraduationOfflineExecutionReport,
        report_ref: ArtifactRef,
    ) -> list[tuple[Any, ArtifactRef]]:
        result: list[tuple[Any, ArtifactRef]] = []
        for spec in plan.cases:
            for vector in spec.vectors:
                loaded = self._read_case_with_dependencies(
                    plan.operation_id,
                    spec.case_id,
                    vector.vector_id,
                    plan,
                    authority,
                    authority_ref,
                    report,
                    report_ref,
                )
                if loaded is None:
                    raise MainGraduationOfflineDrillJournalError(
                        f"missing durable case/vector {spec.case_id}/{vector.vector_id}"
                    )
                result.append(loaded)
        root = (
            self._indexes
            / "case"
            / _path_token(authority.authority_digest)
            / _path_token(report.report_digest)
        )
        expected = {
            f"{spec.case_id}/{vector.vector_id}" for spec in plan.cases for vector in spec.vectors
        }
        actual = (
            {f"{path.parent.name}/{path.stem}" for path in root.glob("*/*.json") if path.is_file()}
            if root.is_dir()
            else set()
        )
        if actual != expected:
            raise MainGraduationOfflineDrillJournalError("durable case index has extra entries")
        return result

    def _read_report_evidence(
        self,
        report: MainGraduationOfflineExecutionReport,
        authority: MainGraduationOfflineExecutionAuthority,
    ) -> tuple[MainGraduationOfflineEvidenceRef, ...]:
        refs = tuple(
            ref for observation in report.observations for ref in observation.evidence_refs
        )
        self._validate_native_refs(refs, authority=authority, report=report, unique=False)
        return refs

    def _read_case_evidence(
        self,
        case: MainGraduationOfflineDrillCaseResult,
        authority: MainGraduationOfflineExecutionAuthority,
        report: MainGraduationOfflineExecutionReport,
    ) -> tuple[MainGraduationOfflineEvidenceRef, ...]:
        refs = case.native_evidence_refs
        self._validate_native_refs(refs, authority=authority, report=report)
        return refs

    def _validate_native_refs(
        self,
        refs: tuple[Any, ...],
        *,
        authority: MainGraduationOfflineExecutionAuthority,
        report: MainGraduationOfflineExecutionReport,
        unique: bool = True,
    ) -> None:
        seen: set[str] = set()
        for typed in refs:
            if unique and typed.artifact.digest in seen:
                raise MainGraduationOfflineDrillJournalError("duplicate native evidence ref")
            seen.add(typed.artifact.digest)
            kind = next(
                (
                    candidate
                    for candidate, (role, media) in _KIND_ROLE_MEDIA.items()
                    if typed.artifact.role == role and typed.artifact.media_type == media
                ),
                None,
            )
            if kind is None:
                raise MainGraduationOfflineDrillJournalError("native evidence role/media mismatch")
            if hasattr(typed, "kind") and typed.kind is not kind:
                raise MainGraduationOfflineDrillJournalError("native evidence kind mismatch")
            if hasattr(typed, "evidence_digest") and typed.evidence_digest != typed.artifact.digest:
                raise MainGraduationOfflineDrillJournalError("native evidence digest mismatch")
            expected_role, expected_media = _KIND_ROLE_MEDIA[kind]
            if typed.artifact.role != expected_role or typed.artifact.media_type != expected_media:
                raise MainGraduationOfflineDrillJournalError("native evidence role/media mismatch")
            try:
                raw = self._store.read_bytes(typed.artifact)
                payload = _strict_loads(raw)
                if canonical_bytes(payload) != raw or not isinstance(payload, dict):
                    raise ValueError("native artifact is not canonical JSON object")
                self._parse_native(kind, payload, authority, report)
            except Exception as exc:
                raise MainGraduationOfflineDrillJournalError(
                    "native evidence is unverifiable"
                ) from exc

    @staticmethod
    def _parse_native(
        kind: MainGraduationOfflineEvidenceKind,
        payload: dict[str, Any],
        authority: MainGraduationOfflineExecutionAuthority,
        report: MainGraduationOfflineExecutionReport,
    ) -> Any:
        if "c7_binding" in payload:
            raise ValueError("legacy generic C7 evidence envelope")
        if kind is MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY:
            parsed = MainGraduationOfflineExecutionAuthority.model_validate(payload)
            if parsed != authority:
                raise ValueError("authority native evidence differs")
            return parsed
        if kind is MainGraduationOfflineEvidenceKind.EXECUTION_REPORT:
            parsed = MainGraduationOfflineExecutionReport.model_validate(payload)
            if parsed != report:
                raise ValueError("report native evidence differs")
            return parsed
        # Native C4/C5/C6 and provider/controller contracts are not yet wired
        # to this journal.  Probing unrelated package models here would turn
        # an untyped blob into authority evidence.  Keep this explicit until
        # each native kind gets its own parser and binding check.
        raise ValueError(f"native evidence kind {kind.value} is unsupported")

    @staticmethod
    def _bind_report_to_authority(
        report: MainGraduationOfflineExecutionReport,
        authority: MainGraduationOfflineExecutionAuthority,
    ) -> None:
        fields = (
            "operation_id",
            "authority_digest",
            "repository_digest",
            "target_ref",
            "source_commit",
            "source_tree",
            "source_tree_digest",
            "protocol_digest",
            "configuration_digest",
            "policy_digest",
            "activation_digest",
            "lockfile_digest",
            "interpreter_digest",
            "pytest_digest",
            "plugin_set_digest",
            "toolchain_digest",
            "argv",
        )
        if (
            any(getattr(report, field) != getattr(authority, field) for field in fields)
            or report.authority_expires_at != authority.expires_at
            or report.executed_at < authority.authorized_at
        ):
            raise MainGraduationOfflineDrillJournalError("execution report differs from authority")
        nodes = {(node.case_id, node.vector_id): node for node in authority.nodes}
        for observation in report.observations:
            node = nodes.get((observation.case_id, observation.vector_id))
            if (
                node is None
                or observation.node_id != node.node_id
                or observation.parameter_id != node.parameter_id
            ):
                raise MainGraduationOfflineDrillJournalError(
                    "report observation differs from authority node"
                )

    @staticmethod
    def _bind_plan_to_authority(
        plan: MainGraduationOfflineDrillPlan,
        authority: MainGraduationOfflineExecutionAuthority,
        authority_ref: ArtifactRef,
    ) -> None:
        if (
            plan.operation_id != authority.operation_id
            or plan.repository_digest != authority.repository_digest
            or plan.protocol_digest != authority.protocol_digest
            or plan.configuration_digest != authority.configuration_digest
            or plan.policy_digest != authority.policy_digest
            or plan.activation_digest != authority.activation_digest
            or plan.controller_authority_digest != authority.controller_authority_digest
            or plan.controller_authority_ref != authority.controller_authority_ref
            or plan.execution_authority_digest != authority.authority_digest
            or plan.execution_authority_ref != authority_ref.digest
        ):
            raise MainGraduationOfflineDrillJournalError("plan differs from execution authority")
        if tuple((c.case_id, v.vector_id) for c in plan.cases for v in c.vectors) != tuple(
            (n.case_id, n.vector_id) for n in authority.nodes
        ):
            raise MainGraduationOfflineDrillJournalError("plan node map differs from authority")

    @staticmethod
    def _bind_case_to_dependencies(
        case: MainGraduationOfflineDrillCaseResult,
        plan: MainGraduationOfflineDrillPlan,
        authority: MainGraduationOfflineExecutionAuthority,
        report: MainGraduationOfflineExecutionReport,
        authority_ref: ArtifactRef,
        report_ref: ArtifactRef,
    ) -> None:
        if (
            case.root_operation_id != plan.operation_id
            or case.plan_digest != plan.plan_digest
            or case.execution_authority_digest != authority_ref.digest
            or case.execution_report_digest != report_ref.digest
            or case.main_before_commit != plan.main_before_commit
            or case.main_before_tree != plan.main_before_tree
            or case.main_before_parents != plan.main_before_parents
            or case.operation_id
            != offline_drill_operation_id(plan.operation_id, case.case_id, case.vector_id)
        ):
            raise MainGraduationOfflineDrillJournalError(
                "case is not bound to durable dependencies"
            )
        spec = next((item for item in plan.cases if item.case_id == case.case_id), None)
        node = next(
            (
                item
                for item in report.observations
                if item.case_id == case.case_id and item.vector_id == case.vector_id
            ),
            None,
        )
        if (
            spec is None
            or node is None
            or case.vector_id not in {v.vector_id for v in spec.vectors}
        ):
            raise MainGraduationOfflineDrillJournalError("case is outside durable execution matrix")
        vector = next(v for v in spec.vectors if v.vector_id == case.vector_id)
        if (
            case.expected_outcome != vector.expected_outcome
            or case.expected_state != vector.expected_state
            or case.injected_fault_digest != vector.fault_digest
            or case.observed_outcome != node.outcome
            or case.reason_code != node.reason_code
        ):
            raise MainGraduationOfflineDrillJournalError(
                "case observation differs from durable report"
            )
        by_digest = {ref.artifact.digest: ref for ref in case.native_evidence_refs}
        if by_digest.get(authority_ref.digest) is None or by_digest.get(report_ref.digest) is None:
            raise MainGraduationOfflineDrillJournalError(
                "case execution refs differ from durable refs"
            )
        node_digests = {ref.artifact.digest for ref in node.evidence_refs}
        if not node_digests.issubset(by_digest) or set(by_digest) != node_digests | {
            authority_ref.digest,
            report_ref.digest,
        }:
            raise MainGraduationOfflineDrillJournalError(
                "case native refs differ from report observation"
            )

    @staticmethod
    def _bind_result_to_dependencies(
        result: MainGraduationOfflineDrillResult,
        plan: MainGraduationOfflineDrillPlan,
        authority: MainGraduationOfflineExecutionAuthority,
        report: MainGraduationOfflineExecutionReport,
        authority_ref: ArtifactRef,
        report_ref: ArtifactRef,
    ) -> None:
        if (
            result.operation_id != plan.operation_id
            or result.plan_digest != plan.plan_digest
            or result.repository_digest != plan.repository_digest
            or result.target_ref != plan.target_ref
            or result.execution_authority_digest != authority_ref.digest
            or result.execution_report_digest != report_ref.digest
            or result.main_before_commit != plan.main_before_commit
            or result.main_before_tree != plan.main_before_tree
            or result.main_before_parents != plan.main_before_parents
            or result.main_after_commit != plan.main_before_commit
            or result.main_after_tree != plan.main_before_tree
            or result.main_after_parents != plan.main_before_parents
        ):
            raise MainGraduationOfflineDrillJournalError("result differs from durable dependencies")

    def _verify(self, kind: str, *args: Any) -> None:
        if self._verifier is None:
            raise MainGraduationOfflineDrillJournalError("injected C7 verifier is required")
        name = {
            "execution_authority": "verify_execution_authority",
            "execution_report": "verify_execution_report",
            "plan": "verify_plan",
            "case": "verify_case_result",
            "result": "verify_result",
        }[kind]
        method = getattr(self._verifier, name, None)
        if method is None or not callable(method):
            raise MainGraduationOfflineDrillJournalError(f"C7 verifier missing {name}")
        try:
            signature = inspect.signature(method)
            parameters = tuple(signature.parameters.values())
            if len(parameters) != len(args) or any(
                p.kind
                not in (
                    inspect.Parameter.POSITIONAL_ONLY,
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                )
                or p.default is not inspect.Parameter.empty
                for p in parameters
            ):
                raise TypeError("verifier signature is not exact")
            signature.bind(*args)
            if method(*args) is not True:
                raise ValueError("verifier did not return literal True")
        except Exception as exc:
            if isinstance(exc, MainGraduationOfflineDrillJournalError):
                raise
            raise MainGraduationOfflineDrillJournalError(f"C7 verifier rejected {kind}") from exc

    def _put(
        self, kind: str, data: bytes, native_kind: MainGraduationOfflineEvidenceKind | None = None
    ) -> ArtifactRef:
        role, media = (
            _KIND_ROLE_MEDIA[native_kind]
            if native_kind is not None
            else (_JOURNAL_ROLE[kind], _JOURNAL_MEDIA[kind])
        )
        return self._store.put_bytes(data, media_type=media, role=role, max_bytes=self._max)

    def _replay_if_existing(self, kind: str, index: Path, data: bytes) -> ArtifactRef | None:
        if not index.is_file():
            return None
        loaded = self._read_indexed(kind, index, _MODELS[kind])
        if loaded is None or self._store.read_bytes(loaded[1]) != data:
            raise MainGraduationOfflineDrillRecordConflictError(
                f"conflicting {kind} record"
            ) from None
        return loaded[1]

    def _create_once(self, index: Path, ref: ArtifactRef, data: bytes, kind: str) -> ArtifactRef:
        existing = self._replay_if_existing(kind, index, data)
        if existing is not None:
            return existing
        index.parent.mkdir(parents=True, exist_ok=True)
        try:
            with index.open("xb") as handle:
                handle.write(canonical_bytes(ref))
                handle.flush()
                os.fsync(handle.fileno())
            _sync_directory(index.parent)
            return ref
        except FileExistsError as exc:
            existing = self._replay_if_existing(kind, index, data)
            if existing is None:
                raise MainGraduationOfflineDrillJournalError(
                    "race lost without durable index"
                ) from exc
            return existing

    def _read_indexed(
        self, kind: str, index: Path, model: type[Any]
    ) -> tuple[Any, ArtifactRef] | None:
        if not index.is_file():
            return None
        try:
            raw = index.read_bytes()
            value = _strict_loads(raw)
            if len(raw) > _MAX_INDEX_BYTES or canonical_bytes(value) != raw:
                raise ValueError("invalid index")
            ref = ArtifactRef.model_validate(value)
            if kind == "authority":
                expected_role, expected_media = _KIND_ROLE_MEDIA[
                    MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY
                ]
            elif kind == "report":
                expected_role, expected_media = _KIND_ROLE_MEDIA[
                    MainGraduationOfflineEvidenceKind.EXECUTION_REPORT
                ]
            else:
                expected_role, expected_media = _JOURNAL_ROLE[kind], _JOURNAL_MEDIA[kind]
            if (
                ref.role != expected_role
                or ref.media_type != expected_media
                or ref.size_bytes > self._max
            ):
                raise ValueError("index metadata mismatch")
            data = self._store.read_bytes(ref)
            parsed = _strict_loads(data)
            if canonical_bytes(parsed) != data:
                raise ValueError("noncanonical record")
            record = model.model_validate(parsed)
            if canonical_bytes(record) != data:
                raise ValueError("record is not canonical")
            return record, ref
        except Exception as exc:
            raise MainGraduationOfflineDrillJournalError(f"malformed C7 {kind}") from exc

    @staticmethod
    def _parse(model: type[Any], value: Any, kind: str) -> Any:
        try:
            if isinstance(value, model):
                value = value.model_dump(mode="json")
            return model.model_validate(value)
        except Exception as exc:
            raise MainGraduationOfflineDrillJournalError(f"invalid C7 {kind}") from exc

    def _authority_index(self, operation_id: str, authority_digest: str) -> Path:
        # authority_digest is a self-digest over operation_id and all authority
        # bindings, so it can safely serve as the compact operation namespace.
        return self._indexes / "authority" / f"{_path_token(authority_digest)}.json"

    def _report_index(self, operation_id: str, authority_digest: str, report_digest: str) -> Path:
        # The authority digest is self-derived from the operation identity, so it
        # is the collision-resistant operation namespace as well.  Omitting the
        # repeated operation component keeps Windows paths below MAX_PATH.
        return (
            self._indexes
            / "report"
            / _path_token(authority_digest)
            / f"{_path_token(report_digest)}.json"
        )

    def _plan_index(self, operation_id: str, authority_digest: str) -> Path:
        return self._indexes / "plan" / f"{_path_token(authority_digest)}.json"

    def _case_index(
        self,
        operation_id: str,
        authority_digest: str,
        report_digest: str,
        case_id: str,
        vector_id: str,
    ) -> Path:
        return (
            self._indexes
            / "case"
            / _path_token(authority_digest)
            / _path_token(report_digest)
            / case_id
            / f"{vector_id}.json"
        )

    def _result_index(self, operation_id: str, authority_digest: str, report_digest: str) -> Path:
        return (
            self._indexes
            / "result"
            / _path_token(authority_digest)
            / f"{_path_token(report_digest)}.json"
        )

    def _find_authority_digest(self, operation_id: str) -> str | None:
        root = self._indexes / "authority"
        values: list[str] = []
        if root.is_dir():
            for path in sorted(root.glob("*.json")):
                if not path.is_file():
                    continue
                loaded = self._read_indexed(
                    "authority", path, MainGraduationOfflineExecutionAuthority
                )
                if loaded is not None and loaded[0].operation_id == operation_id:
                    values.append(loaded[0].authority_digest)
        if len(values) > 1:
            raise MainGraduationOfflineDrillJournalError("multiple execution authorities")
        return values[0] if values else None

    def _find_report_digest(self, operation_id: str, authority_digest: str) -> str | None:
        root = self._indexes / "report" / _path_token(authority_digest)
        values: list[str] = []
        if root.is_dir():
            for path in sorted(root.glob("*.json")):
                if not path.is_file():
                    continue
                loaded = self._read_indexed("report", path, MainGraduationOfflineExecutionReport)
                if loaded is not None:
                    report = loaded[0]
                    if (
                        report.operation_id == operation_id
                        and report.authority_digest == authority_digest
                    ):
                        values.append(report.report_digest)
        if len(values) > 1:
            raise MainGraduationOfflineDrillJournalError("multiple execution reports")
        return values[0] if values else None


def _path_token(digest: str) -> str:
    """Keep nested Windows index paths short; full digests remain authoritative."""
    return digest.removeprefix("sha256:")[:16]


def _strict_loads(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs)


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _sync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        if os.name == "nt" and exc.errno in {
            errno.EINVAL,
            errno.EACCES,
            errno.ENOTSUP,
            errno.EOPNOTSUPP,
        }:
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


OfflineDrillJournal = MainGraduationOfflineDrillJournal
OfflineDrillJournalError = MainGraduationOfflineDrillJournalError
OfflineDrillRecordConflictError = MainGraduationOfflineDrillRecordConflictError

__all__ = [
    "MainGraduationOfflineDrillAuthorityVerifier",
    "MainGraduationOfflineDrillJournal",
    "MainGraduationOfflineDrillJournalError",
    "MainGraduationOfflineDrillRecordConflictError",
    "MainGraduationOfflineDrillVerifier",
    "OfflineDrillAuthorityVerifier",
    "OfflineDrillJournal",
    "OfflineDrillJournalError",
    "OfflineDrillRecordConflictError",
]
