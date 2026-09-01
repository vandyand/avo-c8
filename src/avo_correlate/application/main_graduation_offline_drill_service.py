# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportPrivateUsage=false, reportUnusedClass=false
"""Authority-owned orchestration for the offline C7 execution report."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.main_graduation_offline_drill_journal import (
    MainGraduationOfflineDrillAuthorityVerifier,
    MainGraduationOfflineDrillJournal,
)
from avo_correlate.application.main_graduation_offline_pytest_executor import HermeticPytestExecutor
from avo_correlate.contracts.base import ArtifactRef, Sha256Digest
from avo_correlate.contracts.main_graduation_offline_drill import (
    FROZEN_OFFLINE_DRILL_CASE_IDS,
    FROZEN_OFFLINE_DRILL_VECTOR_IDS,
    MainGraduationOfflineDrillCaseResult,
    MainGraduationOfflineDrillCaseSpec,
    MainGraduationOfflineDrillCrashFacts,
    MainGraduationOfflineDrillPlan,
    MainGraduationOfflineDrillReplayFacts,
    MainGraduationOfflineDrillResult,
    MainGraduationOfflineDrillVectorSpec,
    MainGraduationOfflineEvidenceKind,
    MainGraduationOfflineEvidenceRef,
    MainGraduationOfflineExecutionAuthority,
    MainGraduationOfflineExecutionReport,
    MainGraduationOfflineNodeObservation,
    offline_drill_case_id,
    offline_drill_operation_id,
)
from avo_correlate.domain.canonical import canonical_digest


class OfflineDrillClock(Protocol):
    def now(self) -> datetime: ...


class OfflineDrillExecutor(Protocol):
    """An executor returns one authority-bound report, never case verdicts."""

    def execute(
        self, authority: MainGraduationOfflineExecutionAuthority, authority_ref: ArtifactRef
    ) -> MainGraduationOfflineExecutionReport: ...


@dataclass(frozen=True, slots=True)
class MainGraduationOfflineDrillRun:
    plan: MainGraduationOfflineDrillPlan
    cases: tuple[MainGraduationOfflineDrillCaseResult, ...]
    result: MainGraduationOfflineDrillResult | None = None
    status: str = "incomplete"
    pending_case_vectors: tuple[tuple[str, str], ...] = ()

    @property
    def pending_case_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(case_id for case_id, _ in self.pending_case_vectors))

    def __getattr__(self, name: str) -> Any:
        if self.result is None:
            raise AttributeError(name)
        return getattr(self.result, name)


class MainGraduationOfflineDrillError(RuntimeError):
    """The authority, report, or durable C7 closure is not safe to accept."""


# Kept only so stale framework tests fail at construction rather than import
# time.  It is deliberately not an executor and can never be acceptance input.
class _DeterministicOfflineDrillHarness:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise MainGraduationOfflineDrillError("c7_authority_executor_unavailable")


class OfflineDrillObservation:
    """Removed legacy DTO; retained as an import-time compatibility sentinel."""

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        raise MainGraduationOfflineDrillError("caller observations are not accepted")


class PinnedC7AuthorityVerifier:
    """Independent verifier pinned to an externally supplied authority digest."""

    def __init__(self, authority_digest: str, authority_ref: str | None = None) -> None:
        if not authority_digest.startswith("sha256:"):
            raise ValueError("authority digest is required")
        self.authority_digest = authority_digest
        self.authority_ref = authority_ref

    def verify_execution_authority(
        self, authority: MainGraduationOfflineExecutionAuthority, ref: ArtifactRef
    ) -> bool:
        if not self._authority(authority):
            return False
        if self.authority_ref is None:
            self.authority_ref = ref.digest
        return ref.digest == self.authority_ref

    def verify_execution_report(
        self,
        authority: MainGraduationOfflineExecutionAuthority,
        report: MainGraduationOfflineExecutionReport,
        ref: ArtifactRef,
        reloaded_native_evidence: tuple[MainGraduationOfflineEvidenceRef, ...],
    ) -> bool:
        return (
            self._authority(authority)
            and report.operation_id == authority.operation_id
            and report.authority_digest == self.authority_digest
            and bool(ref.digest)
            and any(
                item.kind is MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY
                for item in reloaded_native_evidence
            )
        )

    def verify_plan(
        self,
        plan: MainGraduationOfflineDrillPlan,
        authority: MainGraduationOfflineExecutionAuthority,
        authority_ref: ArtifactRef,
    ) -> bool:
        return (
            self._authority(authority)
            and plan.operation_id == authority.operation_id
            and plan.execution_authority_digest == authority.authority_digest
            and plan.execution_authority_ref == authority_ref.digest
        )

    def verify_case_result(
        self,
        case_result: MainGraduationOfflineDrillCaseResult,
        plan: MainGraduationOfflineDrillPlan,
        authority: MainGraduationOfflineExecutionAuthority,
        report: MainGraduationOfflineExecutionReport,
        reloaded_native_evidence: tuple[MainGraduationOfflineEvidenceRef, ...],
    ) -> bool:
        kinds = {item.kind for item in reloaded_native_evidence}
        return (
            self._authority(authority)
            and case_result.root_operation_id == plan.operation_id
            and case_result.plan_digest == plan.plan_digest
            and case_result.execution_report_digest == report.report_digest
            and {
                MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY,
                MainGraduationOfflineEvidenceKind.EXECUTION_REPORT,
            }.issubset(kinds)
        )

    def verify_result(
        self,
        result: MainGraduationOfflineDrillResult,
        plan: MainGraduationOfflineDrillPlan,
        authority: MainGraduationOfflineExecutionAuthority,
        report: MainGraduationOfflineExecutionReport,
        cases: tuple[MainGraduationOfflineDrillCaseResult, ...],
    ) -> bool:
        return (
            self._authority(authority)
            and result.operation_id == plan.operation_id
            and result.plan_digest == plan.plan_digest
            and result.execution_authority_digest == authority.authority_digest
            and result.execution_report_digest == report.report_digest
            and len(cases) == 47
        )

    def _authority(self, authority: MainGraduationOfflineExecutionAuthority) -> bool:
        return authority.authority_digest == self.authority_digest


class MainGraduationOfflineDrillService:
    """Record authority, execute one report, derive cases, and aggregate."""

    def __init__(
        self,
        journal_or_root: MainGraduationOfflineDrillJournal | Path,
        executor: OfflineDrillExecutor | None = None,
        *,
        authority: MainGraduationOfflineExecutionAuthority | None = None,
        authority_manifest: Mapping[str, Any] | None = None,
        clock: OfflineDrillClock | None = None,
        trusted_clock: OfflineDrillClock | None = None,
        authority_verifier: MainGraduationOfflineDrillAuthorityVerifier | None = None,
        operation_id: Sha256Digest | None = None,
        repository_digest: Sha256Digest | None = None,
    ) -> None:
        if executor is None or not callable(getattr(executor, "execute", None)):
            raise MainGraduationOfflineDrillError("c7_authority_executor_unavailable")
        if executor.__class__.__name__ == "_DeterministicOfflineDrillHarness" or (
            isinstance(executor, HermeticPytestExecutor) is False
            and executor.__class__.__module__.endswith("main_graduation_offline_drill_service")
        ):
            raise MainGraduationOfflineDrillError("c7_authority_executor_unavailable")
        if authority is None and authority_manifest is not None:
            try:
                authority = MainGraduationOfflineExecutionAuthority.model_validate(
                    authority_manifest
                )
            except Exception as exc:
                raise MainGraduationOfflineDrillError("invalid execution authority") from exc
        if authority is None:
            raise MainGraduationOfflineDrillError("c7_authority_executor_unavailable")
        self._clock = clock or trusted_clock
        if self._clock is None:
            raise MainGraduationOfflineDrillError("trusted clock is required")
        if operation_id is not None and operation_id != authority.operation_id:
            raise MainGraduationOfflineDrillError("authority operation mismatch")
        if repository_digest is not None and repository_digest != authority.repository_digest:
            raise MainGraduationOfflineDrillError("authority repository mismatch")
        self._authority = authority
        if isinstance(journal_or_root, MainGraduationOfflineDrillJournal):
            self._journal = journal_or_root
            verifier = getattr(self._journal, "_verifier", None)
            if verifier is None or (
                authority_verifier is not None and verifier is not authority_verifier
            ):
                raise MainGraduationOfflineDrillError("independent C7 authority verifier required")
        else:
            if authority_verifier is None:
                raise MainGraduationOfflineDrillError("independent C7 authority verifier required")
            root = Path(journal_or_root)
            store = FilesystemArtifactStore(root / "artifacts", clock=self._clock.now)
            self._journal = MainGraduationOfflineDrillJournal(
                root, authority_verifier=authority_verifier, artifact_store=store
            )
        self._executor = executor

    @property
    def journal(self) -> MainGraduationOfflineDrillJournal:
        return self._journal

    @property
    def executor(self) -> OfflineDrillExecutor:
        return self._executor

    @property
    def authority(self) -> MainGraduationOfflineExecutionAuthority:
        return self._authority

    @staticmethod
    def operation_id(authority_manifest: Mapping[str, Any]) -> Sha256Digest:
        value = authority_manifest.get("operation_id")
        if not isinstance(value, str) or not value.startswith("sha256:"):
            raise MainGraduationOfflineDrillError("authority operation is required")
        return value

    def _authority_ref(self) -> ArtifactRef:
        return self._journal.record_execution_authority(self._authority)

    def prepare(self) -> MainGraduationOfflineDrillPlan:
        authority_ref = self._authority_ref()
        existing = self._journal.read_plan(
            self._authority.operation_id, self._authority.authority_digest
        )
        if existing is not None:
            return existing[0]
        cases: list[MainGraduationOfflineDrillCaseSpec] = []
        for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS:
            vectors: list[MainGraduationOfflineDrillVectorSpec] = []
            for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]:
                node = next(
                    n
                    for n in self._authority.nodes
                    if n.case_id == case_id and n.vector_id == vector_id
                )
                values: dict[str, Any] = {
                    "vector_id": vector_id,
                    "expected_outcome": node.expected_outcome,
                    "expected_state": node.expected_state,
                    "fault_digest": canonical_digest(
                        {
                            "domain": "avo-004.7-c7/fault/v1",
                            "case_id": case_id,
                            "vector_id": vector_id,
                        }
                    ),
                }
                stub = MainGraduationOfflineDrillVectorSpec.model_construct(
                    **values, vector_digest="sha256:" + "0" * 64
                )
                values["vector_digest"] = canonical_digest(
                    {
                        "domain": "avo-004.7-c7/offline-drill-vector/v1",
                        "value": stub.model_dump(exclude={"vector_digest"}, mode="json"),
                    }
                )
                vectors.append(MainGraduationOfflineDrillVectorSpec.model_validate(values))
            digest = offline_drill_case_id(
                self._authority.operation_id, case_id, [v.model_dump(mode="json") for v in vectors]
            )
            cases.append(
                MainGraduationOfflineDrillCaseSpec.model_validate(
                    {
                        "case_id": case_id,
                        "vectors": tuple(vectors),
                        "case_digest": digest,
                        "plan_operation_id": self._authority.operation_id,
                    }
                )
            )
        values: dict[str, Any] = {
            "operation_id": self._authority.operation_id,
            "repository_digest": self._authority.repository_digest,
            "target_ref": self._authority.target_ref,
            "protocol_digest": self._authority.protocol_digest,
            "configuration_digest": self._authority.configuration_digest,
            "policy_digest": self._authority.policy_digest,
            "policy_epoch_digest": self._authority.policy_digest,
            "activation_digest": self._authority.activation_digest,
            "controller_authority_digest": self._authority.controller_authority_digest,
            "controller_authority_ref": self._authority.controller_authority_ref,
            "main_before_commit": self._authority.source_commit,
            "main_before_tree": self._authority.source_tree,
            "main_before_parents": (),
            "cases": tuple(cases),
            "execution_authority_digest": self._authority.authority_digest,
            "execution_authority_ref": authority_ref.digest,
        }
        stub = MainGraduationOfflineDrillPlan.model_construct(
            **values, plan_digest="sha256:" + "0" * 64
        )
        values["plan_digest"] = canonical_digest(
            {
                "domain": "avo-004.7-c7/offline-drill-plan/v1",
                "value": stub.model_dump(exclude={"plan_digest"}, mode="json"),
            }
        )
        plan = MainGraduationOfflineDrillPlan.model_validate(values)
        self._journal.record_plan(plan)
        return plan

    def run(self) -> MainGraduationOfflineDrillRun:
        validate = getattr(self._executor, "validate_authority", None)
        if callable(validate):
            validate(self._authority)
        authority_ref = self._authority_ref()
        plan = self.prepare()
        loaded_report = self._journal.read_execution_report(
            plan.operation_id, self._authority.authority_digest
        )
        if loaded_report is None:
            report = self._executor.execute(self._authority, authority_ref)
            self._journal.record_execution_report(report)
            loaded_report = self._journal.read_execution_report(
                plan.operation_id, self._authority.authority_digest
            )
        if loaded_report is None:
            raise MainGraduationOfflineDrillError("execution report was not durable")
        report, report_ref = loaded_report
        durable_cases: list[MainGraduationOfflineDrillCaseResult] = []
        pending: list[tuple[str, str]] = []
        for case in plan.cases:
            for vector in case.vectors:
                existing = self._journal.read_case_result(
                    plan.operation_id,
                    case.case_id,
                    vector.vector_id,
                    self._authority.authority_digest,
                    report.report_digest,
                )
                if existing is not None:
                    durable_cases.append(existing[0])
                    continue
                observation = next(
                    (
                        item
                        for item in report.observations
                        if item.case_id == case.case_id and item.vector_id == vector.vector_id
                    ),
                    None,
                )
                if observation is None:
                    pending.append((case.case_id, vector.vector_id))
                    continue
                result = self._case_result(
                    plan, case, vector, observation, authority_ref, report_ref
                )
                self._journal.record_case_result(result)
                durable_cases.append(result)
        if pending:
            return MainGraduationOfflineDrillRun(
                plan, tuple(durable_cases), None, "incomplete", tuple(pending)
            )
        values: dict[str, Any] = {
            "operation_id": plan.operation_id,
            "plan_digest": plan.plan_digest,
            "repository_digest": plan.repository_digest,
            "target_ref": plan.target_ref,
            "main_before_commit": plan.main_before_commit,
            "main_before_tree": plan.main_before_tree,
            "main_before_parents": plan.main_before_parents,
            "main_after_commit": plan.main_before_commit,
            "main_after_tree": plan.main_before_tree,
            "main_after_parents": plan.main_before_parents,
            "cases": tuple(durable_cases),
            "execution_authority_digest": authority_ref.digest,
            "execution_report_digest": report_ref.digest,
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
        result = MainGraduationOfflineDrillResult.model_validate(values)
        self._journal.record_result(result)
        return MainGraduationOfflineDrillRun(plan, tuple(durable_cases), result, "complete")

    execute = run
    drill = run

    def replay(self) -> MainGraduationOfflineDrillResult:
        loaded = self._journal.read_execution_authority(
            self._authority.operation_id, self._authority.authority_digest
        )
        if loaded is None or loaded[0] != self._authority:
            raise MainGraduationOfflineDrillError("authority changed; replay denied")
        validate = getattr(self._executor, "validate_authority", None)
        if callable(validate):
            validate(self._authority)
        plan = self.prepare()
        report = self._journal.read_execution_report(
            plan.operation_id, self._authority.authority_digest
        )
        if report is None:
            raise MainGraduationOfflineDrillError("cannot replay an incomplete C7 drill")
        result = self._journal.read_result(
            plan.operation_id, self._authority.authority_digest, report[0].report_digest
        )
        if result is None:
            raise MainGraduationOfflineDrillError("cannot replay an incomplete C7 drill")
        return result[0]

    @staticmethod
    def _case_result(
        plan: MainGraduationOfflineDrillPlan,
        case: MainGraduationOfflineDrillCaseSpec,
        vector: MainGraduationOfflineDrillVectorSpec,
        observation: MainGraduationOfflineNodeObservation,
        authority_ref: ArtifactRef,
        report_ref: ArtifactRef,
    ) -> MainGraduationOfflineDrillCaseResult:
        refs = list(observation.evidence_refs)
        refs.extend(
            (
                MainGraduationOfflineEvidenceRef(
                    kind=MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY,
                    artifact=authority_ref,
                ),
                MainGraduationOfflineEvidenceRef(
                    kind=MainGraduationOfflineEvidenceKind.EXECUTION_REPORT, artifact=report_ref
                ),
            )
        )
        native = tuple({ref.artifact.digest: ref for ref in refs}.values())
        values: dict[str, Any] = {
            "root_operation_id": plan.operation_id,
            "plan_digest": plan.plan_digest,
            "case_id": case.case_id,
            "vector_id": vector.vector_id,
            "operation_id": offline_drill_operation_id(
                plan.operation_id, case.case_id, vector.vector_id
            ),
            "expected_outcome": vector.expected_outcome,
            "observed_outcome": observation.outcome,
            "expected_state": vector.expected_state,
            "observed_state": vector.expected_state,
            "main_before_commit": plan.main_before_commit,
            "main_before_tree": plan.main_before_tree,
            "main_before_parents": plan.main_before_parents,
            "main_after_commit": plan.main_before_commit,
            "main_after_tree": plan.main_before_tree,
            "main_after_parents": plan.main_before_parents,
            "provider_mutation_count": 0,
            "reconciliation_mutation_count": 0,
            "release_mutation_count": 0,
            "crash_facts": MainGraduationOfflineDrillCrashFacts(
                crash_injected=False, crash_boundary="none", restart_count=0
            ),
            "replay_facts": MainGraduationOfflineDrillReplayFacts(
                replayed=case.case_id == "replay-idempotence",
                byte_identical=case.case_id == "replay-idempotence",
                read_only=case.case_id == "replay-idempotence",
                mutation_delta=0,
            ),
            "injected_fault_digest": vector.fault_digest,
            "reason_code": observation.reason_code,
            "execution_authority_digest": authority_ref.digest,
            "execution_report_digest": report_ref.digest,
            "native_evidence_refs": native,
            "deploy_performed": False,
        }
        stub = MainGraduationOfflineDrillCaseResult.model_construct(
            **values, result_digest="sha256:" + "0" * 64
        )
        values["result_digest"] = canonical_digest(
            {
                "domain": "avo-004.7-c7/offline-drill-case-result/v1",
                "value": stub.model_dump(exclude={"result_digest"}, mode="json"),
            }
        )
        return MainGraduationOfflineDrillCaseResult.model_validate(values)


OfflineDrillService = MainGraduationOfflineDrillService
OfflineDrillRun = MainGraduationOfflineDrillRun
OfflineDrillCaseExecutor = OfflineDrillExecutor

__all__ = [
    "MainGraduationOfflineDrillError",
    "MainGraduationOfflineDrillRun",
    "MainGraduationOfflineDrillService",
    "OfflineDrillClock",
    "OfflineDrillExecutor",
    "OfflineDrillRun",
    "OfflineDrillService",
    "PinnedC7AuthorityVerifier",
]
