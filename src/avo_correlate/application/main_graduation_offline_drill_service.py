# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnnecessaryCast=false, reportPrivateUsage=false

"""Deterministic, offline-only C7 graduation drill orchestration.

This module is intentionally a small controller around the C7 journal.  An
executor may observe a case and return evidence references, but it cannot
submit a case result or declare that a vector passed.  The service binds the
observation to the frozen plan and lets the journal re-load and verify the
evidence before a result is durable.
"""

from __future__ import annotations

import inspect
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, cast

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.main_graduation_offline_drill_journal import (
    MainGraduationOfflineDrillAuthorityVerifier,
    MainGraduationOfflineDrillJournal,
)
from avo_correlate.contracts.base import ArtifactRef, Sha256Digest
from avo_correlate.contracts.main_graduation_offline_drill import (
    FROZEN_OFFLINE_DRILL_CASE_IDS,
    FROZEN_OFFLINE_DRILL_VECTOR_IDS,
    DrillOutcome,
    DrillState,
    MainGraduationOfflineDrillCaseResult,
    MainGraduationOfflineDrillCaseSpec,
    MainGraduationOfflineDrillCrashFacts,
    MainGraduationOfflineDrillPlan,
    MainGraduationOfflineDrillReplayFacts,
    MainGraduationOfflineDrillResult,
    MainGraduationOfflineDrillVectorSpec,
    offline_drill_case_id,
    offline_drill_operation_id,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


class OfflineDrillClock(Protocol):
    def now(self) -> datetime: ...


class OfflineDrillCaseExecutor(Protocol):
    """Observe one vector; no pass/fail or mutation authority is returned."""

    def observe(
        self,
        plan: MainGraduationOfflineDrillPlan,
        case: MainGraduationOfflineDrillCaseSpec,
        vector: MainGraduationOfflineDrillVectorSpec,
    ) -> object: ...


@dataclass(frozen=True, slots=True)
class OfflineDrillObservation:
    """Narrow observation envelope accepted from an offline executor."""

    observed_outcome: DrillOutcome = "reconciliation_required"
    observed_state: DrillState = "failed_closed"
    evidence_artifacts: tuple[ArtifactRef, ...] = ()
    main_after_commit: str = ""
    main_after_tree: str = ""
    main_after_parents: tuple[str, ...] = ()
    provider_mutation_count: int = 0
    reconciliation_mutation_count: int = 0
    release_mutation_count: int = 0
    crash_injected: bool = False
    crash_boundary: str = "none"
    restart_count: int = 0
    replayed: bool = False
    byte_identical: bool = False
    read_only: bool = False
    mutation_delta: int = 0
    reason_code: str = "expected-rejection"


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
    """The offline observation cannot be safely bound to the frozen plan."""


class _DeterministicOfflineDrillHarness:
    """Reference executor for the fully offline C7 gate.

    The harness writes canonical, typed evidence envelopes through the same
    artifact store consumed by the production journal.  Its observations are
    all safe rejection/reconciliation observations; no hosted component,
    provider, subprocess, clock, or repository is consulted.
    """

    def __init__(
        self, artifact_store: FilesystemArtifactStore, *, clock: OfflineDrillClock | None = None
    ):
        self.artifact_store = artifact_store
        self.clock = clock
        self.calls: list[tuple[str, str]] = []

    def observe(
        self,
        plan: MainGraduationOfflineDrillPlan,
        case: MainGraduationOfflineDrillCaseSpec,
        vector: MainGraduationOfflineDrillVectorSpec,
    ) -> OfflineDrillObservation:
        self.calls.append((case.case_id, vector.vector_id))
        refs: list[ArtifactRef] = []
        for kind in ("c4", "c5", "c6", "provider", "rollback", "ledger", "verifier"):
            payload = {
                "schema_version": 1,
                "c7_binding": {
                    "operation_id": offline_drill_operation_id(
                        plan.operation_id, case.case_id, vector.vector_id
                    ),
                    "root_operation_id": plan.operation_id,
                    "case_id": case.case_id,
                    "vector_id": vector.vector_id,
                    "link_id": f"{kind}-{case.case_id}-{vector.vector_id}",
                },
                "evidence_type": kind,
                "observation": "deterministic-safe-rejection",
            }
            refs.append(
                self.artifact_store.put_bytes(
                    canonical_bytes(payload),
                    media_type="application/vnd.avo.main-graduation-offline-drill+json",
                    role=f"c7-{kind}-evidence",
                    max_bytes=8 * 1024 * 1024,
                )
            )
        expected_outcome, expected_state = _expected_vector(case.case_id, vector.vector_id)
        replayed = case.case_id == "replay-idempotence"
        crash = case.case_id == "crash-boundary-matrix" and vector.vector_id != "after-hold-success"
        return OfflineDrillObservation(
            observed_outcome=expected_outcome,
            observed_state=expected_state,
            evidence_artifacts=tuple(refs),
            main_after_commit=plan.main_before_commit,
            main_after_tree=plan.main_before_tree,
            main_after_parents=plan.main_before_parents,
            crash_injected=crash,
            crash_boundary=vector.vector_id if crash else "none",
            replayed=replayed,
            byte_identical=replayed,
            read_only=replayed,
        )


def _expected_vector(case_id: str, vector_id: str) -> tuple[DrillOutcome, DrillState]:
    if case_id == "replay-idempotence":
        return "replayed", "replayed_read_only"
    if (case_id, vector_id) in {
        ("crash-boundary-matrix", "after-hold-success"),
        ("admission-group-identity", "admission-success"),
    }:
        return "passed", "completed"
    # Safe rejection and reconciliation are valid C7 outcomes.  Keeping the
    # failure vectors independent from provider details is the key offline
    # guarantee of this gate.
    return "reconciliation_required", "failed_closed"


def _coerce_observation(value: object) -> OfflineDrillObservation:
    if isinstance(value, OfflineDrillObservation):
        return value
    if isinstance(value, dict):
        values = dict(cast(dict[str, Any], value))
        aliases = {
            "outcome": "observed_outcome",
            "state": "observed_state",
            "after_main_commit": "main_after_commit",
            "after_main_tree": "main_after_tree",
            "after_main_parents": "main_after_parents",
            "evidence_refs": "evidence_artifacts",
        }
        for old, new in aliases.items():
            if old in values and new not in values:
                values[new] = values.pop(old)
        return OfflineDrillObservation(**values)
    values: dict[str, Any] = {}
    for field in OfflineDrillObservation.__dataclass_fields__:
        if hasattr(value, field):
            values[field] = getattr(value, field)
    if not values:
        raise MainGraduationOfflineDrillError("executor returned no observation")
    return OfflineDrillObservation(**values)


class MainGraduationOfflineDrillService:
    """Prepare, execute, journal, aggregate, and replay the frozen C7 matrix."""

    def __init__(
        self,
        journal_or_root: MainGraduationOfflineDrillJournal | Path,
        executor: OfflineDrillCaseExecutor | None = None,
        *,
        clock: OfflineDrillClock | None = None,
        trusted_clock: OfflineDrillClock | None = None,
        authority_manifest: Mapping[str, Any] | None = None,
        authority_verifier: MainGraduationOfflineDrillAuthorityVerifier | None = None,
        repository_digest: Sha256Digest | None = None,
        operation_id: Sha256Digest | None = None,
    ) -> None:
        if executor is None:
            raise MainGraduationOfflineDrillError("c7_authority_executor_unavailable")
        if isinstance(executor, _DeterministicOfflineDrillHarness):
            raise MainGraduationOfflineDrillError("c7_authority_executor_unavailable")
        if authority_manifest is None:
            raise MainGraduationOfflineDrillError("c7_authority_executor_unavailable")
        manifest = dict(authority_manifest)
        required_manifest = (
            "operation_id",
            "repository_digest",
            "protocol_digest",
            "configuration_digest",
            "policy_digest",
            "policy_epoch_digest",
            "activation_digest",
            "controller_authority_digest",
            "controller_authority_ref",
            "execution_authority_digest",
            "execution_authority_ref",
            "main_before_commit",
            "main_before_tree",
            "main_before_parents",
        )
        if any(key not in manifest for key in required_manifest):
            raise MainGraduationOfflineDrillError("c7_authority_executor_unavailable")
        self._clock = clock or trusted_clock
        self._authority_manifest = manifest
        manifest_operation = cast(Sha256Digest, manifest["operation_id"])
        if operation_id is not None and operation_id != manifest_operation:
            raise MainGraduationOfflineDrillError("authority manifest operation mismatch")
        if repository_digest is not None and repository_digest != manifest["repository_digest"]:
            raise MainGraduationOfflineDrillError("authority manifest repository mismatch")
        if isinstance(journal_or_root, MainGraduationOfflineDrillJournal):
            self._journal = journal_or_root
            store = self._journal.artifact_store
            if self._journal._verifier is None:
                raise MainGraduationOfflineDrillError("independent C7 authority verifier required")
            if authority_verifier is not None and authority_verifier is not self._journal._verifier:
                raise MainGraduationOfflineDrillError("journal/verifier binding mismatch")
        else:
            if authority_verifier is None or self._clock is None:
                raise MainGraduationOfflineDrillError("independent C7 authority verifier required")
            store = FilesystemArtifactStore(
                Path(journal_or_root) / "artifacts", clock=self._clock.now
            )
            self._journal = MainGraduationOfflineDrillJournal(
                Path(journal_or_root), authority_verifier=authority_verifier, artifact_store=store
            )
        self._operation_id = manifest_operation
        self._executor = executor

    @property
    def journal(self) -> MainGraduationOfflineDrillJournal:
        return self._journal

    @property
    def executor(self) -> OfflineDrillCaseExecutor:
        return self._executor

    @staticmethod
    def operation_id(authority_manifest: Mapping[str, Any]) -> Sha256Digest:
        value = authority_manifest.get("operation_id")
        if not isinstance(value, str) or not value.startswith("sha256:"):
            raise MainGraduationOfflineDrillError("authority manifest operation is required")
        return cast(Sha256Digest, value)

    def prepare(self) -> MainGraduationOfflineDrillPlan:
        existing = self._journal.read_plan(self._operation_id)
        if existing is not None:
            return existing[0]
        cases: list[MainGraduationOfflineDrillCaseSpec] = []
        for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS:
            vectors: list[MainGraduationOfflineDrillVectorSpec] = []
            for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]:
                outcome, state = _expected_vector(case_id, vector_id)
                vector_values: dict[str, Any] = {
                    "vector_id": vector_id,
                    "expected_outcome": outcome,
                    "expected_state": state,
                    "fault_digest": cast(
                        Sha256Digest,
                        canonical_digest(
                            {
                                "domain": "avo-004.7-c7/fault/v1",
                                "case_id": case_id,
                                "vector_id": vector_id,
                            }
                        ),
                    ),
                }
                stub = MainGraduationOfflineDrillVectorSpec.model_construct(
                    **vector_values, vector_digest="sha256:" + "0" * 64
                )
                vector_values["vector_digest"] = canonical_digest(
                    {
                        "domain": "avo-004.7-c7/offline-drill-vector/v1",
                        "value": stub.model_dump(exclude={"vector_digest"}, mode="json"),
                    }
                )
                vectors.append(MainGraduationOfflineDrillVectorSpec.model_validate(vector_values))
            case_values: dict[str, Any] = {"case_id": case_id, "vectors": tuple(vectors)}
            case_values["plan_operation_id"] = self._operation_id
            case_values["case_digest"] = offline_drill_case_id(
                self._operation_id,
                case_id,
                [item.model_dump(mode="json") for item in vectors],
            )
            cases.append(MainGraduationOfflineDrillCaseSpec.model_validate(case_values))
        values: dict[str, Any] = {
            "operation_id": self._operation_id,
            **{
                key: self._authority_manifest[key]
                for key in (
                    "repository_digest",
                    "protocol_digest",
                    "configuration_digest",
                    "policy_digest",
                    "policy_epoch_digest",
                    "activation_digest",
                    "controller_authority_digest",
                    "controller_authority_ref",
                    "execution_authority_digest",
                    "execution_authority_ref",
                    "main_before_commit",
                    "main_before_tree",
                    "main_before_parents",
                )
            },
            "cases": tuple(cases),
        }
        plan_stub = MainGraduationOfflineDrillPlan.model_construct(
            **values, plan_digest="sha256:" + "0" * 64
        )
        values["plan_digest"] = canonical_digest(
            {
                "domain": "avo-004.7-c7/offline-drill-plan/v1",
                "value": plan_stub.model_dump(exclude={"plan_digest"}, mode="json"),
            }
        )
        plan = MainGraduationOfflineDrillPlan.model_validate(values)
        self._journal.record_plan(plan)
        return plan

    def run(self) -> MainGraduationOfflineDrillRun:
        plan = self.prepare()
        durable_result = self._journal.read_result(plan.operation_id)
        if durable_result is not None:
            return MainGraduationOfflineDrillRun(
                plan, durable_result[0].cases, durable_result[0], "complete"
            )
        cases: list[MainGraduationOfflineDrillCaseResult] = []
        pending: list[tuple[str, str]] = []
        for case_spec in plan.cases:
            for vector_spec in case_spec.vectors:
                loaded = self._journal.read_case_result(
                    plan.operation_id, case_spec.case_id, vector_spec.vector_id
                )
                if loaded is not None:
                    cases.append(loaded[0])
                    continue
                pending.append((case_spec.case_id, vector_spec.vector_id))
                observer = getattr(self._executor, "observe_once", None)
                if observer is None:
                    observer = getattr(self._executor, "observe", None)
                if observer is None:
                    observer = getattr(self._executor, "execute", None)
                if observer is None or not callable(observer):
                    raise MainGraduationOfflineDrillError(
                        "executor must provide observe(plan, case, vector)"
                    )
                observation = _coerce_observation(
                    self._invoke_observer(observer, plan, case_spec, vector_spec)
                )
                case_result = self._derive_case(plan, case_spec, vector_spec, observation)
                self._journal.record_case_result(case_result)
                cases.append(case_result)
        if len(cases) != sum(len(v) for v in FROZEN_OFFLINE_DRILL_VECTOR_IDS.values()):
            return MainGraduationOfflineDrillRun(
                plan, tuple(cases), None, "incomplete", tuple(pending)
            )
        values: dict[str, Any] = {
            "operation_id": plan.operation_id,
            "plan_digest": plan.plan_digest,
            "repository_digest": plan.repository_digest,
            "main_before_commit": plan.main_before_commit,
            "main_before_tree": plan.main_before_tree,
            "main_before_parents": plan.main_before_parents,
            "main_after_commit": plan.main_before_commit,
            "main_after_tree": plan.main_before_tree,
            "main_after_parents": plan.main_before_parents,
            "cases": tuple(cases),
            "deploy_performed": False,
        }
        result_stub = MainGraduationOfflineDrillResult.model_construct(
            **values, result_digest="sha256:" + "0" * 64
        )
        values["result_digest"] = canonical_digest(
            {
                "domain": "avo-004.7-c7/offline-drill-aggregate-result/v1",
                "value": result_stub.model_dump(exclude={"result_digest"}, mode="json"),
            }
        )
        result = MainGraduationOfflineDrillResult.model_validate(values)
        self._journal.record_result(result)
        return MainGraduationOfflineDrillRun(plan, tuple(cases), result, "complete")

    execute = run
    drill = run

    def replay(self) -> MainGraduationOfflineDrillResult:
        plan = self.prepare()
        loaded = self._journal.read_result(plan.operation_id)
        if loaded is None:
            raise MainGraduationOfflineDrillError("cannot replay an incomplete C7 drill")
        return loaded[0]

    @staticmethod
    def _invoke_observer(
        observer: Any,
        plan: MainGraduationOfflineDrillPlan,
        case: MainGraduationOfflineDrillCaseSpec,
        vector: MainGraduationOfflineDrillVectorSpec,
    ) -> object:
        """Invoke either object-oriented or compact executor protocols."""
        try:
            parameters = tuple(inspect.signature(observer).parameters.values())
        except (TypeError, ValueError) as exc:
            raise MainGraduationOfflineDrillError("executor signature is unavailable") from exc
        names = tuple(parameter.name for parameter in parameters)
        compact: dict[str, object] = {
            "plan": plan,
            "operation_id": plan.operation_id,
            "root_operation_id": plan.operation_id,
            "case": case,
            "case_id": case.case_id,
            "vector": vector,
            "vector_id": vector.vector_id,
        }
        if names and all(name in compact for name in names):
            return observer(**{name: compact[name] for name in names})
        if len(parameters) == 3:
            return observer(plan, case, vector)
        raise MainGraduationOfflineDrillError("unsupported executor signature")

    def _derive_case(
        self,
        plan: MainGraduationOfflineDrillPlan,
        case: MainGraduationOfflineDrillCaseSpec,
        vector: MainGraduationOfflineDrillVectorSpec,
        observation: OfflineDrillObservation,
    ) -> MainGraduationOfflineDrillCaseResult:
        if (
            observation.observed_outcome != vector.expected_outcome
            or observation.observed_state != vector.expected_state
        ):
            raise MainGraduationOfflineDrillError(
                f"observation differs from frozen expectation: {case.case_id}/{vector.vector_id}"
            )
        if (
            observation.main_after_commit != plan.main_before_commit
            or observation.main_after_tree != plan.main_before_tree
            or tuple(observation.main_after_parents) != plan.main_before_parents
        ):
            raise MainGraduationOfflineDrillError("offline observation changed main")
        if (
            observation.provider_mutation_count
            or observation.reconciliation_mutation_count
            or observation.release_mutation_count
        ):
            raise MainGraduationOfflineDrillError("offline observation contains mutation")
        crash = MainGraduationOfflineDrillCrashFacts(
            crash_injected=observation.crash_injected,
            crash_boundary=cast(Any, observation.crash_boundary),
            restart_count=observation.restart_count,
        )
        replay = MainGraduationOfflineDrillReplayFacts(
            replayed=observation.replayed,
            byte_identical=observation.byte_identical,
            read_only=observation.read_only,
            mutation_delta=observation.mutation_delta,
        )
        values: dict[str, Any] = {
            "root_operation_id": plan.operation_id,
            "plan_digest": plan.plan_digest,
            "case_id": case.case_id,
            "vector_id": vector.vector_id,
            "operation_id": offline_drill_operation_id(
                plan.operation_id, case.case_id, vector.vector_id
            ),
            "expected_outcome": vector.expected_outcome,
            "observed_outcome": observation.observed_outcome,
            "expected_state": vector.expected_state,
            "observed_state": observation.observed_state,
            "main_before_commit": plan.main_before_commit,
            "main_before_tree": plan.main_before_tree,
            "main_before_parents": plan.main_before_parents,
            "main_after_commit": observation.main_after_commit,
            "main_after_tree": observation.main_after_tree,
            "main_after_parents": tuple(observation.main_after_parents),
            "provider_mutation_count": 0,
            "reconciliation_mutation_count": 0,
            "release_mutation_count": 0,
            "crash_facts": crash,
            "replay_facts": replay,
            "injected_fault_digest": vector.fault_digest,
            "reason_code": observation.reason_code,
            "evidence_artifacts": observation.evidence_artifacts,
            "deploy_performed": False,
        }
        case_stub = MainGraduationOfflineDrillCaseResult.model_construct(
            **values, result_digest="sha256:" + "0" * 64
        )
        values["result_digest"] = canonical_digest(
            {
                "domain": "avo-004.7-c7/offline-drill-case-result/v1",
                "value": case_stub.model_dump(exclude={"result_digest"}, mode="json"),
            }
        )
        return MainGraduationOfflineDrillCaseResult.model_validate(values)


OfflineDrillService = MainGraduationOfflineDrillService
OfflineDrillRun = MainGraduationOfflineDrillRun
OfflineDrillObservationEnvelope = OfflineDrillObservation
OfflineDrillExecutor = OfflineDrillCaseExecutor

__all__ = [
    "MainGraduationOfflineDrillError",
    "MainGraduationOfflineDrillRun",
    "MainGraduationOfflineDrillService",
    "OfflineDrillCaseExecutor",
    "OfflineDrillClock",
    "OfflineDrillExecutor",
    "OfflineDrillObservation",
    "OfflineDrillObservationEnvelope",
    "OfflineDrillRun",
    "OfflineDrillService",
]
