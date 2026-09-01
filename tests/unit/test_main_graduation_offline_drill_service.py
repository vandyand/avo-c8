# pyright: reportMissingImports=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUntypedFunctionDecorator=false, reportIncompatibleMethodOverride=false

"""Focused framework tests for the deterministic C7 offline drill service.

These tests verify the C7 plan/journal/service framework only.  They do not
claim that the reference executor drives the C4--C6 production boundaries.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.main_graduation_offline_drill_journal import (
    MainGraduationOfflineDrillJournalError,
)
from avo_correlate.application.main_graduation_offline_drill_service import (
    DeterministicOfflineDrillHarness,
    MainGraduationOfflineDrillError,
    MainGraduationOfflineDrillService,
    OfflineDrillObservation,
)
from avo_correlate.contracts.main_graduation_offline_drill import (
    FROZEN_OFFLINE_DRILL_CASE_IDS,
    FROZEN_OFFLINE_DRILL_VECTOR_IDS,
    MainGraduationOfflineDrillCaseSpec,
    MainGraduationOfflineDrillPlan,
)
from avo_correlate.domain.canonical import canonical_digest


class CountingExecutor:
    def __init__(self, root: Path) -> None:
        store = FilesystemArtifactStore(
            root / "artifacts", clock=lambda: datetime(2026, 1, 1, tzinfo=UTC)
        )
        self.delegate = DeterministicOfflineDrillHarness(store)
        self.calls = 0
        self.keys: list[tuple[str, str]] = []

    def observe(self, plan: Any, case: Any, vector: Any) -> OfflineDrillObservation:
        self.calls += 1
        self.keys.append((case.case_id, vector.vector_id))
        return self.delegate.observe(plan, case, vector)


def _run(root: Path) -> tuple[MainGraduationOfflineDrillService, CountingExecutor]:
    executor = CountingExecutor(root)
    service = MainGraduationOfflineDrillService(root, executor=executor)
    return service, executor


@pytest.fixture
def short_root() -> Any:
    """Keep Windows' nested CAS/index paths below MAX_PATH in these tests."""
    root = Path(tempfile.mkdtemp(prefix="c7-", dir=Path.cwd().anchor))
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_full_frozen_matrix_closes_and_aggregates(short_root: Path) -> None:
    service, executor = _run(short_root)
    execution = service.run()

    assert execution.status == "complete"
    assert execution.result is not None
    assert len(execution.cases) == 47
    assert executor.calls == 47
    assert [(case.case_id, case.vector_id) for case in execution.cases] == [
        (case_id, vector_id)
        for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS
        for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]
    ]
    assert execution.plan.main_before_commit == execution.result.main_after_commit
    assert execution.result.deploy_performed is False


def test_two_fresh_roots_are_byte_identical(short_root: Path) -> None:
    first = MainGraduationOfflineDrillService(short_root / "first").run()
    second = MainGraduationOfflineDrillService(short_root / "second").run()

    assert first.plan.plan_digest == second.plan.plan_digest
    assert first.result is not None and second.result is not None
    assert first.result.result_digest == second.result.result_digest
    assert first.result.model_dump_json() == second.result.model_dump_json()


def test_same_root_replay_is_read_only_and_executor_free(short_root: Path) -> None:
    first_service, first_executor = _run(short_root)
    first = first_service.run()
    before = sorted(
        (path.relative_to(short_root).as_posix(), path.read_bytes())
        for path in short_root.rglob("*")
        if path.is_file()
    )

    second_service, second_executor = _run(short_root)
    second = second_service.run()
    after = sorted(
        (path.relative_to(short_root).as_posix(), path.read_bytes())
        for path in short_root.rglob("*")
        if path.is_file()
    )

    assert first.result is not None and second.result is not None
    assert first.result.result_digest == second.result.result_digest
    assert first_executor.calls == 47
    assert second_executor.calls == 0
    assert before == after


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("main_after_commit", "f" * 40),
        ("main_after_tree", "f" * 40),
        ("provider_mutation_count", 1),
        ("reconciliation_mutation_count", 1),
        ("release_mutation_count", 1),
    ],
)
def test_changed_main_and_nonzero_mutation_observations_block(
    short_root: Path, field: str, value: object
) -> None:
    class MutatingExecutor(CountingExecutor):
        def observe(self, plan: Any, case: Any, vector: Any) -> OfflineDrillObservation:
            observation = super().observe(plan, case, vector)
            return replace(observation, **{field: value})

    executor = MutatingExecutor(short_root)
    with pytest.raises(MainGraduationOfflineDrillError):
        MainGraduationOfflineDrillService(short_root, executor=executor).run()


def test_deploy_flag_and_unknown_outcome_observations_block(short_root: Path) -> None:
    class BadExecutor(CountingExecutor):
        def observe(self, plan: Any, case: Any, vector: Any) -> object:
            observation = super().observe(plan, case, vector)
            if self.calls == 1:
                return {"deploy_performed": True}
            return replace(observation, observed_outcome="failed")

    with pytest.raises((MainGraduationOfflineDrillError, TypeError)):
        MainGraduationOfflineDrillService(
            short_root / "deploy", executor=BadExecutor(short_root / "deploy")
        ).run()

    class UnknownExecutor(CountingExecutor):
        def observe(self, plan: Any, case: Any, vector: Any) -> OfflineDrillObservation:
            return replace(super().observe(plan, case, vector), observed_outcome="failed")

    with pytest.raises(MainGraduationOfflineDrillError):
        MainGraduationOfflineDrillService(
            short_root / "unknown", executor=UnknownExecutor(short_root / "unknown")
        ).run()


def test_missing_and_duplicate_evidence_observations_block(short_root: Path) -> None:
    class MissingEvidenceExecutor(CountingExecutor):
        def observe(self, plan: Any, case: Any, vector: Any) -> OfflineDrillObservation:
            return replace(super().observe(plan, case, vector), evidence_artifacts=())

    with pytest.raises(
        (MainGraduationOfflineDrillError, MainGraduationOfflineDrillJournalError, ValidationError)
    ):
        MainGraduationOfflineDrillService(
            short_root / "missing", executor=MissingEvidenceExecutor(short_root / "missing")
        ).run()

    class DuplicateEvidenceExecutor(CountingExecutor):
        def observe(self, plan: Any, case: Any, vector: Any) -> OfflineDrillObservation:
            observation = super().observe(plan, case, vector)
            return replace(
                observation,
                evidence_artifacts=(observation.evidence_artifacts[0],) * 2,
            )

    with pytest.raises((MainGraduationOfflineDrillError, ValidationError)):
        MainGraduationOfflineDrillService(
            short_root / "duplicate", executor=DuplicateEvidenceExecutor(short_root / "duplicate")
        ).run()


def test_unknown_or_duplicate_vector_is_rejected_by_frozen_plan(short_root: Path) -> None:
    # This is a framework-level guard: no service result can be built from an
    # input plan that changes the immutable matrix.
    service = MainGraduationOfflineDrillService(short_root)
    plan = service.prepare().model_dump(mode="json")
    first = plan["cases"][0]
    first["vectors"] = [first["vectors"][0], first["vectors"][0]]
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseSpec.model_validate(first)

    altered = service.prepare().model_dump(mode="json")
    altered["cases"][0]["case_id"] = "unknown-case"
    altered["plan_digest"] = canonical_digest(
        {"domain": "avo-004.7-c7/offline-drill-plan/v1", "value": altered}
    )
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillPlan.model_validate(altered)


def test_restart_reloads_verified_journal_without_executor_calls(short_root: Path) -> None:
    first_service, first_executor = _run(short_root)
    first_service.run()
    second_service, second_executor = _run(short_root)
    replay = second_service.replay()

    assert replay.result_digest == first_service.replay().result_digest
    assert first_executor.calls == 47
    assert second_executor.calls == 0
