"""Filesystem and adversarial coverage for the immutable C7 journal."""

# Test doubles intentionally exercise malformed verifier signatures and the
# repository's test environment does not expose pytest's type stubs to the
# standalone Pyright invocation.
# pyright: reportMissingImports=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportIncompatibleMethodOverride=false

from __future__ import annotations

import json
import multiprocessing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.main_graduation_offline_drill_journal import (
    MainGraduationOfflineDrillJournal,
    MainGraduationOfflineDrillJournalError,
    MainGraduationOfflineDrillRecordConflictError,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation_offline_drill import (
    FROZEN_OFFLINE_DRILL_CASE_IDS,
    FROZEN_OFFLINE_DRILL_VECTOR_IDS,
    MainGraduationOfflineDrillCaseResult,
    MainGraduationOfflineDrillPlan,
    MainGraduationOfflineDrillResult,
    offline_drill_operation_id,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

DIGEST = "sha256:" + "a" * 64
GIT = "a" * 40
NOW = datetime(2026, 9, 1, tzinfo=UTC)


class _Verifier:
    def __init__(self, answer: object = True) -> None:
        self.answer = answer
        self.calls: list[str] = []

    def verify_plan(self, _plan: MainGraduationOfflineDrillPlan) -> object:
        self.calls.append("plan")
        return self.answer

    def verify_case_result(
        self,
        _case: MainGraduationOfflineDrillCaseResult,
        _plan: MainGraduationOfflineDrillPlan,
        _evidence: object,
    ) -> object:
        self.calls.append("case")
        return self.answer

    def verify_result(
        self,
        _result: MainGraduationOfflineDrillResult,
        _plan: MainGraduationOfflineDrillPlan,
        _cases: object,
    ) -> object:
        self.calls.append("result")
        return self.answer


class _NoneVerifier(_Verifier):
    def verify_plan(self, _plan: MainGraduationOfflineDrillPlan) -> None:
        return None


class _ExceptionVerifier(_Verifier):
    def verify_plan(self, _plan: MainGraduationOfflineDrillPlan) -> object:
        raise RuntimeError("rejected")


class _WrongSignatureVerifier(_Verifier):
    def verify_plan(self, _plan: MainGraduationOfflineDrillPlan, _extra: object) -> object:
        return True


def _vector(case_id: str, vector_id: str) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": 1,
        "vector_id": vector_id,
        "expected_outcome": "passed",
        "expected_state": "unchanged",
        "fault_digest": DIGEST,
    }
    value["vector_digest"] = canonical_digest(
        {"domain": "avo-004.7-c7/offline-drill-vector/v1", "value": value}
    )
    return value


def _plan(
    *, operation_id: str = DIGEST, main_before_tree: str = GIT
) -> MainGraduationOfflineDrillPlan:
    cases: list[dict[str, Any]] = []
    for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS:
        vectors = [
            _vector(case_id, vector_id) for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]
        ]
        case: dict[str, Any] = {"schema_version": 1, "case_id": case_id, "vectors": vectors}
        case["case_digest"] = canonical_digest(
            {"domain": "avo-004.7-c7/offline-drill-case-spec/v1", "value": case}
        )
        cases.append(case)
    value: dict[str, Any] = {
        "schema_version": 1,
        "operation_id": operation_id,
        "repository_digest": DIGEST,
        "target_ref": "refs/heads/main",
        "protocol_digest": DIGEST,
        "configuration_digest": DIGEST,
        "policy_digest": DIGEST,
        "policy_epoch_digest": DIGEST,
        "activation_digest": DIGEST,
        "controller_authority_digest": DIGEST,
        "controller_authority_ref": "offline-controller",
        "main_before_commit": GIT,
        "main_before_tree": main_before_tree,
        "main_before_parents": [],
        "proof_class": "deterministic-offline-proof",
        "deploy_performed": False,
        "cases": cases,
    }
    value["plan_digest"] = canonical_digest(
        {"domain": "avo-004.7-c7/offline-drill-plan/v1", "value": value}
    )
    return MainGraduationOfflineDrillPlan.model_validate(value)


def _evidence(
    store: FilesystemArtifactStore,
    plan: MainGraduationOfflineDrillPlan,
    case_id: str,
    vector_id: str,
    *,
    role: str | None = None,
    media_type: str = "application/json",
    digest: str | None = None,
    size_bytes: int | None = None,
) -> tuple[ArtifactRef, ...]:
    operation_id = offline_drill_operation_id(plan.operation_id, case_id, vector_id)
    refs: list[ArtifactRef] = []
    for kind in ("c4", "c5", "c6", "provider", "rollback", "ledger", "verifier"):
        payload = {
            "c7_binding": {
                "schema_version": 1,
                "evidence_type": kind,
                "root_operation_id": plan.operation_id,
                "operation_id": operation_id,
                "case_id": case_id,
                "vector_id": vector_id,
                "link_id": f"{kind}-{case_id}-{vector_id}",
            }
        }
        raw = canonical_bytes(payload)
        ref = store.put_bytes(raw, media_type=media_type, role=role or kind, max_bytes=1024 * 1024)
        if digest is not None or size_bytes is not None:
            ref = ref.model_copy(
                update={
                    "digest": digest or ref.digest,
                    "size_bytes": size_bytes if size_bytes is not None else ref.size_bytes,
                }
            )
        refs.append(ref)
    return tuple(refs)


def _case(
    store: FilesystemArtifactStore,
    plan: MainGraduationOfflineDrillPlan,
    case_id: str,
    vector_id: str,
    *,
    evidence_kwargs: dict[str, Any] | None = None,
) -> MainGraduationOfflineDrillCaseResult:
    spec = next(item for item in plan.cases if item.case_id == case_id)
    vector = next(item for item in spec.vectors if item.vector_id == vector_id)
    operation_id = offline_drill_operation_id(plan.operation_id, case_id, vector_id)
    value: dict[str, Any] = {
        "schema_version": 1,
        "root_operation_id": plan.operation_id,
        "plan_digest": plan.plan_digest,
        "case_id": case_id,
        "vector_id": vector_id,
        "operation_id": operation_id,
        "expected_outcome": vector.expected_outcome,
        "observed_outcome": vector.expected_outcome,
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
        "crash_facts": {
            "schema_version": 1,
            "crash_injected": False,
            "crash_boundary": "none",
            "restart_count": 0,
        },
        "replay_facts": {
            "schema_version": 1,
            "replayed": False,
            "byte_identical": False,
            "read_only": False,
            "mutation_delta": 0,
        },
        "injected_fault_digest": vector.fault_digest,
        "reason_code": "offline-pass",
        "evidence_artifacts": _evidence(store, plan, case_id, vector_id, **(evidence_kwargs or {})),
        "deploy_performed": False,
    }
    value["result_digest"] = canonical_digest(
        {"domain": "avo-004.7-c7/offline-drill-case-result/v1", "value": value}
    )
    return MainGraduationOfflineDrillCaseResult.model_validate(value)


def _result(
    plan: MainGraduationOfflineDrillPlan, cases: tuple[MainGraduationOfflineDrillCaseResult, ...]
) -> MainGraduationOfflineDrillResult:
    value: dict[str, Any] = {
        "schema_version": 1,
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
        "cases": cases,
        "proof_class": "deterministic-offline-proof",
        "deploy_performed": False,
    }
    value["result_digest"] = canonical_digest(
        {"domain": "avo-004.7-c7/offline-drill-aggregate-result/v1", "value": value}
    )
    return MainGraduationOfflineDrillResult.model_validate(value)


_MISSING = object()


def _journal(
    root: Path, verifier: object = _MISSING
) -> tuple[
    MainGraduationOfflineDrillJournal, MainGraduationOfflineDrillPlan, FilesystemArtifactStore
]:
    store = FilesystemArtifactStore(root / "artifacts", clock=lambda: NOW)
    plan = _plan()
    selected = _Verifier() if verifier is _MISSING else verifier
    return (
        MainGraduationOfflineDrillJournal(root, selected, artifact_store=store),  # type: ignore[arg-type]
        plan,
        store,
    )


def _all_cases(
    journal: MainGraduationOfflineDrillJournal,
    plan: MainGraduationOfflineDrillPlan,
    store: FilesystemArtifactStore,
) -> tuple[MainGraduationOfflineDrillCaseResult, ...]:
    cases: list[MainGraduationOfflineDrillCaseResult] = []
    for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS:
        for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]:
            case = _case(store, plan, case_id, vector_id)
            journal.record_case_result(case)
            cases.append(case)
    return tuple(cases)


def test_write_fresh_read_and_replay_complete_matrix(tmp_path: Path) -> None:
    verifier = _Verifier()
    journal, plan, store = _journal(tmp_path, verifier)
    plan_ref = journal.record_plan(plan)
    cases = _all_cases(journal, plan, store)
    aggregate = _result(plan, cases)
    result_ref = journal.record_result(aggregate)
    restarted = MainGraduationOfflineDrillJournal(tmp_path, _Verifier(), artifact_store=store)
    assert restarted.read_plan(plan.operation_id) == (plan, plan_ref)
    for case in cases:
        assert (
            restarted.read_case_result(plan.operation_id, case.case_id, case.vector_id) is not None
        )
    assert restarted.read_result(plan.operation_id) == (aggregate, result_ref)
    assert journal.record_result(aggregate) == result_ref


def test_result_before_complete_matrix_and_durable_omission_rejected(tmp_path: Path) -> None:
    journal, plan, store = _journal(tmp_path)
    journal.record_plan(plan)
    first = _case(
        store,
        plan,
        FROZEN_OFFLINE_DRILL_CASE_IDS[0],
        FROZEN_OFFLINE_DRILL_VECTOR_IDS[FROZEN_OFFLINE_DRILL_CASE_IDS[0]][0],
    )
    journal.record_case_result(first)
    aggregate = _result(
        plan,
        tuple(
            _case(store, plan, case_id, vector_id)
            for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS
            for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]
        ),
    )
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.record_result(aggregate)


def test_create_once_conflict_and_replay_has_no_cas_writes(tmp_path: Path) -> None:
    verifier = _Verifier()
    journal, plan, _store = _journal(tmp_path, verifier)
    first = journal.record_plan(plan)
    calls = 0
    original = journal.artifact_store.put_bytes

    def counted(*args: Any, **kwargs: Any) -> ArtifactRef:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    journal.artifact_store.put_bytes = counted  # type: ignore[method-assign]
    assert journal.record_plan(plan) == first
    assert calls == 0
    with pytest.raises(MainGraduationOfflineDrillRecordConflictError):
        journal.record_plan(_plan(main_before_tree="b" * 40))


@pytest.mark.parametrize(
    "field,value",
    [
        ("role", "wrong-role"),
        ("media_type", "text/plain"),
        ("size_bytes", 999999),
        ("digest", "sha256:" + "b" * 64),
    ],
)
def test_child_ref_metadata_tamper_fails_closed(tmp_path: Path, field: str, value: object) -> None:
    journal, plan, store = _journal(tmp_path)
    journal.record_plan(plan)
    case_id = FROZEN_OFFLINE_DRILL_CASE_IDS[0]
    vector_id = FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id][0]
    case = _case(store, plan, case_id, vector_id)
    refs = list(case.evidence_artifacts)
    refs[0] = refs[0].model_copy(update={field: value})
    altered = case.model_copy(update={"evidence_artifacts": tuple(refs)})
    altered = altered.model_copy(
        update={
            "result_digest": canonical_digest(
                {
                    "domain": "avo-004.7-c7/offline-drill-case-result/v1",
                    "value": altered.model_dump(exclude={"result_digest"}, mode="json"),
                }
            )
        }
    )
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.record_case_result(altered)


def test_child_missing_and_foreign_binding_fail_on_restart(tmp_path: Path) -> None:
    journal, plan, store = _journal(tmp_path)
    journal.record_plan(plan)
    case_id = FROZEN_OFFLINE_DRILL_CASE_IDS[0]
    vector_id = FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id][0]
    case = _case(store, plan, case_id, vector_id)
    journal.record_case_result(case)
    store.delete(case.evidence_artifacts[0].digest)
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        MainGraduationOfflineDrillJournal(
            tmp_path, _Verifier(), artifact_store=store
        ).read_case_result(plan.operation_id, case_id, vector_id)

    foreign = _case(store, plan, case_id, vector_id)
    raw = store.path_for_digest(foreign.evidence_artifacts[0].digest).read_bytes()
    payload = json.loads(raw)
    payload["c7_binding"]["root_operation_id"] = "sha256:" + "b" * 64
    replacement = store.put_bytes(
        canonical_bytes(payload), media_type="application/json", role="c4", max_bytes=1024 * 1024
    )
    refs = list(foreign.evidence_artifacts)
    refs[0] = replacement
    altered = foreign.model_copy(update={"evidence_artifacts": tuple(refs)})
    altered = altered.model_copy(
        update={
            "result_digest": canonical_digest(
                {
                    "domain": "avo-004.7-c7/offline-drill-case-result/v1",
                    "value": altered.model_dump(exclude={"result_digest"}, mode="json"),
                }
            )
        }
    )
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.record_case_result(altered)


def test_plan_index_and_cas_tamper_fail_on_fresh_journal(tmp_path: Path) -> None:
    journal, plan, store = _journal(tmp_path)
    ref = journal.record_plan(plan)
    index = journal._plan_index(plan.operation_id)  # type: ignore[reportPrivateUsage]
    value = json.loads(index.read_text())
    value["role"] = "wrong-role"
    index.write_bytes(canonical_bytes(value))
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        MainGraduationOfflineDrillJournal(tmp_path, _Verifier(), artifact_store=store).read_plan(
            plan.operation_id
        )

    index.write_bytes(canonical_bytes(json.loads(canonical_bytes(ref).decode())))
    store.path_for_digest(ref.digest).write_bytes(b"tampered")
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        MainGraduationOfflineDrillJournal(tmp_path, _Verifier(), artifact_store=store).read_plan(
            plan.operation_id
        )


@pytest.mark.parametrize(
    "verifier",
    [None, _NoneVerifier(), _Verifier(False), _ExceptionVerifier(), _WrongSignatureVerifier()],
)
def test_verifier_failures_on_write(verifier: object | None, tmp_path: Path) -> None:
    journal, plan, _store = _journal(tmp_path, verifier if verifier is not None else None)
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        journal.record_plan(plan)


def test_verifier_failure_on_restart(tmp_path: Path) -> None:
    journal, plan, _store = _journal(tmp_path, _Verifier())
    journal.record_plan(plan)
    with pytest.raises(MainGraduationOfflineDrillJournalError):
        MainGraduationOfflineDrillJournal(
            tmp_path, _Verifier(False), artifact_store=journal.artifact_store
        ).read_plan(plan.operation_id)


def _race_worker(root: str, payload: bytes, queue: Any) -> None:
    plan = MainGraduationOfflineDrillPlan.model_validate(json.loads(payload))
    try:
        journal = MainGraduationOfflineDrillJournal(Path(root), _Verifier())
        queue.put(("ok", journal.record_plan(plan).digest))
    except Exception as exc:  # pragma: no cover - only exercised by spawn
        queue.put(("error", type(exc).__name__))


@pytest.mark.skipif(__import__("os").name != "nt", reason="acceptance race is Windows-specific")
def test_spawned_create_once_race_has_one_canonical_winner(tmp_path: Path) -> None:
    plan = _plan()
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    processes = [
        context.Process(target=_race_worker, args=(str(tmp_path), canonical_bytes(plan), queue))
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(30)
    outcomes = [queue.get(timeout=5) for _ in processes]
    assert all(status == "ok" for status, _digest in outcomes)
    assert len({digest for _status, digest in outcomes}) == 1
