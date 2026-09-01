"""Focused adversarial tests for the C7 deterministic offline drill wires."""

from copy import deepcopy
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from avo_correlate.contracts.base import ArtifactRef
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
    offline_drill_operation_id,
)
from avo_correlate.domain.canonical import canonical_digest

D = "sha256:" + "a" * 64
BASE = "b" * 40
TREE = "c" * 40
PARENT = "d" * 40
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _digest(domain: str, value: object) -> str:
    return canonical_digest({"domain": domain, "value": value})


def _artifact(kind: str, index: int) -> ArtifactRef:
    return ArtifactRef(
        digest="sha256:" + format(index, "064x"),
        size_bytes=index,
        media_type="application/vnd.avo.main-graduation-offline-drill+json",
        role=f"c7-{kind}-evidence",
        created_at=NOW,
    )


def _first_vector() -> tuple[str, str]:
    case_id = FROZEN_OFFLINE_DRILL_CASE_IDS[0]
    return case_id, FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id][0]


def _cases() -> tuple[MainGraduationOfflineDrillCaseSpec, ...]:
    result = []
    for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS:
        vectors = []
        for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]:
            values = {
                "vector_id": vector_id,
                "expected_outcome": "reconciliation_required",
                "expected_state": "failed_closed",
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
        case_stub = MainGraduationOfflineDrillCaseSpec.model_construct(
            case_id=case_id, vectors=tuple(vectors), case_digest=D
        )
        case_values = {
            "case_id": case_id,
            "vectors": tuple(vectors),
            "case_digest": _digest(
                "avo-004.7-c7/offline-drill-case-spec/v1",
                case_stub.model_dump(exclude={"case_digest"}, mode="json"),
            ),
        }
        result.append(MainGraduationOfflineDrillCaseSpec.model_validate(case_values))
    return tuple(result)


def _plan() -> MainGraduationOfflineDrillPlan:
    values = {
        "operation_id": D,
        "repository_digest": D,
        "protocol_digest": D,
        "configuration_digest": D,
        "policy_digest": D,
        "policy_epoch_digest": D,
        "activation_digest": D,
        "controller_authority_digest": D,
        "controller_authority_ref": "refs/avo/c7-controller",
        "main_before_commit": BASE,
        "main_before_tree": TREE,
        "main_before_parents": (PARENT,),
        "cases": _cases(),
    }
    stub = MainGraduationOfflineDrillPlan.model_construct(**values, plan_digest=D)
    values["plan_digest"] = _digest(
        "avo-004.7-c7/offline-drill-plan/v1", stub.model_dump(exclude={"plan_digest"}, mode="json")
    )
    return MainGraduationOfflineDrillPlan.model_validate(values)


def _case_result(plan: MainGraduationOfflineDrillPlan, case_id: str, vector_id: str, index: int):
    values = {
        "root_operation_id": plan.operation_id,
        "plan_digest": plan.plan_digest,
        "case_id": case_id,
        "vector_id": vector_id,
        "operation_id": offline_drill_operation_id(plan.operation_id, case_id, vector_id),
        "expected_outcome": "reconciliation_required",
        "observed_outcome": "reconciliation_required",
        "expected_state": "failed_closed",
        "observed_state": "failed_closed",
        "main_before_commit": BASE,
        "main_before_tree": TREE,
        "main_before_parents": (PARENT,),
        "main_after_commit": BASE,
        "main_after_tree": TREE,
        "main_after_parents": (PARENT,),
        "provider_mutation_count": 0,
        "reconciliation_mutation_count": 0,
        "release_mutation_count": 0,
        "crash_facts": MainGraduationOfflineDrillCrashFacts(
            crash_injected=False, crash_boundary="none", restart_count=0
        ),
        "replay_facts": MainGraduationOfflineDrillReplayFacts(
            replayed=True, byte_identical=True, read_only=True, mutation_delta=0
        ),
        "injected_fault_digest": D,
        "reason_code": "expected-rejection",
        "evidence_artifacts": tuple(_artifact(kind, index + offset) for offset, kind in enumerate(
            ("c4", "c5", "c6", "provider", "rollback", "ledger", "verifier")
        )),
        "deploy_performed": False,
    }
    stub = MainGraduationOfflineDrillCaseResult.model_construct(**values, result_digest=D)
    values["result_digest"] = _digest(
        "avo-004.7-c7/offline-drill-case-result/v1",
        stub.model_dump(exclude={"result_digest"}, mode="json"),
    )
    return MainGraduationOfflineDrillCaseResult.model_validate(values)


def _result(plan: MainGraduationOfflineDrillPlan) -> MainGraduationOfflineDrillResult:
    cases = tuple(
        _case_result(plan, case_id, vector_id, index * 8 + 1)
        for index, (case_id, vector_id) in enumerate(
            pair
            for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS
            for pair in [
                (case_id, vector_id)
                for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]
            ]
        )
    )
    values = {
        "operation_id": plan.operation_id,
        "plan_digest": plan.plan_digest,
        "repository_digest": plan.repository_digest,
        "main_before_commit": BASE,
        "main_before_tree": TREE,
        "main_before_parents": (PARENT,),
        "main_after_commit": BASE,
        "main_after_tree": TREE,
        "main_after_parents": (PARENT,),
        "cases": cases,
    }
    stub = MainGraduationOfflineDrillResult.model_construct(**values, result_digest=D)
    values["result_digest"] = _digest(
        "avo-004.7-c7/offline-drill-aggregate-result/v1",
        stub.model_dump(exclude={"result_digest"}, mode="json"),
    )
    return MainGraduationOfflineDrillResult.model_validate(values)


def test_valid_complete_frozen_matrix_and_schema_is_strict() -> None:
    plan = _plan()
    result = _result(plan)
    assert len(result.cases) == sum(len(ids) for ids in FROZEN_OFFLINE_DRILL_VECTOR_IDS.values())
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillPlan.model_validate({**plan.model_dump(mode="json"), "extra": 1})


def test_digest_is_deterministic_across_input_mapping_order() -> None:
    first = _plan()
    values = deepcopy(first.model_dump(mode="json"))
    reordered = {key: values[key] for key in reversed(tuple(values))}
    assert MainGraduationOfflineDrillPlan.model_validate(reordered).plan_digest == first.plan_digest


@pytest.mark.parametrize("mutation", [
    lambda p: {**p, "cases": p["cases"][:-1]},
    lambda p: {**p, "cases": [*p["cases"][:-1], p["cases"][0]]},
    lambda p: {
        **p,
        "cases": [{**p["cases"][0], "case_id": "unknown-case"}, *p["cases"][1:]],
    },
])
def test_missing_duplicate_unknown_case_rejected(mutation) -> None:
    plan = _plan().model_dump(mode="json")
    changed = mutation(plan)
    changed["plan_digest"] = _digest(
        "avo-004.7-c7/offline-drill-plan/v1",
        {key: value for key, value in changed.items() if key != "plan_digest"},
    )
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillPlan.model_validate(changed)


def test_unknown_or_duplicate_vector_rejected() -> None:
    case = _plan().cases[0].model_dump(mode="json")
    case["vectors"] = [case["vectors"][0], {**case["vectors"][0], "vector_id": "unknown-vector"}]
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseSpec.model_validate(case)


@pytest.mark.parametrize(
    "field", ["root_operation_id", "plan_digest", "expected_outcome", "observed_state"]
)
def test_root_plan_and_expected_observed_drift_rejected(field: str) -> None:
    plan = _plan()
    case_id, vector_id = _first_vector()
    case = _case_result(plan, case_id, vector_id, 1)
    changed = case.model_dump(mode="json")
    changed[field] = "sha256:" + "f" * 64 if field != "observed_state" else "completed"
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseResult.model_validate(changed)


@pytest.mark.parametrize("field,value", [
    ("main_after_commit", "e" * 40),
    ("main_after_tree", "e" * 40),
    ("main_after_parents", []),
    ("deploy_performed", True),
    ("provider_mutation_count", 1),
    ("release_mutation_count", 1),
    ("reconciliation_mutation_count", 1),
])
def test_main_deploy_and_unexplained_mutation_drift_rejected(field: str, value: object) -> None:
    plan = _plan()
    case_id, vector_id = _first_vector()
    case = _case_result(plan, case_id, vector_id, 1)
    changed = case.model_dump(mode="json")
    changed[field] = value
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseResult.model_validate(changed)


def test_replay_mutation_delta_evidence_digest_role_and_self_auth_rejected() -> None:
    plan = _plan()
    case_id, vector_id = _first_vector()
    case = _case_result(plan, case_id, vector_id, 1)
    changed = case.model_dump(mode="json")
    changed["replay_facts"]["mutation_delta"] = 1
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseResult.model_validate(changed)
    changed = case.model_dump(mode="json")
    changed["evidence_artifacts"][0]["role"] = "wrong-role"
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseResult.model_validate(changed)
    changed = case.model_dump(mode="json")
    changed["evidence_artifacts"][0]["digest"] = D
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseResult.model_validate(changed)
    changed = case.model_dump(mode="json")
    changed["self_authenticated"] = True
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseResult.model_validate(changed)
