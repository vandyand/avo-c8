"""Focused adversarial tests for the C7 deterministic offline drill wires."""

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from pydantic import ValidationError

from avo_correlate.contracts.base import ArtifactRef
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
from avo_correlate.domain.canonical import canonical_digest

D = "sha256:" + "a" * 64
REPORT_D = "sha256:" + "e" * 64
JUNIT_D = "sha256:" + "f" * 64
BASE = "b" * 40
TREE = "c" * 40
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


def _first_vector() -> tuple[str, str]:
    case_id = FROZEN_OFFLINE_DRILL_CASE_IDS[0]
    return case_id, FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id][0]


def _workspace() -> MainGraduationOfflineWorkspaceIdentity:
    return MainGraduationOfflineWorkspaceIdentity(
        source_commit=BASE,
        source_tree=TREE,
        source_tree_digest=D,
        lockfile_digest=D,
        interpreter_digest=D,
        pytest_digest=D,
        plugin_set_digest=D,
        toolchain_digest=D,
        environment_identity_digest=D,
        uv_digest=D,
    )


def _junit_artifact() -> ArtifactRef:
    role, media_type = OFFLINE_EVIDENCE_ROLE_MEDIA[MainGraduationOfflineEvidenceKind.JUNIT_XML]
    return ArtifactRef(
        digest=JUNIT_D,
        size_bytes=47,
        media_type=media_type,
        role=role,
        created_at=NOW,
    )


def _cases() -> tuple[MainGraduationOfflineDrillCaseSpec, ...]:
    result: list[MainGraduationOfflineDrillCaseSpec] = []
    for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS:
        vectors: list[MainGraduationOfflineDrillVectorSpec] = []
        for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]:
            outcome, state = _expected(case_id, vector_id)
            values = {
                "vector_id": vector_id,
                "oracle_expected_outcome": outcome,
                "oracle_expected_state": state,
                "fault_digest": D,
            }
            vector_stub = MainGraduationOfflineDrillVectorSpec.model_construct(  # pyright: ignore[reportArgumentType]
                **cast(Any, values), vector_digest=D
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
            "case_digest": offline_drill_case_id(
                D, case_id, [item.model_dump(mode="json") for item in vectors]
            ),
        }
        result.append(MainGraduationOfflineDrillCaseSpec.model_validate(case_values))
    return tuple(result)


def _plan() -> MainGraduationOfflineDrillPlan:
    cases: list[MainGraduationOfflineDrillCaseSpec] = []
    for case in _cases():
        bound_digest = offline_drill_case_id(
            D,
            case.case_id,
            [item.model_dump(mode="json") for item in case.vectors],
        )
        cases.append(
            MainGraduationOfflineDrillCaseSpec.model_construct(  # pyright: ignore[reportArgumentType]
                case_id=case.case_id,
                vectors=case.vectors,
                case_digest=bound_digest,
                plan_operation_id=D,
            )
        )
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
        "cases": tuple(cases),
        "execution_authority_digest": D,
        "execution_authority_ref": "refs/avo/test-execution-authority",
    }
    stub = MainGraduationOfflineDrillPlan.model_construct(**values, plan_digest=D)  # pyright: ignore[reportArgumentType]
    values["plan_digest"] = _digest(
        "avo-004.7-c7/offline-drill-plan/v1",
        stub.model_dump(exclude={"plan_digest"}, mode="json"),
    )
    return MainGraduationOfflineDrillPlan.model_validate(values)


def _native_refs() -> tuple[MainGraduationOfflineEvidenceRef, ...]:
    refs: list[MainGraduationOfflineEvidenceRef] = []
    for kind, digest in (
        (MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY, D),
        (MainGraduationOfflineEvidenceKind.EXECUTION_REPORT, REPORT_D),
    ):
        role, media_type = OFFLINE_EVIDENCE_ROLE_MEDIA[kind]
        artifact = ArtifactRef(
            digest=digest,
            size_bytes=1,
            media_type=media_type,
            role=role,
            created_at=NOW,
        )
        refs.append(MainGraduationOfflineEvidenceRef(kind=kind, artifact=artifact))
    return tuple(refs)


def _case_result(
    plan: MainGraduationOfflineDrillPlan, case_id: str, vector_id: str
) -> MainGraduationOfflineDrillCaseResult:
    outcome, state = _expected(case_id, vector_id)
    values = {
        "root_operation_id": plan.operation_id,
        "plan_digest": plan.plan_digest,
        "case_id": case_id,
        "vector_id": vector_id,
        "operation_id": offline_drill_operation_id(plan.operation_id, case_id, vector_id),
        "oracle_expected_outcome": outcome,
        "oracle_expected_state": state,
        "verification_status": "pass",
        "fault_digest": D,
        "reason_code": "oracle-test-verified",
        "execution_authority_digest": D,
        "execution_report_digest": REPORT_D,
        "junit_xml_digest": JUNIT_D,
        "native_evidence_refs": _native_refs(),
    }
    stub = MainGraduationOfflineDrillCaseResult.model_construct(**values, result_digest=D)  # pyright: ignore[reportArgumentType]
    values["result_digest"] = _digest(
        "avo-004.7-c7/offline-drill-case-result/v1",
        stub.model_dump(exclude={"result_digest"}, mode="json"),
    )
    return MainGraduationOfflineDrillCaseResult.model_validate(values)


def _result(plan: MainGraduationOfflineDrillPlan) -> MainGraduationOfflineDrillResult:
    cases = tuple(
        _case_result(plan, case_id, vector_id)
        for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS
        for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]
    )
    workspace = _workspace()
    values = {
        "operation_id": plan.operation_id,
        "plan_digest": plan.plan_digest,
        "repository_digest": plan.repository_digest,
        "workspace_before_identity": workspace,
        "workspace_after_identity": workspace,
        "cases": cases,
        "execution_authority_digest": D,
        "execution_report_digest": REPORT_D,
        "junit_xml_digest": JUNIT_D,
    }
    stub = MainGraduationOfflineDrillResult.model_construct(**values, result_digest=D)  # pyright: ignore[reportArgumentType]
    values["result_digest"] = _digest(
        "avo-004.7-c7/offline-drill-aggregate-result/v1",
        stub.model_dump(exclude={"result_digest"}, mode="json"),
    )
    return MainGraduationOfflineDrillResult.model_validate(values)


def test_valid_complete_frozen_matrix_and_schema_is_strict() -> None:
    plan = _plan()
    result = _result(plan)
    expected_keys = [
        (case_id, vector_id)
        for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS
        for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]
    ]
    assert len(expected_keys) == 47
    assert [(item.case_id, item.vector_id) for item in result.cases] == expected_keys
    assert result.workspace_before_identity == _workspace()
    assert result.workspace_before_identity == result.workspace_after_identity
    assert all(item.verification_status == "pass" for item in result.cases)
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillPlan.model_validate({**plan.model_dump(mode="json"), "extra": 1})


def test_digest_is_deterministic_across_input_mapping_order() -> None:
    first = _plan()
    values = deepcopy(first.model_dump(mode="json"))
    reordered = {key: values[key] for key in reversed(tuple(values))}
    assert MainGraduationOfflineDrillPlan.model_validate(reordered).plan_digest == first.plan_digest


@pytest.mark.parametrize(  # pyright: ignore[reportUnknownArgumentType]
    "mutation",
    [  # pyright: ignore[reportUnknownArgumentType]
        lambda p: {**p, "cases": p["cases"][:-1]},  # pyright: ignore[reportUnknownLambdaType]
        lambda p: {**p, "cases": [*p["cases"][:-1], p["cases"][0]]},  # pyright: ignore[reportUnknownLambdaType]
        lambda p: {  # pyright: ignore[reportUnknownLambdaType]
            **p,
            "cases": [{**p["cases"][0], "case_id": "unknown-case"}, *p["cases"][1:]],
        },
    ],
)
def test_missing_duplicate_unknown_case_rejected(mutation: object) -> None:  # pyright: ignore[reportUnknownParameterType]
    plan = _plan().model_dump(mode="json")
    changed = cast(Any, mutation)(plan)
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


def test_alternate_local_case_digest_is_rejected() -> None:
    plan = _plan().model_dump(mode="json")
    case = plan["cases"][0]
    case["case_digest"] = _digest(
        "avo-004.7-c7/offline-drill-case-spec/v1",
        {key: value for key, value in case.items() if key != "case_digest"},
    )
    plan["plan_digest"] = _digest(
        "avo-004.7-c7/offline-drill-plan/v1",
        {key: value for key, value in plan.items() if key != "plan_digest"},
    )
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillPlan.model_validate(plan)


@pytest.mark.parametrize(
    "field",
    ["root_operation_id", "plan_digest", "oracle_expected_outcome", "oracle_expected_state"],
)
def test_root_plan_and_oracle_drift_rejected(field: str) -> None:
    plan = _plan()
    case_id, vector_id = _first_vector()
    case = _case_result(plan, case_id, vector_id)
    changed = case.model_dump(mode="json")
    changed[field] = (
        "sha256:" + "f" * 64
        if field in {"root_operation_id", "plan_digest"}
        else "passed"
    )
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseResult.model_validate(changed)


def test_oracle_labels_are_not_domain_observations() -> None:
    plan = _plan()
    case_id, vector_id = _first_vector()
    case = _case_result(plan, case_id, vector_id)
    assert case.verification_status == "pass"
    assert case.oracle_expected_outcome == "reconciliation_required"
    assert "observed_outcome" not in case.model_dump(mode="json")
    changed = case.model_dump(mode="json")
    changed["verification_status"] = "reconciliation_required"
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseResult.model_validate(changed)
    changed = case.model_dump(mode="json")
    changed["observed_outcome"] = "reconciliation_required"
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseResult.model_validate(changed)


@pytest.mark.parametrize(
    "field,value",
    [  # pyright: ignore[reportUnknownArgumentType]
        ("main_before_commit", BASE),
        ("main_after_commit", BASE),
        ("main_before_tree", TREE),
        ("main_after_tree", TREE),
        ("provider_mutation_count", 0),
        ("release_mutation_count", 0),
        ("reconciliation_mutation_count", 0),
        ("crash_facts", {"crash_injected": False, "crash_boundary": "none", "restart_count": 0}),
        (
            "replay_facts",
            {"replayed": False, "byte_identical": False, "read_only": False, "mutation_delta": 0},
        ),
        ("deploy_performed", True),
    ],
)
def test_legacy_main_mutation_crash_replay_facts_are_rejected(field: str, value: object) -> None:
    plan = _plan()
    case_id, vector_id = _first_vector()
    changed = _case_result(plan, case_id, vector_id).model_dump(mode="json")
    changed[field] = value
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseResult.model_validate(changed)


def test_case_evidence_bindings_and_digest_role_rejected() -> None:
    plan = _plan()
    case_id, vector_id = _first_vector()
    case = _case_result(plan, case_id, vector_id)
    changed = case.model_dump(mode="json")
    changed["native_evidence_refs"][0]["artifact"]["digest"] = REPORT_D
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseResult.model_validate(changed)
    changed = case.model_dump(mode="json")
    changed["native_evidence_refs"] = [changed["native_evidence_refs"][0]] * 2
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseResult.model_validate(changed)
    changed = case.model_dump(mode="json")
    changed["self_authenticated"] = True
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillCaseResult.model_validate(changed)


def _authority() -> MainGraduationOfflineExecutionAuthority:
    nodes = tuple(
        MainGraduationOfflineExecutionNodeSpec(
            node_id=FROZEN_OFFLINE_NODE_ID_BY_VECTOR[(case_id, vector_id)],
            parameter_id=vector_id,
            case_id=case_id,
            vector_id=vector_id,
            oracle_expected_outcome=cast(Any, _expected(case_id, vector_id)[0]),
            oracle_expected_state=cast(Any, _expected(case_id, vector_id)[1]),
        )
        for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS
        for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]
    )
    values = dict(
        operation_id=D,
        controller_authority_digest=D,
        controller_authority_ref="refs/avo/c7-controller",
        issuer_identity="c7-harness",
        repository_digest=D,
        source_commit=BASE,
        source_tree=TREE,
        source_tree_digest=D,
        protocol_digest=D,
        configuration_digest=D,
        policy_digest=D,
        activation_digest=D,
        lockfile_digest=D,
        interpreter_digest=D,
        pytest_digest=D,
        plugin_set_digest=D,
        toolchain_digest=D,
        environment_identity_digest=D,
        uv_digest=D,
        argv=("pytest", "-q", "tests/unit/test_main_graduation_offline_drill_contracts.py"),
        normalized_report_schema_digest=D,
        authorized_at=NOW,
        expires_at=datetime(2026, 1, 2, tzinfo=UTC),
        nodes=nodes,
    )
    stub = MainGraduationOfflineExecutionAuthority.model_construct(**values, authority_digest=D)  # pyright: ignore[reportArgumentType]
    values["authority_digest"] = _digest(
        "avo-004.7-c7/offline-execution-authority/v1",
        stub.model_dump(exclude={"authority_digest"}, mode="json"),
    )
    return MainGraduationOfflineExecutionAuthority.model_validate(values)


@pytest.mark.parametrize("field", ["environment_identity_digest", "uv_digest"])
def test_execution_authority_rejects_zero_identity_sentinels(field: str) -> None:
    values = _authority().model_dump(mode="json")
    values[field] = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="zero sentinel"):
        MainGraduationOfflineExecutionAuthority.model_validate(values)


def _execution_report(
    authority: MainGraduationOfflineExecutionAuthority,
) -> MainGraduationOfflineExecutionReport:
    role, media_type = OFFLINE_EVIDENCE_ROLE_MEDIA[
        MainGraduationOfflineEvidenceKind.CONTROLLER_VERIFIER
    ]
    observations: list[MainGraduationOfflineNodeObservation] = []
    for index, node in enumerate(authority.nodes, 1):
        artifact = ArtifactRef(
            digest="sha256:" + format(index + 100, "064x"),
            size_bytes=index,
            media_type=media_type,
            role=role,
            created_at=NOW,
        )
        observations.append(
            MainGraduationOfflineNodeObservation(
                node_id=node.node_id,
                parameter_id=node.parameter_id,
                case_id=node.case_id,
                vector_id=node.vector_id,
                reason_code="oracle-test-verified",
                evidence_refs=(
                    MainGraduationOfflineEvidenceRef(
                        kind=MainGraduationOfflineEvidenceKind.CONTROLLER_VERIFIER,
                        artifact=artifact,
                    ),
                ),
            )
        )
    workspace = MainGraduationOfflineWorkspaceIdentity(
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
    values = dict(
        operation_id=authority.operation_id,
        authority_digest=authority.authority_digest,
        repository_digest=authority.repository_digest,
        source_commit=authority.source_commit,
        source_tree=authority.source_tree,
        source_tree_digest=authority.source_tree_digest,
        protocol_digest=authority.protocol_digest,
        configuration_digest=authority.configuration_digest,
        policy_digest=authority.policy_digest,
        activation_digest=authority.activation_digest,
        lockfile_digest=authority.lockfile_digest,
        interpreter_digest=authority.interpreter_digest,
        pytest_digest=authority.pytest_digest,
        plugin_set_digest=authority.plugin_set_digest,
        toolchain_digest=authority.toolchain_digest,
        environment_identity_digest=authority.environment_identity_digest,
        uv_digest=authority.uv_digest,
        argv=authority.argv,
        collection_count=len(observations),
        collected_node_ids=FROZEN_OFFLINE_EXECUTION_NODE_IDS,
        observations=tuple(observations),
        workspace_before_identity=workspace,
        workspace_after_identity=workspace,
        junit_xml_artifact=_junit_artifact(),
        executed_at=datetime(2026, 1, 1, 12, tzinfo=UTC),
        authority_expires_at=authority.expires_at,
    )
    stub = MainGraduationOfflineExecutionReport.model_construct(**values, report_digest=D)  # pyright: ignore[reportArgumentType]
    values["report_digest"] = _digest(
        "avo-004.7-c7/offline-execution-report/v1",
        stub.model_dump(exclude={"report_digest"}, mode="json"),
    )
    return MainGraduationOfflineExecutionReport.model_validate(values)


def test_exact_authority_and_normalized_execution_report_bind_all_nodes() -> None:
    authority = _authority()
    report = _execution_report(authority)
    assert report.authority_digest == authority.authority_digest
    assert report.collection_count == 47
    assert tuple(report.collected_node_ids) == FROZEN_OFFLINE_EXECUTION_NODE_IDS
    assert all(item.verification_status == "pass" for item in report.observations)
    assert all(
        "oracle_expected_outcome" not in item.model_dump(mode="json")
        for item in report.observations
    )
    assert report.workspace_before_identity == _workspace()
    assert report.workspace_before_identity == report.workspace_after_identity
    assert report.junit_xml_artifact.digest == JUNIT_D


@pytest.mark.parametrize("field", ["source_commit", "toolchain_digest", "argv", "authority_digest"])
def test_execution_manifest_report_drift_rejected(field: str) -> None:
    authority = _authority()
    report = _execution_report(authority)
    changed = report.model_dump(mode="json")
    changed[field] = "sha256:" + "f" * 64 if field.endswith("digest") else ("changed",)
    if field == "source_commit":
        changed[field] = "e" * 40
    with pytest.raises(ValidationError):
        MainGraduationOfflineExecutionReport.model_validate(changed)


@pytest.mark.parametrize(  # pyright: ignore[reportUnknownArgumentType]
    "mutation",
    [  # pyright: ignore[reportUnknownArgumentType]
        lambda r: {  # pyright: ignore[reportUnknownLambdaType]
            **r,
            "workspace_after_identity": {
                **r["workspace_after_identity"],
                "source_tree": "e" * 40,
            },
        },
        lambda r: {**r, "environment_identity_digest": "sha256:" + "f" * 64},  # pyright: ignore[reportUnknownLambdaType]
        lambda r: {**r, "uv_digest": "sha256:" + "f" * 64},  # pyright: ignore[reportUnknownLambdaType]
        lambda r: {**r, "junit_xml_artifact": {**r["junit_xml_artifact"], "role": "generic"}},  # pyright: ignore[reportUnknownLambdaType]
        lambda r: {**r, "junit_xml_artifact": {**r["junit_xml_artifact"], "size_bytes": 0}},  # pyright: ignore[reportUnknownLambdaType]
    ],
)
def test_workspace_identity_and_junit_artifact_drift_rejected(mutation: object) -> None:  # pyright: ignore[reportUnknownParameterType]
    report = _execution_report(_authority())
    changed = cast(Any, mutation)(report.model_dump(mode="json"))
    with pytest.raises(ValidationError):
        MainGraduationOfflineExecutionReport.model_validate(changed)


def test_execution_node_omission_skip_and_generic_evidence_rejected() -> None:
    report = _execution_report(_authority())
    changed = report.model_dump(mode="json")
    changed["observations"] = changed["observations"][:-1]
    with pytest.raises(ValidationError):
        MainGraduationOfflineExecutionReport.model_validate(changed)
    observation = report.observations[0].model_dump(mode="json")
    observation["node_id"] = "unknown-node"
    with pytest.raises(ValidationError):
        MainGraduationOfflineNodeObservation.model_validate(observation)
    with pytest.raises(ValidationError):
        MainGraduationOfflineEvidenceRef(
            kind=MainGraduationOfflineEvidenceKind.C4_COMPLETION,
            artifact=ArtifactRef(
                digest=D,
                size_bytes=1,
                media_type="application/json",
                role="generic",
                created_at=NOW,
            ),
        )


def test_aggregate_requires_full_matrix_workspace_and_shared_digests() -> None:
    plan = _plan()
    result = _result(plan)
    changed = result.model_dump(mode="json")
    changed["cases"] = changed["cases"][:-1]
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillResult.model_validate(changed)
    changed = result.model_dump(mode="json")
    changed["workspace_after_identity"]["uv_digest"] = "sha256:" + "f" * 64
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillResult.model_validate(changed)
    changed = result.model_dump(mode="json")
    changed["cases"][0]["junit_xml_digest"] = D
    with pytest.raises(ValidationError):
        MainGraduationOfflineDrillResult.model_validate(changed)
