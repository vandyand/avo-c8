"""Strict, deterministic contracts for the AVO-004.7 C7 offline gate.

The C7 wire is intentionally independent of the hosted graduation wires.  It
describes a frozen matrix and its observations; it does not grant a provider,
release, or deployment capability.  Self digests are content-addressing aids
only.  A consumer must still load the referenced records and use its
controller-owned verifier.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import (
    AliasChoices,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)

from avo_correlate.contracts.base import (
    ArtifactRef,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.domain.canonical import canonical_digest

GitObject = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")]
BoundedText = Annotated[str, StringConstraints(min_length=1, max_length=256, strip_whitespace=True)]
CaseId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")]
VectorId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{1,95}$")]

OFFLINE_PROOF_CLASS = "deterministic-offline-proof"

# This tuple is part of the protocol.  Do not derive it from an input matrix.
FROZEN_OFFLINE_DRILL_CASE_IDS: tuple[str, ...] = (
    "duplicate-lease-runners",
    "stale-base-cas",
    "package-drift",
    "composition-mismatch",
    "check-queue-protection",
    "provider-ambiguity",
    "wrong-topology",
    "crash-boundary-matrix",
    "rollback-conflict",
    "cleanup-ambiguity",
    "replay-idempotence",
    "regeneration-order-rerun",
    "issuer-capability-separation",
    "admission-group-identity",
    "c6-ledger-identity",
)

_OFFLINE_DRILL_VECTOR_IDS: dict[str, tuple[str, ...]] = {
    "duplicate-lease-runners": ("duplicate-runner", "stale-lease"),
    "stale-base-cas": ("stale-base", "cas-conflict"),
    "package-drift": ("package-digest-drift", "child-digest-drift"),
    "composition-mismatch": ("tree-mismatch", "parent-mismatch", "path-manifest-drift"),
    "check-queue-protection": ("check-failure", "queue-disabled", "protection-drift"),
    "provider-ambiguity": ("timeout", "lost-receipt", "ambiguous-provider"),
    "wrong-topology": ("multi-parent", "wrong-tree", "wrong-main"),
    "crash-boundary-matrix": (
        "before-preparation-auth",
        "after-preparation-auth",
        "before-enqueue",
        "after-enqueue",
        "before-release-auth",
        "after-release-auth",
        "after-hold-success",
    ),
    "rollback-conflict": ("rollback-stale-main", "rollback-delta-conflict"),
    "cleanup-ambiguity": ("cleanup-unknown", "cleanup-replay"),
    "replay-idempotence": ("completed-replay", "byte-identical-replay"),
    "regeneration-order-rerun": (
        "merge-group-regeneration",
        "queue-reorder",
        "check-rerun",
        "stale-hold",
        "duplicate-delivery",
    ),
    "issuer-capability-separation": (
        "wrong-issuer",
        "candidate-controlled-hold",
        "app15368-not-release",
    ),
    "admission-group-identity": (
        "admission-success",
        "group-separation",
        "unrelated-pr",
        "singleton-violation",
        "group-tree-mismatch",
    ),
    "c6-ledger-identity": ("c6-activation-drift", "c6-ledger-identity", "sequence-gap"),
}
FROZEN_OFFLINE_DRILL_VECTOR_IDS = MappingProxyType(_OFFLINE_DRILL_VECTOR_IDS)
# Immutable, order-preserving view useful to runners and parity tests.  The
# mapping above remains the readable public declaration; callers must not sort
# or infer this matrix from result data.
FROZEN_OFFLINE_DRILL_CASE_VECTOR_MATRIX: tuple[tuple[str, tuple[str, ...]], ...] = tuple(
    (case_id, FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id])
    for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS
)


def _domain_digest(domain: str, value: object) -> str:
    return canonical_digest({"domain": domain, "value": value})


def offline_drill_operation_id(root_operation_id: str, case_id: str, vector_id: str) -> str:
    """Derive a case/vector operation identity with domain separation."""
    return _domain_digest(
        "avo-004.7-c7/offline-drill-operation/v1",
        {"root_operation_id": root_operation_id, "case_id": case_id, "vector_id": vector_id},
    )


def offline_drill_case_id(plan_operation_id: str, case_id: str, vectors: object) -> str:
    return _domain_digest(
        "avo-004.7-c7/offline-drill-case/v1",
        {"plan_operation_id": plan_operation_id, "case_id": case_id, "vectors": vectors},
    )


def offline_drill_result_id(value: object) -> str:
    return _domain_digest("avo-004.7-c7/offline-drill-result/v1", value)


DrillOutcome = Literal[
    "passed",
    "pass",
    "success",
    "rejected",
    "safe_rejection",
    "reconciliation_required",
    "reconcile",
    "failed",
    "replayed",
]
DrillState = Literal[
    "unchanged",
    "failed_closed",
    "reconciled",
    "completed",
    "replayed_read_only",
    "rejected",
    "reconciliation_required",
    "read_only",
]


class MainGraduationOfflineEvidenceKind(StrEnum):
    """Controller-defined native evidence namespaces (never substring matched)."""

    C4_COMPLETION = "c4-completion"
    C4_RECOVERY = "c4-recovery"
    C5_ROLLBACK = "c5-rollback"
    C5_CLEANUP = "c5-cleanup"
    C6_LEDGER = "c6-ledger"
    C6_BOUNDARY = "c6-boundary"
    C6_THRESHOLD = "c6-threshold"
    PROVIDER_ATTESTER = "provider-attester"
    CONTROLLER_VERIFIER = "controller-verifier"
    EXECUTION_AUTHORITY = "execution-authority"
    EXECUTION_REPORT = "execution-report"


OFFLINE_EVIDENCE_ROLE_MEDIA: MappingProxyType = MappingProxyType(
    {
        MainGraduationOfflineEvidenceKind.C4_COMPLETION: (
            "c7-c4-completion",
            "application/vnd.avo.c7.c4-completion+json",
        ),
        MainGraduationOfflineEvidenceKind.C4_RECOVERY: (
            "c7-c4-recovery",
            "application/vnd.avo.c7.c4-recovery+json",
        ),
        MainGraduationOfflineEvidenceKind.C5_ROLLBACK: (
            "c7-c5-rollback",
            "application/vnd.avo.c7.c5-rollback+json",
        ),
        MainGraduationOfflineEvidenceKind.C5_CLEANUP: (
            "c7-c5-cleanup",
            "application/vnd.avo.c7.c5-cleanup+json",
        ),
        MainGraduationOfflineEvidenceKind.C6_LEDGER: (
            "c7-c6-ledger",
            "application/vnd.avo.c7.c6-ledger+json",
        ),
        MainGraduationOfflineEvidenceKind.C6_BOUNDARY: (
            "c7-c6-boundary",
            "application/vnd.avo.c7.c6-boundary+json",
        ),
        MainGraduationOfflineEvidenceKind.C6_THRESHOLD: (
            "c7-c6-threshold",
            "application/vnd.avo.c7.c6-threshold+json",
        ),
        MainGraduationOfflineEvidenceKind.PROVIDER_ATTESTER: (
            "c7-provider-attester",
            "application/vnd.avo.c7.provider-attester+json",
        ),
        MainGraduationOfflineEvidenceKind.CONTROLLER_VERIFIER: (
            "c7-controller-verifier",
            "application/vnd.avo.c7.controller-verifier+json",
        ),
        MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY: (
            "c7-execution-authority",
            "application/vnd.avo.c7.execution-authority+json",
        ),
        MainGraduationOfflineEvidenceKind.EXECUTION_REPORT: (
            "c7-execution-report",
            "application/vnd.avo.c7.execution-report+json",
        ),
    }
)


class MainGraduationOfflineEvidenceRef(StrictModel):
    schema_version: Literal[1] = 1
    kind: MainGraduationOfflineEvidenceKind
    artifact: ArtifactRef

    @model_validator(mode="after")
    def validate_native_ref(self) -> MainGraduationOfflineEvidenceRef:
        role, media_type = OFFLINE_EVIDENCE_ROLE_MEDIA[self.kind]
        if self.artifact.role != role or self.artifact.media_type != media_type:
            raise ValueError("native evidence role/media type is not allowed for its kind")
        return self


class MainGraduationOfflineExecutionNodeSpec(StrictModel):
    schema_version: Literal[1] = 1
    node_id: BoundedText
    parameter_id: BoundedText
    case_id: CaseId
    vector_id: VectorId
    expected_outcome: DrillOutcome
    expected_state: DrillState


def _frozen_node_specs() -> tuple[tuple[str, str, str, str], ...]:
    return tuple(
        (
            f"c7::{case_id}::{vector_id}",
            f"params::{case_id}::{vector_id}",
            case_id,
            vector_id,
        )
        for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS
        for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]
    )


FROZEN_OFFLINE_EXECUTION_NODE_IDS = tuple(item[0] for item in _frozen_node_specs())
FROZEN_OFFLINE_EXECUTION_PARAMETER_IDS = tuple(item[1] for item in _frozen_node_specs())


class MainGraduationOfflineExecutionAuthority(StrictModel):
    """Controller-owned authority manifest for one exact offline pytest run."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    authority_digest: Sha256Digest
    controller_authority_digest: Sha256Digest
    controller_authority_ref: BoundedText
    issuer_identity: BoundedText
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/main"] = "refs/heads/main"
    source_commit: GitObject
    source_tree: GitObject
    source_tree_digest: Sha256Digest
    protocol_digest: Sha256Digest
    configuration_digest: Sha256Digest
    policy_digest: Sha256Digest
    activation_digest: Sha256Digest
    lockfile_digest: Sha256Digest
    interpreter_digest: Sha256Digest
    pytest_digest: Sha256Digest
    plugin_set_digest: Sha256Digest
    toolchain_digest: Sha256Digest
    argv: tuple[BoundedText, ...] = Field(min_length=1, max_length=32)
    normalized_report_schema_digest: Sha256Digest
    normalized_report_media_type: Literal[
        "application/vnd.avo.c7.execution-report+json"
    ] = "application/vnd.avo.c7.execution-report+json"
    authorized_at: datetime
    expires_at: datetime
    nodes: tuple[MainGraduationOfflineExecutionNodeSpec, ...] = Field(
        min_length=1, max_length=128
    )

    _aware_authorized = field_validator("authorized_at", "expires_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_authority(self) -> MainGraduationOfflineExecutionAuthority:
        if self.expires_at <= self.authorized_at:
            raise ValueError("offline execution authority expiry must be after authorization")
        expected = _frozen_node_specs()
        actual = tuple((n.node_id, n.parameter_id, n.case_id, n.vector_id) for n in self.nodes)
        if actual != expected or len({item[0] for item in actual}) != len(actual):
            raise ValueError("authority nodes must exactly match the frozen case/vector matrix")
        if self.authority_digest != _domain_digest(
            "avo-004.7-c7/offline-execution-authority/v1",
            self.model_dump(exclude={"authority_digest"}, mode="json"),
        ):
            raise ValueError("offline execution authority digest mismatch")
        return self


class MainGraduationOfflineNodeObservation(StrictModel):
    schema_version: Literal[1] = 1
    node_id: BoundedText = Field(validation_alias=AliasChoices("node_id", "nodeid"))
    parameter_id: BoundedText
    case_id: CaseId
    vector_id: VectorId
    collected: Literal[True] = True
    outcome: DrillOutcome
    exit_status: Literal[0] = 0
    reason_code: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")]
    evidence_refs: tuple[MainGraduationOfflineEvidenceRef, ...] = Field(
        min_length=1, max_length=16
    )

    @model_validator(mode="after")
    def validate_observation(self) -> MainGraduationOfflineNodeObservation:
        if (
            self.node_id,
            self.parameter_id,
            self.case_id,
            self.vector_id,
        ) not in _frozen_node_specs():
            raise ValueError("observation does not identify a frozen node")
        if len({ref.artifact.digest for ref in self.evidence_refs}) != len(self.evidence_refs):
            raise ValueError("node evidence refs must be unique")
        return self


class MainGraduationOfflineExecutionReport(StrictModel):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    authority_digest: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/main"] = "refs/heads/main"
    source_commit: GitObject
    source_tree: GitObject
    source_tree_digest: Sha256Digest
    protocol_digest: Sha256Digest
    configuration_digest: Sha256Digest
    policy_digest: Sha256Digest
    activation_digest: Sha256Digest
    lockfile_digest: Sha256Digest
    interpreter_digest: Sha256Digest
    pytest_digest: Sha256Digest
    plugin_set_digest: Sha256Digest
    toolchain_digest: Sha256Digest
    argv: tuple[BoundedText, ...] = Field(min_length=1, max_length=32)
    collection_count: StrictInt = Field(ge=1, le=128)
    collected_node_ids: tuple[BoundedText, ...] = Field(min_length=1, max_length=128)
    observations: tuple[MainGraduationOfflineNodeObservation, ...] = Field(
        min_length=1, max_length=128
    )
    process_exit_code: Literal[0] = 0
    executed_at: datetime
    report_digest: Sha256Digest

    _aware_executed = field_validator("executed_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_report(self) -> MainGraduationOfflineExecutionReport:
        if len(self.observations) != self.collection_count:
            raise ValueError("execution collection count differs from observations")
        expected = _frozen_node_specs()
        actual = tuple(
            (n.node_id, n.parameter_id, n.case_id, n.vector_id) for n in self.observations
        )
        if actual != expected or (
            tuple(self.collected_node_ids) != FROZEN_OFFLINE_EXECUTION_NODE_IDS
        ):
            raise ValueError("execution report has missing, extra, duplicate, or reordered nodes")
        if self.report_digest != _domain_digest(
            "avo-004.7-c7/offline-execution-report/v1",
            self.model_dump(exclude={"report_digest"}, mode="json"),
        ):
            raise ValueError("offline execution report digest mismatch")
        return self


class MainGraduationOfflineDrillVectorSpec(StrictModel):
    """One immutable expected vector in the C7 matrix."""

    schema_version: Literal[1] = 1
    vector_id: VectorId
    expected_outcome: DrillOutcome
    expected_state: DrillState
    fault_digest: Sha256Digest = Field(
        validation_alias=AliasChoices("fault_digest", "injected_fault_digest")
    )
    vector_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_vector(self) -> MainGraduationOfflineDrillVectorSpec:
        expected = _domain_digest(
            "avo-004.7-c7/offline-drill-vector/v1",
            self.model_dump(exclude={"vector_digest"}, mode="json"),
        )
        if self.vector_digest != expected:
            raise ValueError("offline drill vector digest mismatch")
        return self


class MainGraduationOfflineDrillCaseSpec(StrictModel):
    schema_version: Literal[1] = 1
    case_id: CaseId
    vectors: tuple[MainGraduationOfflineDrillVectorSpec, ...] = Field(
        min_length=1, max_length=16, validation_alias=AliasChoices("vectors", "vector_specs")
    )
    case_digest: Sha256Digest = Field(validation_alias=AliasChoices("case_digest", "digest"))
    plan_operation_id: Sha256Digest | None = None

    @model_validator(mode="after")
    def validate_case(self) -> MainGraduationOfflineDrillCaseSpec:
        required = FROZEN_OFFLINE_DRILL_VECTOR_IDS.get(self.case_id)
        if required is None:
            raise ValueError("unknown frozen offline drill case")
        ids = tuple(item.vector_id for item in self.vectors)
        if ids != required or len(set(ids)) != len(ids):
            raise ValueError("case vectors must exactly match the frozen ordered matrix")
        local = _domain_digest(
            "avo-004.7-c7/offline-drill-case-spec/v1",
            self.model_dump(exclude={"case_digest"}, mode="json"),
        )
        bound = (
            offline_drill_case_id(
                self.plan_operation_id,
                self.case_id,
                [item.model_dump(mode="json") for item in self.vectors],
            )
            if self.plan_operation_id is not None
            else None
        )
        if self.case_digest != local and self.case_digest != bound:
            raise ValueError("offline drill case digest mismatch")
        return self


class MainGraduationOfflineDrillPlan(StrictModel):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/main"] = "refs/heads/main"
    protocol_digest: Sha256Digest = Field(
        validation_alias=AliasChoices("protocol_digest", "protocol_version_digest")
    )
    configuration_digest: Sha256Digest = Field(
        validation_alias=AliasChoices("configuration_digest", "config_digest")
    )
    policy_digest: Sha256Digest
    policy_epoch_digest: Sha256Digest = Field(
        validation_alias=AliasChoices("policy_epoch_digest", "policy_epoch")
    )
    activation_digest: Sha256Digest = Field(
        validation_alias=AliasChoices("activation_digest", "c6_activation_digest")
    )
    controller_authority_digest: Sha256Digest = Field(
        validation_alias=AliasChoices("controller_authority_digest", "controller_digest")
    )
    controller_authority_ref: BoundedText
    main_before_commit: GitObject
    main_before_tree: GitObject
    main_before_parents: tuple[GitObject, ...] = Field(min_length=0, max_length=2)
    proof_class: Literal["deterministic-offline-proof"] = OFFLINE_PROOF_CLASS
    deploy_performed: Literal[False] = False
    cases: tuple[MainGraduationOfflineDrillCaseSpec, ...] = Field(
        min_length=len(FROZEN_OFFLINE_DRILL_CASE_IDS),
        max_length=len(FROZEN_OFFLINE_DRILL_CASE_IDS),
        validation_alias=AliasChoices("cases", "case_specs"),
    )
    execution_authority_digest: Sha256Digest | None = Field(
        default=None,
        validation_alias=AliasChoices("execution_authority_digest", "authority_digest"),
    )
    execution_authority_ref: BoundedText | None = None
    plan_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_plan(self) -> MainGraduationOfflineDrillPlan:
        ids = tuple(item.case_id for item in self.cases)
        if ids != FROZEN_OFFLINE_DRILL_CASE_IDS or len(set(ids)) != len(ids):
            raise ValueError("plan cases must exactly match the frozen ordered matrix")
        if (self.execution_authority_digest is None) != (self.execution_authority_ref is None):
            raise ValueError("execution authority digest and ref must be supplied together")
        for case in self.cases:
            bound = offline_drill_case_id(
                self.operation_id,
                case.case_id,
                [item.model_dump(mode="json") for item in case.vectors],
            )
            local = _domain_digest(
                "avo-004.7-c7/offline-drill-case-spec/v1",
                case.model_dump(exclude={"case_digest"}, mode="json"),
            )
            if case.case_digest not in {bound, local}:
                raise ValueError("offline drill case is not bound to this plan")
        if self.plan_digest != _domain_digest(
            "avo-004.7-c7/offline-drill-plan/v1",
            self.model_dump(exclude={"plan_digest"}, mode="json"),
        ):
            raise ValueError("offline drill plan digest mismatch")
        return self


class MainGraduationOfflineDrillCrashFacts(StrictModel):
    schema_version: Literal[1] = 1
    crash_injected: StrictBool
    crash_boundary: Literal[
        "none",
        "before-preparation-auth",
        "after-preparation-auth",
        "before-enqueue",
        "after-enqueue",
        "before-release-auth",
        "after-release-auth",
        "after-hold-success",
    ]
    restart_count: StrictInt = Field(ge=0, le=32)


class MainGraduationOfflineDrillReplayFacts(StrictModel):
    schema_version: Literal[1] = 1
    replayed: StrictBool
    byte_identical: StrictBool
    read_only: StrictBool
    mutation_delta: StrictInt = Field(ge=0, le=0)

    @model_validator(mode="after")
    def validate_replay(self) -> MainGraduationOfflineDrillReplayFacts:
        if self.replayed and (
            not self.byte_identical or not self.read_only or self.mutation_delta != 0
        ):
            raise ValueError("replay must be byte-identical, read-only, and mutation-free")
        return self


class MainGraduationOfflineDrillEvidenceRef(StrictModel):
    """Typed role wrapper for one immutable C4/C5/C6/provider/rollback/ledger/verifier ref."""

    schema_version: Literal[1] = 1
    evidence_type: Literal["c4", "c5", "c6", "provider", "rollback", "ledger", "verifier"]
    artifact: ArtifactRef
    evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_evidence(self) -> MainGraduationOfflineDrillEvidenceRef:
        if self.evidence_digest != self.artifact.digest:
            raise ValueError("typed evidence digest differs from artifact")
        return self


class MainGraduationOfflineDrillCaseResult(StrictModel):
    schema_version: Literal[1] = 1
    root_operation_id: Sha256Digest
    plan_digest: Sha256Digest
    case_id: CaseId
    vector_id: VectorId
    operation_id: Sha256Digest
    expected_outcome: DrillOutcome
    observed_outcome: DrillOutcome
    expected_state: DrillState
    observed_state: DrillState
    main_before_commit: GitObject
    main_before_tree: GitObject
    main_before_parents: tuple[GitObject, ...] = Field(min_length=0, max_length=2)
    main_after_commit: GitObject
    main_after_tree: GitObject
    main_after_parents: tuple[GitObject, ...] = Field(min_length=0, max_length=2)
    provider_mutation_count: StrictInt = Field(
        ge=0, le=100, validation_alias=AliasChoices("provider_mutation_count", "provider_mutations")
    )
    reconciliation_mutation_count: StrictInt = Field(
        ge=0,
        le=100,
        validation_alias=AliasChoices("reconciliation_mutation_count", "reconciliation_mutations"),
    )
    release_mutation_count: StrictInt = Field(
        ge=0, le=100, validation_alias=AliasChoices("release_mutation_count", "release_mutations")
    )
    crash_facts: MainGraduationOfflineDrillCrashFacts
    replay_facts: MainGraduationOfflineDrillReplayFacts
    injected_fault_digest: Sha256Digest
    reason_code: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")]
    evidence_artifacts: tuple[ArtifactRef, ...] = Field(min_length=7, max_length=32)
    execution_authority_digest: Sha256Digest | None = None
    execution_report_digest: Sha256Digest | None = None
    native_evidence_refs: tuple[MainGraduationOfflineEvidenceRef, ...] = Field(
        default_factory=tuple, max_length=16
    )
    deploy_performed: Literal[False] = False
    result_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_case_result(self) -> MainGraduationOfflineDrillCaseResult:
        if self.case_id not in FROZEN_OFFLINE_DRILL_VECTOR_IDS:
            raise ValueError("unknown frozen offline drill case")
        if self.vector_id not in FROZEN_OFFLINE_DRILL_VECTOR_IDS[self.case_id]:
            raise ValueError("unknown vector for frozen offline drill case")
        if self.operation_id != offline_drill_operation_id(
            self.root_operation_id, self.case_id, self.vector_id
        ):
            raise ValueError("case/vector operation identity mismatch")
        if self.expected_outcome != self.observed_outcome or (
            self.expected_state != self.observed_state
        ):
            raise ValueError("observed drill outcome/state differs from frozen expectation")
        if self.main_before_commit != self.main_after_commit or (
            self.main_before_tree != self.main_after_tree
        ):
            raise ValueError("offline drill changed main")
        if self.main_before_parents != self.main_after_parents:
            raise ValueError("offline drill changed main topology")
        if self.replay_facts.replayed and (
            self.provider_mutation_count
            or self.reconciliation_mutation_count
            or self.release_mutation_count
        ):
            raise ValueError("replay must have zero provider and reconciliation mutations")
        if (
            self.provider_mutation_count
            or self.reconciliation_mutation_count
            or self.release_mutation_count
        ):
            raise ValueError(
                "offline drill must not contain unexplained provider/release mutations"
            )
        if len({item.digest for item in self.evidence_artifacts}) != len(self.evidence_artifacts):
            raise ValueError("case evidence artifacts must be unique")
        if len({item.artifact.digest for item in self.native_evidence_refs}) != len(
            self.native_evidence_refs
        ):
            raise ValueError("native case evidence refs must be unique")
        evidence_roles = {item.role.casefold() for item in self.evidence_artifacts}
        required_kinds = ("c4", "c5", "c6", "provider", "rollback", "ledger", "verifier")
        if any(not any(kind in role for role in evidence_roles) for kind in required_kinds):
            raise ValueError(
                "case evidence must include typed C4/C5/C6/provider/rollback/ledger/verifier refs"
            )
        if self.result_digest != _domain_digest(
            "avo-004.7-c7/offline-drill-case-result/v1",
            self.model_dump(exclude={"result_digest"}, mode="json"),
        ):
            raise ValueError("offline drill case result digest mismatch")
        return self


class MainGraduationOfflineDrillResult(StrictModel):
    """Aggregate C7 result; coverage is exact over the plan's frozen matrix."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    plan_digest: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/main"] = "refs/heads/main"
    main_before_commit: GitObject
    main_before_tree: GitObject
    main_before_parents: tuple[GitObject, ...] = Field(min_length=0, max_length=2)
    main_after_commit: GitObject
    main_after_tree: GitObject
    main_after_parents: tuple[GitObject, ...] = Field(min_length=0, max_length=2)
    cases: tuple[MainGraduationOfflineDrillCaseResult, ...] = Field(min_length=1, max_length=128)
    execution_authority_digest: Sha256Digest | None = None
    execution_report_digest: Sha256Digest | None = None
    proof_class: Literal["deterministic-offline-proof"] = OFFLINE_PROOF_CLASS
    deploy_performed: Literal[False] = False
    result_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_result(self) -> MainGraduationOfflineDrillResult:
        keys = [(item.case_id, item.vector_id) for item in self.cases]
        if len(set(keys)) != len(keys):
            raise ValueError("aggregate has duplicate case/vector results")
        expected_keys = [
            (case_id, vector_id)
            for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS
            for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]
        ]
        if keys != expected_keys:
            raise ValueError(
                "aggregate must contain the complete frozen case/vector matrix in order"
            )
        if any(
            item.root_operation_id != self.operation_id
            or item.plan_digest != self.plan_digest
            or item.main_before_commit != self.main_before_commit
            or item.main_before_tree != self.main_before_tree
            or item.main_before_parents != self.main_before_parents
            or item.main_after_commit != self.main_after_commit
            or item.main_after_tree != self.main_after_tree
            or item.main_after_parents != self.main_after_parents
            or item.deploy_performed
            for item in self.cases
        ):
            raise ValueError("aggregate case binding differs from root")
        if any(
            item.execution_authority_digest != self.execution_authority_digest
            or item.execution_report_digest != self.execution_report_digest
            for item in self.cases
        ):
            raise ValueError("aggregate execution manifest binding differs from root")
        if self.main_before_commit != self.main_after_commit or (
            self.main_before_tree != self.main_after_tree
        ):
            raise ValueError("aggregate changed main")
        if self.main_before_parents != self.main_after_parents:
            raise ValueError("aggregate changed main topology")
        if self.result_digest != _domain_digest(
            "avo-004.7-c7/offline-drill-aggregate-result/v1",
            self.model_dump(exclude={"result_digest"}, mode="json"),
        ):
            raise ValueError("offline drill aggregate digest mismatch")
        return self


# Concise aliases match the names used by the older AVO-004.6 drill runner.
OfflineDrillPlan = MainGraduationOfflineDrillPlan
OfflineDrillCaseSpec = MainGraduationOfflineDrillCaseSpec
OfflineDrillVectorSpec = MainGraduationOfflineDrillVectorSpec
OfflineDrillCaseResult = MainGraduationOfflineDrillCaseResult
OfflineDrillResult = MainGraduationOfflineDrillResult
MainGraduationOfflineDrillAggregateResult = MainGraduationOfflineDrillResult
MainGraduationOfflineDrillCase = MainGraduationOfflineDrillCaseSpec
MainGraduationOfflineDrillVector = MainGraduationOfflineDrillVectorSpec

__all__ = [
    "FROZEN_OFFLINE_DRILL_CASE_IDS",
    "FROZEN_OFFLINE_DRILL_CASE_VECTOR_MATRIX",
    "FROZEN_OFFLINE_DRILL_VECTOR_IDS",
    "OFFLINE_PROOF_CLASS",
    "MainGraduationOfflineDrillAggregateResult",
    "MainGraduationOfflineDrillCase",
    "MainGraduationOfflineDrillCaseResult",
    "MainGraduationOfflineDrillCaseSpec",
    "MainGraduationOfflineDrillCrashFacts",
    "MainGraduationOfflineDrillEvidenceRef",
    "MainGraduationOfflineDrillPlan",
    "MainGraduationOfflineDrillReplayFacts",
    "MainGraduationOfflineDrillResult",
    "MainGraduationOfflineDrillVector",
    "MainGraduationOfflineDrillVectorSpec",
    "OfflineDrillCaseResult",
    "OfflineDrillCaseSpec",
    "OfflineDrillPlan",
    "OfflineDrillResult",
    "OfflineDrillVectorSpec",
    "offline_drill_case_id",
    "offline_drill_operation_id",
    "offline_drill_result_id",
]
