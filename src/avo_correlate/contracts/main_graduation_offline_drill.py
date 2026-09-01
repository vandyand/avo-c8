"""Strict, deterministic contracts for the AVO-004.7 C7 offline gate.

The C7 wire is intentionally independent of the hosted graduation wires.  It
describes a frozen matrix and its observations; it does not grant a provider,
release, or deployment capability.  Self digests are content-addressing aids
only.  A consumer must still load the referenced records and use its
controller-owned verifier.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import AliasChoices, Field, StrictBool, StrictInt, StringConstraints, model_validator

from avo_correlate.contracts.base import ArtifactRef, Sha256Digest, StrictModel
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
        if self.case_digest != local:
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
    plan_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_plan(self) -> MainGraduationOfflineDrillPlan:
        ids = tuple(item.case_id for item in self.cases)
        if ids != FROZEN_OFFLINE_DRILL_CASE_IDS or len(set(ids)) != len(ids):
            raise ValueError("plan cases must exactly match the frozen ordered matrix")
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
