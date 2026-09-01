"""Strict, deterministic contracts for the AVO-004.7 C7 offline gate.

The C7 wire is intentionally independent of the hosted graduation wires.  It
describes a frozen matrix and its observations; it does not grant a provider,
release, or deployment capability.  Self digests are content-addressing aids
only.  A consumer must still load the referenced records and use its
controller-owned verifier.
"""

# Exact pytest node IDs are intentionally long and are protocol data.
# ruff: noqa: E501

from __future__ import annotations

from collections.abc import Mapping
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
_ZERO_SHA256 = "sha256:" + "0" * 64

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
    JUNIT_XML = "junit-xml"


OFFLINE_EVIDENCE_ROLE_MEDIA: Mapping[
    MainGraduationOfflineEvidenceKind, tuple[str, str]
] = MappingProxyType(
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
        MainGraduationOfflineEvidenceKind.JUNIT_XML: (
            "c7-junit-xml",
            "application/vnd.avo.c7.junit+xml",
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
    # These are oracle/assertion coverage labels.  They are never observations
    # of the system under test and must not be copied into a case verdict.
    oracle_expected_outcome: DrillOutcome = Field(
        validation_alias=AliasChoices("oracle_expected_outcome", "expected_outcome")
    )
    oracle_expected_state: DrillState = Field(
        validation_alias=AliasChoices("oracle_expected_state", "expected_state")
    )

    @property
    def expected_outcome(self) -> DrillOutcome:
        """Compatibility accessor; this is oracle metadata, not an observation."""
        return self.oracle_expected_outcome

    @property
    def expected_state(self) -> DrillState:
        return self.oracle_expected_state


_FROZEN_NODE_ID_BY_VECTOR: dict[tuple[str, str], str] = {
    ("duplicate-lease-runners", "duplicate-runner"): "test_main_rollback_authority_recovery_matrix.py::test_duplicate_runner_and_lease_claims_are_single_owner_or_conflicts",
    ("duplicate-lease-runners", "stale-lease"): "test_main_rollback_authority_recovery_matrix.py::test_stale_lease_is_rejected_before_rollback_intent",
    ("stale-base-cas", "stale-base"): "test_main_rollback_composition.py::test_inverse_rejects_advanced_main_before_candidate_retention",
    ("stale-base-cas", "cas-conflict"): "test_main_rollback_authority_recovery_matrix.py::test_fresh_process_rejects_rollback_artifact_index_cas_or_schema_tamper[cas]",
    ("package-drift", "package-digest-drift"): "test_main_graduation_contracts.py::test_preparation_chain_rejects_each_shared_binding_edge[package_digest-sha256:2222222222222222222222222222222222222222222222222222222222222222]",
    ("package-drift", "child-digest-drift"): "test_main_rollback_composition.py::test_inverse_rejects_wrong_completion_digest",
    ("composition-mismatch", "tree-mismatch"): "test_main_graduation_contracts.py::test_reconciliation_rejects_wrong_composition_tree_or_repository",
    ("composition-mismatch", "parent-mismatch"): "test_main_graduation_contracts.py::test_preparation_chain_rejects_each_shared_binding_edge[base_tree-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa]",
    ("composition-mismatch", "path-manifest-drift"): "test_main_graduation_contract_coverage.py::test_path_and_source_contracts_reject_normalization_and_artifact_substitution",
    ("check-queue-protection", "check-failure"): "test_protected_main_adversarial.py::test_check_run_exact_sha_app_state_and_freshness[mutation0]",
    ("check-queue-protection", "queue-disabled"): "test_protected_main_adversarial.py::test_queue_rejects_unsafe_graphql_configuration[maximumEntriesToMerge-2]",
    ("check-queue-protection", "protection-drift"): "test_protected_main_adversarial.py::test_protection_requires_active_full_ruleset_without_bypass[mutation0]",
    ("provider-ambiguity", "timeout"): "test_main_graduation_completion_filesystem.py::test_timeout_then_expired_fresh_recovery_completes_read_only_and_replays_exactly",
    ("provider-ambiguity", "lost-receipt"): "test_main_graduation_completion_filesystem.py::test_no_result_ambiguity_remains_reconciliation_required_after_expiry",
    ("provider-ambiguity", "ambiguous-provider"): "test_main_rollback_coordinator_adversarial_matrix.py::test_provider_crash_persists_ambiguous_once_and_fresh_recovery_is_read_only",
    ("wrong-topology", "multi-parent"): "test_protected_main_adversarial.py::test_merge_group_requires_authenticated_event_and_rechecks_commit_topology",
    ("wrong-topology", "wrong-tree"): "test_main_graduation_contract_coverage.py::test_provider_reconciliation_attestation_and_rollback_guards",
    ("wrong-topology", "wrong-main"): "test_main_graduation_contracts.py::test_main_binding_rejects_wrong_target_and_deploy",
    ("crash-boundary-matrix", "before-preparation-auth"): "test_main_graduation_coordinator_preparation.py::test_fresh_process_recovers_after_intent_before_dispatch_crash[candidate_publication]",
    ("crash-boundary-matrix", "after-preparation-auth"): "test_main_graduation_coordinator_preparation.py::test_fresh_process_recovers_after_applied_mutation_response_loss[candidate_publication]",
    ("crash-boundary-matrix", "before-enqueue"): "test_main_graduation_coordinator_preparation.py::test_fresh_process_recovers_after_intent_before_dispatch_crash[queue_enqueue]",
    ("crash-boundary-matrix", "after-enqueue"): "test_main_graduation_coordinator_preparation.py::test_fresh_process_recovers_after_applied_mutation_response_loss[queue_enqueue]",
    ("crash-boundary-matrix", "before-release-auth"): "test_main_graduation_c4_completion_gates.py::test_restart_matrix_never_repeats_irreversible_release_call[authorization-record_release_authorization-None-False]",
    ("crash-boundary-matrix", "after-release-auth"): "test_main_graduation_c4_completion_gates.py::test_restart_matrix_never_repeats_irreversible_release_call[claim-record_release_claim-None-False]",
    ("crash-boundary-matrix", "after-hold-success"): "test_main_graduation_c4_completion_gates.py::test_restart_matrix_never_repeats_irreversible_release_call[claimed-transition-record_claimed_release_transition-None-True]",
    ("rollback-conflict", "rollback-stale-main"): "test_main_rollback_authority_recovery_matrix.py::test_authority_drift_is_rejected_before_intent_or_provider_mutation[topology]",
    ("rollback-conflict", "rollback-delta-conflict"): "test_main_rollback_composition.py::test_inverse_requires_distinct_source_operation",
    ("cleanup-ambiguity", "cleanup-unknown"): "test_main_rollback_hosted_terminal.py::test_ambiguous_delete_is_reconciled_read_only_with_observer_identity",
    ("cleanup-ambiguity", "cleanup-replay"): "test_main_rollback_hosted_terminal.py::test_cleanup_replay_is_truthful_and_non_dispatching",
    ("replay-idempotence", "completed-replay"): "test_main_graduation_coordinator_preparation.py::test_happy_path_is_exact_four_stage_and_replay_is_read_only",
    ("replay-idempotence", "byte-identical-replay"): "test_main_graduation_ledger_service.py::test_boundary_reset_closes_activation_and_replays_package_read_only",
    ("regeneration-order-rerun", "merge-group-regeneration"): "test_main_graduation_coordinator_preparation.py::test_provider_queue_generation_changes_after_enqueue_and_replays_read_only",
    ("regeneration-order-rerun", "queue-reorder"): "test_main_graduation_c4_completion_gates.py::test_regenerated_queue_generation_cannot_reuse_durable_hold_authorization",
    ("regeneration-order-rerun", "check-rerun"): "test_main_graduation_contracts.py::test_merge_group_checks_reject_duplicate_context_rerun",
    ("regeneration-order-rerun", "stale-hold"): "test_main_graduation_completion_remediation.py::test_completion_rejects_stale_release_authority_chronology[claim_update0-None-release claim chronology]",
    ("regeneration-order-rerun", "duplicate-delivery"): "test_main_graduation_phase_a_adversarial.py::test_run_nonce_and_webhook_global_indexes_repair_missing_local_pointers",
    ("issuer-capability-separation", "wrong-issuer"): "test_main_graduation_contracts.py::test_transition_rejects_attacker_repository_or_issuer[issuer_identity-attacker]",
    ("issuer-capability-separation", "candidate-controlled-hold"): "test_main_graduation_coordinator_preparation.py::test_preparation_surface_has_no_release_or_main_mutation_capability",
    ("issuer-capability-separation", "app15368-not-release"): "test_main_graduation_phase_a_contracts.py::test_claimed_transition_receipt_requires_non_validation_issuer_and_claim",
    ("admission-group-identity", "admission-success"): "test_protected_main_adversarial.py::test_admission_attester_binds_issuer_isolation_and_pr_head_role",
    ("admission-group-identity", "group-separation"): "test_protected_main_adversarial.py::test_group_hold_check_is_exact_isolated_pending_run",
    ("admission-group-identity", "unrelated-pr"): "test_main_graduation_coordinator_preparation.py::test_foreign_pr_observation_fails_closed_before_admission_or_queue",
    ("admission-group-identity", "singleton-violation"): "test_protected_main_adversarial.py::test_graphql_queue_is_official_endpoint_and_binds_singleton_entry",
    ("admission-group-identity", "group-tree-mismatch"): "test_main_graduation_coordinator_preparation.py::test_foreign_post_queue_configuration_fails_closed",
    ("c6-ledger-identity", "c6-activation-drift"): "test_main_graduation_ledger_contracts.py::test_activation_rejects_stale_hosted_prerequisites",
    ("c6-ledger-identity", "c6-ledger-identity"): "test_main_graduation_ledger_journal.py::test_authority_is_mandatory_and_submission_is_gap_free",
    ("c6-ledger-identity", "sequence-gap"): "test_main_graduation_ledger_service.py::test_next_submission_is_rejected_until_predecessor_transitions",
}
FROZEN_OFFLINE_NODE_ID_BY_VECTOR = MappingProxyType(_FROZEN_NODE_ID_BY_VECTOR)


def _frozen_node_specs() -> tuple[tuple[str, str, str, str], ...]:
    return tuple(
        (
            _FROZEN_NODE_ID_BY_VECTOR[(case_id, vector_id)],
            vector_id,
            case_id,
            vector_id,
        )
        for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS
        for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]
    )


def _expected_vector(case_id: str, vector_id: str) -> tuple[DrillOutcome, DrillState]:
    if case_id == "replay-idempotence":
        return "replayed", "replayed_read_only"
    if (case_id, vector_id) in {
        ("crash-boundary-matrix", "after-hold-success"),
        ("admission-group-identity", "admission-success"),
    }:
        return "passed", "completed"
    return "reconciliation_required", "failed_closed"


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
    # A controller may pin the bounded child-process environment.  The zero
    # value is retained only for reading pre-C7 manifests; new authorities
    # should always provide the measured digest.
    environment_identity_digest: Sha256Digest
    uv_digest: Sha256Digest
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
        if self.environment_identity_digest == _ZERO_SHA256 or self.uv_digest == _ZERO_SHA256:
            raise ValueError("offline execution identity digests cannot use a zero sentinel")
        expected = _frozen_node_specs()
        actual = tuple((n.node_id, n.parameter_id, n.case_id, n.vector_id) for n in self.nodes)
        if actual != expected or len({item[0] for item in actual}) != len(actual):
            raise ValueError("authority nodes must exactly match the frozen case/vector matrix")
        if any(
            node.oracle_expected_outcome != _expected_vector(node.case_id, node.vector_id)[0]
            or node.oracle_expected_state != _expected_vector(node.case_id, node.vector_id)[1]
            for node in self.nodes
        ):
            raise ValueError("authority node expectation differs from frozen vector expectation")
        if self.authority_digest != _domain_digest(
            "avo-004.7-c7/offline-execution-authority/v1",
            self.model_dump(exclude={"authority_digest"}, mode="json"),
        ):
            raise ValueError("offline execution authority digest mismatch")
        return self


class MainGraduationOfflineWorkspaceIdentity(StrictModel):
    """Exact, locally measured identity of the verifier workspace/toolchain."""

    schema_version: Literal[1] = 1
    source_commit: GitObject
    source_tree: GitObject
    source_tree_digest: Sha256Digest
    lockfile_digest: Sha256Digest
    interpreter_digest: Sha256Digest
    pytest_digest: Sha256Digest
    plugin_set_digest: Sha256Digest
    toolchain_digest: Sha256Digest
    environment_identity_digest: Sha256Digest
    uv_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_execution_identity(self) -> MainGraduationOfflineWorkspaceIdentity:
        if self.environment_identity_digest == _ZERO_SHA256 or self.uv_digest == _ZERO_SHA256:
            raise ValueError("workspace identity digests cannot use a zero sentinel")
        return self


class MainGraduationOfflineNodeObservation(StrictModel):
    schema_version: Literal[1] = 1
    node_id: BoundedText = Field(validation_alias=AliasChoices("node_id", "nodeid"))
    parameter_id: BoundedText
    case_id: CaseId
    vector_id: VectorId
    collected: Literal[True] = True
    # A passing pytest node proves only that the pinned oracle test passed.
    # It does not prove the expected domain outcome/state.
    verification_status: Literal["pass"] = "pass"
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
    environment_identity_digest: Sha256Digest
    uv_digest: Sha256Digest
    argv: tuple[BoundedText, ...] = Field(min_length=1, max_length=32)
    collection_count: StrictInt = Field(ge=1, le=128)
    collected_node_ids: tuple[BoundedText, ...] = Field(min_length=1, max_length=128)
    observations: tuple[MainGraduationOfflineNodeObservation, ...] = Field(
        min_length=1, max_length=128
    )
    workspace_before_identity: MainGraduationOfflineWorkspaceIdentity = Field(
        validation_alias=AliasChoices("workspace_before_identity", "workspace_before")
    )
    workspace_after_identity: MainGraduationOfflineWorkspaceIdentity = Field(
        validation_alias=AliasChoices("workspace_after_identity", "workspace_after")
    )
    junit_xml_artifact: ArtifactRef = Field(
        validation_alias=AliasChoices("junit_xml_artifact", "junit_xml_ref", "junit_artifact")
    )
    process_exit_code: Literal[0] = 0
    executed_at: datetime
    authority_expires_at: datetime
    report_digest: Sha256Digest

    _aware_executed = field_validator("executed_at", "authority_expires_at")(
        require_aware_datetime
    )

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
        if self.executed_at > self.authority_expires_at:
            raise ValueError("execution report was produced after authority expiry")
        if self.workspace_before_identity != self.workspace_after_identity:
            raise ValueError("workspace identity changed during pytest execution")
        if self.environment_identity_digest != self.workspace_before_identity.environment_identity_digest:
            raise ValueError("execution environment identity differs from workspace identity")
        if self.uv_digest != self.workspace_before_identity.uv_digest:
            raise ValueError("execution uv identity differs from workspace identity")
        if (
            self.junit_xml_artifact.role != "c7-junit-xml"
            or self.junit_xml_artifact.media_type != "application/vnd.avo.c7.junit+xml"
            or self.junit_xml_artifact.size_bytes <= 0
        ):
            raise ValueError("execution report JUnit artifact metadata is invalid")
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
    # Oracle labels describe what assertion coverage the pinned test owns.
    oracle_expected_outcome: DrillOutcome = Field(
        validation_alias=AliasChoices("oracle_expected_outcome", "expected_outcome")
    )
    oracle_expected_state: DrillState = Field(
        validation_alias=AliasChoices("oracle_expected_state", "expected_state")
    )
    fault_digest: Sha256Digest = Field(
        validation_alias=AliasChoices("fault_digest", "injected_fault_digest")
    )
    vector_digest: Sha256Digest

    @property
    def expected_outcome(self) -> DrillOutcome:
        return self.oracle_expected_outcome

    @property
    def expected_state(self) -> DrillState:
        return self.oracle_expected_state

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
    plan_operation_id: Sha256Digest

    @model_validator(mode="after")
    def validate_case(self) -> MainGraduationOfflineDrillCaseSpec:
        required = FROZEN_OFFLINE_DRILL_VECTOR_IDS.get(self.case_id)
        if required is None:
            raise ValueError("unknown frozen offline drill case")
        ids = tuple(item.vector_id for item in self.vectors)
        if ids != required or len(set(ids)) != len(ids):
            raise ValueError("case vectors must exactly match the frozen ordered matrix")
        if any(
            (item.expected_outcome, item.expected_state)
            != _expected_vector(self.case_id, item.vector_id)
            for item in self.vectors
        ):
            raise ValueError("case vector expectation differs from the frozen matrix")
        bound = offline_drill_case_id(
            self.plan_operation_id,
            self.case_id,
            [item.model_dump(mode="json") for item in self.vectors],
        )
        if self.case_digest != bound:
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
    proof_class: Literal["deterministic-offline-proof"] = OFFLINE_PROOF_CLASS
    deploy_performed: Literal[False] = False
    cases: tuple[MainGraduationOfflineDrillCaseSpec, ...] = Field(
        min_length=len(FROZEN_OFFLINE_DRILL_CASE_IDS),
        max_length=len(FROZEN_OFFLINE_DRILL_CASE_IDS),
        validation_alias=AliasChoices("cases", "case_specs"),
    )
    execution_authority_digest: Sha256Digest = Field(
        validation_alias=AliasChoices("execution_authority_digest", "authority_digest")
    )
    execution_authority_ref: BoundedText
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
            if case.case_digest != bound or case.plan_operation_id != self.operation_id:
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
    oracle_expected_outcome: DrillOutcome = Field(
        validation_alias=AliasChoices("oracle_expected_outcome", "expected_outcome")
    )
    oracle_expected_state: DrillState = Field(
        validation_alias=AliasChoices("oracle_expected_state", "expected_state")
    )
    # This is the sole per-node runtime claim: pytest verified the pinned
    # oracle node.  No domain outcome/state is inferred from a pass.
    verification_status: Literal["pass"] = "pass"
    fault_digest: Sha256Digest = Field(
        validation_alias=AliasChoices("fault_digest", "injected_fault_digest")
    )
    reason_code: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")]
    execution_authority_digest: Sha256Digest
    execution_report_digest: Sha256Digest
    junit_xml_digest: Sha256Digest
    native_evidence_refs: tuple[MainGraduationOfflineEvidenceRef, ...] = Field(
        min_length=2, max_length=16
    )
    deploy_performed: Literal[False] = False
    result_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_case_result(self) -> MainGraduationOfflineDrillCaseResult:
        if self.case_id not in FROZEN_OFFLINE_DRILL_VECTOR_IDS:
            raise ValueError("unknown frozen offline drill case")
        if self.vector_id not in FROZEN_OFFLINE_DRILL_VECTOR_IDS[self.case_id]:
            raise ValueError("unknown vector for frozen offline drill case")
        if (self.oracle_expected_outcome, self.oracle_expected_state) != _expected_vector(
            self.case_id, self.vector_id
        ):
            raise ValueError("case result expectation differs from frozen vector expectation")
        if self.operation_id != offline_drill_operation_id(
            self.root_operation_id, self.case_id, self.vector_id
        ):
            raise ValueError("case/vector operation identity mismatch")
        if len({item.artifact.digest for item in self.native_evidence_refs}) != len(
            self.native_evidence_refs
        ):
            raise ValueError("native case evidence refs must be unique")
        native_kinds = {item.kind for item in self.native_evidence_refs}
        if {
            MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY,
            MainGraduationOfflineEvidenceKind.EXECUTION_REPORT,
        } - native_kinds:
            raise ValueError("case must include execution authority and report evidence refs")
        authority_refs = [
            item.artifact.digest
            for item in self.native_evidence_refs
            if item.kind is MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY
        ]
        report_refs = [
            item.artifact.digest
            for item in self.native_evidence_refs
            if item.kind is MainGraduationOfflineEvidenceKind.EXECUTION_REPORT
        ]
        if authority_refs != [self.execution_authority_digest]:
            raise ValueError("execution authority evidence is not bound to the case digest")
        if report_refs != [self.execution_report_digest]:
            raise ValueError("execution report evidence is not bound to the case digest")
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
    workspace_before_identity: MainGraduationOfflineWorkspaceIdentity = Field(
        validation_alias=AliasChoices("workspace_before_identity", "workspace_before")
    )
    workspace_after_identity: MainGraduationOfflineWorkspaceIdentity = Field(
        validation_alias=AliasChoices("workspace_after_identity", "workspace_after")
    )
    cases: tuple[MainGraduationOfflineDrillCaseResult, ...] = Field(min_length=1, max_length=128)
    execution_authority_digest: Sha256Digest
    execution_report_digest: Sha256Digest
    junit_xml_digest: Sha256Digest
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
            or item.deploy_performed
            for item in self.cases
        ):
            raise ValueError("aggregate case binding differs from root")
        if any(
            item.execution_authority_digest != self.execution_authority_digest
            or item.execution_report_digest != self.execution_report_digest
            or item.junit_xml_digest != self.junit_xml_digest
            for item in self.cases
        ):
            raise ValueError("aggregate execution manifest binding differs from root")
        native_kinds = {
            ref.kind
            for item in self.cases
            for ref in item.native_evidence_refs
        }
        if {
            MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY,
            MainGraduationOfflineEvidenceKind.EXECUTION_REPORT,
        } - native_kinds:
            raise ValueError("aggregate lacks controller-owned execution evidence")
        if self.workspace_before_identity != self.workspace_after_identity:
            raise ValueError("aggregate workspace identity changed")
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
    "FROZEN_OFFLINE_EXECUTION_NODE_IDS",
    "FROZEN_OFFLINE_EXECUTION_PARAMETER_IDS",
    "FROZEN_OFFLINE_NODE_ID_BY_VECTOR",
    "OFFLINE_EVIDENCE_ROLE_MEDIA",
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
    "MainGraduationOfflineEvidenceKind",
    "MainGraduationOfflineEvidenceRef",
    "MainGraduationOfflineExecutionAuthority",
    "MainGraduationOfflineExecutionNodeSpec",
    "MainGraduationOfflineExecutionReport",
    "MainGraduationOfflineNodeObservation",
    "MainGraduationOfflineWorkspaceIdentity",
    "OfflineDrillCaseResult",
    "OfflineDrillCaseSpec",
    "OfflineDrillPlan",
    "OfflineDrillResult",
    "OfflineDrillVectorSpec",
    "offline_drill_case_id",
    "offline_drill_operation_id",
    "offline_drill_result_id",
]
