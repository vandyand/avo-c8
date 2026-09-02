"""Offline reader for the forward source of a personal exact-CAS attempt.

This module is intentionally a leaf.  It owns no provider client, token,
writer, controller, or dispatch capability.  Its only authority is the
canonical read surface of a dedicated :class:`MainGraduationJournal`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.application.c4_capabilities import CandidatePublicationRequest
from avo_correlate.contracts.base import ArtifactRef, Sha256Digest, StrictModel
from avo_correlate.contracts.main_graduation import (
    EligibilityLedgerStarted,
    MainGraduationAttempt,
    MainGraduationEligibilityRecord,
    MainGraduationIntent,
    MainGraduationPlan,
    MainPreparationAuthorization,
    MainReleaseIssuerBinding,
    MainRollbackCompletionPackage,
)
from avo_correlate.contracts.main_graduation_phase_a import (
    MainLeaseEvidenceRecord,
    MainMutationIntent,
    MainMutationReceipt,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


class TrustedMainGraduationSourceError(RuntimeError):
    """The durable forward source is missing, malformed, or inconsistent."""


@dataclass(frozen=True)
class TrustedMainGraduationEvidenceRef:
    """Public, immutable locator for an accepted forward evidence source."""

    operation_id: Sha256Digest
    plan_digest: Sha256Digest
    plan_ref: ArtifactRef
    package_digest: Sha256Digest
    composition_digest: Sha256Digest
    base_commit: str
    base_tree: str
    candidate_commit: str
    candidate_tree: str
    candidate_ref: str


@dataclass(frozen=True)
class TrustedMainGraduationJournalConfiguration:
    """Controller-pinned inputs for constructing the read-only source port."""

    source_root: Path
    future_state_root: Path
    repository_digest: Sha256Digest
    release_issuer_binding: MainReleaseIssuerBinding
    policy_epoch: Sha256Digest
    composition_root: Path
    base_reader: object
    phase_a_authority_verifier: object
    rollback_authority_verifier: object
    ledger_activation_digest: Sha256Digest | None = None
    require_ledger: bool = False
    rollback_operation_id: Sha256Digest | None = None


class _MainGraduationReadPort(Protocol):
    def read_plan(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None: ...

    def read_intent(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None: ...

    def read_preparation_authorization(
        self, operation_id: str
    ) -> tuple[StrictModel, ArtifactRef] | None: ...

    def read_lease_evidence_record(
        self, operation_id: str
    ) -> tuple[MainLeaseEvidenceRecord, ArtifactRef] | None: ...

    def read_mutation_intent_by_operation_stage(
        self, operation_id: str, stage: str
    ) -> tuple[MainMutationIntent, ArtifactRef] | None: ...

    def read_mutation_receipt_for_intent(
        self, intent_digest: str
    ) -> tuple[MainMutationReceipt, ArtifactRef] | None: ...

    def read_ledger_started(
        self, activation_digest: str
    ) -> tuple[StrictModel, ArtifactRef] | None: ...

    def read_eligibility(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None: ...

    def read_attempt(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None: ...

    def read_rollback_completion(
        self, operation_id: str
    ) -> tuple[MainRollbackCompletionPackage, ArtifactRef] | None: ...


class _CanonicalMainGraduationReadPort:
    """Narrow adapter over a fully configured journal; no write surface."""

    def __init__(self, journal: MainGraduationJournal) -> None:
        self._journal = journal

    def read_plan(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._journal.read_plan(operation_id)

    def read_intent(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._journal.read_intent(operation_id)

    def read_preparation_authorization(
        self, operation_id: str
    ) -> tuple[StrictModel, ArtifactRef] | None:
        return self._journal.read_preparation_authorization(operation_id)

    def read_lease_evidence_record(
        self, operation_id: str
    ) -> tuple[MainLeaseEvidenceRecord, ArtifactRef] | None:
        return self._journal.read_lease_evidence_record(operation_id)

    def read_mutation_intent_by_operation_stage(
        self, operation_id: str, stage: str
    ) -> tuple[MainMutationIntent, ArtifactRef] | None:
        return self._journal.read_mutation_intent_by_operation_stage(operation_id, stage)  # type: ignore[arg-type]

    def read_mutation_receipt_for_intent(
        self, intent_digest: str
    ) -> tuple[MainMutationReceipt, ArtifactRef] | None:
        return self._journal.read_mutation_receipt_for_intent(intent_digest)

    def read_ledger_started(self, activation_digest: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._journal.read_ledger_started(activation_digest)

    def read_eligibility(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._journal.read_eligibility(operation_id)

    def read_attempt(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._journal.read_attempt(operation_id)

    def read_rollback_completion(
        self, operation_id: str
    ) -> tuple[MainRollbackCompletionPackage, ArtifactRef] | None:
        return self._journal.read_rollback_completion(operation_id)


def _build_read_port(
    config: TrustedMainGraduationJournalConfiguration,
) -> tuple[_MainGraduationReadPort, Path, Path]:
    source_root = _safe_root(config.source_root, must_exist=True)
    future_root = _safe_root(config.future_state_root, must_exist=False)
    if (
        source_root == future_root
        or source_root.is_relative_to(future_root)
        or future_root.is_relative_to(source_root)
    ):
        raise TrustedMainGraduationSourceError(
            "source and future state roots must be distinct and non-nested"
        )
    issuer = config.release_issuer_binding
    if type(issuer) is not MainReleaseIssuerBinding:
        raise TrustedMainGraduationSourceError("release issuer binding is not concrete")
    if (
        issuer.repository_digest != config.repository_digest
        or issuer.target_ref != "refs/heads/main"
        or config.policy_epoch
        != canonical_digest(
            {
                "controller_config_digest": issuer.controller_config_digest,
                "main_policy": "ordinary",
            }
        )
    ):
        raise TrustedMainGraduationSourceError("journal authority pins are inconsistent")
    required_capabilities = {
        "base reader": (config.base_reader, ("fresh_main_base",)),
        "Phase-A authority verifier": (
            config.phase_a_authority_verifier,
            (
                "verify_lease_evidence",
                "verify_fence_resolution",
                "verify_mutation_receipt",
                "verify_provider_post_state",
            ),
        ),
        "rollback authority verifier": (
            config.rollback_authority_verifier,
            (
                "verify_rollback_result",
                "verify_rollback_cleanup_receipt",
                "verify_rollback_cleanup_intent",
                "verify_rollback_cleanup_observation",
                "verify_rollback_post_state",
                "verify_rollback_cleanup_terminal",
            ),
        ),
    }
    for label, (capability, methods) in required_capabilities.items():
        if capability is None or any(
            not callable(getattr(capability, name, None)) for name in methods
        ):
            raise TrustedMainGraduationSourceError(f"{label} is not pinned")
    composition_root = _safe_root(config.composition_root, must_exist=True)
    journal = MainGraduationJournal(
        source_root,
        release_issuer_binding=issuer,
        policy_epoch=config.policy_epoch,
        composition_root=composition_root,
        repository_digest=config.repository_digest,
        base_reader=cast(Any, config.base_reader),
        phase_a_authority_verifier=cast(Any, config.phase_a_authority_verifier),
        rollback_authority_verifier=cast(Any, config.rollback_authority_verifier),
    )
    return _CanonicalMainGraduationReadPort(journal), source_root, future_root


@dataclass(frozen=True)
class TrustedMainGraduationOfflineResult:
    """Safe result of an offline source read.

    The result deliberately contains no writer, transport, controller, or
    authority object.  ``accepted`` means only that the forward evidence is
    internally coherent; it is not permission to mutate a provider.
    """

    operation_id: str
    accepted: bool
    reason: str
    rollback_completion_present: bool = False
    ledger_present: bool = False
    evidence_ref: TrustedMainGraduationEvidenceRef | None = None


@dataclass(frozen=True)
class _VerifiedExactCasForwardSource:
    """Private verified source retained only inside this read boundary."""

    plan: MainGraduationPlan
    intent: MainGraduationIntent
    preparation: MainPreparationAuthorization
    lease: MainLeaseEvidenceRecord
    candidate_intent: MainMutationIntent
    candidate_receipt: MainMutationReceipt
    plan_ref: ArtifactRef
    intent_ref: ArtifactRef
    preparation_ref: ArtifactRef
    lease_ref: ArtifactRef
    candidate_intent_ref: ArtifactRef
    candidate_receipt_ref: ArtifactRef
    ledger_started: EligibilityLedgerStarted | None = None
    eligibility: MainGraduationEligibilityRecord | None = None
    attempt: MainGraduationAttempt | None = None
    rollback_completion: MainRollbackCompletionPackage | None = None


def _safe_root(path: Path, *, must_exist: bool) -> Path:
    """Resolve a root while rejecting symlink components at the boundary."""

    candidate = Path(path)
    absolute = candidate if candidate.is_absolute() else Path.cwd() / candidate
    for component in [*reversed(absolute.parents), absolute]:
        if component.is_symlink():
            raise TrustedMainGraduationSourceError("source/state root contains a symlink")
    try:
        resolved = candidate.resolve(strict=must_exist)
    except OSError as exc:
        raise TrustedMainGraduationSourceError("source/state root cannot be resolved") from exc
    if must_exist and not resolved.is_dir():
        raise TrustedMainGraduationSourceError("source root must be a directory")
    if not must_exist and resolved.exists() and not resolved.is_dir():
        raise TrustedMainGraduationSourceError("future state root must be a directory")
    return resolved


def _require_record[T: StrictModel](
    result: tuple[StrictModel, ArtifactRef] | None,
    expected: type[T],
    label: str,
    role: str,
) -> tuple[T, ArtifactRef]:
    if result is None:
        raise TrustedMainGraduationSourceError(f"{label} is missing")
    record, reference = result
    if type(record) is not expected:
        raise TrustedMainGraduationSourceError(f"{label} is not a concrete typed record")
    try:
        data = canonical_bytes(record)
        checked = expected.model_validate_json(data)
    except (TypeError, ValueError) as exc:
        raise TrustedMainGraduationSourceError(f"{label} is not canonical") from exc
    if type(checked) is not expected or checked != record:
        raise TrustedMainGraduationSourceError(f"{label} canonical value differs")
    if (
        reference.digest != canonical_digest(checked)
        or reference.size_bytes != len(data)
        or reference.role != role
        or reference.media_type != f"application/vnd.avo.{role}+json"
    ):
        raise TrustedMainGraduationSourceError(f"{label} artifact identity differs")
    return checked, reference


def _same_binding(left: Any, right: Any) -> bool:
    return (
        left.operation_id == right.operation_id
        and left.repository_digest == right.repository_digest
        and left.target_ref == right.target_ref
    )


class TrustedMainGraduationEvidenceReader:
    """Read and verify one forward C4 source from an isolated journal.

    ``source_root`` is the only root from which evidence is read.  The
    separate ``future_state_root`` is reserved for later state and is checked
    now so a future implementation cannot accidentally make the source and
    mutation state the same or nested tree.  This class never writes either
    root and never exposes a mutation capability.
    """

    def __init__(
        self,
        config: TrustedMainGraduationJournalConfiguration,
    ) -> None:
        if config.require_ledger and config.ledger_activation_digest is None:
            raise TrustedMainGraduationSourceError(
                "ledger activation digest is required for this reader"
            )
        self._port, self._source_root, self._future_state_root = _build_read_port(config)
        self._repository_digest = config.repository_digest
        self._release_issuer_binding = config.release_issuer_binding
        self._policy_epoch = config.policy_epoch
        self._ledger_activation_digest = config.ledger_activation_digest
        self._require_ledger = config.require_ledger
        self._rollback_operation_id = config.rollback_operation_id

    @property
    def source_root(self) -> Path:
        return self._source_root

    @property
    def future_state_root(self) -> Path:
        return self._future_state_root

    def read(self, operation_id: Sha256Digest) -> TrustedMainGraduationOfflineResult:
        """Return an offline verdict; no positive result can dispatch a write."""

        try:
            source = self._read_verified(operation_id)
            return TrustedMainGraduationOfflineResult(
                operation_id=operation_id,
                accepted=True,
                reason="verified_forward_source",
                rollback_completion_present=source.rollback_completion is not None,
                ledger_present=source.ledger_started is not None,
                evidence_ref=TrustedMainGraduationEvidenceRef(
                    operation_id=source.intent.operation_id,
                    plan_digest=canonical_digest(source.plan),
                    plan_ref=source.plan_ref,
                    package_digest=source.plan.package.package_digest,
                    composition_digest=source.plan.composition.composition_digest,
                    base_commit=source.plan.composition.base_commit,
                    base_tree=source.plan.composition.base_tree,
                    candidate_commit=source.plan.composition.candidate_commit,
                    candidate_tree=source.plan.composition.candidate_tree,
                    candidate_ref=source.plan.composition.candidate_ref,
                ),
            )
        except (TrustedMainGraduationSourceError, MainGraduationJournalError, ValueError) as exc:
            return TrustedMainGraduationOfflineResult(
                operation_id=operation_id,
                accepted=False,
                reason=str(exc),
            )

    def _read_verified(self, operation_id: Sha256Digest) -> _VerifiedExactCasForwardSource:
        journal = self._port
        plan, plan_ref = _require_record(
            journal.read_plan(operation_id),
            MainGraduationPlan,
            "plan",
            "main-graduation-plan",
        )
        intent, intent_ref = _require_record(
            journal.read_intent(operation_id),
            MainGraduationIntent,
            "intent",
            "main-graduation-intent",
        )
        preparation, preparation_ref = _require_record(
            journal.read_preparation_authorization(operation_id),
            MainPreparationAuthorization,
            "preparation authorization",
            "main-graduation-preparation-authorization",
        )
        lease, lease_ref = _require_record(
            journal.read_lease_evidence_record(operation_id),
            MainLeaseEvidenceRecord,
            "lease evidence",
            "main-graduation-lease-evidence-record",
        )
        candidate_intent, candidate_intent_ref = _require_record(
            journal.read_mutation_intent_by_operation_stage(operation_id, "candidate_publication"),
            MainMutationIntent,
            "candidate publication intent",
            "main-graduation-mutation-intent",
        )
        candidate_receipt, candidate_receipt_ref = _require_record(
            journal.read_mutation_receipt_for_intent(candidate_intent.intent_digest),
            MainMutationReceipt,
            "candidate publication receipt",
            "main-graduation-mutation-receipt",
        )
        records = (plan, intent, preparation, lease, candidate_intent, candidate_receipt)
        if any(record.repository_digest != self._repository_digest for record in records):
            raise TrustedMainGraduationSourceError("forward source repository differs")
        if any(record.target_ref != "refs/heads/main" for record in records):
            raise TrustedMainGraduationSourceError("forward source target differs")
        if any(not _same_binding(record, plan) for record in records):
            raise TrustedMainGraduationSourceError("forward source operation binding differs")
        if (
            plan.policy_epoch != self._policy_epoch
            or plan.release_issuer_binding != self._release_issuer_binding
        ):
            raise TrustedMainGraduationSourceError("forward source authority pins differ")
        self._verify_forward_chain(
            plan, intent, preparation, lease, candidate_intent, candidate_receipt
        )
        ledger_started, eligibility, attempt = self._read_ledger(operation_id, plan)
        rollback_completion = self._read_rollback_audit(operation_id)
        return _VerifiedExactCasForwardSource(
            plan=plan,
            intent=intent,
            preparation=preparation,
            lease=lease,
            candidate_intent=candidate_intent,
            candidate_receipt=candidate_receipt,
            plan_ref=plan_ref,
            intent_ref=intent_ref,
            preparation_ref=preparation_ref,
            lease_ref=lease_ref,
            candidate_intent_ref=candidate_intent_ref,
            candidate_receipt_ref=candidate_receipt_ref,
            ledger_started=ledger_started,
            eligibility=eligibility,
            attempt=attempt,
            rollback_completion=rollback_completion,
        )

    @staticmethod
    def _verify_forward_chain(
        plan: MainGraduationPlan,
        intent: MainGraduationIntent,
        preparation: MainPreparationAuthorization,
        lease: MainLeaseEvidenceRecord,
        candidate_intent: MainMutationIntent,
        candidate_receipt: MainMutationReceipt,
    ) -> None:
        composition = plan.composition
        candidate_request = CandidatePublicationRequest.build(
            operation_id=plan.operation_id,
            repository_digest=plan.repository_digest,
            lease_epoch_digest=lease.lease_epoch_digest,
            candidate_ref=composition.candidate_ref,
            candidate_commit=composition.candidate_commit,
            preparation_authorization_digest=preparation.authorization_digest,
        )
        if (
            plan.package.operation_id != plan.operation_id
            or plan.package.repository_digest != plan.repository_digest
            or plan.package.target_ref != plan.target_ref
            or composition.operation_id != plan.operation_id
            or composition.repository_digest != plan.repository_digest
            or composition.target_ref != plan.target_ref
            or intent.plan_digest != canonical_digest(plan)
            or intent.package_digest != plan.package.package_digest
            or intent.composition_digest != composition.composition_digest
            or (intent.base_commit, intent.base_tree)
            != (composition.base_commit, composition.base_tree)
            or (intent.candidate_commit, intent.candidate_tree)
            != (
                composition.candidate_commit,
                composition.candidate_tree,
            )
            or intent.candidate_ref != composition.candidate_ref
            or preparation.plan_digest != canonical_digest(plan)
            or preparation.intent_digest != canonical_digest(intent)
            or preparation.package_digest != plan.package.package_digest
            or preparation.composition_digest != composition.composition_digest
            or (preparation.base_commit, preparation.base_tree)
            != (
                composition.base_commit,
                composition.base_tree,
            )
            or (preparation.candidate_commit, preparation.candidate_tree)
            != (
                composition.candidate_commit,
                composition.candidate_tree,
            )
            or preparation.lease_identity != lease.owner
            or preparation.lease_digest != lease.lease_digest
            or intent.lease_identity != lease.owner
            or intent.lease_digest != lease.lease_digest
            or intent.lease_epoch_digest != lease.lease_epoch_digest
            or intent.policy_epoch != plan.policy_epoch
            or intent.policy_epoch != lease.policy_epoch
            or preparation.policy_epoch != intent.policy_epoch
            or candidate_intent.preparation_authorization_digest != preparation.authorization_digest
            or candidate_intent.stage != "candidate_publication"
            or candidate_intent.lease_epoch_digest != lease.lease_epoch_digest
            or candidate_intent.policy_epoch_digest != intent.policy_epoch
            or candidate_intent.controller_config_digest != plan.controller_config_digest
            or candidate_intent.request_digest != candidate_request.request_digest
            or candidate_intent.external_identity.external_key != candidate_request.external_key
            or candidate_intent.external_identity.identity_digest
            != candidate_request.external_identity
            or candidate_receipt.intent_digest != candidate_intent.intent_digest
            or candidate_receipt.stage != "candidate_publication"
            or candidate_receipt.parent_intent_digest is not None
            or candidate_receipt.external_identity != candidate_intent.external_identity
            or candidate_receipt.preparation_authorization_digest
            != preparation.authorization_digest
            or candidate_receipt.lease_epoch_digest != lease.lease_epoch_digest
            or candidate_receipt.policy_epoch_digest != intent.policy_epoch
            or candidate_receipt.controller_config_digest != plan.controller_config_digest
            or candidate_receipt.lease_digest != lease.lease_digest
            or candidate_receipt.lease_identity != lease.owner
            or candidate_receipt.outcome not in {"applied", "already_applied"}
            or candidate_receipt.dispatch_started is not True
        ):
            raise TrustedMainGraduationSourceError("forward source semantic binding differs")
        if not (
            lease.acquired_at
            <= intent.recorded_at
            <= preparation.authorized_at
            <= candidate_intent.recorded_at
            <= candidate_receipt.observed_at
            < lease.expires_at
        ):
            raise TrustedMainGraduationSourceError("forward source chronology differs")

    def _read_ledger(
        self, operation_id: Sha256Digest, plan: MainGraduationPlan
    ) -> tuple[
        EligibilityLedgerStarted | None,
        MainGraduationEligibilityRecord | None,
        MainGraduationAttempt | None,
    ]:
        if self._ledger_activation_digest is None:
            if self._require_ledger:
                raise TrustedMainGraduationSourceError("ledger activation is missing")
            return None, None, None
        started, _ = _require_record(
            self._port.read_ledger_started(self._ledger_activation_digest),
            EligibilityLedgerStarted,
            "ledger activation",
            "main-graduation-ledger-started",
        )
        eligibility, _ = _require_record(
            self._port.read_eligibility(operation_id),
            MainGraduationEligibilityRecord,
            "eligibility record",
            "main-graduation-eligibility",
        )
        attempt, _ = _require_record(
            self._port.read_attempt(operation_id),
            MainGraduationAttempt,
            "graduation attempt",
            "main-graduation-attempt",
        )
        if (
            started.activation_digest != self._ledger_activation_digest
            or started.repository_digest != plan.repository_digest
            or started.target_ref != plan.target_ref
            or started.controller_config_digest != plan.controller_config_digest
            or eligibility.operation_id != operation_id
            or eligibility.repository_digest != plan.repository_digest
            or eligibility.target_ref != plan.target_ref
            or eligibility.classification != "eligible"
            or eligibility.ordinary is not True
            or eligibility.nonempty is not True
            or eligibility.scheduler_sequence <= started.scheduler_sequence_watermark
            or attempt.operation_id != operation_id
            or attempt.repository_digest != plan.repository_digest
            or attempt.target_ref != plan.target_ref
            or attempt.scheduler_sequence != eligibility.scheduler_sequence
            or attempt.eligibility_record_digest != canonical_digest(eligibility)
            or attempt.package_digest != plan.package.package_digest
        ):
            raise TrustedMainGraduationSourceError("ledger eligibility binding differs")
        return started, eligibility, attempt

    def _read_rollback_audit(
        self, operation_id: Sha256Digest
    ) -> MainRollbackCompletionPackage | None:
        if self._rollback_operation_id is None:
            return None
        result = self._port.read_rollback_completion(self._rollback_operation_id)
        if result is None:
            raise TrustedMainGraduationSourceError("rollback completion audit is missing")
        package, _ = _require_record(
            result,
            MainRollbackCompletionPackage,
            "rollback completion",
            "main-graduation-rollback-completion",
        )
        if package.source_completion.operation_id != operation_id:
            raise TrustedMainGraduationSourceError("rollback completion source differs")
        # Deliberately no field from this package participates in forward
        # authority.  It is parsed only to retain an integrity/audit fact.
        return package


def build_trusted_main_graduation_evidence_reader(
    config: TrustedMainGraduationJournalConfiguration,
) -> TrustedMainGraduationEvidenceReader:
    """Build the offline reader at the trusted controller composition boundary."""

    return TrustedMainGraduationEvidenceReader(config)


__all__ = [
    "TrustedMainGraduationEvidenceReader",
    "TrustedMainGraduationEvidenceRef",
    "TrustedMainGraduationJournalConfiguration",
    "TrustedMainGraduationOfflineResult",
    "TrustedMainGraduationSourceError",
    "build_trusted_main_graduation_evidence_reader",
]
