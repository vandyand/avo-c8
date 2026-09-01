# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportIndexIssue=false, reportUnnecessaryCast=false, reportGeneralTypeIssues=false, reportOptionalMemberAccess=false

"""Pre-stage authority coordinator for protected-main rollback.

This module deliberately stops at the preparation authorization boundary.  It
does not publish a candidate, open a pull request, enqueue anything, or issue a
release transition.  The journal is the authority for every durable boundary;
the coordinator only derives the records and adopts exact records left by an
interrupted invocation.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal, cast

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
    MainGraduationRecordConflictError,
)
from avo_correlate.adapters.git.main_rollback_composition import (
    MainRollbackCompositionResult,
)
from avo_correlate.contracts.base import ArtifactRef, Sha256Digest
from avo_correlate.contracts.main_graduation import (
    MainCompletionPackage,
    MainReleaseIssuerBinding,
    MainRollbackAttemptAuthority,
    MainRollbackAuthorization,
    MainRollbackCompositionArtifact,
    MainRollbackIntent,
    MainRollbackPreparationAuthorization,
    main_rollback_operation_id,
)
from avo_correlate.contracts.main_graduation_phase_a import (
    MainLeaseEvidenceReadRequest,
    MainLeaseEvidenceRecord,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

_ZERO = "sha256:" + "0" * 64


class MainRollbackAuthorityError(RuntimeError):
    """The rollback authority cannot be safely derived or recovered."""


class TrustedClock:
    """Small structural clock protocol kept local to avoid a C4 dependency."""

    def now(self) -> datetime:  # pragma: no cover - protocol-like fallback
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class MainRollbackAuthorityResult:
    """Complete durable pre-stage rollback authority bundle."""

    operation_id: Sha256Digest
    state: Literal["prepared"]
    lease: MainLeaseEvidenceRecord
    composition: MainRollbackCompositionArtifact
    authorization: MainRollbackAuthorization
    intent: MainRollbackIntent
    attempt_authority: MainRollbackAttemptAuthority
    preparation_authorization: MainRollbackPreparationAuthorization
    artifact_refs: Mapping[str, ArtifactRef]

    @property
    def refs(self) -> Mapping[str, ArtifactRef]:
        """Compatibility alias for callers that call durable refs ``refs``."""

        return self.artifact_refs


@dataclass(frozen=True, slots=True)
class MainRollbackAuthorityPreview:
    """Final operation identity callers use to acquire the durable lease."""

    operation_id: Sha256Digest
    candidate_ref: str
    composition_id: Sha256Digest


@dataclass(frozen=True, slots=True)
class MainRollbackCurrentAuthority:
    """Fresh controller-owned protected-main and policy observation."""

    current_main_commit: str
    current_main_tree: str
    current_main_parent_commit: str
    policy_epoch: Sha256Digest
    controller_config_digest: Sha256Digest
    release_issuer_binding: MainReleaseIssuerBinding


def _digest_record(model: Any, values: Mapping[str, object], field: str) -> Any:
    """Build a strict digest-bearing record without trusting a caller digest."""

    data = dict(values)
    probe = model.model_construct(**data, **{field: _ZERO})
    data[field] = canonical_digest(probe.model_dump(exclude={field}, mode="json"))
    return model.model_validate(data)


class MainRollbackAuthority:
    """Derive and durably record one rollback attempt's authority bundle.

    ``composition`` must be the already verified offline inverse-composition
    result.  Its Git objects are treated as claims until the journal reparses
    and binds the exact inverse artifact.  ``lease`` is intentionally optional
    only as a convenience for recovery: when omitted, the coordinator reads
    the lease already persisted for the derived operation.  It never accepts a
    caller-only lease.
    """

    def __init__(
        self,
        *,
        journal: MainGraduationJournal,
        clock: TrustedClock,
        policy_epoch: Sha256Digest | None = None,
        controller_config_digest: Sha256Digest | None = None,
        release_issuer_binding: MainReleaseIssuerBinding | None = None,
        current_authority_reader: Callable[[], MainRollbackCurrentAuthority] | None = None,
        lease_acquirer: Callable[[Sha256Digest, str, str], MainLeaseEvidenceRecord]
        | None = None,
    ) -> None:
        self.journal = journal
        self.clock = clock
        self.policy_epoch = policy_epoch
        self.controller_config_digest = controller_config_digest
        self.release_issuer_binding = release_issuer_binding
        self.current_authority_reader = current_authority_reader
        self.lease_acquirer = lease_acquirer

    def preview(
        self,
        *,
        source_operation_id: Sha256Digest,
        attempt_nonce: str,
        composition: MainRollbackCompositionResult,
        policy_epoch: Sha256Digest | None = None,
        controller_config_digest: Sha256Digest | None = None,
        release_issuer_binding: MainReleaseIssuerBinding | None = None,
    ) -> MainRollbackAuthorityPreview:
        """Derive the final identity before lease acquisition or any writes."""

        source = self._source(source_operation_id)
        composition_artifact, _ = self._durable_composition(
            composition, source_operation_id
        )
        policy = policy_epoch or self.policy_epoch or source.plan.policy_epoch
        config = (
            controller_config_digest
            or self.controller_config_digest
            or source.release_issuer_binding.controller_config_digest
        )
        binding = (
            release_issuer_binding
            or self.release_issuer_binding
            or source.release_issuer_binding
        )
        self._validate_current_authority(source, policy, config, binding)
        operation_id = self._derive_operation_id(
            source_operation_id=source_operation_id,
            attempt_nonce=attempt_nonce,
            source=source,
            composition=composition_artifact,
            policy_epoch=policy,
            controller_config_digest=config,
            binding=binding,
        )
        return MainRollbackAuthorityPreview(
            operation_id=operation_id,
            candidate_ref=f"refs/heads/avo/main-rollback/{operation_id.removeprefix('sha256:')}",
            composition_id=composition_artifact.composition_id,
        )

    def prepare(
        self,
        *,
        source_operation_id: Sha256Digest,
        attempt_nonce: str,
        composition: MainRollbackCompositionResult,
        lease: MainLeaseEvidenceRecord | None = None,
        policy_epoch: Sha256Digest | None = None,
        controller_config_digest: Sha256Digest | None = None,
        release_issuer_binding: MainReleaseIssuerBinding | None = None,
    ) -> MainRollbackAuthorityResult:
        """Create or recover the complete pre-stage authority bundle.

        Every call re-derives the operation identity from immutable source,
        inverse, candidate, policy, and isolated issuer facts.  Timestamps and
        lease metadata never participate in that identity.  A changed nonce,
        source, composition, policy, or issuer therefore cannot adopt an
        existing operation accidentally.
        """

        try:
            source = self._source(source_operation_id)
            composition_artifact, composition_ref = self._durable_composition(
                composition, source_operation_id
            )
            policy = policy_epoch or self.policy_epoch or source.plan.policy_epoch
            config = (
                controller_config_digest
                or self.controller_config_digest
                or source.release_issuer_binding.controller_config_digest
            )
            binding = (
                release_issuer_binding
                or self.release_issuer_binding
                or source.release_issuer_binding
            )
            self._validate_current_authority(source, policy, config, binding)
            operation_id = self._derive_operation_id(
                source_operation_id=source_operation_id,
                attempt_nonce=attempt_nonce,
                source=source,
                composition=composition_artifact,
                policy_epoch=policy,
                controller_config_digest=config,
                binding=binding,
            )
            # Once the intent exists, recovery is strictly local adoption.  It
            # must remain possible after the transient lease expires: no new
            # provider dispatch is authorized by replaying local records.
            recovery = getattr(self.journal, "rollback_authority_recovery", None)
            if callable(recovery):
                with recovery(source_operation_id):
                    prior_intent = self.journal.read_rollback_intent(operation_id)
                    prior_auth = self.journal.read_rollback_authorization(operation_id)
            else:
                prior_intent = self.journal.read_rollback_intent(operation_id)
                prior_auth = self.journal.read_rollback_authorization(operation_id)
            if prior_intent is None and lease is None and self.lease_acquirer is not None:
                try:
                    lease = self.lease_acquirer(
                        operation_id, source.repository_digest, source.target_ref
                    )
                except Exception as exc:
                    raise MainRollbackAuthorityError(
                        "rollback lease acquisition was not durably confirmed"
                    ) from exc
            durable_lease = self._durable_lease(
                operation_id, lease, require_active=prior_intent is None
            )
            now = self._trusted_now()
            if prior_intent is None and not (
                durable_lease.acquired_at <= now < durable_lease.expires_at
            ):
                raise MainRollbackAuthorityError("rollback lease is expired or not yet active")
            if prior_intent is None:
                self._revalidate_after_lease(
                    source, composition_artifact, policy, config, binding
                )
            authority_at = now
            if prior_auth is not None:
                authority_at = cast(MainRollbackAuthorization, prior_auth[0]).authorized_at
            elif prior_intent is not None:
                authority_at = cast(MainRollbackIntent, prior_intent[0]).recorded_at

            candidate_ref = f"refs/heads/avo/main-rollback/{operation_id.removeprefix('sha256:')}"
            auth = self._build_authorization(
                operation_id=operation_id,
                source=source,
                composition=composition_artifact,
                lease=durable_lease,
                policy_epoch=policy,
                controller_config_digest=config,
                binding=binding,
                authorized_at=authority_at,
            )
            intent = self._build_intent(
                operation_id=operation_id,
                source=source,
                composition=composition_artifact,
                candidate_ref=candidate_ref,
                lease=durable_lease,
                policy_epoch=policy,
                authorization=auth,
                recorded_at=authority_at,
            )
            intent_ref = self._record_or_adopt(
                "rollback-intent",
                operation_id,
                intent,
                self.journal.record_rollback_intent,
                source_operation_id,
            )
            auth_ref = self._record_or_adopt(
                "rollback-authorization",
                operation_id,
                auth,
                self.journal.record_rollback_authorization,
                source_operation_id,
            )
            attempt = self._build_attempt(
                operation_id=operation_id,
                source=source,
                composition=composition_artifact,
                candidate_ref=candidate_ref,
                lease=durable_lease,
                policy_epoch=policy,
                controller_config_digest=config,
                binding=binding,
                attempt_nonce=attempt_nonce,
            )
            attempt_ref = self._record_or_adopt(
                "rollback-attempt-authority",
                operation_id,
                attempt,
                self.journal.record_rollback_attempt_authority,
                source_operation_id,
            )
            preparation = self._build_preparation(
                operation_id=operation_id,
                source=source,
                composition=composition_artifact,
                candidate_ref=candidate_ref,
                lease=durable_lease,
                policy_epoch=policy,
                authorization=auth,
                intent=intent,
                authorized_at=authority_at,
            )
            preparation_ref = self._record_or_adopt(
                "rollback-preparation-authorization",
                operation_id,
                preparation,
                self.journal.record_rollback_preparation_authorization,
                source_operation_id,
            )
            lease_loaded = self.journal.read_lease_evidence_record(operation_id)
            if lease_loaded is None:
                raise MainRollbackAuthorityError("rollback lease disappeared during preparation")
            return MainRollbackAuthorityResult(
                operation_id=operation_id,
                state="prepared",
                lease=cast(MainLeaseEvidenceRecord, lease_loaded[0]),
                composition=composition_artifact,
                authorization=auth,
                intent=intent,
                attempt_authority=attempt,
                preparation_authorization=preparation,
                artifact_refs={
                    "lease-evidence-record": lease_loaded[1],
                    "rollback-composition": composition_ref,
                    "rollback-intent": intent_ref,
                    "rollback-authorization": auth_ref,
                    "rollback-attempt-authority": attempt_ref,
                    "rollback-preparation-authorization": preparation_ref,
                },
            )
        except MainRollbackAuthorityError:
            raise
        except (
            MainGraduationJournalError,
            MainGraduationRecordConflictError,
            AttributeError,
            TypeError,
            ValueError,
        ) as exc:
            raise MainRollbackAuthorityError(
                "rollback authority preparation failed closed"
            ) from exc

    # ``authorize`` and ``prepare_authority`` are intentionally aliases: both
    # names appeared in early C5 callers and map to the same bounded operation.
    authorize = prepare
    prepare_authority = prepare

    def _source(self, operation_id: Sha256Digest) -> MainCompletionPackage:
        recovery = getattr(self.journal, "rollback_authority_recovery", None)
        if callable(recovery):
            with recovery(operation_id):
                loaded = self.journal.read_completion(operation_id)
        else:
            loaded = self.journal.read_completion(operation_id)
        if loaded is None:
            raise MainRollbackAuthorityError("source completion is not durably recorded")
        source = cast(MainCompletionPackage, loaded[0])
        if source.operation_id != operation_id or canonical_digest(source) != loaded[1].digest:
            raise MainRollbackAuthorityError("source completion canonical identity differs")
        if source.deploy_performed or source.reconciliation.state != "completed":
            raise MainRollbackAuthorityError("source completion is not an applied no-deploy result")
        return source

    @staticmethod
    def _composition(
        composition: MainRollbackCompositionResult, source_operation_id: Sha256Digest
    ) -> MainRollbackCompositionArtifact:
        artifact = cast(MainRollbackCompositionArtifact, composition.composition)
        if artifact.source_operation_id != source_operation_id:
            raise MainRollbackAuthorityError("composition source operation differs")
        if composition.source_operation_id != source_operation_id:
            raise MainRollbackAuthorityError("composition source operation differs")
        if composition.composition_artifact.digest != canonical_digest(artifact):
            raise MainRollbackAuthorityError("composition artifact reference digest differs")
        if artifact.composition_id != composition.composition_id:
            raise MainRollbackAuthorityError("composition identity differs")
        return artifact

    def _durable_composition(
        self,
        composition: MainRollbackCompositionResult,
        source_operation_id: Sha256Digest,
    ) -> tuple[MainRollbackCompositionArtifact, ArtifactRef]:
        """Adopt only the exact composition already recorded by the adapter."""

        artifact = self._composition(composition, source_operation_id)
        recovery = getattr(self.journal, "rollback_authority_recovery", None)
        context = recovery(source_operation_id) if callable(recovery) else None
        if context is None:
            loaded = self.journal.read_rollback_composition(artifact.composition_id)
        else:
            with context:
                loaded = self.journal.read_rollback_composition(artifact.composition_id)
        if loaded is None:
            raise MainRollbackAuthorityError(
                "rollback composition is not durably recorded"
            )
        durable = cast(MainRollbackCompositionArtifact, loaded[0])
        durable_ref = loaded[1]
        if (
            canonical_bytes(durable) != canonical_bytes(artifact)
            or durable_ref != composition.composition_artifact
        ):
            raise MainRollbackAuthorityError(
                "durable rollback composition differs from verified composition"
            )
        return durable, durable_ref

    def _durable_lease(
        self,
        operation_id: Sha256Digest,
        supplied: MainLeaseEvidenceRecord | None,
        *,
        require_active: bool,
    ) -> MainLeaseEvidenceRecord:
        loaded = self.journal.read_lease_evidence_record(operation_id)
        if loaded is None:
            raise MainRollbackAuthorityError("fresh rollback lease is not durably recorded")
        durable = cast(MainLeaseEvidenceRecord, loaded[0])
        if durable.operation_id != operation_id or durable.target_ref != "refs/heads/main":
            raise MainRollbackAuthorityError("rollback lease target binding differs")
        if supplied is not None and canonical_bytes(supplied) != canonical_bytes(durable):
            raise MainRollbackAuthorityError("caller lease differs from durable rollback lease")
        requested_at = self._trusted_now()
        request = MainLeaseEvidenceReadRequest(
            operation_id=operation_id,
            repository_digest=durable.repository_digest,
            target_ref=durable.target_ref,
            lease_digest=durable.lease_digest,
            requested_at=requested_at,
        )
        if require_active:
            checker = getattr(self.journal, "assert_lease_evidence", None)
            if not callable(checker):
                raise MainRollbackAuthorityError(
                    "journal cannot authenticate target-scoped lease"
                )
            try:
                checked = checker(request)
            except (
                MainGraduationJournalError,
                MainGraduationRecordConflictError,
                ValueError,
            ) as exc:
                raise MainRollbackAuthorityError(
                    "rollback lease is not current target-scoped authority"
                ) from exc
        else:
            # The public active-reader intentionally rejects expired leases.
            # The durable CAS read above has already authenticated the record;
            # recovery uses it only to adopt local records and never as
            # authority for a new stage.
            checked = durable
        if canonical_bytes(checked) != canonical_bytes(durable):
            raise MainRollbackAuthorityError("lease verifier returned a different durable record")
        return durable

    def _validate_current_authority(
        self,
        source: MainCompletionPackage,
        policy: Sha256Digest,
        config: Sha256Digest,
        binding: MainReleaseIssuerBinding,
    ) -> None:
        expected = source.release_issuer_binding
        if policy != source.plan.policy_epoch:
            raise MainRollbackAuthorityError("current rollback policy epoch differs from source")
        if config != expected.controller_config_digest or binding != expected:
            raise MainRollbackAuthorityError(
                "current rollback controller authority differs from source"
            )
        if binding.app_id == 15368:
            raise MainRollbackAuthorityError("validation App 15368 cannot issue rollback")

    def _revalidate_after_lease(
        self,
        source: MainCompletionPackage,
        composition: MainRollbackCompositionArtifact,
        policy: Sha256Digest,
        config: Sha256Digest,
        binding: MainReleaseIssuerBinding,
    ) -> None:
        reader = self.current_authority_reader
        if reader is None:
            raise MainRollbackAuthorityError(
                "current rollback authority reader is required before first intent"
            )
        try:
            current = reader()
        except Exception as exc:
            raise MainRollbackAuthorityError(
                "current rollback authority could not be revalidated"
            ) from exc
        if (
            current.current_main_commit != composition.current_main_commit
            or current.current_main_tree != composition.current_main_tree
            or current.current_main_parent_commit != composition.current_main_parent_commit
            or current.policy_epoch != policy
            or current.controller_config_digest != config
            or current.release_issuer_binding != binding
        ):
            raise MainRollbackAuthorityError(
                "current rollback protected-main authority drifted after lease"
            )
        self._validate_current_authority(
            source,
            current.policy_epoch,
            current.controller_config_digest,
            current.release_issuer_binding,
        )

    @staticmethod
    def _derive_operation_id(
        *,
        source_operation_id: Sha256Digest,
        attempt_nonce: str,
        source: MainCompletionPackage,
        composition: MainRollbackCompositionArtifact,
        policy_epoch: Sha256Digest,
        controller_config_digest: Sha256Digest,
        binding: MainReleaseIssuerBinding,
    ) -> Sha256Digest:
        identity = {
            "schema_version": 2,
            "attempt_nonce": attempt_nonce,
            "source_operation_id": source_operation_id,
            "completion_package_digest": canonical_digest(source),
            "repository_digest": source.repository_digest,
            "target_ref": source.target_ref,
            "composition_id": composition.composition_id,
            "composition_artifact_digest": canonical_digest(composition),
            "current_main_commit": composition.current_main_commit,
            "current_main_tree": composition.current_main_tree,
            "current_main_parent_commit": composition.current_main_parent_commit,
            "original_delta_digest": composition.original_delta_digest,
            "inverse_delta_digest": composition.inverse_delta_digest,
            "inverse_delta_artifact_digest": canonical_digest(composition),
            "inverse_tree": composition.inverse_tree,
            "candidate_commit": composition.candidate_commit,
            "candidate_tree": composition.candidate_tree,
            "candidate_parent_commit": composition.candidate_parent_commit,
            "policy_epoch": policy_epoch,
            "controller_config_digest": controller_config_digest,
            "release_issuer_identity": binding.issuer_id,
            "release_issuer_app_id": binding.app_id,
            "issuer_isolation_digest": binding.isolation_digest,
            "deploy_performed": False,
        }
        return main_rollback_operation_id(**identity)

    @staticmethod
    def _build_authorization(
        *,
        operation_id: Sha256Digest,
        source: MainCompletionPackage,
        composition: MainRollbackCompositionArtifact,
        lease: MainLeaseEvidenceRecord,
        policy_epoch: Sha256Digest,
        controller_config_digest: Sha256Digest,
        binding: MainReleaseIssuerBinding,
        authorized_at: datetime,
    ) -> MainRollbackAuthorization:
        values: dict[str, object] = {
            "operation_id": operation_id,
            "source_operation_id": source.operation_id,
            "completion_package_digest": canonical_digest(source),
            "repository_digest": source.repository_digest,
            "target_ref": source.target_ref,
            "original_delta_digest": composition.original_delta_digest,
            "current_main_commit": composition.current_main_commit,
            "current_main_tree": composition.current_main_tree,
            "current_main_parent_commit": composition.current_main_parent_commit,
            "inverse_delta_digest": composition.inverse_delta_digest,
            "inverse_delta_artifact_digest": canonical_digest(composition),
            "inverse_tree": composition.inverse_tree,
            "composition_id": composition.composition_id,
            "composition_artifact_digest": canonical_digest(composition),
            "lease_identity": lease.owner,
            "lease_digest": lease.lease_digest,
            "lease_epoch_digest": lease.lease_epoch_digest,
            "policy_epoch": policy_epoch,
            "controller_config_digest": controller_config_digest,
            "release_issuer_identity": binding.issuer_id,
            "release_issuer_app_id": binding.app_id,
            "issuer_isolation_digest": binding.isolation_digest,
            "authorized_at": authorized_at,
            "expires_at": lease.expires_at,
            "authorized": True,
            "deploy_performed": False,
        }
        return _digest_record(MainRollbackAuthorization, values, "authorization_digest")

    @staticmethod
    def _build_intent(
        *,
        operation_id: Sha256Digest,
        source: MainCompletionPackage,
        composition: MainRollbackCompositionArtifact,
        candidate_ref: str,
        lease: MainLeaseEvidenceRecord,
        policy_epoch: Sha256Digest,
        authorization: MainRollbackAuthorization,
        recorded_at: datetime,
    ) -> MainRollbackIntent:
        values: dict[str, object] = {
            "operation_id": operation_id,
            "source_operation_id": source.operation_id,
            "completion_package_digest": canonical_digest(source),
            "repository_digest": source.repository_digest,
            "target_ref": source.target_ref,
            "original_delta_digest": composition.original_delta_digest,
            "inverse_delta_digest": composition.inverse_delta_digest,
            "inverse_delta_artifact_digest": canonical_digest(composition),
            "base_commit": composition.current_main_commit,
            "base_tree": composition.current_main_tree,
            "current_main_commit": composition.current_main_commit,
            "current_main_tree": composition.current_main_tree,
            "current_main_parent_commit": composition.current_main_parent_commit,
            "candidate_commit": composition.candidate_commit,
            "candidate_tree": composition.candidate_tree,
            "candidate_parent_commit": composition.candidate_parent_commit,
            "candidate_ref": candidate_ref,
            "inverse_tree": composition.inverse_tree,
            "composition_id": composition.composition_id,
            "composition_artifact_digest": canonical_digest(composition),
            "lease_identity": lease.owner,
            "lease_digest": lease.lease_digest,
            "lease_epoch_digest": lease.lease_epoch_digest,
            "policy_epoch": policy_epoch,
            "authorization_digest": authorization.authorization_digest,
            "recorded_at": recorded_at,
        }
        return _digest_record(MainRollbackIntent, values, "intent_digest")

    @staticmethod
    def _build_attempt(
        *,
        operation_id: Sha256Digest,
        source: MainCompletionPackage,
        composition: MainRollbackCompositionArtifact,
        candidate_ref: str,
        lease: MainLeaseEvidenceRecord,
        policy_epoch: Sha256Digest,
        controller_config_digest: Sha256Digest,
        binding: MainReleaseIssuerBinding,
        attempt_nonce: str,
    ) -> MainRollbackAttemptAuthority:
        values: dict[str, object] = {
            "operation_id": operation_id,
            "attempt_nonce": attempt_nonce,
            "source_operation_id": source.operation_id,
            "completion_package_digest": canonical_digest(source),
            "repository_digest": source.repository_digest,
            "target_ref": source.target_ref,
            "current_main_commit": composition.current_main_commit,
            "current_main_tree": composition.current_main_tree,
            "current_main_parent_commit": composition.current_main_parent_commit,
            "original_delta_digest": composition.original_delta_digest,
            "inverse_delta_digest": composition.inverse_delta_digest,
            "inverse_delta_artifact_digest": canonical_digest(composition),
            "inverse_tree": composition.inverse_tree,
            "candidate_commit": composition.candidate_commit,
            "candidate_tree": composition.candidate_tree,
            "candidate_parent_commit": composition.candidate_parent_commit,
            "candidate_ref": candidate_ref,
            "composition_id": composition.composition_id,
            "composition_artifact_digest": canonical_digest(composition),
            "policy_epoch": policy_epoch,
            "controller_config_digest": controller_config_digest,
            "release_issuer_identity": binding.issuer_id,
            "release_issuer_app_id": binding.app_id,
            "issuer_isolation_digest": binding.isolation_digest,
            "deploy_performed": False,
        }
        probe = cast(Any, MainRollbackAttemptAuthority).model_construct(
            **values, manifest_digest=_ZERO
        )
        values["operation_id"] = main_rollback_operation_id(
            **probe.model_dump(
                exclude={"operation_id", "manifest_digest", "candidate_ref"}, mode="json"
            )
        )
        if values["operation_id"] != operation_id:
            raise MainRollbackAuthorityError("rollback attempt identity derivation drift")
        attempt_probe = cast(Any, MainRollbackAttemptAuthority).model_construct(
            **values, manifest_digest=_ZERO
        )
        values["manifest_digest"] = canonical_digest(
            attempt_probe.model_dump(exclude={"manifest_digest"}, mode="json")
        )
        return MainRollbackAttemptAuthority.model_validate(values)

    @staticmethod
    def _build_preparation(
        *,
        operation_id: Sha256Digest,
        source: MainCompletionPackage,
        composition: MainRollbackCompositionArtifact,
        candidate_ref: str,
        lease: MainLeaseEvidenceRecord,
        policy_epoch: Sha256Digest,
        authorization: MainRollbackAuthorization,
        intent: MainRollbackIntent,
        authorized_at: datetime,
    ) -> MainRollbackPreparationAuthorization:
        values: dict[str, object] = {
            "operation_id": operation_id,
            "rollback_authorization_digest": authorization.authorization_digest,
            "rollback_intent_digest": intent.intent_digest,
            "package_digest": canonical_digest(source),
            "composition_digest": canonical_digest(composition),
            "composition_id": composition.composition_id,
            "composition_artifact_digest": canonical_digest(composition),
            "repository_digest": source.repository_digest,
            "target_ref": source.target_ref,
            "base_commit": composition.current_main_commit,
            "base_tree": composition.current_main_tree,
            "candidate_commit": composition.candidate_commit,
            "candidate_tree": composition.candidate_tree,
            "candidate_ref": candidate_ref,
            "lease_identity": lease.owner,
            "lease_digest": lease.lease_digest,
            "lease_epoch_digest": lease.lease_epoch_digest,
            "policy_epoch": policy_epoch,
            "authorized_at": authorized_at,
            "authorized": True,
            "deploy_performed": False,
        }
        return _digest_record(
            MainRollbackPreparationAuthorization, values, "authorization_digest"
        )

    @staticmethod
    def _record_or_adopt(
        kind: str,
        operation_id: Sha256Digest,
        record: Any,
        writer: Any,
        source_operation_id: Sha256Digest,
    ) -> ArtifactRef:
        reader_name = {
            "rollback-intent": "read_rollback_intent",
            "rollback-authorization": "read_rollback_authorization",
            "rollback-attempt-authority": "read_rollback_attempt_authority",
            "rollback-preparation-authorization": "read_rollback_preparation_authorization",
        }[kind]
        loaded = getattr(record, "operation_id", None)
        if loaded != operation_id:
            raise MainRollbackAuthorityError(f"{kind} operation identity differs")
        prior = getattr(writer, "__self__", None)
        reader = getattr(prior, reader_name, None)
        if callable(reader):
            recovery = getattr(prior, "rollback_authority_recovery", None)
            if callable(recovery):
                with recovery(source_operation_id):
                    existing = reader(operation_id)
            else:
                existing = reader(operation_id)
            if existing is not None:
                if canonical_bytes(existing[0]) != canonical_bytes(record):
                    raise MainRollbackAuthorityError(f"conflicting durable {kind}")
                return cast(ArtifactRef, existing[1])
        try:
            recovery = getattr(prior, "rollback_authority_recovery", None)
            if callable(recovery):
                with recovery(source_operation_id):
                    return cast(ArtifactRef, writer(record))
            return cast(ArtifactRef, writer(record))
        except MainGraduationRecordConflictError as exc:
            raise MainRollbackAuthorityError(f"conflicting durable {kind}") from exc

    def _trusted_now(self) -> datetime:
        now = self.clock.now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise MainRollbackAuthorityError("trusted clock returned a naive timestamp")
        return now


__all__ = [
    "MainRollbackAuthority",
    "MainRollbackAuthorityError",
    "MainRollbackAuthorityResult",
]
