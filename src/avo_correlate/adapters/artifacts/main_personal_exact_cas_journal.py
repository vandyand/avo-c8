"""Offline durable journal for one personal exact-CAS authority chain."""

from __future__ import annotations

import json
import os
from pathlib import Path
from threading import RLock
from typing import Any, Protocol, TypeVar

from avo_correlate.adapters.artifacts.durable_backend_gate import (
    DurableBackendQualification,
    require_durable_backend,
)
from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef, StrictModel
from avo_correlate.contracts.main_personal_exact_cas import (
    MainPersonalExactCasActivation,
    MainPersonalExactCasAuthorization,
    MainPersonalExactCasCompletion,
    MainPersonalExactCasDispatchStarted,
    MainPersonalExactCasIntent,
    MainPersonalExactCasPostStateObservation,
    MainPersonalExactCasReceipt,
    MainPersonalExactCasReconciliation,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

_LOCK = RLock()
_T = TypeVar("_T", bound=StrictModel)


class MainPersonalExactCasJournalError(RuntimeError):
    """The personal exact-CAS journal is missing, malformed, or inconsistent."""


class MainPersonalExactCasRecordConflictError(MainPersonalExactCasJournalError):
    """A create-once identity was already bound to different canonical bytes."""


class MainPersonalExactCasAuthorityVerifier(Protocol):
    """Controller-rooted authentication for offline authority transitions."""

    def verify_activation(
        self, activation: MainPersonalExactCasActivation, evidence: object
    ) -> object: ...

    def verify_authorization(
        self,
        authorization: MainPersonalExactCasAuthorization,
        activation: MainPersonalExactCasActivation,
    ) -> object: ...

    def verify_receipt(
        self,
        receipt: MainPersonalExactCasReceipt,
        intent: MainPersonalExactCasIntent,
        dispatch_marker: MainPersonalExactCasDispatchStarted,
    ) -> object: ...

    def verify_post_state(
        self,
        observation: MainPersonalExactCasPostStateObservation,
        receipt: MainPersonalExactCasReceipt,
    ) -> object: ...

    def verify_reconciliation(
        self,
        reconciliation: MainPersonalExactCasReconciliation,
        receipt: MainPersonalExactCasReceipt,
        observation: MainPersonalExactCasPostStateObservation,
    ) -> object: ...

    def verify_completion(
        self,
        completion: MainPersonalExactCasCompletion,
        receipt: MainPersonalExactCasReceipt,
        observation: MainPersonalExactCasPostStateObservation,
        reconciliation: MainPersonalExactCasReconciliation | None,
    ) -> object: ...


_RECORDS: dict[str, type[StrictModel]] = {
    "activation": MainPersonalExactCasActivation,
    "authorization": MainPersonalExactCasAuthorization,
    "intent": MainPersonalExactCasIntent,
    "dispatch-started": MainPersonalExactCasDispatchStarted,
    "receipt": MainPersonalExactCasReceipt,
    "post-state": MainPersonalExactCasPostStateObservation,
    "reconciliation": MainPersonalExactCasReconciliation,
    "completion": MainPersonalExactCasCompletion,
}


class MainPersonalExactCasJournal:
    """Create-once local journal with no provider, transport, or token surface."""

    def __init__(
        self,
        root: Path,
        *,
        authority_verifier: MainPersonalExactCasAuthorityVerifier,
        trusted_source_reader: object,
        artifact_store: FilesystemArtifactStore | None = None,
        max_record_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        if max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        required = (
            "verify_activation",
            "verify_authorization",
            "verify_receipt",
            "verify_post_state",
            "verify_reconciliation",
            "verify_completion",
        )
        if any(not callable(getattr(authority_verifier, name, None)) for name in required):
            raise ValueError("controller-rooted exact-CAS authority verifier is required")
        from avo_correlate.adapters.artifacts.trusted_main_graduation_source import (
            TrustedMainGraduationEvidenceReader,
        )

        if type(trusted_source_reader) is not TrustedMainGraduationEvidenceReader:
            raise ValueError("controller-pinned trusted source reader is required")
        self._qualification = require_durable_backend(root)
        self._root = self._qualification.root
        expected_store_root = self._prepare_controlled_directory(self._root / "artifacts")
        if artifact_store is not None:
            if type(artifact_store) is not FilesystemArtifactStore:
                raise ValueError(
                    "personal exact-CAS artifact store must be canonical filesystem store"
                )
            if _canonical_non_symlink_path(artifact_store.root) != expected_store_root:
                raise ValueError("artifact store must be beneath the qualified journal root")
            self._store = artifact_store
        else:
            self._store = FilesystemArtifactStore(expected_store_root)
        # Re-qualify effective controlled paths after their creation.  A
        # nested mount must not be able to bypass the journal-root decision.
        self._artifact_qualification = self._qualify_same_backend(
            expected_store_root, "artifact store"
        )
        self._indexes = self._prepare_controlled_directory(
            self._root / "main-personal-exact-cas-index"
        )
        self._index_qualification = self._qualify_same_backend(self._indexes, "index directory")
        self._authority = authority_verifier
        self._trusted_source_reader = trusted_source_reader
        self._max = max_record_bytes

    @property
    def root(self) -> Path:
        return self._root

    @property
    def artifact_store(self) -> FilesystemArtifactStore:
        return self._store

    @property
    def backend_qualification(self) -> DurableBackendQualification:
        return self._qualification

    def record_activation(
        self, activation: MainPersonalExactCasActivation, evidence: object
    ) -> ArtifactRef:
        del evidence  # Admission is always re-read from the controller-pinned source.
        trusted_evidence = self._trusted_evidence_for_activation(activation)
        self._verify("activation", activation, trusted_evidence)
        return self._record("activation", activation.activation_digest, activation)

    def record_authorization(self, authorization: MainPersonalExactCasAuthorization) -> ArtifactRef:
        activation = self._require_activation(authorization.activation_digest)
        self._assert_activation_scope(authorization, activation)
        self._verify("authorization", authorization, activation)
        return self._record("authorization", authorization.operation_id, authorization)

    def record_intent(self, intent: MainPersonalExactCasIntent) -> ArtifactRef:
        authorization = self._require(
            "authorization", intent.operation_id, MainPersonalExactCasAuthorization
        )
        self._require_trusted_activation(authorization.activation_digest)
        self._assert_scope(intent, authorization)
        if intent.authorization_digest != authorization.authorization_digest:
            raise MainPersonalExactCasJournalError("intent authorization binding differs")
        return self._record("intent", intent.operation_id, intent)

    def record_dispatch_started(self, marker: MainPersonalExactCasDispatchStarted) -> ArtifactRef:
        intent = self._require("intent", marker.operation_id, MainPersonalExactCasIntent)
        self._require_trusted_activation(intent.activation_digest)
        self._assert_scope(marker, intent)
        if marker.intent_digest != intent.intent_digest:
            raise MainPersonalExactCasJournalError("dispatch marker intent binding differs")
        return self._record("dispatch-started", marker.operation_id, marker)

    def claim_dispatch_started(
        self, marker: MainPersonalExactCasDispatchStarted
    ) -> tuple[ArtifactRef, bool]:
        """Create the dispatch marker and report whether this caller won.

        The create-once index is the dispatch ownership claim.  Ownership is
        reported from the exact ``O_EXCL`` publication outcome, so it remains
        correct across processes as well as threads.  A caller that observes
        an existing marker must reconcile and never invoke a provider
        capability.
        """

        intent = self._require("intent", marker.operation_id, MainPersonalExactCasIntent)
        self._require_trusted_activation(intent.activation_digest)
        self._assert_scope(marker, intent)
        if marker.intent_digest != intent.intent_digest:
            raise MainPersonalExactCasJournalError("dispatch marker intent binding differs")
        created: list[bool] = []
        reference = self._record(
            "dispatch-started", marker.operation_id, marker, created_out=created
        )
        return reference, created[0]

    def record_receipt(self, receipt: MainPersonalExactCasReceipt) -> ArtifactRef:
        intent = self._require("intent", receipt.operation_id, MainPersonalExactCasIntent)
        self._require_trusted_activation(intent.activation_digest)
        marker = self._require(
            "dispatch-started", receipt.operation_id, MainPersonalExactCasDispatchStarted
        )
        self._assert_scope(receipt, intent)
        if (
            receipt.authorization_digest != intent.authorization_digest
            or receipt.intent_digest != intent.intent_digest
            or receipt.dispatch_marker_digest != marker.dispatch_marker_digest
        ):
            raise MainPersonalExactCasJournalError("receipt authority binding differs")
        self._verify("receipt", receipt, intent, marker)
        return self._record("receipt", receipt.operation_id, receipt)

    def record_post_state(
        self, observation: MainPersonalExactCasPostStateObservation
    ) -> ArtifactRef:
        receipt = self._require_verified_receipt(observation.operation_id)
        self._assert_scope(observation, receipt)
        if (
            observation.authorization_digest != receipt.authorization_digest
            or observation.intent_digest != receipt.intent_digest
            or observation.receipt_digest != receipt.receipt_digest
            or observation.receipt_outcome != receipt.outcome
        ):
            raise MainPersonalExactCasJournalError("post-state receipt binding differs")
        self._verify("post-state", observation, receipt)
        return self._record("post-state", observation.operation_id, observation)

    def record_reconciliation(
        self, reconciliation: MainPersonalExactCasReconciliation
    ) -> ArtifactRef:
        receipt = self._require_verified_receipt(reconciliation.operation_id)
        observation = self._require(
            "post-state", reconciliation.operation_id, MainPersonalExactCasPostStateObservation
        )
        if receipt.outcome != "ambiguous":
            raise MainPersonalExactCasJournalError("only ambiguous receipts can be reconciled")
        if reconciliation.ambiguous_receipt != receipt or reconciliation.observation != observation:
            raise MainPersonalExactCasJournalError("reconciliation evidence differs")
        self._verify("reconciliation", reconciliation, receipt, observation)
        return self._record("reconciliation", reconciliation.operation_id, reconciliation)

    def record_completion(self, completion: MainPersonalExactCasCompletion) -> ArtifactRef:
        receipt = self._require_verified_receipt(completion.operation_id)
        observation = self._require(
            "post-state", completion.operation_id, MainPersonalExactCasPostStateObservation
        )
        reconciliation_result = self.read_reconciliation(completion.operation_id)
        reconciliation = None if reconciliation_result is None else reconciliation_result[0]
        self._assert_completion_arm(completion, receipt, observation, reconciliation)
        self._verify("completion", completion, receipt, observation, reconciliation)
        return self._record("completion", completion.operation_id, completion)

    def read_activation(self) -> tuple[MainPersonalExactCasActivation, ArtifactRef] | None:
        result = self._read_raw("activation", "activation", MainPersonalExactCasActivation)
        if result is not None:
            self._verify("activation", result[0], self._trusted_evidence_for_activation(result[0]))
        return result

    def read_authorization(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasAuthorization, ArtifactRef] | None:
        result = self._read_raw("authorization", operation_id, MainPersonalExactCasAuthorization)
        if result is not None:
            self._revalidate_chain(operation_id, through="authorization")
        return result

    def read_intent(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasIntent, ArtifactRef] | None:
        result = self._read_raw("intent", operation_id, MainPersonalExactCasIntent)
        if result is not None:
            self._revalidate_chain(operation_id, through="intent")
        return result

    def read_dispatch_started(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasDispatchStarted, ArtifactRef] | None:
        result = self._read_raw(
            "dispatch-started", operation_id, MainPersonalExactCasDispatchStarted
        )
        if result is not None:
            self._revalidate_chain(operation_id, through="dispatch-started")
        return result

    def read_receipt(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasReceipt, ArtifactRef] | None:
        result = self._read_raw("receipt", operation_id, MainPersonalExactCasReceipt)
        if result is not None:
            self._revalidate_chain(operation_id, through="receipt")
        return result

    def read_post_state(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasPostStateObservation, ArtifactRef] | None:
        result = self._read_raw(
            "post-state", operation_id, MainPersonalExactCasPostStateObservation
        )
        if result is not None:
            self._revalidate_chain(operation_id, through="post-state")
        return result

    def read_reconciliation(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasReconciliation, ArtifactRef] | None:
        result = self._read_raw("reconciliation", operation_id, MainPersonalExactCasReconciliation)
        if result is not None:
            self._revalidate_chain(operation_id, through="reconciliation")
        return result

    def read_completion(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasCompletion, ArtifactRef] | None:
        result = self._read_raw("completion", operation_id, MainPersonalExactCasCompletion)
        if result is not None:
            self._revalidate_chain(operation_id, through="completion")
        return result

    def _require_activation(self, activation_digest: str) -> MainPersonalExactCasActivation:
        activation = self._require(
            "activation",
            "activation",
            MainPersonalExactCasActivation,
            activation_digest=activation_digest,
        )
        evidence = self._trusted_evidence_for_activation(activation)
        self._verify("activation", activation, evidence)
        return activation

    def _require_trusted_activation(self, activation_digest: str) -> MainPersonalExactCasActivation:
        return self._require_activation(activation_digest)

    def _trusted_evidence_for_activation(
        self, activation: MainPersonalExactCasActivation
    ) -> object:
        from avo_correlate.adapters.artifacts.trusted_main_graduation_source import (
            TrustedMainGraduationOfflineResult,
        )

        try:
            data = canonical_bytes(activation)
            checked = MainPersonalExactCasActivation.model_validate_json(data)
            if checked != activation:
                raise ValueError("activation is not canonical")
        except (AttributeError, TypeError, ValueError) as exc:
            raise MainPersonalExactCasJournalError("trusted source revalidation failed") from exc
        try:
            result = self._trusted_source_reader.read(activation.source_operation_id)
        except Exception as exc:
            raise MainPersonalExactCasJournalError("trusted source revalidation failed") from exc
        if type(result) is not TrustedMainGraduationOfflineResult or not result.accepted:
            raise MainPersonalExactCasJournalError("trusted source rejected activation")
        evidence_ref = result.evidence_ref
        if evidence_ref is None or (
            evidence_ref.operation_id != activation.source_operation_id
            or evidence_ref.plan_digest != activation.source_plan_digest
            or evidence_ref.plan_ref != activation.source_plan_artifact
            or evidence_ref.package_digest != activation.source_package_digest
            or evidence_ref.composition_digest != activation.source_composition_digest
            or evidence_ref.base_commit != activation.base_commit
            or evidence_ref.base_tree != activation.base_tree
            or evidence_ref.candidate_commit != activation.candidate_commit
            or evidence_ref.candidate_tree != activation.candidate_tree
            or evidence_ref.candidate_ref != activation.candidate_ref
        ):
            raise MainPersonalExactCasJournalError("activation source binding differs")
        return result

    def _require(self, kind: str, key: str, expected: type[_T], **identity: str) -> _T:
        result = self._read_raw(kind, key, expected)
        if result is None:
            raise MainPersonalExactCasJournalError(f"{kind} is missing")
        record = result[0]
        for name, value in identity.items():
            if getattr(record, name) != value:
                raise MainPersonalExactCasJournalError(f"{kind} identity differs")
        return record

    def _require_verified_receipt(self, operation_id: str) -> MainPersonalExactCasReceipt:
        """Read a receipt and authenticate its complete intent/dispatch binding."""

        intent = self._require("intent", operation_id, MainPersonalExactCasIntent)
        self._require_trusted_activation(intent.activation_digest)
        marker = self._require(
            "dispatch-started", operation_id, MainPersonalExactCasDispatchStarted
        )
        receipt = self._require("receipt", operation_id, MainPersonalExactCasReceipt)
        self._assert_scope(receipt, intent)
        if (
            receipt.authorization_digest != intent.authorization_digest
            or receipt.intent_digest != intent.intent_digest
            or receipt.dispatch_marker_digest != marker.dispatch_marker_digest
        ):
            raise MainPersonalExactCasJournalError("receipt authority binding differs")
        self._verify("receipt", receipt, intent, marker)
        return receipt

    def _revalidate_chain(self, operation_id: str, *, through: str) -> None:
        activation_result = self._read_raw(
            "activation", "activation", MainPersonalExactCasActivation
        )
        if activation_result is None:
            raise MainPersonalExactCasJournalError("activation is missing")
        activation, _ = activation_result
        self._verify("activation", activation, self._trusted_evidence_for_activation(activation))
        auth_result = self._read_raw(
            "authorization", operation_id, MainPersonalExactCasAuthorization
        )
        if auth_result is None:
            raise MainPersonalExactCasJournalError("authorization is missing")
        authorization, _ = auth_result
        self._assert_activation_scope(authorization, activation)
        self._verify("authorization", authorization, activation)
        if through == "authorization":
            return
        intent_result = self._read_raw("intent", operation_id, MainPersonalExactCasIntent)
        if intent_result is None:
            raise MainPersonalExactCasJournalError("intent is missing")
        intent, _ = intent_result
        self._assert_scope(intent, authorization)
        if intent.authorization_digest != authorization.authorization_digest:
            raise MainPersonalExactCasJournalError("intent authorization binding differs")
        if through == "intent":
            return
        marker_result = self._read_raw(
            "dispatch-started", operation_id, MainPersonalExactCasDispatchStarted
        )
        if marker_result is None:
            raise MainPersonalExactCasJournalError("dispatch marker is missing")
        marker, _ = marker_result
        self._assert_scope(marker, intent)
        if marker.intent_digest != intent.intent_digest:
            raise MainPersonalExactCasJournalError("dispatch marker intent binding differs")
        if through == "dispatch-started":
            return
        receipt_result = self._read_raw("receipt", operation_id, MainPersonalExactCasReceipt)
        if receipt_result is None:
            raise MainPersonalExactCasJournalError("receipt is missing")
        receipt, _ = receipt_result
        self._assert_scope(receipt, intent)
        if (
            receipt.authorization_digest != intent.authorization_digest
            or receipt.intent_digest != intent.intent_digest
            or receipt.dispatch_marker_digest != marker.dispatch_marker_digest
        ):
            raise MainPersonalExactCasJournalError("receipt authority binding differs")
        self._verify("receipt", receipt, intent, marker)
        if through == "receipt":
            return
        observation_result = self._read_raw(
            "post-state", operation_id, MainPersonalExactCasPostStateObservation
        )
        if observation_result is None:
            raise MainPersonalExactCasJournalError("post-state is missing")
        observation, _ = observation_result
        self._assert_scope(observation, receipt)
        if (
            observation.authorization_digest != receipt.authorization_digest
            or observation.intent_digest != receipt.intent_digest
            or observation.receipt_digest != receipt.receipt_digest
            or observation.receipt_outcome != receipt.outcome
        ):
            raise MainPersonalExactCasJournalError("post-state receipt binding differs")
        self._verify("post-state", observation, receipt)
        if through == "post-state":
            return
        reconciliation_result = self._read_raw(
            "reconciliation", operation_id, MainPersonalExactCasReconciliation
        )
        reconciliation = None if reconciliation_result is None else reconciliation_result[0]
        if reconciliation is not None:
            if (
                receipt.outcome != "ambiguous"
                or reconciliation.ambiguous_receipt != receipt
                or reconciliation.observation != observation
            ):
                raise MainPersonalExactCasJournalError("reconciliation evidence differs")
            self._verify("reconciliation", reconciliation, receipt, observation)
        if through == "reconciliation":
            if reconciliation is None:
                raise MainPersonalExactCasJournalError("reconciliation is missing")
            return
        completion_result = self._read_raw(
            "completion", operation_id, MainPersonalExactCasCompletion
        )
        if completion_result is not None:
            self._assert_completion_arm(completion_result[0], receipt, observation, reconciliation)
            self._verify("completion", completion_result[0], receipt, observation, reconciliation)

    @staticmethod
    def _assert_activation_scope(
        authorization: MainPersonalExactCasAuthorization,
        activation: MainPersonalExactCasActivation,
    ) -> None:
        for name in (
            "activation_digest",
            "repository_digest",
            "target_ref",
            "source_operation_id",
            "source_plan_digest",
            "source_package_digest",
            "source_composition_digest",
            "base_commit",
            "base_tree",
            "candidate_commit",
            "candidate_tree",
            "candidate_ref",
            "candidate_parents",
            "protection_ruleset_digest",
            "writer_app_id",
            "writer_installation_id",
            "writer_identity",
        ):
            if getattr(authorization, name) != getattr(activation, name):
                raise MainPersonalExactCasJournalError(f"{name} binding differs")

    @staticmethod
    def _assert_completion_arm(
        completion: MainPersonalExactCasCompletion,
        receipt: MainPersonalExactCasReceipt,
        observation: MainPersonalExactCasPostStateObservation,
        reconciliation: MainPersonalExactCasReconciliation | None,
    ) -> None:
        exact = (
            observation.observed_commit == observation.candidate_commit
            and observation.observed_tree == observation.candidate_tree
            and observation.observed_parents == (observation.base_commit,)
        )
        applied_arm = (
            receipt.outcome == "applied"
            and observation.receipt_outcome == "applied"
            and reconciliation is None
        )
        recovered_arm = (
            receipt.outcome == "ambiguous"
            and observation.receipt_outcome == "ambiguous"
            and reconciliation is not None
            and reconciliation.outcome == "applied"
        )
        if not exact or not (applied_arm or recovered_arm):
            raise MainPersonalExactCasJournalError(
                "completion is not an authenticated applied result"
            )
        expected_reconciliation = None if applied_arm else canonical_digest(reconciliation)
        if (
            completion.activation_digest != receipt.activation_digest
            or completion.receipt_digest != receipt.receipt_digest
            or completion.post_state_observation_digest != canonical_digest(observation)
            or completion.reconciliation_digest != expected_reconciliation
        ):
            raise MainPersonalExactCasJournalError("completion binding differs")

    @staticmethod
    def _assert_scope(record: Any, authority: Any) -> None:
        for name in (
            "activation_digest",
            "repository_digest",
            "target_ref",
            "source_operation_id",
            "source_plan_digest",
            "source_package_digest",
            "source_composition_digest",
            "base_commit",
            "base_tree",
            "candidate_commit",
            "candidate_tree",
            "candidate_ref",
            "candidate_parents",
            "protection_ruleset_digest",
            "writer_app_id",
            "writer_installation_id",
            "writer_identity",
            "lease_identity",
            "lease_digest",
            "lease_expires_at",
            "claim_nonce",
            "claim_digest",
        ):
            if getattr(record, name) != getattr(authority, name):
                raise MainPersonalExactCasJournalError(f"{name} binding differs")

    def _verify(self, kind: str, *values: object) -> None:
        method = getattr(self._authority, f"verify_{kind.replace('-', '_')}")
        try:
            accepted = method(*values)
        except Exception as exc:
            raise MainPersonalExactCasJournalError(f"{kind} authority verification failed") from exc
        if accepted is not True:
            raise MainPersonalExactCasJournalError(f"{kind} authority verification failed")

    def _prepare_controlled_directory(self, path: Path) -> Path:
        """Create and qualify a journal-controlled directory before writes."""

        canonical = _canonical_non_symlink_path(path)
        try:
            canonical.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise MainPersonalExactCasJournalError(
                "journal controlled directory cannot be created"
            ) from exc
        # Resolve again after mkdir: a mount or symlink change must not alter
        # the effective directory between preflight and use.
        return _canonical_existing_non_symlink_directory(canonical)

    def _qualify_same_backend(self, path: Path, label: str) -> DurableBackendQualification:
        qualification = require_durable_backend(path)
        if not qualification.qualified:
            raise MainPersonalExactCasJournalError(
                f"{label} is not on a qualified journal backend"
            )
        root = self._qualification
        if (
            qualification.mount_id is not None
            and root.mount_id is not None
            and qualification.mount_id != root.mount_id
        ) or (
            qualification.device is not None
            and root.device is not None
            and qualification.device != root.device
        ):
            raise MainPersonalExactCasJournalError(
                f"{label} is not on the qualified journal backend"
            )
        return qualification

    def _record(
        self,
        kind: str,
        key: str,
        record: StrictModel,
        *,
        created_out: list[bool] | None = None,
    ) -> ArtifactRef:
        model = _RECORDS[kind]
        if type(record) is not model:
            raise TypeError(f"{kind} requires its concrete contract")
        try:
            data = canonical_bytes(record)
            checked = model.model_validate_json(data)
            data = canonical_bytes(checked)
            # FilesystemArtifactStore creates the object fan-out lazily.  Own
            # and qualify the exact leaf directory before put_bytes can write
            # into it, including a re-check of the store root for replacement
            # or mount changes after construction.
            canonical_store_root = _canonical_existing_non_symlink_directory(
                self._store.root
            )
            if canonical_store_root != self._artifact_qualification.root:
                raise MainPersonalExactCasJournalError(
                    "artifact store moved outside its qualified root"
                )
            self._qualify_same_backend(canonical_store_root, "artifact store")
            object_path = self._store.path_for_digest(canonical_digest(checked))
            self._prepare_controlled_directory(object_path.parent)
            self._qualify_same_backend(object_path.parent, "artifact object directory")
            reference = self._store.put_bytes(
                data,
                media_type=f"application/vnd.avo.main-personal-exact-cas-{kind}+json",
                role=f"main-personal-exact-cas-{kind}",
                max_bytes=self._max,
            )
        except MainPersonalExactCasJournalError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise MainPersonalExactCasJournalError(f"invalid {kind}") from exc
        try:
            _fsync_store_ancestors(self._store.path_for_digest(reference.digest), self._store.root)
        except OSError as exc:
            raise MainPersonalExactCasJournalError(
                f"{kind} object was not durably committed"
            ) from exc
        index = self._index_path(kind, key)
        try:
            # Re-check immediately before publishing the create-once index.
            self._prepare_controlled_directory(index.parent)
            self._qualify_same_backend(index.parent, "index directory")
            _fsync_directory(index.parent)
            _fsync_directory(index.parent.parent)
        except OSError as exc:
            raise MainPersonalExactCasJournalError(
                f"{kind} index directory is not durable"
            ) from exc
        payload = canonical_bytes(reference)
        with _LOCK:
            try:
                descriptor = os.open(index, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                _fsync_directory(index.parent)
                _fsync_directory(index.parent.parent)
                if created_out is not None:
                    created_out.append(True)
                return reference
            except FileExistsError:
                try:
                    old = self._read_reference(index, kind)
                    old_data = self._store.read_bytes(old)
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    raise MainPersonalExactCasJournalError(f"{kind} index is malformed") from exc
                if old_data == data and old.digest == reference.digest:
                    if created_out is not None:
                        created_out.append(False)
                    return old
                raise MainPersonalExactCasRecordConflictError(f"conflicting {kind}") from None
            except OSError as exc:
                raise MainPersonalExactCasJournalError(
                    f"{kind} index was not durably committed"
                ) from exc

    def _index_path(self, kind: str, key: str) -> Path:
        if kind == "activation":
            return self._indexes / "activation.json"
        return self._indexes / kind / f"{key.removeprefix('sha256:')}.json"

    def _read_raw(self, kind: str, key: str, expected: type[_T]) -> tuple[_T, ArtifactRef] | None:
        index = self._index_path(kind, key)
        if not index.is_file():
            return None
        try:
            reference = self._read_reference(index, kind)
            data = self._store.read_bytes(reference)
            model = expected.model_validate_json(data)
            if type(model) is not expected or canonical_bytes(model) != data:
                raise ValueError("record is not canonical")
            return model, reference
        except (
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise MainPersonalExactCasJournalError(f"malformed {kind}") from exc

    @staticmethod
    def _read_reference(index: Path, kind: str) -> ArtifactRef:
        raw = index.read_bytes()
        parsed = json.loads(raw.decode("utf-8"))
        reference = ArtifactRef.model_validate(parsed)
        expected_role = f"main-personal-exact-cas-{kind}"
        expected_media_type = f"application/vnd.avo.main-personal-exact-cas-{kind}+json"
        if (
            canonical_bytes(reference) != raw
            or reference.role != expected_role
            or reference.media_type != expected_media_type
            or reference.size_bytes < 0
        ):
            raise ValueError("index is not canonical")
        return reference


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _canonical_non_symlink_path(path: Path) -> Path:
    candidate = Path(path)
    absolute = candidate if candidate.is_absolute() else Path.cwd() / candidate
    for component in [*reversed(absolute.parents), absolute]:
        if component.is_symlink():
            raise ValueError("personal exact-CAS path contains a symlink")
    return absolute.resolve(strict=False)


def _canonical_existing_non_symlink_directory(path: Path) -> Path:
    canonical = _canonical_non_symlink_path(path)
    if not canonical.is_dir():
        raise MainPersonalExactCasJournalError(
            "journal controlled path is not a directory"
        )
    return canonical


def _fsync_store_ancestors(object_path: Path, store_root: Path) -> None:
    """Flush the object directory chain before exposing its index reference."""

    current = object_path.parent
    root = store_root.resolve(strict=False)
    while True:
        _fsync_directory(current)
        if current == root:
            return
        if not current.is_relative_to(root):
            raise OSError("artifact object escaped its pinned store root")
        current = current.parent


__all__ = [
    "MainPersonalExactCasAuthorityVerifier",
    "MainPersonalExactCasJournal",
    "MainPersonalExactCasJournalError",
    "MainPersonalExactCasRecordConflictError",
]
