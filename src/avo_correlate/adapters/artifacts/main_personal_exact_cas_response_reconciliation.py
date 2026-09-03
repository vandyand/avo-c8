"""Durable, non-authoritative personal CAS response classification.

Only the concrete response-evidence journal and concrete authority journal
are accepted.  This leaf has no caller-supplied DTO, post-state, receipt,
transport, token, provider, or controller capability.
"""

from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime
from pathlib import Path
from threading import RLock

from avo_correlate.adapters.artifacts.durable_backend_gate import (
    DurableBackendQualification,
    require_durable_backend,
)
from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.main_personal_exact_cas_journal import (
    MainPersonalExactCasJournal,
    MainPersonalExactCasJournalError,
)
from avo_correlate.adapters.artifacts.main_personal_exact_cas_response_evidence import (
    MainPersonalExactCasResponseEvidenceJournal,
    MainPersonalExactCasResponseEvidenceJournalError,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_personal_exact_cas import (
    MainPersonalExactCasDispatchStarted,
    MainPersonalExactCasIntent,
)
from avo_correlate.contracts.main_personal_exact_cas_response_reconciliation import (
    MainPersonalExactCasResponseReconciliationClassification,
)
from avo_correlate.domain.canonical import canonical_bytes

_LOCK = RLock()
_ROLE = "main-personal-exact-cas-response-reconciliation-classification"
_MEDIA = "application/vnd.avo.main-personal-exact-cas-response-reconciliation+json"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class MainPersonalExactCasResponseReconciliationError(RuntimeError):
    """Value-free failure reading or classifying durable response evidence."""


class MainPersonalExactCasResponseReconciliationConflictError(
    MainPersonalExactCasResponseReconciliationError
):
    """Create-once classification identity was bound to different bytes."""


class MainPersonalExactCasResponseReconciliationClassificationJournal:
    """Create-once journal for nonterminal provider-response classification."""

    def __init__(
        self,
        root: Path,
        *,
        response_evidence_journal: MainPersonalExactCasResponseEvidenceJournal,
        authority_journal: MainPersonalExactCasJournal,
        max_record_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        if type(response_evidence_journal) is not MainPersonalExactCasResponseEvidenceJournal:
            raise ValueError("response evidence journal is required")
        if type(authority_journal) is not MainPersonalExactCasJournal:
            raise ValueError("authority journal is required")
        if type(max_record_bytes) is not int or max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        self._qualification = require_durable_backend(root)
        self._root = self._qualification.root
        self._store_root = self._prepare_directory(self._root / "artifacts")
        self._store = FilesystemArtifactStore(self._store_root)
        self._artifact_qualification = self._qualify(self._store_root, "artifact store")
        self._indexes = self._prepare_directory(
            self._root / "main-personal-exact-cas-response-reconciliation-index"
        )
        self._index_qualification = self._qualify(self._indexes, "index directory")
        self._evidence = response_evidence_journal
        self._authority = authority_journal
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

    def classify(
        self, operation_id: str
    ) -> MainPersonalExactCasResponseReconciliationClassification:
        """Re-read durable authority, classify, and publish create-once."""

        failure: MainPersonalExactCasResponseReconciliationError | None = None
        result: MainPersonalExactCasResponseReconciliationClassification | None = None
        try:
            evidence, intent, marker = self._read_inputs(operation_id)
            classification = (
                "candidate_observed"
                if evidence.response_classification == "candidate_response"
                else (
                    "conclusive_rejection_observed"
                    if evidence.response_classification
                    in {
                        "conflict_or_rejected",
                        "configuration_or_validation_rejected",
                        "authentication_or_authorization_rejected",
                    }
                    else "reconciliation_required"
                )
            )
            result = MainPersonalExactCasResponseReconciliationClassification.build(
                operation_id=intent.operation_id,
                repository_digest=intent.repository_digest,
                target_ref=intent.target_ref,
                writer_app_id=intent.writer_app_id,
                writer_installation_id=intent.writer_installation_id,
                writer_identity=intent.writer_identity,
                intent_digest=intent.intent_digest,
                dispatch_marker_digest=marker.dispatch_marker_digest,
                response_evidence_digest=evidence.evidence_digest,
                response_status=evidence.response_status,
                response_classification=evidence.response_classification,
                classification=classification,
                classified_at=evidence.observed_at,
            )
            data = canonical_bytes(result)
            reference = self._put(data, result.classified_at)
            reference = self._publish(operation_id, reference, data)
            del reference
        except MainPersonalExactCasResponseReconciliationError as exc:
            failure = MainPersonalExactCasResponseReconciliationError(str(exc))
        except (MainPersonalExactCasJournalError, MainPersonalExactCasResponseEvidenceJournalError):
            failure = MainPersonalExactCasResponseReconciliationError("authority_unresolved")
        except Exception:
            failure = MainPersonalExactCasResponseReconciliationError("classification_failed")
        if failure is not None:
            raise failure
        if result is None:
            raise MainPersonalExactCasResponseReconciliationError("classification_failed")
        return result

    def read_classification(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasResponseReconciliationClassification, ArtifactRef] | None:
        """Re-read classification and all durable inputs before returning it."""

        index = self._index_path(operation_id)
        if not index.is_file():
            return None
        failure: MainPersonalExactCasResponseReconciliationError | None = None
        result: (
            tuple[MainPersonalExactCasResponseReconciliationClassification, ArtifactRef] | None
        ) = None
        try:
            reference = self._read_reference(index)
            data = self._store.read_bytes(reference)
            classification = (
                MainPersonalExactCasResponseReconciliationClassification.model_validate_json(data)
            )
            if (
                type(classification) is not MainPersonalExactCasResponseReconciliationClassification
                or canonical_bytes(classification) != data
            ):
                raise ValueError("classification is not canonical")
            evidence, intent, marker = self._read_inputs(operation_id)
            if (
                classification.operation_id != intent.operation_id
                or classification.repository_digest != intent.repository_digest
                or classification.target_ref != intent.target_ref
                or classification.writer_app_id != intent.writer_app_id
                or classification.writer_installation_id != intent.writer_installation_id
                or classification.writer_identity != intent.writer_identity
                or classification.intent_digest != intent.intent_digest
                or classification.dispatch_marker_digest != marker.dispatch_marker_digest
                or classification.response_evidence_digest != evidence.evidence_digest
                or classification.response_status != evidence.response_status
                or classification.response_classification != evidence.response_classification
                or classification.classified_at != evidence.observed_at
            ):
                raise ValueError("classification binding differs")
            result = (classification, reference)
        except MainPersonalExactCasResponseReconciliationError as exc:
            failure = MainPersonalExactCasResponseReconciliationError(str(exc))
        except Exception:
            failure = MainPersonalExactCasResponseReconciliationError("malformed_classification")
        if failure is not None:
            raise failure
        return result

    def _read_inputs(self, operation_id: str):
        if type(operation_id) is not str or _DIGEST.fullmatch(operation_id) is None:
            raise MainPersonalExactCasResponseReconciliationError("invalid_operation_id")
        evidence_result = self._evidence.read_response_evidence(operation_id)
        if evidence_result is None:
            raise MainPersonalExactCasResponseReconciliationError("evidence_missing")
        intent_result = self._authority.read_intent(operation_id)
        marker_result = self._authority.read_dispatch_started(operation_id)
        if intent_result is None or marker_result is None:
            raise MainPersonalExactCasResponseReconciliationError("authority_missing")
        intent = intent_result[0]
        marker = marker_result[0]
        if (
            type(intent) is not MainPersonalExactCasIntent
            or type(marker) is not MainPersonalExactCasDispatchStarted
        ):
            raise MainPersonalExactCasResponseReconciliationError("authority_invalid")
        evidence = evidence_result[0]
        if (
            evidence.operation_id != intent.operation_id
            or evidence.intent_digest != intent.intent_digest
            or evidence.dispatch_marker_digest != marker.dispatch_marker_digest
            or marker.intent_digest != intent.intent_digest
        ):
            raise MainPersonalExactCasResponseReconciliationError("binding_differs")
        return evidence, intent, marker

    def _put(self, data: bytes, classified_at: datetime) -> ArtifactRef:
        if len(data) > self._max:
            raise MainPersonalExactCasResponseReconciliationError("record_too_large")
        failure: MainPersonalExactCasResponseReconciliationError | None = None
        reference: ArtifactRef | None = None
        try:
            digest = "sha256:" + hashlib.sha256(data).hexdigest()
            object_path = self._store.path_for_digest(digest)
            self._prepare_directory(object_path.parent)
            self._qualify(object_path.parent, "artifact object directory")
            _fsync_directory(object_path.parent)
            reference = self._store.put_bytes(
                data, media_type=_MEDIA, role=_ROLE, max_bytes=self._max
            )
            reference = reference.model_copy(update={"created_at": classified_at})
            _fsync_ancestors(self._store.path_for_digest(reference.digest), self._store.root)
        except Exception:
            failure = MainPersonalExactCasResponseReconciliationError("artifact_write_failed")
        if failure is not None:
            raise failure
        if reference is None:
            raise MainPersonalExactCasResponseReconciliationError("artifact_write_failed")
        return reference

    def _publish(self, operation_id: str, reference: ArtifactRef, data: bytes) -> ArtifactRef:
        index = self._index_path(operation_id)
        failure: MainPersonalExactCasResponseReconciliationError | None = None
        try:
            if self._canonical_path(index) != index:
                raise ValueError("index path changed")
            self._prepare_directory(index.parent)
            self._qualify(index.parent, "index directory")
            _fsync_directory(index.parent)
            payload = canonical_bytes(reference)
            with _LOCK:
                try:
                    descriptor = os.open(index, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                    with os.fdopen(descriptor, "wb") as handle:
                        handle.write(payload)
                        handle.flush()
                        os.fsync(handle.fileno())
                    _fsync_directory(index.parent)
                except FileExistsError:
                    old = self._read_reference(index)
                    if old.digest == reference.digest and self._store.read_bytes(old) == data:
                        reference = old
                    else:
                        failure = MainPersonalExactCasResponseReconciliationConflictError(
                            "conflicting_classification"
                        )
        except Exception:
            failure = MainPersonalExactCasResponseReconciliationError("index_write_failed")
        if failure is not None:
            raise failure
        return reference

    def _read_reference(self, index: Path) -> ArtifactRef:
        failure: MainPersonalExactCasResponseReconciliationError | None = None
        reference: ArtifactRef | None = None
        try:
            if self._canonical_path(index) != index:
                raise ValueError("index path changed")
            raw = index.read_bytes()
            reference = ArtifactRef.model_validate_json(raw)
            if (
                canonical_bytes(reference) != raw
                or reference.role != _ROLE
                or reference.media_type != _MEDIA
                or reference.size_bytes > self._max
            ):
                raise ValueError("reference differs")
        except Exception:
            failure = MainPersonalExactCasResponseReconciliationError("malformed_index")
        if failure is not None:
            raise failure
        if reference is None:
            raise MainPersonalExactCasResponseReconciliationError("malformed_index")
        return reference

    def _index_path(self, operation_id: str) -> Path:
        if type(operation_id) is not str or _DIGEST.fullmatch(operation_id) is None:
            raise MainPersonalExactCasResponseReconciliationError("invalid_operation_id")
        digest = operation_id.removeprefix("sha256:")
        return self._indexes / digest[:2] / (digest[2:] + ".json")

    def _prepare_directory(self, path: Path) -> Path:
        canonical = self._canonical_path(path)
        failure = False
        try:
            canonical.mkdir(parents=True, exist_ok=True)
            if not canonical.is_dir():
                raise ValueError("not directory")
        except Exception:
            failure = True
        if failure:
            raise MainPersonalExactCasResponseReconciliationError("directory_unavailable")
        return canonical

    @staticmethod
    def _canonical_path(path: Path) -> Path:
        candidate = path if path.is_absolute() else Path.cwd() / path
        for component in [*reversed(candidate.parents), candidate]:
            if component.is_symlink():
                raise ValueError("classification path contains a symlink")
        return candidate.resolve(strict=False)

    def _qualify(self, path: Path, label: str) -> DurableBackendQualification:
        qualification = require_durable_backend(path)
        if (
            qualification.mount_id != self._qualification.mount_id
            or qualification.device != self._qualification.device
        ):
            raise MainPersonalExactCasResponseReconciliationError(f"{label}_backend_mismatch")
        return qualification


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_ancestors(path: Path, root: Path) -> None:
    current = path.parent
    root = root.resolve(strict=False)
    while True:
        _fsync_directory(current)
        if current == root:
            return
        if not current.is_relative_to(root):
            raise OSError("artifact escaped root")
        current = current.parent


__all__ = [
    "MainPersonalExactCasResponseReconciliationClassificationJournal",
    "MainPersonalExactCasResponseReconciliationConflictError",
    "MainPersonalExactCasResponseReconciliationError",
]
