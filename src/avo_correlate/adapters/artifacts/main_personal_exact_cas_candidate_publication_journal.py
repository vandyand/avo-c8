"""Fail-closed durable journal for the isolated candidate publisher leaf."""

from __future__ import annotations

import json
import os
from pathlib import Path
from threading import RLock
from typing import Protocol, TypeVar

from avo_correlate.adapters.artifacts.durable_backend_gate import (
    DurableBackendQualification,
    require_durable_backend,
)
from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef, StrictModel
from avo_correlate.contracts.main_personal_exact_cas_candidate_publication import (
    MainPersonalExactCasCandidatePublicationDispatchStarted,
    MainPersonalExactCasCandidatePublicationIntent,
    MainPersonalExactCasCandidatePublicationReconciliation,
    MainPersonalExactCasCandidatePublicationResponseEvidence,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

_LOCK = RLock()
_T = TypeVar("_T", bound=StrictModel)
_RECORDS: dict[str, type[StrictModel]] = {
    "intent": MainPersonalExactCasCandidatePublicationIntent,
    "dispatch-started": MainPersonalExactCasCandidatePublicationDispatchStarted,
    "response-evidence": MainPersonalExactCasCandidatePublicationResponseEvidence,
    "reconciliation": MainPersonalExactCasCandidatePublicationReconciliation,
}


class CandidatePublicationJournalError(RuntimeError):
    """The candidate journal is missing, tampered with, or not durable."""


class CandidatePublicationRecordConflictError(CandidatePublicationJournalError):
    """A create-once identity was already bound to other bytes."""


class CandidatePublicationAuthorityVerifier(Protocol):
    def verify_intent(self, intent: MainPersonalExactCasCandidatePublicationIntent) -> object: ...

    def verify_response_evidence(
        self,
        evidence: MainPersonalExactCasCandidatePublicationResponseEvidence,
        intent: MainPersonalExactCasCandidatePublicationIntent,
        marker: MainPersonalExactCasCandidatePublicationDispatchStarted,
    ) -> object: ...

    def verify_reconciliation(
        self,
        reconciliation: MainPersonalExactCasCandidatePublicationReconciliation,
        intent: MainPersonalExactCasCandidatePublicationIntent,
        marker: MainPersonalExactCasCandidatePublicationDispatchStarted,
    ) -> object: ...


class MainPersonalExactCasCandidatePublicationJournal:
    """Create-once records with no provider, token, receipt, or completion API."""

    def __init__(
        self,
        root: Path,
        *,
        authority_verifier: CandidatePublicationAuthorityVerifier,
        artifact_store: FilesystemArtifactStore | None = None,
        max_record_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        if max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        required = ("verify_intent", "verify_response_evidence", "verify_reconciliation")
        if any(not callable(getattr(authority_verifier, name, None)) for name in required):
            raise ValueError("controller-owned candidate publication verifier is required")
        self._qualification = require_durable_backend(root)
        self._root = self._qualification.root
        artifacts = self._prepare(self._root / "artifacts")
        if artifact_store is not None:
            if type(artifact_store) is not FilesystemArtifactStore:
                raise ValueError("candidate artifact store must be canonical filesystem store")
            if self._canonical(artifact_store.root) != artifacts:
                raise ValueError("artifact store must be beneath journal root")
            self._store = artifact_store
        else:
            self._store = FilesystemArtifactStore(artifacts)
        self._artifact_qualification = self._same_backend(artifacts, "artifact store")
        self._indexes = self._prepare(
            self._root / "main-personal-exact-cas-candidate-publication-index"
        )
        self._same_backend(self._indexes, "index directory")
        self._authority = authority_verifier
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

    def record_intent(self, intent: MainPersonalExactCasCandidatePublicationIntent) -> ArtifactRef:
        self._verify("intent", intent)
        return self._record("intent", intent.operation_id, intent)

    def claim_dispatch_started(
        self, marker: MainPersonalExactCasCandidatePublicationDispatchStarted
    ) -> tuple[ArtifactRef, bool]:
        intent = self._require(
            "intent", marker.operation_id, MainPersonalExactCasCandidatePublicationIntent
        )
        self._bind_marker(marker, intent)
        created: list[bool] = []
        reference = self._record(
            "dispatch-started", marker.operation_id, marker, created_out=created
        )
        return reference, created[0]

    def record_response_evidence(
        self, evidence: MainPersonalExactCasCandidatePublicationResponseEvidence
    ) -> ArtifactRef:
        intent, marker = self._scope(evidence.operation_id)
        if (
            evidence.intent_digest != intent.intent_digest
            or evidence.dispatch_marker_digest != marker.dispatch_marker_digest
        ):
            raise CandidatePublicationJournalError("response evidence binding differs")
        self._verify("response-evidence", evidence, intent, marker)
        return self._record("response-evidence", evidence.evidence_digest, evidence)

    def record_reconciliation(
        self, reconciliation: MainPersonalExactCasCandidatePublicationReconciliation
    ) -> ArtifactRef:
        intent, marker = self._scope(reconciliation.operation_id)
        if reconciliation.repository_digest != intent.repository_digest:
            raise CandidatePublicationJournalError("reconciliation repository binding differs")
        self._verify("reconciliation", reconciliation, intent, marker)
        return self._record("reconciliation", reconciliation.reconciliation_digest, reconciliation)

    def read_intent(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasCandidatePublicationIntent, ArtifactRef] | None:
        return self._read_raw(
            "intent", operation_id, MainPersonalExactCasCandidatePublicationIntent
        )

    def read_dispatch_started(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasCandidatePublicationDispatchStarted, ArtifactRef] | None:
        return self._read_raw(
            "dispatch-started",
            operation_id,
            MainPersonalExactCasCandidatePublicationDispatchStarted,
        )

    def read_response_evidence(
        self, evidence_digest: str
    ) -> tuple[MainPersonalExactCasCandidatePublicationResponseEvidence, ArtifactRef] | None:
        return self._read_raw(
            "response-evidence",
            evidence_digest,
            MainPersonalExactCasCandidatePublicationResponseEvidence,
        )

    def read_reconciliation(
        self, reconciliation_digest: str
    ) -> tuple[MainPersonalExactCasCandidatePublicationReconciliation, ArtifactRef] | None:
        return self._read_raw(
            "reconciliation",
            reconciliation_digest,
            MainPersonalExactCasCandidatePublicationReconciliation,
        )

    def _scope(
        self, operation_id: str
    ) -> tuple[
        MainPersonalExactCasCandidatePublicationIntent,
        MainPersonalExactCasCandidatePublicationDispatchStarted,
    ]:
        intent = self._require(
            "intent", operation_id, MainPersonalExactCasCandidatePublicationIntent
        )
        marker = self._require(
            "dispatch-started",
            operation_id,
            MainPersonalExactCasCandidatePublicationDispatchStarted,
        )
        self._bind_marker(marker, intent)
        return intent, marker

    @staticmethod
    def _bind_marker(
        marker: MainPersonalExactCasCandidatePublicationDispatchStarted,
        intent: MainPersonalExactCasCandidatePublicationIntent,
    ) -> None:
        if (
            marker.intent_digest != intent.intent_digest
            or marker.configuration_digest != intent.configuration_digest
            or marker.candidate_ref != intent.candidate_ref
        ):
            raise CandidatePublicationJournalError("dispatch marker binding differs")

    def _require(self, kind: str, key: str, model: type[_T]) -> _T:
        value = self._read_raw(kind, key, model)
        if value is None:
            raise CandidatePublicationJournalError(f"missing {kind}")
        return value[0]

    def _verify(self, kind: str, record: StrictModel, *args: object) -> None:
        try:
            if kind == "intent":
                self._authority.verify_intent(record)  # type: ignore[arg-type]
            elif kind == "response-evidence":
                self._authority.verify_response_evidence(record, args[0], args[1])  # type: ignore[arg-type]
            else:
                self._authority.verify_reconciliation(record, args[0], args[1])  # type: ignore[arg-type]
        except Exception as exc:
            raise CandidatePublicationJournalError(f"{kind} verification failed") from exc

    def _record(
        self, kind: str, key: str, record: StrictModel, *, created_out: list[bool] | None = None
    ) -> ArtifactRef:
        model = _RECORDS[kind]
        if type(record) is not model:
            raise TypeError(f"{kind} requires its concrete contract")
        try:
            data = canonical_bytes(model.model_validate_json(canonical_bytes(record)))
            if len(data) > self._max:
                raise ValueError("record exceeds configured bound")
            self._same_backend(self._store.root, "artifact store")
            digest = canonical_digest(record)
            self._prepare(self._store.path_for_digest(digest).parent)
            reference = self._store.put_bytes(
                data,
                media_type=f"application/vnd.avo.candidate-publication-{kind}+json",
                role=f"candidate-publication-{kind}",
                max_bytes=self._max,
            )
            _fsync_ancestors(self._store.path_for_digest(reference.digest), self._store.root)
        except CandidatePublicationJournalError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise CandidatePublicationJournalError(f"invalid {kind}") from exc
        index = self._index_path(kind, key)
        try:
            self._prepare(index.parent)
            self._same_backend(index.parent, "index directory")
            _fsync_directory(index.parent)
            with _LOCK:
                descriptor = os.open(index, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                with os.fdopen(descriptor, "wb") as handle:
                    payload = canonical_bytes(reference)
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                _fsync_directory(index.parent)
            if created_out is not None:
                created_out.append(True)
            return reference
        except FileExistsError:
            old = self._read_reference(index, kind)
            old_data = self._store.read_bytes(old)
            if old.digest == reference.digest and old_data == data:
                if created_out is not None:
                    created_out.append(False)
                return old
            raise CandidatePublicationRecordConflictError(f"conflicting {kind}") from None
        except CandidatePublicationRecordConflictError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise CandidatePublicationJournalError(f"{kind} index was not durable") from exc

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
            raise CandidatePublicationJournalError(f"malformed {kind}") from exc

    def _read_reference(self, index: Path, kind: str) -> ArtifactRef:
        reference = ArtifactRef.model_validate(json.loads(index.read_text(encoding="utf-8")))
        if (
            canonical_bytes(reference) != index.read_bytes()
            or reference.role != f"candidate-publication-{kind}"
            or reference.media_type != f"application/vnd.avo.candidate-publication-{kind}+json"
        ):
            raise ValueError("index is not canonical")
        return reference

    def _index_path(self, kind: str, key: str) -> Path:
        return self._indexes / kind / f"{key.removeprefix('sha256:')}.json"

    def _same_backend(self, path: Path, label: str) -> DurableBackendQualification:
        result = require_durable_backend(path)
        if (
            result.mount_id != self._qualification.mount_id
            or result.device != self._qualification.device
        ):
            raise CandidatePublicationJournalError(f"{label} is not on journal backend")
        return result

    @staticmethod
    def _canonical(path: Path) -> Path:
        return Path(path).absolute().resolve(strict=False)

    @classmethod
    def _prepare(cls, path: Path) -> Path:
        canonical = cls._canonical(path)
        canonical.mkdir(parents=True, exist_ok=True)
        if not canonical.is_dir() or canonical.is_symlink():
            raise CandidatePublicationJournalError("controlled path is not a directory")
        return canonical


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_ancestors(path: Path, root: Path) -> None:
    current = path.parent
    stop = root.parent
    while current != stop and root in current.parents:
        _fsync_directory(current)
        current = current.parent


__all__ = [
    "CandidatePublicationAuthorityVerifier",
    "CandidatePublicationJournalError",
    "CandidatePublicationRecordConflictError",
    "MainPersonalExactCasCandidatePublicationJournal",
]
