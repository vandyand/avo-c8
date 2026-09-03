"""Restart-safe durable storage for nonterminal personal CAS response evidence.

This module stores a sanitized transport observation and its canonical payload.
It intentionally imports neither the provider transport nor receipt/controller
contracts.  A separate authority layer must authenticate this evidence before
it can influence any state transition.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Any, Protocol, cast

from avo_correlate.adapters.artifacts.durable_backend_gate import (
    DurableBackendQualification,
    require_durable_backend,
)
from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_response import (
    MainPersonalExactCasResponse,
    parse_main_personal_exact_cas_response,
)
from avo_correlate.contracts.base import ArtifactRef, StrictModel
from avo_correlate.contracts.main_personal_exact_cas import (
    MainPersonalExactCasDispatchStarted,
    MainPersonalExactCasIntent,
)
from avo_correlate.contracts.main_personal_exact_cas_response_evidence import (
    MainPersonalExactCasResponseEvidence,
    main_personal_exact_cas_request_digest,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

_LOCK = RLock()
_INDEX_ROLE = "main-personal-exact-cas-response-evidence"
_INDEX_MEDIA = "application/vnd.avo.main-personal-exact-cas-response-evidence+json"
_PAYLOAD_ROLE = "main-personal-exact-cas-response"
_PAYLOAD_MEDIA = "application/vnd.avo.main-personal-exact-cas-response+json"
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_UNSIGNED_INTEGER_PATTERN = re.compile(r"^[0-9]{1,20}$")
_RESOURCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ALLOWED_METADATA = frozenset(
    {
        "retry-after",
        "x-github-request-id",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "x-ratelimit-resource",
    }
)


class MainPersonalExactCasResponseEvidenceJournalError(RuntimeError):
    """Value-free failure reading or recording response evidence."""


class MainPersonalExactCasResponseEvidenceConflictError(
    MainPersonalExactCasResponseEvidenceJournalError
):
    """An operation's create-once evidence index is bound to other bytes."""


class _EvidenceAuthorityReader(Protocol):
    def read_intent(self, operation_id: str) -> object: ...

    def read_dispatch_started(self, operation_id: str) -> object: ...


class _Observation(Protocol):
    operation_id: str
    repository_digest: str
    target_ref: str
    writer_app_id: int
    writer_installation_id: int
    writer_identity: str
    intent_digest: str
    dispatch_marker_digest: str
    status: int
    classification: str
    request_id: str | None
    metadata: object
    observed_at: datetime
    payload_bytes: bytes
    payload_digest: str


class MainPersonalExactCasResponseEvidenceJournal:
    """Qualified create-once evidence recorder with no authority capability."""

    def __init__(
        self,
        root: Path,
        *,
        authority_reader: _EvidenceAuthorityReader,
        artifact_store: FilesystemArtifactStore | None = None,
        max_record_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        if type(max_record_bytes) is not int or max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        if not callable(getattr(authority_reader, "read_intent", None)) or not callable(
            getattr(authority_reader, "read_dispatch_started", None)
        ):
            raise ValueError("authority reader is required")
        self._qualification = require_durable_backend(root)
        self._root = self._qualification.root
        store_root = self._prepare_directory(self._root / "artifacts")
        if artifact_store is not None:
            if type(artifact_store) is not FilesystemArtifactStore:
                raise ValueError(
                    "response evidence artifact store must be canonical filesystem store"
                )
            if self._canonical_path(artifact_store.root) != store_root:
                raise ValueError("artifact store must be beneath the qualified evidence root")
            self._store = artifact_store
        else:
            self._store = FilesystemArtifactStore(store_root)
        self._artifact_qualification = self._qualify_same_backend(store_root, "artifact store")
        self._indexes = self._prepare_directory(
            self._root / "main-personal-exact-cas-response-evidence-index"
        )
        self._index_qualification = self._qualify_same_backend(self._indexes, "index directory")
        self._authority = authority_reader
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

    def record_response_evidence(
        self,
        intent: MainPersonalExactCasIntent,
        marker: MainPersonalExactCasDispatchStarted,
        observation: _Observation,
    ) -> ArtifactRef:
        """Persist payload bytes before create-once evidence-index publication."""
        failure: MainPersonalExactCasResponseEvidenceJournalError | None = None
        evidence_ref: ArtifactRef | None = None
        try:
            self._validate_authority_chain(intent, marker)
            payload, metadata, observed_at = self._validate_scope(intent, marker, observation)
            payload_ref = self._put(
                payload,
                role=_PAYLOAD_ROLE,
                media_type=_PAYLOAD_MEDIA,
                max_bytes=self._max,
            )
            # The content-addressed bytes are the artifact identity.  Bind its
            # descriptive timestamp to the trusted observation so retrying an
            # identical observation produces identical evidence bytes.
            payload_ref = payload_ref.model_copy(update={"created_at": observed_at})
            evidence = MainPersonalExactCasResponseEvidence.build(
                operation_id=intent.operation_id,
                repository_digest=intent.repository_digest,
                target_ref=intent.target_ref,
                writer_app_id=intent.writer_app_id,
                writer_installation_id=intent.writer_installation_id,
                writer_identity=intent.writer_identity,
                intent_digest=intent.intent_digest,
                dispatch_marker_digest=marker.dispatch_marker_digest,
                candidate_commit=intent.candidate_commit,
                request_digest=main_personal_exact_cas_request_digest(
                    repository_digest=intent.repository_digest,
                    target_ref=intent.target_ref,
                    candidate_commit=intent.candidate_commit,
                ),
                response_status=observation.status,
                response_classification=observation.classification,
                response_request_id=observation.request_id,
                response_metadata=metadata,
                response_metadata_digest=_metadata_digest(metadata),
                response_payload_artifact=payload_ref,
                observed_at=observed_at,
            )
            evidence_bytes = canonical_bytes(evidence)
            evidence_ref = self._put(
                evidence_bytes,
                role=_INDEX_ROLE,
                media_type=_INDEX_MEDIA,
                max_bytes=self._max,
            )
            evidence_ref = self._publish_index(intent.operation_id, evidence_ref, evidence_bytes)
        except MainPersonalExactCasResponseEvidenceJournalError as exc:
            failure = exc
        except Exception:
            failure = MainPersonalExactCasResponseEvidenceJournalError("record_failed")
        if failure is not None:
            raise failure
        if evidence_ref is None:
            raise MainPersonalExactCasResponseEvidenceJournalError("record_failed")
        return evidence_ref

    def read_response_evidence(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasResponseEvidence, ArtifactRef] | None:
        """Re-read canonical evidence, payload, and current intent/marker binding."""

        index = self._index_path(operation_id)
        if not index.is_file():
            return None
        result: tuple[MainPersonalExactCasResponseEvidence, ArtifactRef] | None = None
        failure: MainPersonalExactCasResponseEvidenceJournalError | None = None
        try:
            reference = self._read_reference(index)
            data = self._store.read_bytes(reference)
            evidence = MainPersonalExactCasResponseEvidence.model_validate_json(data)
            if (
                type(evidence) is not MainPersonalExactCasResponseEvidence
                or canonical_bytes(evidence) != data
            ):
                raise ValueError("noncanonical evidence")
            payload = self._store.read_bytes(evidence.response_payload_artifact)
            if len(payload) > self._max or not _is_canonical_payload(payload):
                raise ValueError("noncanonical payload")
            if evidence.operation_id != operation_id:
                raise ValueError("operation binding differs")
            intent = self._authority_model("read_intent", operation_id, MainPersonalExactCasIntent)
            marker = self._authority_model(
                "read_dispatch_started", operation_id, MainPersonalExactCasDispatchStarted
            )
            self._validate_evidence_binding(evidence, intent, marker)
            parsed = _parse_payload(evidence.response_status, payload, evidence.response_metadata)
            if (
                parsed.classification != evidence.response_classification
                or parsed.metadata.get("x-github-request-id") != evidence.response_request_id
                or _metadata_digest(parsed.metadata) != evidence.response_metadata_digest
            ):
                raise ValueError("response classification or metadata differs")
            result = (evidence, reference)
        except MainPersonalExactCasResponseEvidenceJournalError as exc:
            failure = MainPersonalExactCasResponseEvidenceJournalError(str(exc))
        except Exception:
            failure = MainPersonalExactCasResponseEvidenceJournalError("malformed_evidence")
        if failure is not None:
            raise failure
        return result

    def _validate_scope(
        self,
        intent: MainPersonalExactCasIntent,
        marker: MainPersonalExactCasDispatchStarted,
        observation: _Observation,
    ) -> tuple[bytes, dict[str, str], datetime]:
        if (
            type(intent) is not MainPersonalExactCasIntent
            or type(marker) is not MainPersonalExactCasDispatchStarted
        ):
            raise MainPersonalExactCasResponseEvidenceJournalError("invalid_scope")
        failure: MainPersonalExactCasResponseEvidenceJournalError | None = None
        try:
            payload_value = observation.payload_bytes
            metadata_value = observation.metadata
            observed_at = observation.observed_at
            if type(observed_at) is not datetime:
                raise ValueError("timestamp differs")
            try:
                aware = observed_at.tzinfo is not None and observed_at.utcoffset() is not None
            except Exception:
                aware = False
            if not aware:
                raise ValueError("timestamp differs")
            if (
                observation.operation_id != intent.operation_id
                or observation.repository_digest != intent.repository_digest
                or observation.target_ref != intent.target_ref
                or observation.writer_app_id != intent.writer_app_id
                or observation.writer_installation_id != intent.writer_installation_id
                or observation.writer_identity != intent.writer_identity
                or observation.intent_digest != intent.intent_digest
                or observation.dispatch_marker_digest != marker.dispatch_marker_digest
                or observation.target_ref != "refs/heads/main"
                or observed_at < marker.started_at
                or type(payload_value) is not bytes
                or _payload_digest(payload_value) != observation.payload_digest
                or not _is_canonical_payload(payload_value)
            ):
                raise ValueError("scope differs")
            metadata = _strict_metadata(metadata_value)
            parsed = _parse_payload(observation.status, payload_value, metadata)
            if (
                parsed.classification != observation.classification
                or parsed.metadata.get("x-github-request-id") != observation.request_id
            ):
                raise ValueError("response differs")
        except Exception:
            failure = MainPersonalExactCasResponseEvidenceJournalError("invalid_scope")
        else:
            return payload_value, metadata, observed_at
        raise failure

    def _validate_authority_chain(
        self,
        intent: MainPersonalExactCasIntent,
        marker: MainPersonalExactCasDispatchStarted,
    ) -> None:
        failure: MainPersonalExactCasResponseEvidenceJournalError | None = None
        try:
            current_intent = self._authority_model(
                "read_intent", intent.operation_id, MainPersonalExactCasIntent
            )
            current_marker = self._authority_model(
                "read_dispatch_started", intent.operation_id, MainPersonalExactCasDispatchStarted
            )
            if canonical_bytes(current_intent) != canonical_bytes(intent) or canonical_bytes(
                current_marker
            ) != canonical_bytes(marker):
                raise ValueError("authority chain differs")
        except MainPersonalExactCasResponseEvidenceJournalError as exc:
            failure = MainPersonalExactCasResponseEvidenceJournalError(str(exc))
        except Exception:
            failure = MainPersonalExactCasResponseEvidenceJournalError("authority_record_invalid")
        if failure is not None:
            raise failure

    def _validate_evidence_binding(
        self,
        evidence: MainPersonalExactCasResponseEvidence,
        intent: MainPersonalExactCasIntent,
        marker: MainPersonalExactCasDispatchStarted,
    ) -> None:
        expected = (
            evidence.operation_id == intent.operation_id
            and evidence.repository_digest == intent.repository_digest
            and evidence.target_ref == intent.target_ref
            and evidence.writer_app_id == intent.writer_app_id
            and evidence.writer_installation_id == intent.writer_installation_id
            and evidence.writer_identity == intent.writer_identity
            and evidence.intent_digest == intent.intent_digest
            and evidence.dispatch_marker_digest == marker.dispatch_marker_digest
            and evidence.candidate_commit == intent.candidate_commit
            and evidence.request_digest
            == main_personal_exact_cas_request_digest(
                repository_digest=intent.repository_digest,
                target_ref=intent.target_ref,
                candidate_commit=intent.candidate_commit,
            )
        )
        if not expected:
            raise MainPersonalExactCasResponseEvidenceJournalError("binding_differs")

    def _authority_model(self, method: str, operation_id: str, expected: type[StrictModel]) -> Any:
        failure: MainPersonalExactCasResponseEvidenceJournalError | None = None
        checked: Any = None
        try:
            result = getattr(self._authority, method)(operation_id)
            if result is None:
                failure = MainPersonalExactCasResponseEvidenceJournalError(
                    "authority_record_missing"
                )
            else:
                candidate: Any = cast(Any, result[0]) if isinstance(result, tuple) else result
                if type(candidate) is not expected:
                    failure = MainPersonalExactCasResponseEvidenceJournalError(
                        "authority_record_invalid"
                    )
                else:
                    checked = expected.model_validate(candidate.model_dump(mode="json"))
                    if type(checked) is not expected or canonical_bytes(checked) != canonical_bytes(
                        candidate
                    ):
                        failure = MainPersonalExactCasResponseEvidenceJournalError(
                            "authority_record_invalid"
                        )
        except Exception:
            failure = MainPersonalExactCasResponseEvidenceJournalError("authority_record_invalid")
        if failure is not None:
            raise failure
        return checked

    def _put(self, data: bytes, *, role: str, media_type: str, max_bytes: int) -> ArtifactRef:
        if len(data) > max_bytes:
            raise MainPersonalExactCasResponseEvidenceJournalError("record_too_large")
        failure: MainPersonalExactCasResponseEvidenceJournalError | None = None
        reference: ArtifactRef | None = None
        try:
            root = self._canonical_path(self._store.root)
            if root != self._artifact_qualification.root:
                raise ValueError("artifact store moved")
            self._qualify_same_backend(root, "artifact store")
            digest = "sha256:" + hashlib.sha256(data).hexdigest()
            object_path = self._store.path_for_digest(digest)
            self._prepare_directory(object_path.parent)
            self._qualify_same_backend(object_path.parent, "artifact object directory")
            reference = self._store.put_bytes(
                data, media_type=media_type, role=role, max_bytes=max_bytes
            )
            _fsync_store_ancestors(self._store.path_for_digest(reference.digest), self._store.root)
        except Exception:
            failure = MainPersonalExactCasResponseEvidenceJournalError("artifact_write_failed")
        if failure is not None:
            raise failure
        if reference is None:
            raise MainPersonalExactCasResponseEvidenceJournalError("artifact_write_failed")
        return reference

    def _publish_index(self, operation_id: str, reference: ArtifactRef, data: bytes) -> ArtifactRef:
        index = self._index_path(operation_id)
        failure: MainPersonalExactCasResponseEvidenceJournalError | None = None
        try:
            self._prepare_directory(index.parent)
            self._qualify_same_backend(index.parent, "index directory")
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
                    _fsync_directory(index.parent.parent)
                except FileExistsError:
                    try:
                        old = self._read_reference(index)
                        old_data = self._store.read_bytes(old)
                    except Exception:
                        failure = MainPersonalExactCasResponseEvidenceJournalError(
                            "index_write_failed"
                        )
                    else:
                        if old.digest == reference.digest and old_data == data:
                            reference = old
                        else:
                            failure = MainPersonalExactCasResponseEvidenceConflictError(
                                "conflicting_evidence"
                            )
        except Exception:
            failure = MainPersonalExactCasResponseEvidenceJournalError("index_write_failed")
        if failure is not None:
            raise failure
        return reference

    def _read_reference(self, index: Path) -> ArtifactRef:
        reference: ArtifactRef | None = None
        failure: MainPersonalExactCasResponseEvidenceJournalError | None = None
        try:
            raw = index.read_bytes()
            reference = ArtifactRef.model_validate_json(raw)
            if (
                canonical_bytes(reference) != raw
                or reference.role != _INDEX_ROLE
                or reference.media_type != _INDEX_MEDIA
                or reference.size_bytes > self._max
            ):
                raise ValueError("reference differs")
        except Exception:
            failure = MainPersonalExactCasResponseEvidenceJournalError("malformed_index")
        if failure is not None:
            raise failure
        if reference is None:
            raise MainPersonalExactCasResponseEvidenceJournalError("malformed_index")
        return reference

    def _index_path(self, operation_id: str) -> Path:
        if type(operation_id) is not str or _DIGEST_PATTERN.fullmatch(operation_id) is None:
            raise MainPersonalExactCasResponseEvidenceJournalError("invalid_operation_id")
        return (
            self._indexes
            / operation_id.removeprefix("sha256:")[:2]
            / (operation_id.removeprefix("sha256:")[2:] + ".json")
        )

    def _prepare_directory(self, path: Path) -> Path:
        canonical = self._canonical_path(path)
        failure: MainPersonalExactCasResponseEvidenceJournalError | None = None
        result: Path | None = None
        try:
            canonical.mkdir(parents=True, exist_ok=True)
            result = self._canonical_existing_directory(canonical)
        except Exception:
            failure = MainPersonalExactCasResponseEvidenceJournalError("directory_unavailable")
        if failure is not None:
            raise failure
        if result is None:
            raise MainPersonalExactCasResponseEvidenceJournalError("directory_unavailable")
        return result

    def _qualify_same_backend(self, path: Path, label: str) -> DurableBackendQualification:
        qualification = require_durable_backend(path)
        root = self._qualification
        if qualification.mount_id != root.mount_id or qualification.device != root.device:
            raise MainPersonalExactCasResponseEvidenceJournalError(f"{label}_backend_mismatch")
        return qualification

    @staticmethod
    def _canonical_path(path: Path) -> Path:
        candidate = path if path.is_absolute() else Path.cwd() / path
        for component in [*reversed(candidate.parents), candidate]:
            if component.is_symlink():
                raise ValueError("symlink path")
        return candidate.resolve(strict=False)

    @classmethod
    def _canonical_existing_directory(cls, path: Path) -> Path:
        canonical = cls._canonical_path(path)
        if not canonical.is_dir():
            raise ValueError("not a directory")
        return canonical


def _metadata_digest(metadata: object) -> str:
    return canonical_digest(_strict_metadata(metadata))


def _strict_metadata(metadata: object) -> dict[str, str]:
    if not isinstance(metadata, Mapping):
        raise ValueError("metadata is not a mapping")
    failure = False
    clean: dict[str, str] = {}
    try:
        typed_metadata = cast(Mapping[object, object], metadata)
        iterator = iter(typed_metadata.items())
        for _ in range(65):
            try:
                key, value = next(iterator)
            except StopIteration:
                break
            if type(key) is not str or type(value) is not str:
                raise ValueError("metadata is not sanitized")
            if (
                not key
                or key.lower() != key
                or key not in _ALLOWED_METADATA
                or len(key) > 128
                or len(value) > 2048
                or any(ord(char) < 0x20 or ord(char) > 0x7E for char in key)
                or any(ord(char) < 0x20 or ord(char) > 0x7E for char in value)
            ):
                raise ValueError("metadata is not sanitized")
            if key == "x-github-request-id":
                valid = _REQUEST_ID_PATTERN.fullmatch(value) is not None
            elif key == "x-ratelimit-resource":
                valid = _RESOURCE_PATTERN.fullmatch(value) is not None
            else:
                valid = _UNSIGNED_INTEGER_PATTERN.fullmatch(value) is not None
            if not valid:
                raise ValueError("metadata is not sanitized")
            if key in clean:
                raise ValueError("metadata has duplicate keys")
            clean[key] = value
        else:
            raise ValueError("metadata has too many fields")
    except Exception:
        failure = True
    if failure:
        raise ValueError("metadata is not sanitized")
    return clean


def _payload_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _is_canonical_payload(data: bytes) -> bool:
    try:
        parsed = json.loads(data.decode("ascii"), object_pairs_hook=_pairs)
        return canonical_json_bytes(parsed) == data
    except Exception:
        return False


def _parse_payload(
    status: int, data: bytes, metadata: dict[str, str]
) -> MainPersonalExactCasResponse:
    parsed = json.loads(data.decode("ascii"), object_pairs_hook=_pairs)
    return parse_main_personal_exact_cas_response(status, parsed, metadata)


def _pairs(pairs: list[tuple[object, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_store_ancestors(object_path: Path, store_root: Path) -> None:
    current = object_path.parent
    root = store_root.resolve(strict=False)
    while True:
        _fsync_directory(current)
        if current == root:
            return
        if not current.is_relative_to(root):
            raise OSError("artifact escaped store")
        current = current.parent


__all__ = [
    "MainPersonalExactCasResponseEvidenceConflictError",
    "MainPersonalExactCasResponseEvidenceJournal",
    "MainPersonalExactCasResponseEvidenceJournalError",
]
