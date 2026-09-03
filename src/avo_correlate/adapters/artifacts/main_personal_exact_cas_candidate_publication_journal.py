"""Fail-closed durable journal for the isolated candidate publisher leaf."""
# ruff: noqa: E501

from __future__ import annotations

import json
import os
import re
import stat
import sys
from contextlib import suppress
from pathlib import Path
from threading import RLock
from typing import TypeVar

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
from avo_correlate.contracts.main_personal_exact_cas_controller_composition import (
    MainPersonalExactCasControllerComposition,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

_LOCK = RLock()
_DIGEST_KEY = re.compile(r"^sha256:[0-9a-f]{64}$")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
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


class _CandidatePublicationAuthorityRoot:
    """Reserved exact authority root; unavailable until full closure exists."""

    def __init__(
        self,
        composition: MainPersonalExactCasControllerComposition,
        *,
        configuration_digest: str,
        publisher_app_id: int,
        publisher_installation_id: int,
    ) -> None:
        if type(composition) is not MainPersonalExactCasControllerComposition:
            raise ValueError("approved composition root is required")
        if (
            not _DIGEST_KEY.fullmatch(configuration_digest)
            or publisher_app_id <= 0
            or publisher_installation_id <= 0
        ):
            raise ValueError("candidate publication authority identity is malformed")
        composition.model_validate(composition.model_dump(mode="python"), strict=True)
        self._composition: MainPersonalExactCasControllerComposition = composition
        self._configuration_digest: str = configuration_digest
        self._app_id: int = publisher_app_id
        self._installation_id: int = publisher_installation_id
        # The existing composition root is deliberately non-authoritative and
        # does not yet close over the fresh policy/identity/authorization
        # journals required to authorize this distinct publisher.  Keep the
        # transport unreachable until that exact durable authority root is
        # composed and reopen-validated; a caller-supplied verifier is never
        # accepted as a substitute.
        raise ValueError("candidate publication authority root is not provisioned")

    def verify_intent(self, intent: MainPersonalExactCasCandidatePublicationIntent) -> bool:
        if (
            intent.operation_id != self._composition.operation_id
            or intent.repository_digest != self._composition.repository_digest
            or intent.candidate_ref != self._composition.candidate_ref
            or intent.base_commit != self._composition.base_commit
            or intent.candidate_commit != self._composition.candidate_commit
            or intent.candidate_tree != self._composition.candidate_tree
            or intent.candidate_parents != self._composition.candidate_parents
            or intent.source_composition_digest != self._composition.source_composition_digest
            or intent.verified_policy_digest != self._composition.policy_digest
            or intent.configuration_digest != self._configuration_digest
            or intent.publisher_app_id != self._app_id
            or intent.publisher_installation_id != self._installation_id
        ):
            raise ValueError("candidate intent is not rooted in approved composition")
        return True

    def verify_response_evidence(
        self,
        evidence: MainPersonalExactCasCandidatePublicationResponseEvidence,
        intent: MainPersonalExactCasCandidatePublicationIntent,
        marker: MainPersonalExactCasCandidatePublicationDispatchStarted,
    ) -> bool:
        if (
            evidence.operation_id != intent.operation_id
            or evidence.repository_digest != intent.repository_digest
            or evidence.candidate_ref != intent.candidate_ref
            or evidence.candidate_commit != intent.candidate_commit
            or evidence.intent_digest != intent.intent_digest
            or evidence.dispatch_marker_digest != marker.dispatch_marker_digest
            or evidence.publisher_app_id != self._app_id
            or evidence.publisher_installation_id != self._installation_id
            or evidence.publisher_identity != intent.publisher_identity
            or evidence.configuration_digest != intent.configuration_digest
        ):
            raise ValueError("response evidence is not rooted in approved composition")
        return True

    def verify_reconciliation(
        self,
        reconciliation: MainPersonalExactCasCandidatePublicationReconciliation,
        intent: MainPersonalExactCasCandidatePublicationIntent,
        marker: MainPersonalExactCasCandidatePublicationDispatchStarted,
    ) -> bool:
        if (
            reconciliation.operation_id != intent.operation_id
            or reconciliation.repository_digest != intent.repository_digest
            or reconciliation.candidate_ref != intent.candidate_ref
            or reconciliation.candidate_commit != intent.candidate_commit
            or reconciliation.candidate_tree != intent.candidate_tree
            or reconciliation.candidate_parents != intent.candidate_parents
        ):
            raise ValueError("reconciliation is not rooted in approved composition")
        return True


class MainPersonalExactCasCandidatePublicationJournal:
    """Create-once records with no provider, token, receipt, or completion API."""

    def __init__(
        self,
        root: Path,
        *,
        approved_composition: MainPersonalExactCasControllerComposition,
        configuration_digest: str,
        publisher_app_id: int,
        publisher_installation_id: int,
        artifact_store: FilesystemArtifactStore | None = None,
        max_record_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        if max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        authority = _CandidatePublicationAuthorityRoot(
            approved_composition,
            configuration_digest=configuration_digest,
            publisher_app_id=publisher_app_id,
            publisher_installation_id=publisher_installation_id,
        )
        self._qualification = require_durable_backend(root)
        self._root = self._qualification.root
        self._descriptor_mode = bool(
            sys.platform == "linux"
            and hasattr(os, "O_NOFOLLOW")
            and hasattr(os, "O_DIRECTORY")
            and not self._qualification.reason.startswith("test-")
        )
        self._root_fd: int | None = None
        self._index_fd: int | None = None
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
        self._authority = authority
        self._max = max_record_bytes
        if self._descriptor_mode:
            try:
                self._root_fd = _open_directory(self._root)
                self._index_fd = _open_dir_at(
                    self._root_fd, "main-personal-exact-cas-candidate-publication-index", create=False
                )
                self._check_descriptors()
            except BaseException:
                self.close()
                raise

    @property
    def root(self) -> Path:
        return self._root

    @property
    def artifact_store(self) -> FilesystemArtifactStore:
        return self._store

    def close(self) -> None:
        for descriptor in (self._index_fd, self._root_fd):
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
        self._index_fd = None
        self._root_fd = None

    def _check_descriptors(self) -> None:
        if self._root_fd is None or self._index_fd is None:
            raise CandidatePublicationJournalError("journal descriptors unavailable")
        root_stat = os.fstat(self._root_fd)
        index_stat = os.fstat(self._index_fd)
        if not stat.S_ISDIR(root_stat.st_mode) or not stat.S_ISDIR(index_stat.st_mode):
            raise CandidatePublicationJournalError("journal descriptor is not a directory")
        if (root_stat.st_dev, _mount_id(self._root_fd)) != (
            index_stat.st_dev,
            _mount_id(self._index_fd),
        ):
            raise CandidatePublicationJournalError("journal descriptor backend changed")
        if self._qualification.mount_id is None or _mount_id(self._root_fd) != self._qualification.mount_id:
            raise CandidatePublicationJournalError("journal backend qualification changed")

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
        existing = self.read_dispatch_started(marker.operation_id)
        if existing is not None:
            self._bind_marker(existing[0], intent)
            return existing[1], False
        created: list[bool] = []
        try:
            reference = self._record(
                "dispatch-started", marker.operation_id, marker, created_out=created
            )
        except CandidatePublicationRecordConflictError:
            # A competing process may have won O_EXCL after our initial read.
            # Its timestamp is intentionally irrelevant: adopt only the valid
            # durable winner and never issue a second dispatch.
            existing = self.read_dispatch_started(marker.operation_id)
            if existing is None:
                raise CandidatePublicationJournalError("dispatch winner disappeared") from None
            self._bind_marker(existing[0], intent)
            if created:
                created.clear()
            created.append(False)
            return existing[1], False
        return reference, created[0]

    def record_response_evidence(
        self, evidence: MainPersonalExactCasCandidatePublicationResponseEvidence
    ) -> ArtifactRef:
        intent, marker = self._scope(evidence.operation_id)
        if (
            evidence.intent_digest != intent.intent_digest
            or evidence.dispatch_marker_digest != marker.dispatch_marker_digest
            or evidence.publisher_app_id != intent.publisher_app_id
            or evidence.publisher_installation_id != intent.publisher_installation_id
            or evidence.publisher_identity != intent.publisher_identity
        ):
            raise CandidatePublicationJournalError("response evidence binding differs")
        self._verify("response-evidence", evidence, intent, marker)
        return self._record("response-evidence", evidence.operation_id, evidence)

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
        value = self._read_raw(
            "intent", operation_id, MainPersonalExactCasCandidatePublicationIntent
        )
        if value is not None:
            self._verify("intent", value[0])
        return value

    def read_dispatch_started(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasCandidatePublicationDispatchStarted, ArtifactRef] | None:
        value = self._read_raw(
            "dispatch-started",
            operation_id,
            MainPersonalExactCasCandidatePublicationDispatchStarted,
        )
        if value is not None:
            intent = self._require("intent", operation_id, MainPersonalExactCasCandidatePublicationIntent)
            self._bind_marker(value[0], intent)
        return value

    def read_response_evidence(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasCandidatePublicationResponseEvidence, ArtifactRef] | None:
        value = self._read_raw(
            "response-evidence",
            operation_id,
            MainPersonalExactCasCandidatePublicationResponseEvidence,
        )
        if value is not None:
            intent, marker = self._scope(operation_id)
            self._verify("response-evidence", value[0], intent, marker)
        return value

    def read_reconciliation(
        self, reconciliation_digest: str
    ) -> tuple[MainPersonalExactCasCandidatePublicationReconciliation, ArtifactRef] | None:
        value = self._read_raw(
            "reconciliation",
            reconciliation_digest,
            MainPersonalExactCasCandidatePublicationReconciliation,
        )
        if value is not None:
            intent, marker = self._scope(value[0].operation_id)
            self._verify("reconciliation", value[0], intent, marker)
        return value

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
                result = self._authority.verify_intent(record)  # type: ignore[arg-type]
            elif kind == "response-evidence":
                result = self._authority.verify_response_evidence(record, args[0], args[1])  # type: ignore[arg-type]
            else:
                result = self._authority.verify_reconciliation(record, args[0], args[1])  # type: ignore[arg-type]
            if result is not True:
                raise ValueError("verifier did not accept record")
        except Exception as exc:
            del exc
            raise CandidatePublicationJournalError(f"{kind} verification failed") from None

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
            del exc
            raise CandidatePublicationJournalError(f"invalid {kind}") from None
        index = self._index_path(kind, key)
        try:
            self._prepare(index.parent)
            self._same_backend(index.parent, "index directory")
            with _LOCK:
                self._write_index(index, kind, canonical_bytes(reference))
            if created_out is not None:
                created_out.append(True)
            return reference
        except FileExistsError:
            try:
                old = self._read_reference(index, kind)
                old_data = self._store.read_bytes(old)
            except (OSError, RuntimeError, TypeError, ValueError, UnicodeError) as exc:
                del exc
                raise CandidatePublicationJournalError(f"malformed {kind} index") from None
            if old.digest == reference.digest and old_data == data:
                if created_out is not None:
                    created_out.append(False)
                return old
            raise CandidatePublicationRecordConflictError(f"conflicting {kind}") from None
        except CandidatePublicationRecordConflictError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            del exc
            raise CandidatePublicationJournalError(f"{kind} index was not durable") from None

    def _read_raw(self, kind: str, key: str, expected: type[_T]) -> tuple[_T, ArtifactRef] | None:
        index = self._index_path(kind, key)
        if not self._index_exists(index, kind):
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
            del exc
            raise CandidatePublicationJournalError(f"malformed {kind}") from None

    def _read_reference(self, index: Path, kind: str) -> ArtifactRef:
        data = self._read_index(index, kind)
        reference = ArtifactRef.model_validate(json.loads(data))
        if (
            canonical_bytes(reference) != data
            or reference.role != f"candidate-publication-{kind}"
            or reference.media_type != f"application/vnd.avo.candidate-publication-{kind}+json"
        ):
            raise ValueError("index is not canonical")
        return reference

    def _index_exists(self, index: Path, kind: str) -> bool:
        if self._descriptor_mode:
            try:
                self._read_index(index, kind)
            except FileNotFoundError:
                return False
            return True
        return index.is_file() and not index.is_symlink()

    def _read_index(self, index: Path, kind: str) -> bytes:
        if self._descriptor_mode:
            self._check_descriptors()
            if self._index_fd is None:
                raise CandidatePublicationJournalError("journal index descriptor unavailable")
            kind_fd = _open_dir_at(self._index_fd, kind, create=False)
            try:
                descriptor = os.open(index.name, os.O_RDONLY | _NOFOLLOW, dir_fd=kind_fd)
                try:
                    _check_regular(descriptor)
                    result = _read_bounded(descriptor, self._max)
                    os.fsync(descriptor)
                    return result
                finally:
                    os.close(descriptor)
            finally:
                os.close(kind_fd)
        return _read_no_follow(index)

    def _write_index(self, index: Path, kind: str, payload: bytes) -> None:
        if self._descriptor_mode:
            self._check_descriptors()
            if self._index_fd is None:
                raise CandidatePublicationJournalError("journal index descriptor unavailable")
            kind_fd = _open_dir_at(self._index_fd, kind, create=True)
            try:
                descriptor = os.open(
                    index.name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    mode=0o600,
                    dir_fd=kind_fd,
                )
                try:
                    _write_all(descriptor, payload)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.fsync(kind_fd)
                os.fsync(self._index_fd)
                if self._root_fd is not None:
                    os.fsync(self._root_fd)
                return
            finally:
                os.close(kind_fd)
        descriptor = os.open(
            index, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600
        )
        try:
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(index.parent)

    def _index_path(self, kind: str, key: str) -> Path:
        if kind not in _RECORDS or not _DIGEST_KEY.fullmatch(key):
            raise CandidatePublicationJournalError("journal key is malformed")
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
        candidate = Path(path).absolute()
        for component in [*reversed(candidate.parents), candidate]:
            if component.is_symlink():
                raise CandidatePublicationJournalError("controlled path contains a symlink")
        canonical = candidate.resolve(strict=False)
        canonical.mkdir(parents=True, exist_ok=True)
        if not canonical.is_dir() or canonical.is_symlink():
            raise CandidatePublicationJournalError("controlled path is not a directory")
        return canonical


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_no_follow(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
    try:
        _check_regular(descriptor)
        return _read_bounded(descriptor, 1024 * 1024)
    finally:
        os.close(descriptor)


def _check_regular(descriptor: int) -> None:
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise ValueError("journal index is not a regular file")


def _read_bounded(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) > maximum:
        raise ValueError("journal index exceeds bound")
    return data


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        offset += os.write(descriptor, data[offset:])


def _open_directory(path: Path) -> int:
    descriptor = os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("journal path is not a directory")
    return descriptor


def _open_dir_at(parent: int, name: str, *, create: bool) -> int:
    if create:
        with suppress(FileExistsError):
            os.mkdir(name, 0o700, dir_fd=parent)
    return _open_directory_at(parent, name)


def _open_directory_at(parent: int, name: str) -> int:
    descriptor = os.open(name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=parent)
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("journal path is not a directory")
    return descriptor


def _mount_id(descriptor: int) -> int:
    if sys.platform != "linux":
        raise ValueError("descriptor mount IDs require Linux")
    fdinfo = os.open(f"/proc/self/fdinfo/{descriptor}", os.O_RDONLY | _NOFOLLOW)
    try:
        text = _read_bounded(fdinfo, 4096).decode("ascii")
    finally:
        os.close(fdinfo)
    values = [line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith("mnt_id:")]
    if len(values) != 1 or not re.fullmatch(r"[1-9][0-9]*", values[0]):
        raise ValueError("fdinfo mount identity is malformed")
    return int(values[0])


def _fsync_ancestors(path: Path, root: Path) -> None:
    current = path.parent
    stop = root.parent
    while current != stop and root in current.parents:
        _fsync_directory(current)
        current = current.parent


__all__ = [
    "CandidatePublicationJournalError",
    "CandidatePublicationRecordConflictError",
    "MainPersonalExactCasCandidatePublicationJournal",
]
