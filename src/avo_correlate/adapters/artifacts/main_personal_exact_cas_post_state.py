"""Restart-safe storage for nonterminal personal CAS post-state observations.

This journal accepts only the controller's concrete authority journal and the
fixed-origin read-only GitHub reader.  It persists topology observations for
later reconciliation; it never creates authority, receipts, or mutations.
"""

from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Any, cast

from avo_correlate.adapters.artifacts.durable_backend_gate import (
    DurableBackendQualification,
    require_durable_backend,
)
from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.main_personal_exact_cas_journal import (
    MainPersonalExactCasJournal,
)
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_post_state import (
    MainPersonalExactCasGitHubPostStateReader,
)
from avo_correlate.contracts.base import ArtifactRef, StrictModel
from avo_correlate.contracts.main_personal_exact_cas import (
    MainPersonalExactCasDispatchStarted,
    MainPersonalExactCasIntent,
)
from avo_correlate.contracts.main_personal_exact_cas_post_state import (
    MainPersonalExactCasReadOnlyPostState,
)
from avo_correlate.domain.canonical import canonical_bytes

_LOCK = RLock()
_INDEX_ROLE = "main-personal-exact-cas-post-state"
_INDEX_MEDIA = "application/vnd.avo.main-personal-exact-cas-post-state+json"
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class MainPersonalExactCasPostStateJournalError(RuntimeError):
    """Value-free failure reading or recording a post-state observation."""

    _CODES = frozenset(
        {
            "post_state_record_failed",
            "post_state_malformed",
            "post_state_conflict",
        }
    )

    def __init__(self, code: str = "post_state_record_failed") -> None:
        self.code = code if code in self._CODES else "post_state_record_failed"
        super().__init__(self.code)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.code!r})"


class MainPersonalExactCasPostStateJournalConflictError(MainPersonalExactCasPostStateJournalError):
    """The create-once operation index is bound to different bytes."""

    def __init__(self) -> None:
        super().__init__("post_state_conflict")


class MainPersonalExactCasReadOnlyPostStateJournal:
    """Durably record reader output without making it terminal or authoritative."""

    def __init__(
        self,
        root: Path,
        *,
        authority_journal: MainPersonalExactCasJournal,
        reader: MainPersonalExactCasGitHubPostStateReader,
        artifact_store: FilesystemArtifactStore | None = None,
        max_record_bytes: int = 8 * 1024 * 1024,
    ) -> None:
        if type(authority_journal) is not MainPersonalExactCasJournal:
            raise ValueError("controller authority journal is required")
        if type(reader) is not MainPersonalExactCasGitHubPostStateReader:
            raise ValueError("fixed post-state reader is required")
        if type(max_record_bytes) is not int or max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        self._qualification = require_durable_backend(root)
        self._root = self._qualification.root
        store_root = self._prepare_directory(self._root / "artifacts")
        if artifact_store is not None:
            if type(artifact_store) is not FilesystemArtifactStore:
                raise ValueError("post-state artifact store must be canonical filesystem store")
            if self._canonical_path(artifact_store.root) != store_root:
                raise ValueError("artifact store must be beneath the qualified journal root")
            self._store = artifact_store
        else:
            self._store = FilesystemArtifactStore(store_root)
        self._artifact_qualification = self._qualify_same_backend(store_root, "artifact store")
        self._indexes = self._prepare_directory(
            self._root / "main-personal-exact-cas-post-state-index"
        )
        self._index_qualification = self._qualify_same_backend(self._indexes, "index directory")
        _fsync_directory(self._root)
        self._authority = authority_journal
        self._reader = reader
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

    def capture(self, operation_id: str) -> ArtifactRef:
        """Read authority, observe once, and publish one create-once record."""

        existing = self.read(operation_id)
        if existing is not None:
            return existing[1]
        failure: MainPersonalExactCasPostStateJournalError | None = None
        result: ArtifactRef | None = None
        try:
            intent, marker = self._authority_chain(operation_id)
            observation = self._observe(intent)
            after_intent, after_marker = self._authority_chain(operation_id)
            if canonical_bytes(after_intent) != canonical_bytes(intent) or canonical_bytes(
                after_marker
            ) != canonical_bytes(marker):
                raise ValueError("authority chain changed")
            checked, data = self._validate_observation(observation, intent, marker)
            reference = self._put(data, checked.finished_at)
            result = self._publish_index(operation_id, reference, data)
        except MainPersonalExactCasPostStateJournalError as exc:
            failure = exc
        except Exception:
            failure = MainPersonalExactCasPostStateJournalError()
        if failure is not None:
            raise failure
        if result is None:
            raise MainPersonalExactCasPostStateJournalError()
        return result

    def read(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasReadOnlyPostState, ArtifactRef] | None:
        """Read and fully revalidate one observation without invoking the reader."""

        failure: MainPersonalExactCasPostStateJournalError | None = None
        result: tuple[MainPersonalExactCasReadOnlyPostState, ArtifactRef] | None = None
        try:
            index = self._checked_index_path(operation_id)
            if not index.is_file():
                return None
            reference = self._read_reference(index)
            object_path = self._checked_object_path(reference.digest)
            self._qualify_same_backend(object_path.parent, "artifact object directory")
            data = self._store.read_bytes(reference)
            if len(data) > self._max:
                raise ValueError("record is too large")
            observation = MainPersonalExactCasReadOnlyPostState.model_validate_json(data)
            if (
                type(observation) is not MainPersonalExactCasReadOnlyPostState
                or canonical_bytes(observation) != data
                or reference.created_at != observation.finished_at
            ):
                raise ValueError("record is not canonical")
            intent, marker = self._authority_chain(operation_id)
            self._validate_observation(observation, intent, marker)
            result = (observation, reference)
        except MainPersonalExactCasPostStateJournalError:
            failure = MainPersonalExactCasPostStateJournalError("post_state_malformed")
        except Exception:
            failure = MainPersonalExactCasPostStateJournalError("post_state_malformed")
        if failure is not None:
            raise failure
        return result

    def _authority_chain(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasIntent, MainPersonalExactCasDispatchStarted]:
        intent = self._authority_model("read_intent", operation_id, MainPersonalExactCasIntent)
        marker = self._authority_model(
            "read_dispatch_started", operation_id, MainPersonalExactCasDispatchStarted
        )
        if (
            intent.operation_id != operation_id
            or marker.operation_id != operation_id
            or marker.operation_id != intent.operation_id
            or marker.intent_digest != intent.intent_digest
        ):
            raise MainPersonalExactCasPostStateJournalError("post_state_malformed")
        return intent, marker

    def _authority_model(self, method: str, operation_id: str, expected: type[StrictModel]) -> Any:
        failure: MainPersonalExactCasPostStateJournalError | None = None
        result: Any = None
        try:
            raw_value: object = getattr(self._authority, method)(operation_id)
            if not isinstance(raw_value, tuple):
                raise ValueError("authority record shape")
            raw = cast(tuple[object, object], raw_value)
            if len(raw) != 2:
                raise ValueError("authority record shape")
            candidate = raw[0]
            if type(candidate) is not expected:
                raise ValueError("authority record type")
            checked = expected.model_validate_json(canonical_bytes(candidate))
            if type(checked) is not expected or checked != candidate:
                raise ValueError("authority record canonicality")
            result = checked
        except Exception:
            failure = MainPersonalExactCasPostStateJournalError("post_state_malformed")
        if failure is not None:
            raise failure
        return result

    def _observe(self, intent: MainPersonalExactCasIntent) -> Any:
        failure: MainPersonalExactCasPostStateJournalError | None = None
        result: Any = None
        try:
            result = self._reader.observe(intent)
        except Exception:
            failure = MainPersonalExactCasPostStateJournalError()
        if failure is not None:
            raise failure
        return result

    def _validate_observation(
        self,
        observation: object,
        intent: MainPersonalExactCasIntent,
        marker: MainPersonalExactCasDispatchStarted,
    ) -> tuple[MainPersonalExactCasReadOnlyPostState, bytes]:
        failure: MainPersonalExactCasPostStateJournalError | None = None
        result: tuple[MainPersonalExactCasReadOnlyPostState, bytes] | None = None
        try:
            if type(observation) is not MainPersonalExactCasReadOnlyPostState:
                raise ValueError("observation type")
            data = canonical_bytes(observation)
            checked = MainPersonalExactCasReadOnlyPostState.model_validate_json(data)
            if type(checked) is not MainPersonalExactCasReadOnlyPostState or checked != observation:
                raise ValueError("observation canonicality")
            expected_owner = getattr(self._reader, "_owner", None)
            expected_repo = getattr(self._reader, "_repo", None)
            if (
                checked.operation_id != intent.operation_id
                or checked.intent_digest != intent.intent_digest
                or checked.repository_digest != intent.repository_digest
                or checked.repository_digest != getattr(self._reader, "_repository_digest", None)
                or checked.owner != expected_owner
                or checked.repository != expected_repo
                or checked.target_ref != intent.target_ref
                or checked.target_ref != "refs/heads/main"
                or checked.base_commit != intent.base_commit
                or checked.candidate_commit != intent.candidate_commit
                or checked.started_at < intent.recorded_at
                or checked.started_at < marker.started_at
                or checked.finished_at < checked.started_at
                or checked.is_terminal is not False
                or checked.is_authoritative is not False
            ):
                raise ValueError("observation scope")
            result = (checked, data)
        except Exception:
            failure = MainPersonalExactCasPostStateJournalError()
        if failure is not None:
            raise failure
        if result is None:
            raise MainPersonalExactCasPostStateJournalError()
        return result

    def _put(self, data: bytes, created_at: datetime) -> ArtifactRef:
        if len(data) > self._max:
            raise MainPersonalExactCasPostStateJournalError()
        failure: MainPersonalExactCasPostStateJournalError | None = None
        result: ArtifactRef | None = None
        try:
            store_root = self._canonical_path(self._store.root)
            if store_root != self._artifact_qualification.root:
                raise ValueError("artifact store moved")
            self._qualify_same_backend(store_root, "artifact store")
            digest = "sha256:" + hashlib.sha256(data).hexdigest()
            object_path = self._checked_object_path(digest)
            self._prepare_directory(object_path.parent)
            object_path = self._checked_object_path(digest)
            self._qualify_same_backend(object_path.parent, "artifact object directory")
            reference = self._store.put_bytes(
                data,
                media_type=_INDEX_MEDIA,
                role=_INDEX_ROLE,
                max_bytes=self._max,
            )
            result = reference.model_copy(update={"created_at": created_at})
            persisted_path = self._checked_object_path(result.digest)
            _fsync_store_ancestors(persisted_path, self._store.root)
            _fsync_directory(self._root)
        except Exception:
            failure = MainPersonalExactCasPostStateJournalError()
        if failure is not None:
            raise failure
        if result is None:
            raise MainPersonalExactCasPostStateJournalError()
        return result

    def _publish_index(self, operation_id: str, reference: ArtifactRef, data: bytes) -> ArtifactRef:
        index = self._checked_index_path(operation_id)
        failure: MainPersonalExactCasPostStateJournalError | None = None
        result: ArtifactRef | None = None
        try:
            self._prepare_directory(index.parent)
            self._qualify_same_backend(index.parent, "index directory")
            _fsync_directory(index.parent)
            with _LOCK:
                try:
                    descriptor = os.open(index, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                    with os.fdopen(descriptor, "wb") as handle:
                        handle.write(canonical_bytes(reference))
                        handle.flush()
                        os.fsync(handle.fileno())
                    _fsync_directory(index.parent)
                    _fsync_directory(index.parent.parent)
                    _fsync_directory(self._root)
                    result = reference
                except FileExistsError:
                    old = self._read_reference(index)
                    old_path = self._checked_object_path(old.digest)
                    self._qualify_same_backend(old_path.parent, "artifact object directory")
                    old_data = self._store.read_bytes(old)
                    if old == reference and old_data == data:
                        result = old
                    else:
                        raise MainPersonalExactCasPostStateJournalConflictError() from None
        except MainPersonalExactCasPostStateJournalConflictError as exc:
            failure = exc
        except Exception:
            failure = MainPersonalExactCasPostStateJournalError()
        if failure is not None:
            raise failure
        if result is None:
            raise MainPersonalExactCasPostStateJournalError()
        return result

    def _read_reference(self, index: Path) -> ArtifactRef:
        failure: MainPersonalExactCasPostStateJournalError | None = None
        result: ArtifactRef | None = None
        try:
            if self._canonical_path(index) != index:
                raise ValueError("index path changed")
            raw = index.read_bytes()
            reference = ArtifactRef.model_validate_json(raw)
            if (
                canonical_bytes(reference) != raw
                or reference.role != _INDEX_ROLE
                or reference.media_type != _INDEX_MEDIA
                or reference.size_bytes > self._max
            ):
                raise ValueError("reference differs")
            result = reference
        except Exception:
            failure = MainPersonalExactCasPostStateJournalError("post_state_malformed")
        if failure is not None:
            raise failure
        if result is None:
            raise MainPersonalExactCasPostStateJournalError("post_state_malformed")
        return result

    def _index_path(self, operation_id: str) -> Path:
        if type(operation_id) is not str or _DIGEST_PATTERN.fullmatch(operation_id) is None:
            raise MainPersonalExactCasPostStateJournalError("post_state_malformed")
        hex_digest = operation_id.removeprefix("sha256:")
        return self._indexes / hex_digest[:2] / f"{hex_digest[2:]}.json"

    def _checked_index_path(self, operation_id: str) -> Path:
        index = self._index_path(operation_id)
        if self._canonical_path(index) != index:
            raise MainPersonalExactCasPostStateJournalError("post_state_malformed")
        return index

    def _checked_object_path(self, digest: str) -> Path:
        object_path = self._store.path_for_digest(digest)
        if self._canonical_path(object_path) != object_path:
            raise MainPersonalExactCasPostStateJournalError("post_state_malformed")
        return object_path

    def _prepare_directory(self, path: Path) -> Path:
        failure: MainPersonalExactCasPostStateJournalError | None = None
        result: Path | None = None
        try:
            canonical = self._canonical_path(path)
            canonical.mkdir(parents=True, exist_ok=True)
            result = self._canonical_path(canonical)
            if not result.is_dir():
                raise ValueError("not a directory")
        except Exception:
            failure = MainPersonalExactCasPostStateJournalError()
        if failure is not None:
            raise failure
        if result is None:
            raise MainPersonalExactCasPostStateJournalError()
        return result

    def _qualify_same_backend(self, path: Path, label: str) -> DurableBackendQualification:
        qualification = require_durable_backend(path)
        if not qualification.qualified:
            raise MainPersonalExactCasPostStateJournalError()
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
            raise MainPersonalExactCasPostStateJournalError()
        del label
        return qualification

    @staticmethod
    def _canonical_path(path: Path) -> Path:
        candidate = path if path.is_absolute() else Path.cwd() / path
        for component in [*reversed(candidate.parents), candidate]:
            if component.is_symlink():
                raise ValueError("symlink path")
        return candidate.resolve(strict=False)


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
    "MainPersonalExactCasPostStateJournalConflictError",
    "MainPersonalExactCasPostStateJournalError",
    "MainPersonalExactCasReadOnlyPostStateJournal",
]
