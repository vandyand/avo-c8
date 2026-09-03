"""Durable, offline, non-authoritative hosted identity evidence journal.

Only already-sanitized observations are accepted.  This boundary has no
provider, transport, credential, clock, controller, receipt, or mutation
capability.  The singleton root binds five content-addressed child records to
the exact hosted identity bundle produced by the existing offline validators.
"""

# Runtime exact-type and canonical round trips are intentional at this
# persistence boundary; the concrete checks are stronger than static unions.
# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnnecessaryCast=false, reportArgumentType=false

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from contextlib import suppress
from dataclasses import fields
from pathlib import Path
from threading import RLock
from typing import Any, cast

from avo_correlate.adapters.artifacts.durable_backend_gate import (
    DurableBackendQualification,
    require_durable_backend,
)
from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.git.main_composition import MainBaseSnapshot
from avo_correlate.adapters.hosted_git.github_main_base_reader import (
    GitHubMainBaseReaderConfiguration,
)
from avo_correlate.adapters.hosted_git.github_read_provenance import (
    GitHubReadProvenance,
    GitHubReadRequest,
    GitHubReadWithProvenance,
)
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_hosted_identity_bundle import (
    MainPersonalExactCasHostedIdentityEvidenceBundle,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_personal_exact_cas_hosted_configuration import (
    MainPersonalExactCasHostedConfigurationDiagnostic,
)
from avo_correlate.contracts.main_personal_exact_cas_hosted_identity import (
    MainPersonalExactCasHostedIdentityEvidenceRoot,
)
from avo_correlate.domain.canonical import canonical_bytes

_LOCK = RLock()
_MAX_INDEX_BYTES = 1024 * 1024
_DEFAULT_MAX = 8 * 1024 * 1024
_INDEX_DIR = "main-personal-exact-cas-hosted-identity-index"
_INDEX_NAME = "root.json"
_DIGEST_PREFIX = "sha256:"
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_FDINFO_MAX_BYTES = 4096

_CHILD_SPECS: dict[str, tuple[str, str, type[Any]]] = {
    "writer_diagnostic_artifact": (
        "main-personal-exact-cas-hosted-configuration-diagnostic",
        "application/vnd.avo.main-personal-exact-cas-hosted-configuration-diagnostic+json",
        MainPersonalExactCasHostedConfigurationDiagnostic,
    ),
    "writer_provenance_artifact": (
        "github-read-provenance",
        "application/vnd.avo.github-read-provenance+json",
        GitHubReadProvenance,
    ),
    "observer_snapshot_artifact": (
        "main-base-snapshot",
        "application/vnd.avo.main-base-snapshot+json",
        MainBaseSnapshot,
    ),
    "observer_provenance_artifact": (
        "github-read-provenance",
        "application/vnd.avo.github-read-provenance+json",
        GitHubReadProvenance,
    ),
    "observer_configuration_artifact": (
        "github-main-base-reader-configuration",
        "application/vnd.avo.github-main-base-reader-configuration+json",
        GitHubMainBaseReaderConfiguration,
    ),
}


class MainPersonalExactCasHostedIdentityJournalError(RuntimeError):
    """Value-free failure to bind or read hosted identity evidence."""

    def __init__(self, code: str = "hosted_identity_unresolved") -> None:
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.code!r})"


class MainPersonalExactCasHostedIdentityJournalConflictError(
    MainPersonalExactCasHostedIdentityJournalError
):
    """The singleton root was exclusively won by different canonical bytes."""

    def __init__(self) -> None:
        super().__init__("hosted_identity_conflict")


def _failure(
    code: str = "hosted_identity_unresolved",
) -> MainPersonalExactCasHostedIdentityJournalError:
    return MainPersonalExactCasHostedIdentityJournalError(code)


def _exact_model(value: object, expected: type[Any]) -> Any:
    if type(value) is not expected:
        raise ValueError("exact concrete model is required")
    data = canonical_bytes(value)
    rebuilt = expected.model_validate_json(data)
    if type(rebuilt) is not expected or canonical_bytes(rebuilt) != data or rebuilt != value:
        raise ValueError("model is not canonical")
    return rebuilt


def _provenance_payload(value: GitHubReadProvenance) -> dict[str, object]:
    if type(value) is not GitHubReadProvenance:
        raise TypeError("exact provenance is required")
    return {
        "reader_identity": value.reader_identity,
        "api_origin": value.api_origin,
        "api_version": value.api_version,
        "owner": value.owner,
        "owner_id": value.owner_id,
        "repository": value.repository,
        "repository_id": value.repository_id,
        "repository_digest": value.repository_digest,
        "target_ref": value.target_ref,
        "app_slug": value.app_slug,
        "app_id": value.app_id,
        "installation_id": value.installation_id,
        "requested_repository_id": value.requested_repository_id,
        "requested_permissions": value.requested_permissions,
        "observed_permissions": value.observed_permissions,
        "repository_selection": value.repository_selection,
        "token_expiry_policy": value.token_expiry_policy,
        "requests": tuple(
            {"method": item.method, "path": item.path, "credential_role": item.credential_role}
            for item in value.requests
        ),
        "endpoint_observation_digests": value.endpoint_observation_digests,
        "initial_ref_digest": value.initial_ref_digest,
        "commit_digest": value.commit_digest,
        "final_ref_digest": value.final_ref_digest,
        "configuration_pass_digests": value.configuration_pass_digests,
        "configuration_digest": value.configuration_digest,
        "writer_app_id": value.writer_app_id,
        "writer_installation_id": value.writer_installation_id,
    }


def _revalidate_provenance(value: object) -> GitHubReadProvenance:
    if type(value) is not GitHubReadProvenance:
        raise TypeError("exact provenance is required")
    payload = _provenance_payload(cast(GitHubReadProvenance, value))
    raw_requests = payload["requests"]
    requests = tuple(
        GitHubReadRequest(
            method=cast(dict[str, str], item)["method"],
            path=cast(dict[str, str], item)["path"],
            credential_role=cast(dict[str, str], item)["credential_role"],
        )
        for item in cast(tuple[dict[str, str], ...], raw_requests)
    )
    payload["requests"] = requests
    payload["requested_permissions"] = tuple(
        cast(tuple[str, ...], payload["requested_permissions"])
    )
    payload["observed_permissions"] = tuple(
        cast(tuple[str, ...], payload["observed_permissions"])
    )
    payload["configuration_pass_digests"] = tuple(
        cast(tuple[str, ...], payload["configuration_pass_digests"])
    )
    payload["endpoint_observation_digests"] = tuple(
        (cast(tuple[str, str], item)[0], cast(tuple[str, str], item)[1])
        for item in cast(tuple[tuple[str, str], ...], payload["endpoint_observation_digests"])
    )
    rebuilt = GitHubReadProvenance(**payload)
    if rebuilt != value or rebuilt.provenance_digest != value.provenance_digest:
        raise ValueError("provenance changed during validation")
    return rebuilt


def _configuration_payload(value: GitHubMainBaseReaderConfiguration) -> dict[str, object]:
    if type(value) is not GitHubMainBaseReaderConfiguration:
        raise TypeError("exact reader configuration is required")
    value.assert_valid()
    expected = {
        item.name: getattr(value, item.name)
        for item in fields(GitHubMainBaseReaderConfiguration)
        if item.name != "configuration_digest"
    }
    expected["configuration_digest"] = value.configuration_digest
    return expected


def _revalidate_configuration(value: object) -> GitHubMainBaseReaderConfiguration:
    if type(value) is not GitHubMainBaseReaderConfiguration:
        raise TypeError("exact reader configuration is required")
    payload = _configuration_payload(cast(GitHubMainBaseReaderConfiguration, value))
    expected_digest = payload.pop("configuration_digest")
    rebuilt = GitHubMainBaseReaderConfiguration(**payload)
    if rebuilt.configuration_digest != expected_digest or rebuilt != value:
        raise ValueError("reader configuration changed during validation")
    rebuilt.assert_valid()
    return rebuilt


def _snapshot_payload(value: MainBaseSnapshot) -> dict[str, object]:
    if type(value) is not MainBaseSnapshot:
        raise TypeError("exact main base snapshot is required")
    if set(vars(value)) != {"repository_digest", "commit", "tree", "target_ref"}:
        raise ValueError("snapshot has reflective state")
    return {
        "repository_digest": value.repository_digest,
        "commit": value.commit,
        "tree": value.tree,
        "target_ref": value.target_ref,
    }


def _revalidate_snapshot(value: object) -> MainBaseSnapshot:
    if type(value) is not MainBaseSnapshot:
        raise TypeError("exact main base snapshot is required")
    payload = _snapshot_payload(cast(MainBaseSnapshot, value))
    rebuilt = MainBaseSnapshot(**payload)
    if rebuilt != value or canonical_bytes(payload) != canonical_bytes(_snapshot_payload(rebuilt)):
        raise ValueError("snapshot changed during validation")
    return rebuilt


class MainPersonalExactCasHostedIdentityJournal:
    """Create-once durable storage for one exact hosted identity bundle."""

    def __init__(
        self,
        root: Path,
        *,
        artifact_store: FilesystemArtifactStore | None = None,
        max_record_bytes: int = _DEFAULT_MAX,
    ) -> None:
        self._closed = False
        self._descriptor_mode = False
        self._root_fd: int | None = None
        self._artifacts_fd: int | None = None
        self._indexes_fd: int | None = None
        if type(max_record_bytes) is not int or max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        self._qualification = require_durable_backend(root)
        self._root = self._qualification.root
        artifacts = self._prepare_directory(self._root / "artifacts")
        if artifact_store is not None:
            if type(artifact_store) is not FilesystemArtifactStore:
                raise ValueError("artifact store must be canonical filesystem store")
            if self._canonical_path(artifact_store.root) != artifacts:
                raise ValueError("artifact store must be beneath journal root")
            self._store = artifact_store
        else:
            self._store = FilesystemArtifactStore(artifacts)
        self._qualify_same_backend(artifacts)
        self._indexes = self._prepare_directory(self._root / _INDEX_DIR)
        self._qualify_same_backend(self._indexes)
        self._descriptor_mode = self._supports_descriptor_backend()
        if self._descriptor_mode:
            try:
                self._root_fd = self._open_directory(self._root)
                self._artifacts_fd = _open_dir_at(self._root_fd, "artifacts", create=False)
                self._indexes_fd = _open_dir_at(self._root_fd, _INDEX_DIR, create=False)
                self._check_descriptor_backend(self._root_fd)
                self._check_descriptor_backend(self._artifacts_fd)
                self._check_descriptor_backend(self._indexes_fd)
            except BaseException:
                self.close()
                raise
        try:
            _fsync_directory(self._root)
        except BaseException:
            self.close()
            raise
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

    @property
    def root_path(self) -> Path:
        return self._indexes / _INDEX_NAME

    @property
    def index_path(self) -> Path:
        return self.root_path

    def _index_path(self) -> Path:
        """Stable private path hook used by recovery and adversarial checks."""

        return self.root_path

    def close(self) -> None:
        """Close retained descriptors exactly once; safe to call repeatedly."""

        if self._closed:
            return
        self._closed = True
        descriptors = (self._indexes_fd, self._artifacts_fd, self._root_fd)
        self._indexes_fd = None
        self._artifacts_fd = None
        self._root_fd = None
        for descriptor in descriptors:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)

    def __enter__(self) -> MainPersonalExactCasHostedIdentityJournal:
        self._ensure_open()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> bool:
        self.close()
        return False

    def _ensure_open(self) -> None:
        if self._closed:
            raise _failure("hosted_identity_closed")

    def _verify_retained_directories(self) -> None:
        """Reject a renamed/recreated root or retained directory split."""

        self._ensure_open()
        if not self._descriptor_mode:
            return
        if self._root_fd is None or self._artifacts_fd is None or self._indexes_fd is None:
            raise ValueError("retained directory descriptors are unavailable")
        current_root = self._open_directory(self._root)
        current_artifacts: int | None = None
        current_indexes: int | None = None
        try:
            self._compare_directory_identity(self._root_fd, current_root)
            current_artifacts = _open_dir_at(current_root, "artifacts", create=False)
            current_indexes = _open_dir_at(current_root, _INDEX_DIR, create=False)
            self._compare_directory_identity(self._artifacts_fd, current_artifacts)
            self._compare_directory_identity(self._indexes_fd, current_indexes)
        finally:
            for descriptor in (current_indexes, current_artifacts, current_root):
                if descriptor is not None:
                    with suppress(OSError):
                        os.close(descriptor)

    def _compare_directory_identity(self, expected: int, current: int) -> None:
        expected_stat = os.fstat(expected)
        current_stat = os.fstat(current)
        if not stat.S_ISDIR(current_stat.st_mode):
            raise ValueError("current retained path is not a directory")
        if (expected_stat.st_dev, expected_stat.st_ino) != (
            current_stat.st_dev,
            current_stat.st_ino,
        ):
            raise ValueError("retained directory was renamed or recreated")
        if _fd_mount_id(expected) != _fd_mount_id(current):
            raise ValueError("retained directory mount differs")

    def _supports_descriptor_backend(self) -> bool:
        """Use anchored Linux descriptors; permit only explicit test shims elsewhere."""

        if sys.platform == "linux":
            if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
                raise ValueError("descriptor no-follow semantics unavailable")
            return True
        # The real durable backend gate rejects native Windows/WSL.  This
        # compatibility branch is reachable only under a test qualification
        # shim, and never permits an unqualified production backend.
        if self._qualification.reason.startswith("test-"):
            return False
        raise ValueError("descriptor backend is unsupported")

    @staticmethod
    def _open_directory(path: Path) -> int:
        descriptor = os.open(path, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise ValueError("directory is not a canonical regular directory")
        return descriptor

    def bind(
        self,
        writer: GitHubReadWithProvenance[MainPersonalExactCasHostedConfigurationDiagnostic],
        observer: GitHubReadWithProvenance[MainBaseSnapshot],
        observer_configuration: GitHubMainBaseReaderConfiguration,
    ) -> MainPersonalExactCasHostedIdentityEvidenceRoot:
        """Validate inputs, persist leaves, then exclusively publish the root."""

        try:
            self._verify_retained_directories()
            checked_writer, checked_observer, checked_configuration = self._inputs(
                writer, observer, observer_configuration
            )
            bundle = MainPersonalExactCasHostedIdentityEvidenceBundle.build(
                checked_writer, checked_observer, checked_configuration
            )
            timestamp = checked_writer.result.finished_at
            payloads = {
                "writer_diagnostic_artifact": canonical_bytes(checked_writer.result),
                "writer_provenance_artifact": canonical_bytes(
                    _provenance_payload(checked_writer.provenance)
                ),
                "observer_snapshot_artifact": canonical_bytes(
                    _snapshot_payload(checked_observer.result)
                ),
                "observer_provenance_artifact": canonical_bytes(
                    _provenance_payload(checked_observer.provenance)
                ),
                "observer_configuration_artifact": canonical_bytes(
                    _configuration_payload(checked_configuration)
                ),
            }
            refs = {
                name: self._persist_child(name, data, timestamp)
                for name, data in payloads.items()
            }
            root = MainPersonalExactCasHostedIdentityEvidenceRoot.build(
                **refs, bundle_digest=bundle.bundle_digest
            )
            data = canonical_bytes(root)
            if len(data) > min(self._max, _MAX_INDEX_BYTES):
                raise ValueError("root is too large")
            published = self._publish_root(root, data)
            self._verify_retained_directories()
            return published
        except MainPersonalExactCasHostedIdentityJournalError:
            raise
        except Exception:
            raise _failure() from None

    bind_once = bind
    record = bind

    def read(
        self,
    ) -> tuple[
        MainPersonalExactCasHostedIdentityEvidenceBundle,
        MainPersonalExactCasHostedIdentityEvidenceRoot,
    ] | None:
        """Reparse every leaf, rebuild the bundle, and verify the root binding."""

        try:
            self._verify_retained_directories()
            path = self._checked_path(self.root_path)
            self._qualify_same_backend(path.parent)
            if self._descriptor_mode:
                if self._indexes_fd is None:
                    raise ValueError("index descriptor is unavailable")
                self._check_descriptor_backend(self._indexes_fd)
                try:
                    descriptor = os.open(
                        _INDEX_NAME, os.O_RDONLY | _O_NOFOLLOW, dir_fd=self._indexes_fd
                    )
                except FileNotFoundError:
                    self._verify_retained_directories()
                    return None
                try:
                    self._check_descriptor_backend(descriptor)
                    raw = _read_regular_fd(descriptor, min(self._max, _MAX_INDEX_BYTES))
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                _fsync_fd(self._indexes_fd)
                _fsync_fd(self._root_fd)
            else:
                if not path.is_file():
                    self._verify_retained_directories()
                    return None
                raw = _read_regular_path(
                    path, sync=True, max_bytes=min(self._max, _MAX_INDEX_BYTES)
                )
            if len(raw) > min(self._max, _MAX_INDEX_BYTES):
                raise ValueError("root is too large")
            root = MainPersonalExactCasHostedIdentityEvidenceRoot.model_validate_json(raw)
            if canonical_bytes(root) != raw:
                raise ValueError("root is not canonical")
            children = {
                name: self._read_child(name, getattr(root, name))
                for name in _CHILD_SPECS
            }
            writer = GitHubReadWithProvenance(
                result=children["writer_diagnostic_artifact"],
                provenance=children["writer_provenance_artifact"],
            )
            observer = GitHubReadWithProvenance(
                result=children["observer_snapshot_artifact"],
                provenance=children["observer_provenance_artifact"],
            )
            configuration = cast(
                GitHubMainBaseReaderConfiguration,
                children["observer_configuration_artifact"],
            )
            bundle = MainPersonalExactCasHostedIdentityEvidenceBundle.build(
                writer, observer, configuration
            )
            timestamp = cast(
                MainPersonalExactCasHostedConfigurationDiagnostic, writer.result
            ).finished_at
            for name in _CHILD_SPECS:
                if getattr(root, name).created_at != timestamp:
                    raise ValueError("child timestamp differs from writer observation")
            if bundle.bundle_digest != root.bundle_digest:
                raise ValueError("bundle digest differs from root")
            self._verify_retained_directories()
            return bundle, root
        except MainPersonalExactCasHostedIdentityJournalError:
            raise
        except Exception:
            raise _failure("hosted_identity_malformed") from None

    def read_root(self) -> MainPersonalExactCasHostedIdentityEvidenceRoot | None:
        result = self.read()
        return None if result is None else result[1]

    read_record = read_root

    def read_with_bundle(
        self,
    ) -> tuple[
        MainPersonalExactCasHostedIdentityEvidenceBundle,
        MainPersonalExactCasHostedIdentityEvidenceRoot,
    ] | None:
        return self.read()

    def read_bundle(self) -> MainPersonalExactCasHostedIdentityEvidenceBundle | None:
        result = self.read()
        return None if result is None else result[0]

    reopen = read

    def _inputs(self, writer: object, observer: object, configuration: object):
        if (
            type(writer) is not GitHubReadWithProvenance
            or type(observer) is not GitHubReadWithProvenance
        ):
            raise TypeError("exact hosted reads are required")
        writer_any = cast(Any, writer)
        observer_any = cast(Any, observer)
        writer_result = _exact_model(
            writer_any.result, MainPersonalExactCasHostedConfigurationDiagnostic
        )
        writer_provenance = _revalidate_provenance(writer_any.provenance)
        observer_result = _revalidate_snapshot(observer_any.result)
        observer_provenance = _revalidate_provenance(observer_any.provenance)
        checked_configuration = _revalidate_configuration(configuration)
        checked_writer = GitHubReadWithProvenance(writer_result, writer_provenance)
        checked_observer = GitHubReadWithProvenance(observer_result, observer_provenance)
        return checked_writer, checked_observer, checked_configuration

    def _persist_child(self, name: str, data: bytes, created_at: Any) -> ArtifactRef:
        role, media, expected = _CHILD_SPECS[name]
        del expected
        if len(data) > self._max:
            raise ValueError("child is too large")
        digest = _DIGEST_PREFIX + hashlib.sha256(data).hexdigest()
        path = self._checked_path(self._store.path_for_digest(digest))
        ref = ArtifactRef(
            digest=digest,
            size_bytes=len(data),
            media_type=media,
            role=role,
            created_at=created_at,
        )
        if self._descriptor_mode:
            self._persist_child_descriptor(digest, data, path)
            return ref
        self._prepare_directory(path.parent)
        self._qualify_same_backend(path.parent)
        try:
            with path.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            existing = _read_regular_path(path, sync=True, max_bytes=self._max)
            if existing != data:
                raise ValueError("content-addressed child differs") from None
        _fsync_store_ancestors(path, self._store.root)
        _fsync_directory(self._root)
        return ref

    def _persist_child_descriptor(self, digest: str, data: bytes, path: Path) -> None:
        self._qualify_same_backend(self._store.root)
        fanout_fd = self._open_child_fanout(digest, create=True)
        descriptor: int | None = None
        try:
            self._qualify_same_backend(path.parent)
            leaf = digest.removeprefix(_DIGEST_PREFIX)[2:]
            try:
                descriptor = os.open(
                    leaf,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW,
                    0o600,
                    dir_fd=fanout_fd,
                )
                self._check_descriptor_backend(descriptor)
            except FileExistsError:
                descriptor = os.open(leaf, os.O_RDONLY | _O_NOFOLLOW, dir_fd=fanout_fd)
                self._check_descriptor_backend(descriptor)
                existing = _read_regular_fd(descriptor, self._max)
                os.fsync(descriptor)
                if existing != data:
                    raise ValueError("content-addressed child differs") from None
            else:
                _write_all(descriptor, data)
                os.fsync(descriptor)
            _fsync_fd(fanout_fd)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(fanout_fd)
        self._sync_retained_directories()

    def _publish_root(
        self, root: MainPersonalExactCasHostedIdentityEvidenceRoot, data: bytes
    ) -> MainPersonalExactCasHostedIdentityEvidenceRoot:
        path = self._checked_path(self.root_path)
        self._qualify_same_backend(path.parent)
        if self._descriptor_mode:
            if self._indexes_fd is None:
                raise ValueError("index descriptor is unavailable")
            _fsync_fd(self._indexes_fd)
        else:
            _fsync_directory(path.parent)
        with _LOCK:
            try:
                if self._descriptor_mode:
                    if self._indexes_fd is None:
                        raise ValueError("index descriptor is unavailable")
                    self._check_descriptor_backend(self._indexes_fd)
                    descriptor = os.open(
                        _INDEX_NAME,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW,
                        0o600,
                        dir_fd=self._indexes_fd,
                    )
                    try:
                        self._check_descriptor_backend(descriptor)
                        _write_all(descriptor, data)
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    _fsync_fd(self._indexes_fd)
                    _fsync_fd(self._root_fd)
                else:
                    with path.open("xb") as handle:
                        handle.write(data)
                        handle.flush()
                        os.fsync(handle.fileno())
                    _fsync_directory(path.parent)
                    _fsync_directory(self._root)
                self._verify_retained_directories()
                return root
            except FileExistsError:
                existing = self.read()
                if existing is not None and existing[1] == root:
                    self._sync_reused_root()
                    self._verify_retained_directories()
                    return existing[1]
                raise MainPersonalExactCasHostedIdentityJournalConflictError() from None

    def _read_child(self, name: str, reference: object) -> Any:
        role, media, expected = _CHILD_SPECS[name]
        if type(reference) is not ArtifactRef:
            raise ValueError("child reference type differs")
        if (
            reference.role != role
            or reference.media_type != media
            or reference.size_bytes > self._max
        ):
            raise ValueError("child reference metadata differs")
        path = self._checked_path(self._store.path_for_digest(reference.digest))
        self._qualify_same_backend(self._store.root)
        self._qualify_same_backend(path.parent)
        if self._descriptor_mode:
            data = self._read_child_descriptor(reference.digest, path)
        else:
            data = _read_regular_path(path, sync=self._descriptor_mode, max_bytes=self._max)
        if len(data) != reference.size_bytes or hashlib.sha256(data).hexdigest() != (
            reference.digest.removeprefix(_DIGEST_PREFIX)
        ):
            raise ValueError("child bytes differ")
        if name == "writer_provenance_artifact" or name == "observer_provenance_artifact":
            raw = _json_object(data)
            requests = raw.get("requests")
            if type(requests) is not list:
                raise ValueError("provenance requests malformed")
            raw["requests"] = tuple(
                GitHubReadRequest(**cast(dict[str, Any], item)) for item in requests
            )
            for key in (
                "requested_permissions",
                "observed_permissions",
                "configuration_pass_digests",
            ):
                raw[key] = tuple(cast(list[Any], raw[key]))
            raw["endpoint_observation_digests"] = tuple(
                (cast(list[Any], item)[0], cast(list[Any], item)[1])
                for item in cast(list[Any], raw["endpoint_observation_digests"])
            )
            value = GitHubReadProvenance(**raw)
            if canonical_bytes(_provenance_payload(value)) != data:
                raise ValueError("provenance is not canonical")
            return value
        if name == "observer_configuration_artifact":
            raw = _json_object(data)
            digest = raw.pop("configuration_digest")
            value = GitHubMainBaseReaderConfiguration(**raw)
            if value.configuration_digest != digest or canonical_bytes(
                _configuration_payload(value)
            ) != data:
                raise ValueError("configuration is not canonical")
            return value
        if name == "writer_diagnostic_artifact":
            value = expected.model_validate_json(data)
            if type(value) is not expected or canonical_bytes(value) != data:
                raise ValueError("child is not canonical")
            return _exact_model(value, MainPersonalExactCasHostedConfigurationDiagnostic)
        raw = _json_object(data)
        value = MainBaseSnapshot(**raw)
        if canonical_bytes(_snapshot_payload(value)) != data:
            raise ValueError("snapshot is not canonical")
        return _revalidate_snapshot(value)

    def _read_child_descriptor(self, digest: str, path: Path) -> bytes:
        fanout_fd = self._open_child_fanout(digest, create=False)
        descriptor: int | None = None
        try:
            self._qualify_same_backend(path.parent)
            descriptor = os.open(
                digest.removeprefix(_DIGEST_PREFIX)[2:],
                os.O_RDONLY | _O_NOFOLLOW,
                dir_fd=fanout_fd,
            )
            self._check_descriptor_backend(descriptor)
            data = _read_regular_fd(descriptor, self._max)
            os.fsync(descriptor)
            _fsync_fd(fanout_fd)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(fanout_fd)
        self._sync_retained_directories()
        return data

    def _open_child_fanout(self, digest: str, *, create: bool) -> int:
        if self._artifacts_fd is None:
            raise ValueError("artifact descriptor is unavailable")
        objects = _open_dir_at(self._artifacts_fd, "objects", create=create)
        sha256: int | None = None
        fanout: int | None = None
        try:
            self._check_descriptor_backend(objects)
            sha256 = _open_dir_at(objects, "sha256", create=create)
            if create:
                _fsync_fd(objects)
            self._check_descriptor_backend(sha256)
            fanout = _open_dir_at(
                sha256, digest.removeprefix(_DIGEST_PREFIX)[:2], create=create
            )
            self._check_descriptor_backend(fanout)
            if create:
                _fsync_fd(sha256)
            result = fanout
            fanout = None
            return result
        finally:
            for descriptor in (fanout, sha256, objects):
                if descriptor is not None:
                    with suppress(OSError):
                        os.close(descriptor)

    def _check_descriptor_backend(self, descriptor: int) -> None:
        if self._root_fd is None:
            raise ValueError("root descriptor is unavailable")
        if os.fstat(descriptor).st_dev != os.fstat(self._root_fd).st_dev:
            raise ValueError("nested mount/device differs")
        if _fd_mount_id(descriptor) != _fd_mount_id(self._root_fd):
            raise ValueError("nested mount differs")

    def _sync_reused_root(self) -> None:
        if self._descriptor_mode:
            if self._indexes_fd is None or self._root_fd is None:
                raise ValueError("retained root descriptors are unavailable")
            _fsync_fd(self._indexes_fd)
            _fsync_fd(self._root_fd)
        else:
            _fsync_directory(self.root_path.parent)
            _fsync_directory(self._root)

    def _sync_retained_directories(self) -> None:
        if self._descriptor_mode:
            if self._artifacts_fd is None or self._root_fd is None:
                raise ValueError("retained artifact descriptors are unavailable")
            _fsync_fd(self._artifacts_fd)
            _fsync_fd(self._root_fd)

    def _prepare_directory(self, path: Path) -> Path:
        canonical = self._canonical_path(path)
        canonical.mkdir(parents=True, exist_ok=True)
        if not canonical.is_dir() or self._canonical_path(canonical) != canonical:
            raise ValueError("directory is not canonical")
        return canonical

    def _qualify_same_backend(self, path: Path) -> DurableBackendQualification:
        qualification = require_durable_backend(path)
        if not qualification.qualified:
            raise ValueError("backend is not durable")
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
            raise ValueError("backend identity differs")
        return qualification

    @staticmethod
    def _canonical_path(path: Path) -> Path:
        candidate = path if path.is_absolute() else Path.cwd() / path
        for component in [*reversed(candidate.parents), candidate]:
            if component.is_symlink():
                raise ValueError("symlink path")
        return candidate.resolve(strict=False)

    def _checked_path(self, path: Path) -> Path:
        canonical = self._canonical_path(path)
        if canonical != path:
            raise ValueError("path is not canonical")
        return path


def _json_object(data: bytes) -> dict[str, Any]:
    import json

    value = json.loads(data)
    if type(value) is not dict:
        raise ValueError("child JSON is not an object")
    return cast(dict[str, Any], value)


def _fd_mount_id(descriptor: int) -> int:
    """Read one strict Linux fdinfo mount ID, bounded and fail-closed."""

    if sys.platform != "linux":
        raise ValueError("descriptor mount IDs require Linux")
    path = f"/proc/self/fdinfo/{descriptor}"
    fdinfo = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
    try:
        raw = _read_descriptor_bytes(fdinfo, _FDINFO_MAX_BYTES)
    finally:
        os.close(fdinfo)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("fdinfo is not ASCII") from exc
    values: list[int] = []
    for line in text.splitlines():
        if line.startswith("mnt_id:"):
            match = re.fullmatch(r"mnt_id:\s+([1-9][0-9]*)", line)
            if match is None:
                raise ValueError("fdinfo mount ID is malformed")
            values.append(int(match.group(1)))
    if len(values) != 1:
        raise ValueError("fdinfo must contain one mount ID")
    return values[0]


def _read_descriptor_bytes(descriptor: int, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    if sum(map(len, chunks)) > max_bytes:
        raise ValueError("fdinfo exceeds bounded read")
    return b"".join(chunks)


def _open_dir_at(parent_fd: int, name: str, *, create: bool) -> int:
    """Open one directory relative to a retained descriptor."""

    if create:
        with suppress(FileExistsError):
            os.mkdir(name, 0o700, dir_fd=parent_fd)
    descriptor = os.open(
        name,
        os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW,
        dir_fd=parent_fd,
    )
    mode = os.fstat(descriptor).st_mode
    if not stat.S_ISDIR(mode):
        os.close(descriptor)
        raise ValueError("fanout component is not a directory")
    return descriptor


def _read_regular_fd(descriptor: int, max_bytes: int | None = None) -> bytes:
    mode = os.fstat(descriptor).st_mode
    if not stat.S_ISREG(mode):
        raise ValueError("artifact is not a regular file")
    chunks: list[bytes] = []
    remaining = None if max_bytes is None else max_bytes + 1
    while remaining is None or remaining > 0:
        read_size = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
        chunk = os.read(descriptor, read_size)
        if not chunk:
            break
        chunks.append(chunk)
        if remaining is not None:
            remaining -= len(chunk)
    if max_bytes is not None and sum(map(len, chunks)) > max_bytes:
        raise ValueError("file exceeds bounded read")
    return b"".join(chunks)


def _read_regular_path(path: Path, *, sync: bool, max_bytes: int | None = None) -> bytes:
    flags = (os.O_RDWR if sync else os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        data = _read_regular_fd(descriptor, max_bytes)
        if sync:
            os.fsync(descriptor)
        return data
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("short artifact write")
        offset += written


def _fsync_fd(descriptor: int | None) -> None:
    if descriptor is None:
        raise ValueError("descriptor is unavailable")
    os.fsync(descriptor)


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


# Descriptive alias retained for callers that name the persisted leaf journal.
MainPersonalExactCasHostedIdentityEvidenceJournal = MainPersonalExactCasHostedIdentityJournal
MainPersonalExactCasHostedIdentityJournalConflict = (
    MainPersonalExactCasHostedIdentityJournalConflictError
)

__all__ = [
    "MainPersonalExactCasHostedIdentityEvidenceJournal",
    "MainPersonalExactCasHostedIdentityJournal",
    "MainPersonalExactCasHostedIdentityJournalConflict",
    "MainPersonalExactCasHostedIdentityJournalConflictError",
    "MainPersonalExactCasHostedIdentityJournalError",
]
