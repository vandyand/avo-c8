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
        _fsync_directory(self._root)
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

    def bind(
        self,
        writer: GitHubReadWithProvenance[MainPersonalExactCasHostedConfigurationDiagnostic],
        observer: GitHubReadWithProvenance[MainBaseSnapshot],
        observer_configuration: GitHubMainBaseReaderConfiguration,
    ) -> MainPersonalExactCasHostedIdentityEvidenceRoot:
        """Validate inputs, persist leaves, then exclusively publish the root."""

        try:
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
            return self._publish_root(root, data)
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
            path = self._checked_path(self.root_path)
            if not path.is_file():
                return None
            raw = path.read_bytes()
            if len(raw) > min(self._max, _MAX_INDEX_BYTES):
                raise ValueError("root is too large")
            root = MainPersonalExactCasHostedIdentityEvidenceRoot.model_validate_json(raw)
            if canonical_bytes(root) != raw:
                raise ValueError("root is not canonical")
            self._qualify_same_backend(path.parent)
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
        self._prepare_directory(path.parent)
        self._qualify_same_backend(path.parent)
        ref = ArtifactRef(
            digest=digest,
            size_bytes=len(data),
            media_type=media,
            role=role,
            created_at=created_at,
        )
        try:
            with path.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            existing = path.read_bytes()
            if existing != data:
                raise ValueError("content-addressed child differs") from None
        _fsync_store_ancestors(path, self._store.root)
        _fsync_directory(self._root)
        return ref

    def _publish_root(
        self, root: MainPersonalExactCasHostedIdentityEvidenceRoot, data: bytes
    ) -> MainPersonalExactCasHostedIdentityEvidenceRoot:
        path = self._checked_path(self.root_path)
        self._qualify_same_backend(path.parent)
        _fsync_directory(path.parent)
        with _LOCK:
            try:
                with path.open("xb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                _fsync_directory(path.parent)
                _fsync_directory(self._root)
                return root
            except FileExistsError:
                existing = self.read()
                if existing is not None and existing[1] == root:
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
        data = path.read_bytes()
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
