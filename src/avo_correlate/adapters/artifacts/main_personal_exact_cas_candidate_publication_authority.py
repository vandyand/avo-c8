"""Controller-owned resolution of the candidate-publication authority root.

The resolver accepts only the concrete durable journals that already own the
source evidence.  It performs no hosted I/O and never receives a verifier,
DTO, credential, or provider capability from a caller.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
from contextlib import suppress
from datetime import datetime
from pathlib import Path

from avo_correlate.adapters.artifacts.durable_backend_gate import (
    require_durable_backend,
)
from avo_correlate.adapters.artifacts.main_graduation_journal import MainGraduationJournal
from avo_correlate.adapters.artifacts.main_personal_exact_cas_controller_composition import (
    MainPersonalExactCasControllerCompositionJournal,
)
from avo_correlate.adapters.artifacts.main_personal_exact_cas_hosted_identity_journal import (
    MainPersonalExactCasHostedIdentityJournal,
)
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_candidate_publisher import (
    GitHubCandidatePublisherConfiguration,
)
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_hosted_identity_bundle import (
    MainPersonalExactCasHostedIdentityEvidenceBundle,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation import MainPreparationAuthorization
from avo_correlate.contracts.main_personal_exact_cas_candidate_observation import (
    candidate_ref_for_operation,
)
from avo_correlate.contracts.main_personal_exact_cas_candidate_publication import (
    MainPersonalExactCasCandidatePublicationAuthorityRoot,
)
from avo_correlate.contracts.main_personal_exact_cas_controller_composition import (
    MainPersonalExactCasControllerComposition,
)
from avo_correlate.contracts.main_personal_exact_cas_hosted_configuration import (
    MainPersonalExactCasHostedConfigurationDiagnostic,
)
from avo_correlate.contracts.main_personal_exact_cas_hosted_identity import (
    MainPersonalExactCasHostedIdentityEvidenceRoot,
)
from avo_correlate.domain.canonical import canonical_bytes

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_MAX = 8 * 1024 * 1024


class CandidatePublicationAuthorityResolutionError(RuntimeError):
    """The exact durable authority closure is absent, stale, or tampered."""


class MainPersonalExactCasCandidatePublicationAuthorityResolver:
    """Re-resolve one authority root from exact existing journal instances."""

    def __init__(
        self,
        *,
        composition_journal: MainPersonalExactCasControllerCompositionJournal,
        graduation_journal: MainGraduationJournal,
        hosted_identity_journal: MainPersonalExactCasHostedIdentityJournal,
        configuration: GitHubCandidatePublisherConfiguration,
    ) -> None:
        exact = (
            (composition_journal, MainPersonalExactCasControllerCompositionJournal),
            (graduation_journal, MainGraduationJournal),
            (hosted_identity_journal, MainPersonalExactCasHostedIdentityJournal),
            (configuration, GitHubCandidatePublisherConfiguration),
        )
        if any(type(value) is not expected for value, expected in exact):
            raise TypeError("exact durable journals and publisher configuration are required")
        if configuration.owner_id is None:
            raise ValueError("publisher owner ID must be pinned")
        self._composition = composition_journal
        self._graduation = graduation_journal
        self._identity = hosted_identity_journal
        self._configuration = configuration

    def resolve(self, operation_id: str) -> MainPersonalExactCasCandidatePublicationAuthorityRoot:
        try:
            if _DIGEST.fullmatch(operation_id or "") is None:
                raise ValueError("operation identity is malformed")
            composition = self._composition.read(operation_id)
            if composition is None:
                raise ValueError("composition root is missing")
            preparation_result = self._graduation.read_preparation_authorization(operation_id)
            if preparation_result is None:
                raise ValueError("preparation authorization is missing")
            preparation, preparation_ref = preparation_result
            if type(preparation) is not MainPreparationAuthorization:
                raise ValueError("preparation authorization type differs")
            _require_record_ref(
                preparation_ref,
                preparation,
                "main-graduation-preparation-authorization",
                "application/vnd.avo.main-graduation-preparation-authorization+json",
            )
            identity_result = self._identity.read()
            if identity_result is None:
                raise ValueError("hosted identity root is missing")
            bundle, identity_root = identity_result
            if type(identity_root) is not MainPersonalExactCasHostedIdentityEvidenceRoot:
                raise ValueError("hosted identity root type differs")
            bundle.assert_valid()
            diagnostic_ref = identity_root.writer_diagnostic_artifact
            diagnostic = self._read_diagnostic(diagnostic_ref)
            self._bind(
                operation_id,
                composition,
                preparation,
                bundle,
                diagnostic,
                identity_root,
            )
            return MainPersonalExactCasCandidatePublicationAuthorityRoot.build(
                operation_id=operation_id,
                repository_digest=composition.repository_digest,
                candidate_ref=composition.candidate_ref,
                base_commit=composition.base_commit,
                base_tree=composition.base_tree,
                candidate_commit=composition.candidate_commit,
                candidate_tree=composition.candidate_tree,
                candidate_parents=composition.candidate_parents,
                lease_identity=composition.lease_identity,
                lease_digest=composition.lease_digest,
                lease_expires_at=composition.lease_expires_at,
                configuration_digest=self._configuration.configuration_digest,
                publisher_app_id=self._configuration.app_id,
                publisher_installation_id=self._configuration.installation_id,
                publisher_identity=self._configuration.app_name,
                owner_id=diagnostic.owner_id,
                composition_digest=composition.source_composition_artifact.digest,
                composition_artifact=composition.source_composition_artifact,
                preparation_authorization_record_digest=preparation_ref.digest,
                preparation_authorization_digest=preparation.authorization_digest,
                preparation_authorization_artifact=preparation_ref,
                hosted_identity_root_digest=composition.hosted_identity_root_artifact.digest,
                hosted_identity_root_artifact=composition.hosted_identity_root_artifact,
                hosted_identity_bundle_digest=identity_root.bundle_digest,
                candidate_policy_digest=diagnostic.protection_ruleset_digest,
                candidate_policy_artifact=diagnostic_ref,
                candidate_policy_ruleset_digests=(
                    diagnostic.writer_ruleset_digest,
                    diagnostic.safety_ruleset_digest,
                    diagnostic.rollback_ruleset_digest,
                    diagnostic.candidate_creation_ruleset_digest,
                    diagnostic.candidate_immutable_ruleset_digest,
                ),
            )
        except CandidatePublicationAuthorityResolutionError:
            raise
        except Exception:
            raise CandidatePublicationAuthorityResolutionError() from None

    def _read_diagnostic(
        self, reference: ArtifactRef
    ) -> MainPersonalExactCasHostedConfigurationDiagnostic:
        raw = self._identity.artifact_store.read_bytes(reference)
        if (
            len(raw) != reference.size_bytes
            or hashlib.sha256(raw).hexdigest() != reference.digest.removeprefix("sha256:")
        ):
            raise ValueError("hosted diagnostic artifact digest differs")
        value = MainPersonalExactCasHostedConfigurationDiagnostic.model_validate_json(raw)
        if (
            type(value) is not MainPersonalExactCasHostedConfigurationDiagnostic
            or canonical_bytes(value) != raw
        ):
            raise ValueError("hosted diagnostic artifact is not canonical")
        return value

    def _bind(
        self,
        operation_id: str,
        composition: MainPersonalExactCasControllerComposition,
        preparation: MainPreparationAuthorization,
        bundle: MainPersonalExactCasHostedIdentityEvidenceBundle,
        diagnostic: MainPersonalExactCasHostedConfigurationDiagnostic,
        identity_root: MainPersonalExactCasHostedIdentityEvidenceRoot,
    ) -> None:
        config = self._configuration
        if (
            composition.operation_id != operation_id
            or composition.candidate_ref != candidate_ref_for_operation(operation_id)
            or preparation.operation_id != operation_id
            or preparation.plan_digest != composition.source_plan_digest
            or preparation.composition_digest != composition.source_composition_digest
            or preparation.policy_epoch != composition.policy_digest
            or preparation.base_commit != composition.base_commit
            or preparation.base_tree != composition.base_tree
            or preparation.candidate_commit != composition.candidate_commit
            or preparation.candidate_tree != composition.candidate_tree
            or preparation.package_digest != composition.source_package_digest
            or preparation.lease_identity != composition.lease_identity
            or preparation.lease_digest != composition.lease_digest
            or preparation.authorized is not True
            or not _artifact_matches(
                composition.hosted_identity_root_artifact,
                identity_root_artifact(
                    identity_root, composition.hosted_identity_root_artifact.created_at
                ),
            )
            or identity_root.bundle_digest != bundle.bundle_digest
            or identity_root.writer_diagnostic_artifact.digest != diagnostic_ref_digest(diagnostic)
            or bundle.writer_diagnostic_digest != diagnostic_ref_digest(diagnostic)
            or bundle.writer_app_id != diagnostic.writer_app_id
            or bundle.writer_installation_id != diagnostic.writer_installation_id
            or bundle.writer_protection_ruleset_digest != diagnostic.protection_ruleset_digest
            or bundle.writer_ruleset_digest != diagnostic.writer_ruleset_digest
            or bundle.writer_safety_ruleset_digest != diagnostic.safety_ruleset_digest
            or bundle.writer_rollback_ruleset_digest != diagnostic.rollback_ruleset_digest
            or bundle.repository_digest != composition.repository_digest
            or diagnostic.repository_digest != composition.repository_digest
            or diagnostic.owner != "vandyand"
            or diagnostic.repository != "avo-c8"
            or diagnostic.repository_id != 1354880741
            or diagnostic.owner_id != config.owner_id
            or diagnostic.target_ref != "refs/heads/main"
            or diagnostic.verification_status != "matched"
            or diagnostic.selected_repository_ids != (1354880741,)
            or diagnostic.contents_permission != "write"
            or diagnostic.metadata_permission != "read"
            or diagnostic.subscribed_events != ()
            or diagnostic.protection_ruleset_digest != composition.protection_ruleset_digest
            or diagnostic.candidate_publisher_app_id != config.app_id
            or diagnostic.candidate_publisher_installation_id != config.installation_id
            or diagnostic.candidate_publisher_app_slug != config.app_name
            or diagnostic.candidate_publisher_app_name != config.app_name
        ):
            raise ValueError("candidate publication authority dependencies differ")


class MainPersonalExactCasCandidatePublicationAuthorityJournal:
    """Create-once durable storage for resolver-produced authority roots."""

    def __init__(
        self,
        root: Path,
        *,
        resolver: MainPersonalExactCasCandidatePublicationAuthorityResolver,
    ) -> None:
        if type(resolver) is not MainPersonalExactCasCandidatePublicationAuthorityResolver:
            raise TypeError("exact authority resolver is required")
        self._closed = False
        self._descriptor_mode = False
        self._root_fd: int | None = None
        self._index_fd: int | None = None
        self._qualification = require_durable_backend(root)
        self._root = _prepare(self._qualification.root)
        self._indexes = _prepare(self._root / "main-personal-exact-cas-candidate-authority-index")
        self._index_qualification = require_durable_backend(self._indexes)
        _same_backend(self._qualification, self._index_qualification)
        self._root_identity = _directory_identity(self._root)
        self._index_identity = _directory_identity(self._indexes)
        self._descriptor_mode = _supports_descriptor_backend(self._qualification)
        if self._descriptor_mode:
            try:
                self._root_fd = _open_directory(self._root)
                self._index_fd = _open_dir_at(self._root_fd, self._indexes.name)
                self._verify_retained_directories()
            except BaseException:
                self.close()
                raise
        self._resolver = resolver

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for descriptor in (self._index_fd, self._root_fd):
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
        self._index_fd = None
        self._root_fd = None

    def __enter__(self) -> MainPersonalExactCasCandidatePublicationAuthorityJournal:
        self._ensure_open()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> bool:
        self.close()
        return False

    def _ensure_open(self) -> None:
        if self._closed:
            raise CandidatePublicationAuthorityResolutionError()

    def bind(self, operation_id: str) -> MainPersonalExactCasCandidatePublicationAuthorityRoot:
        try:
            self._ensure_open()
            self._check_layout()
            authority = self._resolver.resolve(operation_id)
            data = canonical_bytes(authority)
            descriptor, operation_descriptor, path = self._open_record(
                operation_id, write=True
            )
            try:
                _write_all(descriptor, data)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if operation_descriptor is None:
                _fsync_directory(path.parent)
                _fsync_directory(self._root)
            else:
                try:
                    os.fsync(operation_descriptor)
                    if self._index_fd is not None and self._root_fd is not None:
                        os.fsync(self._index_fd)
                        os.fsync(self._root_fd)
                finally:
                    os.close(operation_descriptor)
            return authority
        except FileExistsError:
            authority = self._resolver.resolve(operation_id)
            existing = self.read(operation_id)
            if existing != authority:
                raise CandidatePublicationAuthorityResolutionError() from None
            if existing is None:
                raise CandidatePublicationAuthorityResolutionError() from None
            return existing
        except CandidatePublicationAuthorityResolutionError:
            raise
        except Exception:
            raise CandidatePublicationAuthorityResolutionError() from None

    def read(
        self, operation_id: str
    ) -> MainPersonalExactCasCandidatePublicationAuthorityRoot | None:
        try:
            self._ensure_open()
            self._check_layout()
            descriptor, operation_descriptor, path = self._open_record(
                operation_id, write=False
            )
            try:
                _check_regular(descriptor)
                raw = _read_bounded(descriptor, _MAX)
            finally:
                os.close(descriptor)
                if operation_descriptor is not None:
                    os.close(operation_descriptor)
            stored = MainPersonalExactCasCandidatePublicationAuthorityRoot.model_validate_json(raw)
            if canonical_bytes(stored) != raw:
                raise ValueError("authority root is not canonical")
            current = self._resolver.resolve(operation_id)
            if current != stored:
                raise ValueError("authority root dependencies changed")
            if operation_descriptor is None:
                _fsync_directory(path.parent)
                _fsync_directory(self._root)
            elif self._index_fd is not None and self._root_fd is not None:
                os.fsync(self._index_fd)
                os.fsync(self._root_fd)
            return stored
        except FileNotFoundError:
            return None
        except Exception:
            raise CandidatePublicationAuthorityResolutionError() from None

    def _path(self, operation_id: str) -> Path:
        if _DIGEST.fullmatch(operation_id or "") is None:
            raise CandidatePublicationAuthorityResolutionError()
        return self._indexes / operation_id.removeprefix("sha256:") / "root.json"

    def _check_layout(self) -> None:
        self._verify_retained_directories()
        _same_backend(self._qualification, require_durable_backend(self._root))
        _same_backend(self._qualification, require_durable_backend(self._indexes))
        if _directory_identity(self._root) != self._root_identity:
            raise CandidatePublicationAuthorityResolutionError()
        if _directory_identity(self._indexes) != self._index_identity:
            raise CandidatePublicationAuthorityResolutionError()

    def _verify_retained_directories(self) -> None:
        if not self._descriptor_mode:
            return
        if self._root_fd is None or self._index_fd is None:
            raise CandidatePublicationAuthorityResolutionError()
        current_root = _open_directory(self._root)
        current_index: int | None = None
        try:
            _compare_directory_identity(self._root_fd, current_root)
            current_index = _open_dir_at(current_root, self._indexes.name)
            _compare_directory_identity(self._index_fd, current_index)
        finally:
            if current_index is not None:
                os.close(current_index)
            os.close(current_root)

    def _open_record(
        self, operation_id: str, *, write: bool
    ) -> tuple[int, int | None, Path]:
        path = self._path(operation_id)
        if self._descriptor_mode:
            if self._index_fd is None:
                raise CandidatePublicationAuthorityResolutionError()
            operation_name = operation_id.removeprefix("sha256:")
            if write:
                with suppress(FileExistsError):
                    os.mkdir(operation_name, 0o700, dir_fd=self._index_fd)
            operation_descriptor = _open_dir_at(
                self._index_fd, operation_name, create=False
            )
            try:
                if self._root_fd is None:
                    raise CandidatePublicationAuthorityResolutionError()
                _compare_directory_mount(self._index_fd, operation_descriptor)
                _compare_directory_mount(self._root_fd, operation_descriptor)
            except BaseException:
                os.close(operation_descriptor)
                raise
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL if write else os.O_RDONLY
            try:
                descriptor = os.open(
                    "root.json", flags | _NOFOLLOW, 0o600, dir_fd=operation_descriptor
                )
            except BaseException:
                os.close(operation_descriptor)
                raise
            return descriptor, operation_descriptor, path
        if write:
            _prepare(path.parent)
        elif not path.is_file() or path.is_symlink():
            raise FileNotFoundError(path)
        return os.open(
            path,
            (os.O_WRONLY | os.O_CREAT | os.O_EXCL if write else os.O_RDONLY) | _NOFOLLOW,
            0o600,
        ), None, path


def identity_root_artifact(
    value: MainPersonalExactCasHostedIdentityEvidenceRoot, created_at: datetime
) -> ArtifactRef:
    data = canonical_bytes(value)
    return ArtifactRef(
        digest="sha256:" + hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        role="main-personal-exact-cas-hosted-identity-root",
        media_type="application/vnd.avo.main-personal-exact-cas-hosted-identity-root+json",
        created_at=created_at,
    )


def diagnostic_ref_digest(value: MainPersonalExactCasHostedConfigurationDiagnostic) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _require_record_ref(
    reference: ArtifactRef, value: object, role: str, media_type: str
) -> None:
    raw = canonical_bytes(value)
    if (
        type(reference) is not ArtifactRef
        or reference.digest != "sha256:" + hashlib.sha256(raw).hexdigest()
        or reference.size_bytes != len(raw)
        or reference.role != role
        or reference.media_type != media_type
    ):
        raise ValueError("record artifact reference differs")


def _artifact_matches(left: ArtifactRef, right: ArtifactRef) -> bool:
    return (
        left.digest == right.digest
        and left.size_bytes == right.size_bytes
        and left.role == right.role
        and left.media_type == right.media_type
        and left.created_at == right.created_at
    )


def _prepare(path: Path) -> Path:
    candidate = Path(path).absolute()
    for component in [*reversed(candidate.parents), candidate]:
        if component.is_symlink():
            raise CandidatePublicationAuthorityResolutionError()
    canonical = candidate.resolve(strict=False)
    canonical.mkdir(parents=True, exist_ok=True)
    if not canonical.is_dir() or canonical.is_symlink():
        raise CandidatePublicationAuthorityResolutionError()
    return canonical


def _directory_identity(path: Path) -> tuple[int, int]:
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise CandidatePublicationAuthorityResolutionError()
    return info.st_dev, info.st_ino


def _supports_descriptor_backend(qualification: object) -> bool:
    if sys.platform == "linux":
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise CandidatePublicationAuthorityResolutionError()
        return True
    if str(getattr(qualification, "reason", "")).startswith("test-"):
        return False
    raise CandidatePublicationAuthorityResolutionError()


def _open_directory(path: Path) -> int:
    descriptor = os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise CandidatePublicationAuthorityResolutionError()
    return descriptor


def _open_dir_at(parent: int, name: str, *, create: bool = False) -> int:
    if create:
        with suppress(FileExistsError):
            os.mkdir(name, 0o700, dir_fd=parent)
    descriptor = os.open(name, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=parent)
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise CandidatePublicationAuthorityResolutionError()
    return descriptor


def _compare_directory_identity(expected: int, current: int) -> None:
    expected_stat = os.fstat(expected)
    current_stat = os.fstat(current)
    if (expected_stat.st_dev, expected_stat.st_ino) != (
        current_stat.st_dev,
        current_stat.st_ino,
    ):
        raise CandidatePublicationAuthorityResolutionError()
    if _fd_mount_id(expected) != _fd_mount_id(current):
        raise CandidatePublicationAuthorityResolutionError()


def _compare_directory_mount(expected: int, current: int) -> None:
    expected_stat = os.fstat(expected)
    current_stat = os.fstat(current)
    if expected_stat.st_dev != current_stat.st_dev:
        raise CandidatePublicationAuthorityResolutionError()
    if _fd_mount_id(expected) != _fd_mount_id(current):
        raise CandidatePublicationAuthorityResolutionError()


def _fd_mount_id(descriptor: int) -> int:
    try:
        raw = Path(f"/proc/self/fdinfo/{descriptor}").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        raise CandidatePublicationAuthorityResolutionError() from None
    for line in raw.splitlines():
        if line.startswith("mnt_id:"):
            value = line.partition(":")[2].strip()
            if value.isdigit():
                return int(value)
            break
    raise CandidatePublicationAuthorityResolutionError()


def _same_backend(left: object, right: object) -> None:
    if (
        getattr(left, "qualified", False) is not True
        or getattr(right, "qualified", False) is not True
    ):
        raise CandidatePublicationAuthorityResolutionError()
    left_mount = getattr(left, "mount_id", None)
    right_mount = getattr(right, "mount_id", None)
    left_device = getattr(left, "device", None)
    right_device = getattr(right, "device", None)
    if (left_mount is not None and right_mount is not None and left_mount != right_mount) or (
        left_device is not None and right_device is not None and left_device != right_device
    ):
        raise CandidatePublicationAuthorityResolutionError()


def _check_regular(descriptor: int) -> None:
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise ValueError("authority root is not a regular file")


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
        raise ValueError("authority root is too large")
    return data


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        offset += os.write(descriptor, data[offset:])


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "CandidatePublicationAuthorityResolutionError",
    "MainPersonalExactCasCandidatePublicationAuthorityJournal",
    "MainPersonalExactCasCandidatePublicationAuthorityResolver",
]
