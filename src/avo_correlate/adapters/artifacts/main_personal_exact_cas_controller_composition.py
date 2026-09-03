"""Durable, offline, non-authoritative personal exact-CAS composition root."""

from __future__ import annotations

import os
import re
import stat
import sys
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Any

from avo_correlate.adapters.artifacts.durable_backend_gate import (
    DurableBackendQualification,
    require_durable_backend,
)
from avo_correlate.adapters.artifacts.main_graduation_journal import MainGraduationJournal
from avo_correlate.adapters.artifacts.main_personal_exact_cas_hosted_identity_journal import (
    MainPersonalExactCasHostedIdentityJournal,
)
from avo_correlate.adapters.artifacts.main_personal_exact_cas_journal import (
    MainPersonalExactCasJournal,
)
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_hosted_identity_bundle import (
    MainPersonalExactCasHostedIdentityEvidenceBundle,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation import (
    MainCompositionArtifact,
    MainCompositionProof,
    MainGraduationPlan,
    MainLeaseEvidenceRecord,
    MainSourcePackageBinding,
)
from avo_correlate.contracts.main_personal_exact_cas import (
    MainPersonalExactCasActivation,
    personal_cas_claim_digest,
)
from avo_correlate.contracts.main_personal_exact_cas_controller_composition import (
    MainPersonalExactCasControllerComposition,
)
from avo_correlate.contracts.main_personal_exact_cas_hosted_identity import (
    MainPersonalExactCasHostedIdentityEvidenceRoot,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

_LOCK = RLock()
_INDEX_DIR = "main-personal-exact-cas-controller-index"
_ROLE = "main-personal-exact-cas-controller-composition"
_MEDIA = "application/vnd.avo.main-personal-exact-cas-controller-composition+json"
_ROOT_ROLE = "main-personal-exact-cas-hosted-identity-root"
_ROOT_MEDIA = "application/vnd.avo.main-personal-exact-cas-hosted-identity-root+json"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_INDEX = 1024 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


class MainPersonalExactCasControllerCompositionError(RuntimeError):
    """Value-free failure to bind or reopen the composition root."""


class MainPersonalExactCasControllerCompositionConflictError(
    MainPersonalExactCasControllerCompositionError
):
    """The per-operation root was created with different bytes."""


def _exact(value: object, expected: type[Any]) -> Any:
    if type(value) is not expected:
        raise ValueError("dependency has the wrong concrete type")
    data = canonical_bytes(value)
    checked = expected.model_validate_json(data)
    if type(checked) is not expected or checked != value or canonical_bytes(checked) != data:
        raise ValueError("dependency is not canonical")
    return checked


def _reference(value: object, expected_role: str, expected_media: str) -> ArtifactRef:
    result = _exact(value, ArtifactRef)
    if result.role != expected_role or result.media_type != expected_media:
        raise ValueError("dependency artifact identity differs")
    return result


def _revalidate_identity_bundle(
    value: object,
) -> MainPersonalExactCasHostedIdentityEvidenceBundle:
    """Close dataclass/model-construction escapes at this composition boundary."""

    if type(value) is not MainPersonalExactCasHostedIdentityEvidenceBundle:
        raise ValueError("hosted identity bundle is not exact")
    bundle = value
    bundle.assert_valid()
    return bundle


class MainPersonalExactCasControllerCompositionJournal:
    """Create-once evidence root; no provider or mutation capability."""

    def __init__(self, root: Path, *, max_record_bytes: int = 8 * 1024 * 1024) -> None:
        if type(max_record_bytes) is not int or max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        self._closed = False
        self._descriptor_mode = False
        self._root_fd: int | None = None
        self._index_fd: int | None = None
        try:
            self._qualification = require_durable_backend(root)
            self._root = self._qualification.root
            self._root.mkdir(parents=True, exist_ok=True)
            if not self._root.is_dir() or self._root.is_symlink():
                raise ValueError("composition root is not a directory")
            self._indexes = self._root / _INDEX_DIR
            self._indexes.mkdir(parents=True, exist_ok=True)
            self._qualify(self._indexes)
            self._descriptor_mode = self._supports_descriptors()
            if self._descriptor_mode:
                self._root_fd = _open_directory(self._root)
                self._index_fd = _open_dir_at(self._root_fd, _INDEX_DIR, create=False)
                self._check_descriptor(self._root_fd)
                self._check_descriptor(self._index_fd)
            _fsync_directory(self._root)
            self._max = max_record_bytes
        except BaseException:
            self.close()
            raise

    @property
    def root(self) -> Path:
        return self._root

    @property
    def index_root(self) -> Path:
        return self._indexes

    @property
    def backend_qualification(self) -> DurableBackendQualification:
        return self._qualification

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        values = (self._index_fd, self._root_fd)
        self._index_fd = None
        self._root_fd = None
        for descriptor in values:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)

    def __enter__(self) -> MainPersonalExactCasControllerCompositionJournal:
        self._ensure_open()
        return self

    def __exit__(self, *_values: object) -> bool:
        self.close()
        return False

    def bind(
        self,
        *,
        hosted_identity_journal: MainPersonalExactCasHostedIdentityJournal,
        personal_journal: MainPersonalExactCasJournal,
        source_journal: MainGraduationJournal,
        operation_id: str,
        lease_identity: str,
        lease_digest: str,
        lease_expires_at: datetime,
        claim_nonce: str,
        policy_digest: str,
        protocol_digest: str,
    ) -> MainPersonalExactCasControllerComposition:
        """Load exact durable dependencies and exclusively publish one root."""

        self._ensure_open()
        try:
            self._verify_directories()
            if type(hosted_identity_journal) is not MainPersonalExactCasHostedIdentityJournal:
                raise ValueError("hosted identity journal is required")
            if type(personal_journal) is not MainPersonalExactCasJournal:
                raise ValueError("personal CAS journal is required")
            if type(source_journal) is not MainGraduationJournal:
                raise ValueError("source journal is required")
            if not _DIGEST.fullmatch(operation_id or ""):
                raise ValueError("operation identity is malformed")
            identity = hosted_identity_journal.read()
            if identity is None:
                raise ValueError("hosted identity evidence is missing")
            identity_bundle, identity_root = identity
            identity_bundle = _revalidate_identity_bundle(identity_bundle)
            identity_root = _exact(identity_root, MainPersonalExactCasHostedIdentityEvidenceRoot)
            activation_result = personal_journal.read_activation()
            if activation_result is None:
                raise ValueError("activation is missing")
            activation, activation_ref = activation_result
            activation = _exact(activation, MainPersonalExactCasActivation)
            activation_ref = _reference(
                activation_ref,
                "main-personal-exact-cas-activation",
                "application/vnd.avo.main-personal-exact-cas-activation+json",
            )
            self._check_ref(
                activation_ref,
                canonical_digest(activation),
                "main-personal-exact-cas-activation",
                "application/vnd.avo.main-personal-exact-cas-activation+json",
                len(canonical_bytes(activation)),
            )
            lease_result = source_journal.read_lease_evidence_record(operation_id)
            if lease_result is None:
                raise ValueError("durable lease evidence is missing")
            lease = _exact(lease_result[0], MainLeaseEvidenceRecord)
            lease_ref = _reference(
                lease_result[1],
                "main-graduation-lease-evidence-record",
                "application/vnd.avo.main-graduation-lease-evidence-record+json",
            )
            self._check_ref(
                lease_ref,
                canonical_digest(lease),
                "main-graduation-lease-evidence-record",
                "application/vnd.avo.main-graduation-lease-evidence-record+json",
                len(canonical_bytes(lease)),
            )
            if (
                lease.operation_id != operation_id
                or lease.repository_digest != activation.repository_digest
                or lease.target_ref != activation.target_ref
                or lease.owner != lease_identity
                or lease.lease_digest != lease_digest
                or lease.expires_at != lease_expires_at
            ):
                raise ValueError("lease evidence is not exact")
            plan_result = source_journal.read_plan(activation.source_operation_id)
            if plan_result is None:
                raise ValueError("source plan is missing")
            plan, plan_ref = (
                _exact(plan_result[0], MainGraduationPlan),
                _exact(plan_result[1], ArtifactRef),
            )
            package = _exact(plan.package, MainSourcePackageBinding)
            package_ref = _reference(
                package.package_artifact,
                "integration-campaign-package",
                "application/vnd.avo.integration-campaign+json",
            )
            package_result = source_journal.read_source_package(activation.source_operation_id)
            if package_result is None:
                raise ValueError("source package is missing")
            stored_package = _exact(package_result[0], MainSourcePackageBinding)
            stored_package_ref = _reference(
                package_result[1],
                "main-graduation-source-package",
                "application/vnd.avo.main-graduation-source-package+json",
            )
            if stored_package != package:
                raise ValueError("source package differs from plan")
            self._check_ref(
                stored_package_ref,
                canonical_digest(stored_package),
                "main-graduation-source-package",
                "application/vnd.avo.main-graduation-source-package+json",
                len(canonical_bytes(stored_package)),
            )
            composition_result = source_journal.read_composition(activation.source_operation_id)
            proof_result = source_journal.read_composition_proof(activation.source_operation_id)
            if composition_result is None or proof_result is None:
                raise ValueError("source composition proof is incomplete")
            composition = _exact(composition_result[0], MainCompositionArtifact)
            composition_ref = _exact(composition_result[1], ArtifactRef)
            proof = _exact(proof_result[0], MainCompositionProof)
            proof_ref = _exact(proof_result[1], ArtifactRef)
            self._check_ref(
                plan_ref,
                canonical_digest(plan),
                "main-graduation-plan",
                "application/vnd.avo.main-graduation-plan+json",
                len(canonical_bytes(plan)),
            )
            self._check_ref(
                composition_ref,
                canonical_digest(composition),
                "main-graduation-composition",
                "application/vnd.avo.main-graduation-composition+json",
                len(canonical_bytes(composition)),
            )
            self._check_ref(
                proof_ref,
                canonical_digest(proof),
                "main-graduation-composition-proof",
                "application/vnd.avo.main-graduation-composition-proof+json",
                len(canonical_bytes(proof)),
            )
            if (
                activation.source_operation_id != plan.operation_id
                or activation.source_plan_digest != canonical_digest(plan)
                or activation.source_package_digest != package.package_digest
                or activation.source_composition_digest != composition.composition_digest
                or activation.base_commit != composition.base_commit
                or activation.base_tree != composition.base_tree
                or activation.candidate_commit != composition.candidate_commit
                or activation.candidate_tree != composition.candidate_tree
                or activation.candidate_ref != composition.candidate_ref
                or activation.candidate_parents != (composition.candidate_parent_commit,)
                or identity_bundle.bundle_digest != identity_root.bundle_digest
                or identity_bundle.repository_digest != activation.repository_digest
                or identity_bundle.main_commit != activation.base_commit
                or identity_bundle.writer_protection_ruleset_digest
                != activation.protection_ruleset_digest
                or identity_bundle.writer_app_id != activation.writer_app_id
                or identity_bundle.writer_installation_id != activation.writer_installation_id
                or identity_bundle.writer_configuration_digest == ""
            ):
                raise ValueError("composition dependencies are not cross-bound")
            if not all(
                type(value) is str and _DIGEST.fullmatch(value) is not None
                for value in (lease_digest, policy_digest, protocol_digest)
            ):
                raise ValueError("composition identity digest is malformed")
            root = MainPersonalExactCasControllerComposition.build(
                operation_id=operation_id,
                activation_digest=activation.activation_digest,
                repository_digest=activation.repository_digest,
                hosted_identity_root_artifact=self._identity_ref(
                    identity_root, activation.activated_at
                ),
                hosted_identity_bundle_digest=identity_bundle.bundle_digest,
                activation_artifact=activation_ref,
                source_operation_id=activation.source_operation_id,
                source_plan_digest=activation.source_plan_digest,
                source_plan_artifact=plan_ref,
                source_package_digest=activation.source_package_digest,
                source_package_artifact=package_ref,
                source_composition_digest=activation.source_composition_digest,
                source_composition_artifact=composition_ref,
                source_composition_proof_artifact=proof_ref,
                base_commit=activation.base_commit,
                base_tree=activation.base_tree,
                candidate_commit=activation.candidate_commit,
                candidate_tree=activation.candidate_tree,
                candidate_ref=activation.candidate_ref,
                candidate_parents=activation.candidate_parents,
                writer_app_id=activation.writer_app_id,
                writer_installation_id=activation.writer_installation_id,
                writer_identity=activation.writer_identity,
                writer_configuration_digest=identity_bundle.writer_configuration_digest,
                observer_configuration_digest=identity_bundle.observer_configuration_digest,
                protection_ruleset_digest=activation.protection_ruleset_digest,
                lease_identity=lease_identity,
                lease_digest=lease_digest,
                lease_artifact=lease_ref,
                lease_expires_at=lease_expires_at,
                claim_nonce=claim_nonce,
                claim_digest=personal_cas_claim_digest(
                    operation_id=operation_id,
                    lease_identity=lease_identity,
                    lease_digest=lease_digest,
                    lease_expires_at=lease_expires_at,
                    claim_nonce=claim_nonce,
                ),
                policy_digest=policy_digest,
                protocol_digest=protocol_digest,
            )
            # Build validates the real claim digest; the provisional value above
            # is deliberately replaced before construction.
            return self._publish(operation_id, root)
        except MainPersonalExactCasControllerCompositionError:
            raise
        except Exception:
            raise MainPersonalExactCasControllerCompositionError() from None

    bind_once = bind
    record = bind

    def read(self, operation_id: str) -> MainPersonalExactCasControllerComposition | None:
        """Read the canonical persisted manifest, without authority implications.

        This operation validates the root file and its filesystem identity. It
        intentionally does not claim that referenced dependency journals still
        exist or remain trusted; a later authority verifier must resolve the
        recorded closure again before any action.
        """
        self._ensure_open()
        try:
            self._verify_directories()
            path = self._path(operation_id)
            if self._descriptor_mode:
                if self._index_fd is None:
                    raise ValueError("index descriptor is unavailable")
                op_fd = _open_dir_at(
                    self._index_fd, operation_id.removeprefix("sha256:"), create=False
                )
                try:
                    descriptor = os.open("root.json", os.O_RDONLY | _NOFOLLOW, dir_fd=op_fd)
                    try:
                        self._check_descriptor(descriptor, directory=False)
                        raw = _read_bounded(descriptor, min(self._max, _MAX_INDEX))
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                finally:
                    os.close(op_fd)
            else:
                if not path.is_file() or path.is_symlink():
                    return None
                raw = _read_path(path, min(self._max, _MAX_INDEX))
            value = MainPersonalExactCasControllerComposition.model_validate_json(raw)
            if (
                type(value) is not MainPersonalExactCasControllerComposition
                or canonical_bytes(value) != raw
            ):
                raise ValueError("root is not canonical")
            if value.operation_id != operation_id:
                raise ValueError("root operation differs")
            self._verify_directories()
            return value
        except FileNotFoundError:
            return None
        except Exception:
            raise MainPersonalExactCasControllerCompositionError() from None

    reopen = read

    def _publish(
        self, operation_id: str, root: MainPersonalExactCasControllerComposition
    ) -> MainPersonalExactCasControllerComposition:
        data = canonical_bytes(root)
        if len(data) > min(self._max, _MAX_INDEX):
            raise ValueError("composition root is too large")
        with _LOCK:
            if self._descriptor_mode:
                if self._index_fd is None or self._root_fd is None:
                    raise ValueError("retained descriptors unavailable")
                op_fd = _open_dir_at(
                    self._index_fd, operation_id.removeprefix("sha256:"), create=True
                )
                try:
                    self._check_descriptor(op_fd)
                    try:
                        descriptor = os.open(
                            "root.json",
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                            mode=0o600,
                            dir_fd=op_fd,
                        )
                        try:
                            self._check_descriptor(descriptor, directory=False)
                            _write_all(descriptor, data)
                            os.fsync(descriptor)
                        finally:
                            os.close(descriptor)
                    except FileExistsError:
                        existing = _read_bounded_fd_at(
                            op_fd, "root.json", min(self._max, _MAX_INDEX), sync=True
                        )
                        if existing != data:
                            raise MainPersonalExactCasControllerCompositionConflictError() from None
                    os.fsync(op_fd)
                    os.fsync(self._index_fd)
                finally:
                    os.close(op_fd)
                os.fsync(self._root_fd)
            else:
                path = self._path(operation_id)
                path.parent.mkdir(parents=True, exist_ok=True)
                self._qualify(path.parent)
                try:
                    descriptor = os.open(
                        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, mode=0o600
                    )
                    try:
                        _write_all(descriptor, data)
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                except FileExistsError:
                    if _read_path(path, min(self._max, _MAX_INDEX), sync=True) != data:
                        raise MainPersonalExactCasControllerCompositionConflictError() from None
                _fsync_directory(path.parent)
                _fsync_directory(self._root)
        self._verify_directories()
        return root

    def _identity_ref(
        self, root: MainPersonalExactCasHostedIdentityEvidenceRoot, created_at: datetime
    ) -> ArtifactRef:
        data = canonical_bytes(root)
        return ArtifactRef(
            # The hosted identity root is a durable journal file, not a CAS
            # child. Its ArtifactRef therefore names the digest of the exact
            # persisted bytes, never the root's internal digest field.
            digest=canonical_digest(root.model_dump(mode="json")),
            size_bytes=len(data),
            media_type=_ROOT_MEDIA,
            role=_ROOT_ROLE,
            created_at=created_at,
        )

    @staticmethod
    def _check_ref(ref: ArtifactRef, digest: str, role: str, media: str, size: int) -> None:
        if (
            ref.digest != digest
            or ref.role != role
            or ref.media_type != media
            or ref.size_bytes != size
        ):
            raise ValueError("source artifact reference differs")

    def _path(self, operation_id: str) -> Path:
        if type(operation_id) is not str or _DIGEST.fullmatch(operation_id) is None:
            raise ValueError("operation identity is malformed")
        return self._indexes / operation_id.removeprefix("sha256:") / "root.json"

    def _ensure_open(self) -> None:
        if self._closed:
            raise MainPersonalExactCasControllerCompositionError("composition journal is closed")

    def _supports_descriptors(self) -> bool:
        if sys.platform == "linux":
            if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
                raise ValueError("descriptor no-follow semantics unavailable")
            return True
        if self._qualification.reason.startswith("test-"):
            return False
        raise ValueError("descriptor backend is unsupported")

    def _qualify(self, path: Path) -> None:
        result = require_durable_backend(path)
        if (
            not result.qualified
            or result.device != self._qualification.device
            or result.mount_id != self._qualification.mount_id
        ):
            raise ValueError("backend identity differs")

    def _check_descriptor(self, descriptor: int, *, directory: bool = True) -> None:
        if self._root_fd is None:
            raise ValueError("root descriptor unavailable")
        if directory and not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise ValueError("descriptor is not a directory")
        if os.fstat(descriptor).st_dev != os.fstat(self._root_fd).st_dev:
            raise ValueError("nested device differs")
        if _mount_id(descriptor) != _mount_id(self._root_fd):
            raise ValueError("nested mount differs")

    def _verify_directories(self) -> None:
        self._ensure_open()
        if not self._descriptor_mode:
            self._qualify(self._root)
            self._qualify(self._indexes)
            return
        if self._root_fd is None or self._index_fd is None:
            raise ValueError("retained descriptors unavailable")
        current = _open_directory(self._root)
        current_index: int | None = None
        try:
            current_stat = os.fstat(current)
            retained_stat = os.fstat(self._root_fd)
            if (current_stat.st_dev, current_stat.st_ino) != (
                retained_stat.st_dev,
                retained_stat.st_ino,
            ):
                raise ValueError("root was recreated")
            self._check_descriptor(current)
            current_index = _open_dir_at(current, _INDEX_DIR, create=False)
            self._check_descriptor(current_index)
            current_stat = os.fstat(current_index)
            retained_stat = os.fstat(self._index_fd)
            if (current_stat.st_dev, current_stat.st_ino) != (
                retained_stat.st_dev,
                retained_stat.st_ino,
            ):
                raise ValueError("index was recreated")
        finally:
            if current_index is not None:
                os.close(current_index)
            os.close(current)


def _open_directory(path: Path) -> int:
    descriptor = os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("not a directory")
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
        raise ValueError("not a directory")
    return descriptor


def _read_bounded(descriptor: int, maximum: int) -> bytes:
    if maximum < 0 or not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise ValueError("bounded regular read failed")
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
        raise ValueError("bounded regular read failed")
    return data


def _read_bounded_fd_at(parent: int, name: str, maximum: int, *, sync: bool = False) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=parent)
    try:
        result = _read_bounded(descriptor, maximum)
        if sync:
            os.fsync(descriptor)
        return result
    finally:
        os.close(descriptor)


def _read_path(path: Path, maximum: int, *, sync: bool = False) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
    try:
        result = _read_bounded(descriptor, maximum)
        if sync:
            os.fsync(descriptor)
        return result
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        count = os.write(descriptor, data[offset:])
        if count <= 0:
            raise OSError("short write")
        offset += count


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _mount_id(descriptor: int) -> int:
    if sys.platform != "linux":
        raise ValueError("mount IDs unavailable")
    fd = os.open(f"/proc/self/fdinfo/{descriptor}", os.O_RDONLY | _NOFOLLOW)
    try:
        data = _read_bounded(fd, 4096).decode("ascii")
    finally:
        os.close(fd)
    values = [
        line.split(":", 1)[1].strip() for line in data.splitlines() if line.startswith("mnt_id:")
    ]
    if len(values) != 1 or not re.fullmatch(r"[1-9][0-9]*", values[0]):
        raise ValueError("fdinfo mount identity is malformed")
    return int(values[0])


__all__ = [
    "MainPersonalExactCasControllerCompositionConflictError",
    "MainPersonalExactCasControllerCompositionError",
    "MainPersonalExactCasControllerCompositionJournal",
]
