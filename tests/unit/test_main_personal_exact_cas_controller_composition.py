"""Canaries for the offline personal exact-CAS composition root."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportArgumentType=false, reportAttributeAccessIssue=false

from __future__ import annotations

import hashlib
import os
from dataclasses import fields
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from avo_correlate.adapters.artifacts import (
    main_personal_exact_cas_controller_composition as module,
)
from avo_correlate.adapters.artifacts.durable_backend_gate import DurableBackendQualification
from avo_correlate.contracts import MainPersonalExactCasControllerComposition
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_personal_exact_cas import (
    MainPersonalExactCasActivation,
    personal_cas_claim_digest,
    personal_cas_operation_id,
)
from avo_correlate.contracts.main_personal_exact_cas_hosted_identity import (
    MainPersonalExactCasHostedIdentityEvidenceRoot,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_main_personal_exact_cas_hosted_identity_bundle import _bundle
from tests.unit.test_trusted_main_graduation_source import _configured_reader

_TIME = datetime(2026, 1, 1, tzinfo=UTC)
_DIGEST = "sha256:" + "a" * 64
_BASE = "b" * 40
_CANDIDATE = "c" * 40
_TREE = "d" * 40


def _ref(role: str, media: str) -> ArtifactRef:
    return ArtifactRef(
        digest=_DIGEST,
        size_bytes=7,
        role=role,
        media_type=media,
        created_at=_TIME,
    )


def _root() -> MainPersonalExactCasControllerComposition:
    values: dict[str, Any] = {
        "activation_digest": _DIGEST,
        "repository_digest": _DIGEST,
        "hosted_identity_root_artifact": _ref(
            "main-personal-exact-cas-hosted-identity-root",
            "application/vnd.avo.main-personal-exact-cas-hosted-identity-root+json",
        ),
        "hosted_identity_bundle_digest": _DIGEST,
        "activation_artifact": _ref(
            "main-personal-exact-cas-activation",
            "application/vnd.avo.main-personal-exact-cas-activation+json",
        ),
        "source_operation_id": "sha256:" + "1" * 64,
        "source_plan_digest": _DIGEST,
        "source_plan_artifact": _ref(
            "main-graduation-plan", "application/vnd.avo.main-graduation-plan+json"
        ),
        "source_package_digest": _DIGEST,
        "source_package_artifact": _ref(
            "integration-campaign-package", "application/vnd.avo.integration-campaign+json"
        ),
        "source_package_binding_artifact": _ref(
            "main-graduation-source-package",
            "application/vnd.avo.main-graduation-source-package+json",
        ),
        "source_composition_digest": _DIGEST,
        "source_composition_artifact": _ref(
            "main-graduation-composition",
            "application/vnd.avo.main-graduation-composition+json",
        ),
        "source_composition_proof_artifact": _ref(
            "main-graduation-composition-proof",
            "application/vnd.avo.main-graduation-composition-proof+json",
        ),
        "base_commit": _BASE,
        "base_tree": _TREE,
        "candidate_commit": _CANDIDATE,
        "candidate_tree": _TREE,
        "candidate_ref": "refs/heads/avo/candidate/" + "1" * 64,
        "candidate_parents": (_BASE,),
        "writer_app_id": 1,
        "writer_installation_id": 2,
        "writer_identity": "writer",
        "writer_configuration_digest": _DIGEST,
        "observer_configuration_digest": _DIGEST,
        "protection_ruleset_digest": _DIGEST,
        "lease_identity": "lease",
        "lease_digest": _DIGEST,
        "lease_artifact": _ref(
            "main-graduation-lease-evidence-record",
            "application/vnd.avo.main-graduation-lease-evidence-record+json",
        ),
        "lease_expires_at": datetime(2026, 1, 2, tzinfo=UTC),
        "claim_nonce": "nonce",
        "policy_digest": _DIGEST,
        "protocol_digest": _DIGEST,
    }
    values["operation_id"] = personal_cas_operation_id(
        activation_digest=values["activation_digest"],
        repository_digest=values["repository_digest"],
        target_ref="refs/heads/main",
        source_operation_id=values["source_operation_id"],
        source_plan_digest=values["source_plan_digest"],
        source_composition_digest=values["source_composition_digest"],
        base_commit=_BASE,
        base_tree=_TREE,
        candidate_commit=_CANDIDATE,
        candidate_tree=_TREE,
        candidate_ref=values["candidate_ref"],
        candidate_parents=(_BASE,),
        protection_ruleset_digest=values["protection_ruleset_digest"],
        writer_app_id=1,
        writer_installation_id=2,
        writer_identity="writer",
        lease_identity="lease",
        lease_digest=_DIGEST,
        lease_expires_at=values["lease_expires_at"],
        claim_nonce="nonce",
    )
    values["claim_digest"] = personal_cas_claim_digest(
        operation_id=values["operation_id"],
        lease_identity="lease",
        lease_digest=_DIGEST,
        lease_expires_at=values["lease_expires_at"],
        claim_nonce="nonce",
    )
    return MainPersonalExactCasControllerComposition.build(**values)


def _identity_root() -> MainPersonalExactCasHostedIdentityEvidenceRoot:
    return MainPersonalExactCasHostedIdentityEvidenceRoot.build(
        writer_diagnostic_artifact=_ref(
            "main-personal-exact-cas-hosted-configuration-diagnostic",
            "application/vnd.avo.main-personal-exact-cas-hosted-configuration-diagnostic+json",
        ),
        writer_provenance_artifact=_ref(
            "github-read-provenance", "application/vnd.avo.github-read-provenance+json"
        ),
        observer_snapshot_artifact=_ref(
            "main-base-snapshot", "application/vnd.avo.main-base-snapshot+json"
        ),
        observer_provenance_artifact=_ref(
            "github-read-provenance", "application/vnd.avo.github-read-provenance+json"
        ),
        observer_configuration_artifact=_ref(
            "github-main-base-reader-configuration",
            "application/vnd.avo.github-main-base-reader-configuration+json",
        ),
        bundle_digest=_DIGEST,
    )


def test_contract_is_frozen_canonical_and_non_authoritative() -> None:
    root = _root()
    assert canonical_bytes(root) == canonical_bytes(
        MainPersonalExactCasControllerComposition.model_validate_json(canonical_bytes(root))
    )
    assert all(
        getattr(root, name) is False
        for name in (
            "activation_authority_sufficient",
            "is_authoritative",
            "is_terminal",
            "readiness_authorized",
            "mutation_performed",
            "receipt_issued",
            "completion_claimed",
            "deploy_performed",
        )
    )
    with pytest.raises(ValidationError):
        MainPersonalExactCasControllerComposition.model_validate(
            root.model_dump() | {"unexpected": True}
        )
    forged_values = root.model_dump()
    forged_values["is_authoritative"] = True
    forged = MainPersonalExactCasControllerComposition.model_construct(**forged_values)
    with pytest.raises(ValidationError):
        MainPersonalExactCasControllerComposition.model_validate_json(canonical_bytes(forged))


def test_bounded_read_rejects_oversized_regular_file(tmp_path: Path) -> None:
    path = tmp_path / "hostile.json"
    path.write_bytes(b"x" * 32)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(ValueError):
            module._read_bounded(descriptor, 8)
    finally:
        os.close(descriptor)


def test_hosted_identity_bundle_is_semantically_revalidated() -> None:
    bundle = _bundle()
    assert module._revalidate_identity_bundle(bundle) == bundle
    tampered = object.__new__(type(bundle))
    for item in fields(bundle):
        object.__setattr__(tampered, item.name, getattr(bundle, item.name))
    object.__setattr__(tampered, "main_commit", "f" * 40)
    with pytest.raises(ValueError):
        module._revalidate_identity_bundle(tampered)
    with pytest.raises(ValueError):
        module._revalidate_identity_bundle(object())


def test_identity_artifact_ref_uses_identity_evidence_creation_time() -> None:
    journal = object.__new__(module.MainPersonalExactCasControllerCompositionJournal)
    identity = _identity_root()
    reference = journal._identity_ref(identity)
    assert reference.created_at == identity.writer_diagnostic_artifact.created_at


def test_descriptor_child_reads_validate_the_opened_leaf(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def qualified(root: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=root.resolve(), qualified=True, reason="test-qualified", mount_id=1, device="8:0"
        )

    monkeypatch.setattr(module, "require_durable_backend", qualified)
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "journal")
    if not journal._descriptor_mode:
        pytest.skip("descriptor leaf validation is Linux-only")
    parent = os.open(journal.root / "objects" / "sha256", os.O_RDONLY)
    try:
        digest = "e" * 64
        (journal.root / "objects" / "sha256" / digest).write_bytes(b"child")
        seen: list[bool] = []

        def check(_descriptor: int, *, directory: bool = True) -> None:
            seen.append(directory)

        monkeypatch.setattr(journal, "_check_descriptor", check)
        assert journal._read_bounded_fd_at(parent, digest, 16) == b"child"
        assert seen == [False]
    finally:
        os.close(parent)


def test_close_is_idempotent_and_blocks_operations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def qualified(root: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=root.resolve(),
            qualified=True,
            reason="test-qualified",
            mount_id=1,
            device="8:0",
        )

    monkeypatch.setattr(module, "require_durable_backend", qualified)

    def no_fsync(_path: Path) -> None:
        return None

    monkeypatch.setattr(module, "_fsync_directory", no_fsync)
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "journal")
    assert journal.root.is_dir()
    assert journal.index_root.is_dir()
    assert journal.backend_qualification.qualified
    journal.close()
    journal.close()
    with pytest.raises(module.MainPersonalExactCasControllerCompositionError):
        journal.read(_DIGEST)


def test_journal_create_once_reuse_conflict_and_reuse_fsync_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def qualified(root: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=root.resolve(),
            qualified=True,
            reason="test-qualified",
            mount_id=1,
            device="8:0",
        )

    def no_fsync(_path: Path) -> None:
        return None

    def no_fd_fsync(_descriptor: int) -> None:
        return None

    monkeypatch.setattr(module, "require_durable_backend", qualified)
    monkeypatch.setattr(module, "_fsync_directory", no_fsync)
    monkeypatch.setattr(module.os, "fsync", no_fd_fsync)
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "journal")
    root = _root()
    assert journal._publish(root.operation_id, root) == root
    with pytest.raises(ValueError, match="operation identity"):
        journal._publish("../escape", root)
    with pytest.raises(ValueError, match="composition root"):
        forged_values = root.model_dump()
        forged_values["protocol_digest"] = "sha256:" + "f" * 64
        forged = MainPersonalExactCasControllerComposition.model_construct(**forged_values)
        journal._publish(root.operation_id, forged)

    if journal._descriptor_mode:
        def fail_fd_fsync(_descriptor: int) -> None:
            raise OSError("reuse directory fsync failure")

        monkeypatch.setattr(module.os, "fsync", fail_fd_fsync)
    else:
        def fail_fsync(_path: Path) -> None:
            raise OSError("reuse directory fsync failure")

        monkeypatch.setattr(module, "_fsync_directory", fail_fsync)
    with pytest.raises(OSError, match="reuse directory fsync failure"):
        journal._publish(root.operation_id, root)


def test_exact_and_reference_boundaries_reject_forged_or_wrong_identity() -> None:
    root = _root()
    assert module._exact(root, MainPersonalExactCasControllerComposition) == root
    with pytest.raises(ValueError, match="concrete type"):
        module._exact(root.model_dump(), MainPersonalExactCasControllerComposition)
    forged_values = root.model_dump()
    forged_values["protocol_digest"] = "sha256:" + "f" * 64
    forged = MainPersonalExactCasControllerComposition.model_construct(**forged_values)
    with pytest.raises(ValueError):
        module._exact(forged, MainPersonalExactCasControllerComposition)

    reference = _ref("main-graduation-plan", "application/vnd.avo.main-graduation-plan+json")
    assert module._reference(
        reference, "main-graduation-plan", "application/vnd.avo.main-graduation-plan+json"
    ) == reference
    with pytest.raises(ValueError, match="identity"):
        module._reference(reference, "wrong-role", reference.media_type)


def test_exact_rejects_a_canonical_but_different_reparse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _root()
    forged_values = root.model_dump()
    forged_values["protocol_digest"] = "sha256:" + "f" * 64
    forged = MainPersonalExactCasControllerComposition.model_construct(**forged_values)
    monkeypatch.setattr(
        MainPersonalExactCasControllerComposition,
        "model_validate_json",
        classmethod(lambda _cls, _data: forged),
    )
    with pytest.raises(ValueError, match="canonical"):
        module._exact(root, MainPersonalExactCasControllerComposition)


def test_fallback_read_and_child_persistence_are_create_once_and_bounded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def qualified(root: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=root.resolve(), qualified=True, reason="test-qualified", mount_id=1, device="8:0"
        )

    monkeypatch.setattr(module, "require_durable_backend", qualified)
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)
    monkeypatch.setattr(module.os, "fsync", lambda _descriptor: None)
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "journal")
    root = _root()
    assert journal._publish(root.operation_id, root) == root
    monkeypatch.setattr(journal, "_validate_child_closure", lambda _root: None)
    assert journal.read(root.operation_id) == root
    assert journal.read("sha256:" + "f" * 64) is None
    journal._path(root.operation_id).write_bytes(b"different")
    with pytest.raises(module.MainPersonalExactCasControllerCompositionConflictError):
        journal._publish(root.operation_id, root)

    data = b"composition-child"
    reference = ArtifactRef(
        digest="sha256:" + hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        role="main-graduation-plan",
        media_type="application/vnd.avo.main-graduation-plan+json",
        created_at=_TIME,
    )
    journal._persist_child(reference, data)
    assert journal._child_bytes(reference) == data
    journal._persist_child(reference, data)
    path = journal.root / "objects" / "sha256" / reference.digest[7:9] / reference.digest[9:]
    path.write_bytes(b"different")
    with pytest.raises(ValueError, match="conflicts"):
        journal._persist_child(reference, data)


def test_read_rejects_noncanonical_or_wrong_operation_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def qualified(root: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=root.resolve(), qualified=True, reason="test-qualified", mount_id=1, device="8:0"
        )

    monkeypatch.setattr(module, "require_durable_backend", qualified)
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "journal")
    root = _root()
    journal._publish(root.operation_id, root)
    monkeypatch.setattr(journal, "_validate_child_closure", lambda _root: None)
    path = journal._path(root.operation_id)
    path.write_bytes(canonical_bytes(root) + b"x")
    with pytest.raises(module.MainPersonalExactCasControllerCompositionError):
        journal.read(root.operation_id)


def test_read_rejects_canonical_root_under_different_operation_and_missing_leaf(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        module,
        "require_durable_backend",
        lambda root: DurableBackendQualification(
            root=root.resolve(), qualified=True, reason="test-qualified", mount_id=1, device="8:0"
        ),
    )
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "journal")
    root = _root()
    journal._publish(root.operation_id, root)
    other = "sha256:" + "f" * 64
    other_path = journal._path(other)
    other_path.parent.mkdir(parents=True)
    journal._path(root.operation_id).replace(other_path)
    with pytest.raises(module.MainPersonalExactCasControllerCompositionError):
        journal.read(other)
    journal._path(root.operation_id).write_bytes(canonical_bytes(root))

    def missing(*_args: object, **_kwargs: object) -> bytes:
        raise FileNotFoundError

    monkeypatch.setattr(module, "_read_path", missing)
    assert journal.read(root.operation_id) is None


def test_publish_revalidates_root_and_enforces_index_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        module,
        "require_durable_backend",
        lambda root: DurableBackendQualification(
            root=root.resolve(), qualified=True, reason="test-qualified", mount_id=1, device="8:0"
        ),
    )
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)
    root = _root()
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "journal")
    original = module.MainPersonalExactCasControllerComposition.model_validate_json
    monkeypatch.setattr(
        module.MainPersonalExactCasControllerComposition,
        "model_validate_json",
        classmethod(lambda _cls, _data: object()),
    )
    with pytest.raises(ValueError, match="canonical"):
        journal._publish(root.operation_id, root)
    monkeypatch.setattr(
        module.MainPersonalExactCasControllerComposition,
        "model_validate_json",
        original,
    )
    small = module.MainPersonalExactCasControllerCompositionJournal(
        tmp_path / "small", max_record_bytes=1
    )
    with pytest.raises(ValueError, match="large"):
        small._publish(root.operation_id, root)


def test_platform_and_descriptor_guards_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal = object.__new__(module.MainPersonalExactCasControllerCompositionJournal)
    journal._closed = False
    journal._qualification = DurableBackendQualification(
        root=tmp_path, qualified=True, reason="ordinary", mount_id=1, device="8:0"
    )
    if module.sys.platform == "linux":
        assert journal._supports_descriptors()
    else:
        with pytest.raises(ValueError, match="unsupported"):
            journal._supports_descriptors()
    journal._root_fd = None
    with pytest.raises(ValueError, match="root descriptor"):
        journal._check_descriptor(0)
    if module.sys.platform != "linux":
        with pytest.raises(ValueError, match="mount IDs"):
            module._mount_id(0)


def test_utility_filesystem_guards_and_context_lifecycle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="positive"):
        module.MainPersonalExactCasControllerCompositionJournal(
            tmp_path / "bad", max_record_bytes=0
        )

    payload = b"payload"
    path = tmp_path / "payload"
    path.write_bytes(payload)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        assert module._read_bounded(descriptor, len(payload)) == payload
    finally:
        os.close(descriptor)
    with pytest.raises(FileNotFoundError):
        module._read_path(tmp_path / "missing", 8)

    descriptor = os.open(path, os.O_WRONLY)
    try:
        with pytest.raises(OSError, match="short write"):
            monkeypatch.setattr(module.os, "write", lambda *_args: 0)
            module._write_all(descriptor, payload)
    finally:
        os.close(descriptor)

    def qualified(root: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=root.resolve(), qualified=True, reason="test-qualified", mount_id=1, device="8:0"
        )

    monkeypatch.setattr(module, "require_durable_backend", qualified)
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)
    with module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "context") as journal:
        assert journal.__enter__() is journal
    with pytest.raises(module.MainPersonalExactCasControllerCompositionError):
        journal.read(_DIGEST)


def test_filesystem_helpers_use_regular_bounded_and_sync_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    payload = b"payload"
    path = tmp_path / "payload"
    path.write_bytes(payload)
    fsync_calls: list[int] = []
    monkeypatch.setattr(module.os, "fsync", lambda value: fsync_calls.append(value))
    assert module._read_path(path, len(payload), sync=True) == payload
    if module.sys.platform != "linux":
        assert len(fsync_calls) == 1
        return
    descriptor = module._open_directory(tmp_path)
    try:
        child = module._open_dir_at(descriptor, "child", create=True)
        os.close(child)
        child = module._open_directory_at(descriptor, "child")
        os.close(child)
    finally:
        os.close(descriptor)
    module._fsync_directory(tmp_path)
    assert len(fsync_calls) == 2
    descriptor = os.open(path, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="bounded"):
            module._read_bounded(descriptor, -1)
    finally:
        os.close(descriptor)
    directory_descriptor = module._open_directory(tmp_path)
    try:
        with pytest.raises(ValueError, match="bounded"):
            module._read_bounded(directory_descriptor, 8)
    finally:
        os.close(directory_descriptor)


def test_linux_descriptor_publish_read_and_reuse_conflict(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if module.sys.platform != "linux":
        pytest.skip("descriptor anchoring is Linux-only")
    monkeypatch.setattr(
        module,
        "require_durable_backend",
        lambda root: DurableBackendQualification(
            root=root.resolve(), qualified=True, reason="test-qualified", mount_id=1, device="8:0"
        ),
    )
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "journal")
    root = _root()
    assert journal._publish(root.operation_id, root) == root
    assert journal._publish(root.operation_id, root) == root
    monkeypatch.setattr(journal, "_validate_child_closure", lambda _root: None)
    assert journal.read(root.operation_id) == root
    operation_dir = (
        journal.root / "main-personal-exact-cas-controller-index" / root.operation_id[7:]
    )
    (operation_dir / "root.json").write_bytes(b"different")
    with pytest.raises(module.MainPersonalExactCasControllerCompositionConflictError):
        journal._publish(root.operation_id, root)


def test_linux_descriptor_checks_reject_wrong_leaf_and_mount(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if module.sys.platform != "linux":
        pytest.skip("descriptor anchoring is Linux-only")
    monkeypatch.setattr(
        module,
        "require_durable_backend",
        lambda root: DurableBackendQualification(
            root=root.resolve(), qualified=True, reason="test-qualified", mount_id=1, device="8:0"
        ),
    )
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "journal")
    assert journal._root_fd is not None
    file_path = journal.root / "file"
    file_path.write_bytes(b"x")
    file_descriptor = os.open(file_path, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="directory"):
            journal._check_descriptor(file_descriptor)
        monkeypatch.setattr(module, "_mount_id", lambda _fd: 1)
        journal._check_descriptor(file_descriptor, directory=False)
        monkeypatch.setattr(module, "_mount_id", lambda fd: 1 if fd == journal._root_fd else 2)
        with pytest.raises(ValueError, match="mount"):
            journal._check_descriptor(file_descriptor, directory=False)
    finally:
        os.close(file_descriptor)


def test_bind_rejects_wrong_concrete_journal_and_malformed_operation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        module,
        "require_durable_backend",
        lambda root: DurableBackendQualification(
            root=root.resolve(), qualified=True, reason="test-qualified", mount_id=1, device="8:0"
        ),
    )
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "journal")
    identity = object.__new__(module.MainPersonalExactCasHostedIdentityJournal)
    personal = object.__new__(module.MainPersonalExactCasJournal)
    source = object.__new__(module.MainGraduationJournal)
    identity.read = lambda: None
    personal.read_activation = lambda: None
    source.read_lease_evidence_record = lambda _operation: None
    source.read_plan = lambda _operation: None
    source.read_source_package = lambda _operation: None
    source.read_composition = lambda _operation: None
    source.read_composition_proof = lambda _operation: None
    values: dict[str, Any] = {
        "hosted_identity_journal": identity,
        "personal_journal": personal,
        "source_journal": source,
        "operation_id": _DIGEST,
        "lease_identity": "lease",
        "lease_digest": _DIGEST,
        "lease_expires_at": _TIME,
        "claim_nonce": "nonce",
        "policy_digest": _DIGEST,
        "protocol_digest": _DIGEST,
    }
    for name in (
        "hosted_identity_journal",
        "personal_journal",
        "source_journal",
    ):
        altered = dict(values)
        altered[name] = object()
        with pytest.raises(module.MainPersonalExactCasControllerCompositionError):
            journal.bind(**altered)
    malformed = dict(values)
    malformed["operation_id"] = "../escape"
    with pytest.raises(module.MainPersonalExactCasControllerCompositionError):
        journal.bind(**malformed)


def test_linux_descriptor_open_and_mount_guards(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if module.sys.platform != "linux":
        pytest.skip("descriptor anchoring is Linux-only")

    def qualified(root: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=root.resolve(), qualified=True, reason="test-qualified", mount_id=1, device="8:0"
        )

    monkeypatch.setattr(module, "require_durable_backend", qualified)
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "journal")
    assert journal._descriptor_mode
    assert journal._root_fd is not None
    assert journal._objects_fd is not None
    child = module._open_dir_at(journal._objects_fd, "ab", create=True)
    try:
        assert os.fstat(child).st_dev == os.fstat(journal._root_fd).st_dev
    finally:
        os.close(child)


def test_bind_admission_revalidates_exact_dependency_journal_types_and_presence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def qualified(root: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=root.resolve(), qualified=True, reason="test-qualified", mount_id=1, device="8:0"
        )

    monkeypatch.setattr(module, "require_durable_backend", qualified)
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "journal")

    def shell(expected: type[Any], read: Any = None) -> Any:
        value = object.__new__(expected)
        if read is not None:
            value.read = read
        return value

    identity = shell(module.MainPersonalExactCasHostedIdentityJournal, lambda: None)
    personal = shell(module.MainPersonalExactCasJournal, lambda: None)
    source = shell(module.MainGraduationJournal, lambda _operation_id: None)
    arguments = {
        "hosted_identity_journal": identity,
        "personal_journal": personal,
        "source_journal": source,
        "operation_id": _DIGEST,
        "lease_identity": "lease",
        "lease_digest": _DIGEST,
        "lease_expires_at": datetime(2026, 1, 2, tzinfo=UTC),
        "claim_nonce": "nonce",
        "policy_digest": _DIGEST,
        "protocol_digest": _DIGEST,
    }
    with pytest.raises(module.MainPersonalExactCasControllerCompositionError):
        journal.bind(**arguments)

    identity.read = lambda: (object(), object())
    with pytest.raises(module.MainPersonalExactCasControllerCompositionError):
        journal.bind(**arguments)

    identity.read = lambda: (_bundle(), _identity_root())
    with pytest.raises(module.MainPersonalExactCasControllerCompositionError):
        journal.bind(**arguments)
    assert not list(journal.root.glob("main-personal-exact-cas-controller-index/*/*"))


def test_private_reference_and_backend_guards_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _root()
    reference = ArtifactRef(
        digest=canonical_digest(root),
        size_bytes=len(canonical_bytes(root)),
        role="composition",
        media_type="application/json",
        created_at=_TIME,
    )
    assert module.MainPersonalExactCasControllerCompositionJournal._record_reference(
        root, "composition", "application/json", _TIME
    ).digest == reference.digest
    with pytest.raises(ValueError, match="differs"):
        module.MainPersonalExactCasControllerCompositionJournal._check_ref(
            reference, _DIGEST, "composition", "application/json", reference.size_bytes
        )
    with pytest.raises(ValueError, match="malformed"):
        module.MainPersonalExactCasControllerCompositionJournal._path(
            object.__new__(module.MainPersonalExactCasControllerCompositionJournal), "../escape"
        )

    def qualified(path: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=path.resolve(), qualified=False, reason="unqualified", mount_id=1, device="8:0"
        )

    monkeypatch.setattr(module, "require_durable_backend", qualified)
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)
    with pytest.raises(ValueError):
        module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "unqualified")


def test_bind_loads_and_revalidates_the_complete_durable_dependency_closure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Drive bind through every typed dependency before the operation root gate."""

    def qualified(root: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=root.resolve(), qualified=True, reason="test-qualified", mount_id=1, device="8:0"
        )

    monkeypatch.setattr(module, "require_durable_backend", qualified)
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "composition")
    source, reader, source_operation = _configured_reader(tmp_path / "source")
    evidence = reader.read(source_operation)
    assert evidence.accepted and evidence.evidence_ref is not None
    source_ref = evidence.evidence_ref
    plan_result = source.read_plan(source_operation)
    package_result = source.read_source_package(source_operation)
    composition_result = source.read_composition(source_operation)
    proof_result = source.read_composition_proof(source_operation)
    lease_result = source.read_lease_evidence_record(source_operation)
    assert plan_result and package_result and composition_result and proof_result and lease_result
    _plan, _plan_ref = plan_result
    _package, _package_ref = package_result
    _composition, _composition_ref = composition_result
    _proof, _proof_ref = proof_result
    lease, _lease_ref = lease_result

    bundle = _bundle()
    bundle_payload = {
        item.name: getattr(bundle, item.name)
        for item in fields(bundle)
        if item.name != "bundle_digest"
    }
    bundle_payload["main_commit"] = source_ref.base_commit
    bundle_payload["repository_digest"] = source._composition_repository_digest
    bundle = type(bundle)(**bundle_payload, bundle_digest=canonical_digest(bundle_payload))
    identity_template = _identity_root()
    identity = MainPersonalExactCasHostedIdentityEvidenceRoot.build(
        writer_diagnostic_artifact=identity_template.writer_diagnostic_artifact,
        writer_provenance_artifact=identity_template.writer_provenance_artifact,
        observer_snapshot_artifact=identity_template.observer_snapshot_artifact,
        observer_provenance_artifact=identity_template.observer_provenance_artifact,
        observer_configuration_artifact=identity_template.observer_configuration_artifact,
        bundle_digest=bundle.bundle_digest,
    )
    activation = MainPersonalExactCasActivation.build(
        repository_digest=source._composition_repository_digest,
        source_operation_id=source_ref.operation_id,
        source_plan_digest=canonical_digest(_plan),
        source_plan_artifact=_plan_ref,
        source_package_digest=source_ref.package_digest,
        source_composition_digest=source_ref.composition_digest,
        base_commit=source_ref.base_commit,
        base_tree=source_ref.base_tree,
        candidate_commit=source_ref.candidate_commit,
        candidate_tree=source_ref.candidate_tree,
        candidate_ref=source_ref.candidate_ref,
        candidate_parents=(source_ref.base_commit,),
        protection_ruleset_digest=bundle.writer_protection_ruleset_digest,
        writer_app_id=bundle.writer_app_id,
        writer_installation_id=bundle.writer_installation_id,
        writer_identity="fixture-controller",
        activated_at=_TIME,
    )
    activation_ref = ArtifactRef(
        digest=canonical_digest(activation),
        size_bytes=len(canonical_bytes(activation)),
        role="main-personal-exact-cas-activation",
        media_type="application/vnd.avo.main-personal-exact-cas-activation+json",
        created_at=_TIME,
    )
    operation_id = personal_cas_operation_id(
        activation_digest=activation.activation_digest,
        repository_digest=activation.repository_digest,
        target_ref=activation.target_ref,
        source_operation_id=activation.source_operation_id,
        source_plan_digest=activation.source_plan_digest,
        source_composition_digest=activation.source_composition_digest,
        base_commit=activation.base_commit,
        base_tree=activation.base_tree,
        candidate_commit=activation.candidate_commit,
        candidate_tree=activation.candidate_tree,
        candidate_ref=activation.candidate_ref,
        candidate_parents=activation.candidate_parents,
        protection_ruleset_digest=activation.protection_ruleset_digest,
        writer_app_id=activation.writer_app_id,
        writer_installation_id=activation.writer_installation_id,
        writer_identity=activation.writer_identity,
        lease_identity=lease.owner,
        lease_digest=lease.lease_digest,
        lease_expires_at=lease.expires_at,
        claim_nonce="fixture-claim",
    )
    lease_values = lease.model_dump(mode="json", exclude={"lease_digest", "evidence_digest"})
    lease_values["operation_id"] = operation_id
    lease_digest = canonical_digest(lease_values)
    lease = type(lease).model_validate(
        lease_values
        | {
            "lease_digest": lease_digest,
            "evidence_digest": canonical_digest(lease_values | {"lease_digest": lease_digest}),
        }
    )
    lease_ref = ArtifactRef(
        digest=canonical_digest(lease),
        size_bytes=len(canonical_bytes(lease)),
        role="main-graduation-lease-evidence-record",
        media_type="application/vnd.avo.main-graduation-lease-evidence-record+json",
        created_at=_TIME,
    )

    def shell(expected: type[Any], **methods: Any) -> Any:
        value = object.__new__(expected)
        for name, method in methods.items():
            setattr(value, name, method)
        return value

    hosted = shell(
        module.MainPersonalExactCasHostedIdentityJournal, read=lambda: (bundle, identity)
    )
    personal = shell(
        module.MainPersonalExactCasJournal,
        read_activation=lambda: (activation, activation_ref),
    )
    source_shell = shell(
        module.MainGraduationJournal,
        read_lease_evidence_record=lambda _operation: (lease, lease_ref),
        read_plan=lambda _operation: plan_result,
        read_source_package=lambda _operation: package_result,
        read_composition=lambda _operation: composition_result,
        read_composition_proof=lambda _operation: proof_result,
    )
    # The source lease intentionally owns the operation identity while the
    # personal-CAS operation identity also commits the lease digest.  A test
    # fixture cannot solve that cryptographic fixed point without replacing a
    # production dependency; replace only the final model factory to exercise
    # all durable dependency admission and child publication inputs.
    replacement_root = _root()
    monkeypatch.setattr(
        module.MainPersonalExactCasControllerComposition,
        "build", classmethod(lambda _cls, **_values: replacement_root),
    )
    monkeypatch.setattr(journal, "_publish", lambda _operation, root: root)
    result = journal.bind(
            hosted_identity_journal=hosted,
            personal_journal=personal,
            source_journal=source_shell,
            operation_id=operation_id,
            lease_identity=lease.owner,
            lease_digest=lease_digest,
            lease_expires_at=lease.expires_at,
            claim_nonce="fixture-claim",
            policy_digest=_DIGEST,
            protocol_digest=_DIGEST,
    )
    assert result is replacement_root

    bad_bundle_values = {
        item.name: getattr(bundle, item.name)
        for item in fields(bundle)
        if item.name != "bundle_digest"
    }
    bad_bundle_values["main_commit"] = "e" * 40
    bad_bundle = type(bundle)(
        **bad_bundle_values, bundle_digest=canonical_digest(bad_bundle_values)
    )
    bad_identity = MainPersonalExactCasHostedIdentityEvidenceRoot.build(
        writer_diagnostic_artifact=identity.writer_diagnostic_artifact,
        writer_provenance_artifact=identity.writer_provenance_artifact,
        observer_snapshot_artifact=identity.observer_snapshot_artifact,
        observer_provenance_artifact=identity.observer_provenance_artifact,
        observer_configuration_artifact=identity.observer_configuration_artifact,
        bundle_digest=bad_bundle.bundle_digest,
    )
    hosted.read = lambda: (bad_bundle, bad_identity)
    with pytest.raises(module.MainPersonalExactCasControllerCompositionError):
        journal.bind(
            hosted_identity_journal=hosted,
            personal_journal=personal,
            source_journal=source_shell,
            operation_id=operation_id,
            lease_identity=lease.owner,
            lease_digest=lease_digest,
            lease_expires_at=lease.expires_at,
            claim_nonce="fixture-claim",
            policy_digest=_DIGEST,
            protocol_digest=_DIGEST,
        )
    hosted.read = lambda: (bundle, identity)
    with pytest.raises(module.MainPersonalExactCasControllerCompositionError):
        journal.bind(
            hosted_identity_journal=hosted,
            personal_journal=personal,
            source_journal=source_shell,
            operation_id=operation_id,
            lease_identity=lease.owner,
            lease_digest=lease_digest,
            lease_expires_at=lease.expires_at,
            claim_nonce="fixture-claim",
            policy_digest="malformed",
            protocol_digest=_DIGEST,
        )
    hosted.read = lambda: (_ for _ in ()).throw(RuntimeError("unexpected"))
    with pytest.raises(module.MainPersonalExactCasControllerCompositionError):
        journal.bind(
            hosted_identity_journal=hosted,
            personal_journal=personal,
            source_journal=source_shell,
            operation_id=operation_id,
            lease_identity=lease.owner,
            lease_digest=lease_digest,
            lease_expires_at=lease.expires_at,
            claim_nonce="fixture-claim",
            policy_digest=_DIGEST,
            protocol_digest=_DIGEST,
        )


def test_reopen_closure_rebuilds_all_children_and_rejects_raw_ref_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The persisted closure is content-bound, including the external raw package ref."""

    monkeypatch.setattr(module, "require_durable_backend", lambda root: DurableBackendQualification(
        root=root.resolve(), qualified=True, reason="test-qualified", mount_id=1, device="8:0"
    ))
    monkeypatch.setattr(module, "_fsync_directory", lambda _path: None)
    journal = module.MainPersonalExactCasControllerCompositionJournal(tmp_path / "composition")
    source, reader, source_operation = _configured_reader(tmp_path / "source")
    evidence = reader.read(source_operation)
    assert evidence.evidence_ref is not None
    source_ref = evidence.evidence_ref
    plan_result = source.read_plan(source_operation)
    package_result = source.read_source_package(source_operation)
    composition_result = source.read_composition(source_operation)
    proof_result = source.read_composition_proof(source_operation)
    lease_result = source.read_lease_evidence_record(source_operation)
    assert plan_result and package_result and composition_result and proof_result and lease_result
    plan, plan_ref = plan_result
    package, _package_ref = package_result
    composition, composition_ref = composition_result
    proof, proof_ref = proof_result
    lease, lease_ref = lease_result

    bundle_template = _bundle()
    bundle_values = {
        item.name: getattr(bundle_template, item.name)
        for item in fields(bundle_template)
        if item.name != "bundle_digest"
    }
    bundle_values["main_commit"] = source_ref.base_commit
    bundle_values["repository_digest"] = source._composition_repository_digest
    bundle = type(bundle_template)(
        **bundle_values, bundle_digest=canonical_digest(bundle_values)
    )
    identity_template = _identity_root()
    identity = MainPersonalExactCasHostedIdentityEvidenceRoot.build(
        writer_diagnostic_artifact=identity_template.writer_diagnostic_artifact,
        writer_provenance_artifact=identity_template.writer_provenance_artifact,
        observer_snapshot_artifact=identity_template.observer_snapshot_artifact,
        observer_provenance_artifact=identity_template.observer_provenance_artifact,
        observer_configuration_artifact=identity_template.observer_configuration_artifact,
        bundle_digest=bundle.bundle_digest,
    )
    identity_ref = journal._identity_ref(identity)
    activation = MainPersonalExactCasActivation.build(
        repository_digest=source._composition_repository_digest,
        source_operation_id=source_ref.operation_id,
        source_plan_digest=canonical_digest(plan),
        source_plan_artifact=plan_ref,
        source_package_digest=source_ref.package_digest,
        source_composition_digest=source_ref.composition_digest,
        base_commit=source_ref.base_commit,
        base_tree=source_ref.base_tree,
        candidate_commit=source_ref.candidate_commit,
        candidate_tree=source_ref.candidate_tree,
        candidate_ref=source_ref.candidate_ref,
        candidate_parents=(source_ref.base_commit,),
        protection_ruleset_digest=bundle.writer_protection_ruleset_digest,
        writer_app_id=bundle.writer_app_id,
        writer_installation_id=bundle.writer_installation_id,
        writer_identity="fixture-controller",
        activated_at=_TIME,
    )
    activation_ref = ArtifactRef(
        digest=canonical_digest(activation),
        size_bytes=len(canonical_bytes(activation)),
        role="main-personal-exact-cas-activation",
        media_type="application/vnd.avo.main-personal-exact-cas-activation+json",
        created_at=_TIME,
    )
    package_binding_ref = journal._record_reference(
        package,
        "main-graduation-source-package",
        "application/vnd.avo.main-graduation-source-package+json",
        _package_ref.created_at,
    )
    records: dict[str, bytes] = {
        identity_ref.digest: canonical_bytes(identity),
        activation_ref.digest: canonical_bytes(activation),
        plan_ref.digest: canonical_bytes(plan),
        package_binding_ref.digest: canonical_bytes(package),
        composition_ref.digest: canonical_bytes(composition),
        proof_ref.digest: canonical_bytes(proof),
        lease_ref.digest: canonical_bytes(lease),
    }
    monkeypatch.setattr(journal, "_child_bytes", lambda reference: records[reference.digest])
    root = SimpleNamespace(
        hosted_identity_root_artifact=identity_ref,
        hosted_identity_bundle_digest=identity.bundle_digest,
        activation_artifact=activation_ref,
        activation_digest=activation.activation_digest,
        source_operation_id=plan.operation_id,
        source_plan_digest=canonical_digest(plan),
        source_plan_artifact=plan_ref,
        source_package_digest=package.package_digest,
        source_package_artifact=package.package_artifact,
        source_package_binding_artifact=package_binding_ref,
        source_composition_digest=composition.composition_digest,
        source_composition_artifact=composition_ref,
        source_composition_proof_artifact=proof_ref,
        base_commit=composition.base_commit,
        base_tree=composition.base_tree,
        candidate_commit=composition.candidate_commit,
        candidate_tree=composition.candidate_tree,
        candidate_ref=composition.candidate_ref,
        candidate_parents=(composition.base_commit,),
        lease_identity=lease.owner,
        lease_digest=lease.lease_digest,
        lease_artifact=lease_ref,
        lease_expires_at=lease.expires_at,
    )
    journal._validate_child_closure(root)

    bad_records = dict(records)
    bad_records[identity_ref.digest] = b"not-the-identity"
    monkeypatch.setattr(journal, "_child_bytes", lambda reference: bad_records[reference.digest])
    with pytest.raises(ValueError, match="digest or size"):
        journal._validate_child_closure(root)
    canonical_identity = canonical_bytes(identity)
    noncanonical_identity = canonical_identity + b" "
    noncanonical_ref = identity_ref.model_copy(
        update={
            "digest": "sha256:" + hashlib.sha256(noncanonical_identity).hexdigest(),
            "size_bytes": len(noncanonical_identity),
        }
    )
    noncanonical_values = vars(root).copy()
    noncanonical_values["hosted_identity_root_artifact"] = noncanonical_ref
    noncanonical_root = SimpleNamespace(**noncanonical_values)
    noncanonical_records = dict(records)
    noncanonical_records[noncanonical_ref.digest] = noncanonical_identity
    monkeypatch.setattr(
        journal, "_child_bytes", lambda reference: noncanonical_records[reference.digest]
    )
    with pytest.raises(ValueError, match="canonical"):
        journal._validate_child_closure(noncanonical_root)
    monkeypatch.setattr(journal, "_child_bytes", lambda reference: records[reference.digest])

    altered_raw_ref = package.package_artifact.model_copy(
        update={"size_bytes": package.package_artifact.size_bytes + 1}
    )
    root.source_package_artifact = altered_raw_ref
    with pytest.raises(ValueError, match="child closure"):
        journal._validate_child_closure(root)
