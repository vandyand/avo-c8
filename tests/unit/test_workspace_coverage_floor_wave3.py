"""Focused validation and recovery coverage for workspace security controls."""

from __future__ import annotations

import io
import os
import stat
import subprocess
import tarfile
import unicodedata
import zipfile
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal, Never, cast

import pytest
import rfc8785
from pydantic import BaseModel

import avo_correlate.application.main_graduation_activation as activation_module
import avo_correlate.application.main_graduation_activation_service as activation_service_module
import avo_correlate.domain.canonical as canonical_module
import avo_correlate.domain.workspace as workspace_module
from avo_correlate.application.main_graduation_activation import (
    LocalActivationCandidateArtifact,
    MainGraduationActivationPreparationError,
    prepare_local_main_graduation_activation_draft,
)
from avo_correlate.application.main_graduation_activation_service import (
    CONTROLLER_AUTHORITY_MEDIA_TYPE,
    CONTROLLER_AUTHORITY_ROLE,
    MainGraduationActivationService,
    MainGraduationActivationServiceError,
)
from avo_correlate.contracts.base import ArtifactRef, StrictModel
from avo_correlate.contracts.experiment import WorkspaceSpec
from avo_correlate.domain.canonical import CanonicalizationError
from avo_correlate.domain.workspace import (
    UnsafeWorkspaceError,
    _check_archive_size,  # pyright: ignore[reportPrivateUsage]
    _permitted,  # pyright: ignore[reportPrivateUsage]
    _safe_target,  # pyright: ignore[reportPrivateUsage]
    _within,  # pyright: ignore[reportPrivateUsage]
    create_vcs_free_binary_patch,
    safe_extract_tar,
    safe_extract_zip,
    validate_workspace,
)
from tests.conftest import DIGEST_A
from tests.unit.test_main_graduation_activation_service import (
    _service,  # pyright: ignore[reportPrivateUsage]
)


def _spec(**updates: Any) -> WorkspaceSpec:
    values: dict[str, Any] = {
        "source_uri": "https://example.invalid/source.git",
        "source_revision": "revision",
        "source_tree_digest": DIGEST_A,
        "allowed_paths": ["src", "manifest.txt"],
        "forbidden_paths": [],
        "required_paths": ["manifest.txt"],
        "max_file_bytes": 100,
        "max_tree_bytes": 500,
        "submodules": "deny",
        "symlinks": "deny",
    }
    values.update(updates)
    return WorkspaceSpec(**values)


def _workspace(root: Path, *, manifest: str = "ok") -> None:
    (root / "src").mkdir(parents=True)
    (root / "src" / "module.py").write_text("value = 1\n", encoding="utf-8")
    (root / "manifest.txt").write_text(manifest, encoding="utf-8")


def test_vcs_free_patch_success_and_binary_change(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    metadata = tmp_path / "metadata"
    baseline.mkdir()
    candidate.mkdir()
    (baseline / "same.txt").write_text("same\n", encoding="utf-8")
    (candidate / "same.txt").write_text("changed\n", encoding="utf-8")

    patch = create_vcs_free_binary_patch(baseline, candidate, git_metadata=metadata)

    assert patch.startswith(b"diff --git")
    assert metadata.is_dir()
    assert not (baseline / ".git").exists()
    assert not (candidate / ".git").exists()


@pytest.mark.parametrize("case", ["metadata_inside", "nested_git", "metadata_file"])
def test_vcs_free_patch_rejects_unsafe_metadata_targets(tmp_path: Path, case: str) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    if case == "metadata_inside":
        metadata = baseline / "metadata"
    elif case == "nested_git":
        metadata = tmp_path / "metadata"
        (candidate / ".git").mkdir()
    else:
        metadata = tmp_path / "metadata"
        metadata.write_text("not a directory", encoding="utf-8")

    with pytest.raises(UnsafeWorkspaceError, match=r"outside|VCS-free|empty directory"):
        create_vcs_free_binary_patch(baseline, candidate, git_metadata=metadata)


@pytest.mark.parametrize("init_code", [1])
def test_vcs_free_patch_reports_git_initialization_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, init_code: int
) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()

    def failed_init(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        return subprocess.CompletedProcess([], init_code, b"", b"init failed")

    monkeypatch.setattr(workspace_module.subprocess, "run", failed_init)
    with pytest.raises(UnsafeWorkspaceError, match="could not initialize"):
        create_vcs_free_binary_patch(baseline, candidate, git_metadata=tmp_path / "metadata")


def test_vcs_free_patch_reports_external_git_operation_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    calls = 0

    def failed_git(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        del args, kwargs
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess([], 0, b"", b"")
        return subprocess.CompletedProcess([], 2, b"", b"diff failed")

    monkeypatch.setattr(workspace_module.subprocess, "run", failed_git)
    with pytest.raises(UnsafeWorkspaceError, match="external Git metadata operation"):
        create_vcs_free_binary_patch(baseline, candidate, git_metadata=tmp_path / "metadata")


def test_validate_workspace_accepts_nested_allowed_files_and_returns_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _workspace(tmp_path)
    (tmp_path / "src" / "nested").mkdir()
    (tmp_path / "src" / "nested" / "child.py").write_text("child\n", encoding="utf-8")
    expected = "sha256:" + "b" * 64

    def digest_stub(*_args: object, **_kwargs: object) -> str:
        return expected

    monkeypatch.setattr(workspace_module, "source_tree_digest", digest_stub)

    assert validate_workspace(tmp_path, _spec()) == expected


@pytest.mark.parametrize(
    ("filename", "message"),
    [
        ("outside.txt", "outside the workspace"),
        ("large.bin", "maximum size"),
    ],
)
def test_validate_workspace_rejects_manifest_and_file_size_violations(
    tmp_path: Path, filename: str, message: str
) -> None:
    _workspace(tmp_path)
    if filename == "outside.txt":
        (tmp_path / filename).write_text("outside", encoding="utf-8")
    else:
        (tmp_path / "src" / filename).write_bytes(b"x" * 101)

    with pytest.raises(UnsafeWorkspaceError, match=message):
        validate_workspace(tmp_path, _spec())


def test_validate_workspace_rejects_tree_limit_and_missing_required_path(tmp_path: Path) -> None:
    _workspace(tmp_path, manifest="x" * 10)
    (tmp_path / "src" / "second.py").write_bytes(b"y" * 10)
    with pytest.raises(UnsafeWorkspaceError, match="tree size"):
        validate_workspace(tmp_path, _spec(max_file_bytes=15, max_tree_bytes=15))

    (tmp_path / "manifest.txt").unlink()
    with pytest.raises(UnsafeWorkspaceError, match="required path"):
        validate_workspace(tmp_path, _spec(required_paths=["manifest.txt"]))


def test_validate_workspace_rejects_nested_git_and_hardlinks(tmp_path: Path) -> None:
    _workspace(tmp_path)
    (tmp_path / "src" / ".git").mkdir()
    with pytest.raises(UnsafeWorkspaceError, match="nested Git"):
        validate_workspace(tmp_path, _spec())

    (tmp_path / "src" / ".git").rmdir()
    try:
        os.link(tmp_path / "manifest.txt", tmp_path / "src" / "hardlink.txt")
    except (OSError, NotImplementedError):
        pytest.skip("hard links are unavailable")
    with pytest.raises(UnsafeWorkspaceError, match="hardlinked"):
        validate_workspace(tmp_path, _spec(allowed_paths=["src", "manifest.txt"]))


def test_validate_workspace_rejects_non_nfc_and_case_collisions(tmp_path: Path) -> None:
    _workspace(tmp_path)
    decomposed = "e\u0301.txt"
    assert unicodedata.normalize("NFC", decomposed) != decomposed
    (tmp_path / decomposed).write_text("bad", encoding="utf-8")
    with pytest.raises(UnsafeWorkspaceError, match="NFC"):
        validate_workspace(tmp_path, _spec())

    (tmp_path / decomposed).unlink()
    (tmp_path / "src" / "Case.txt").write_text("one", encoding="utf-8")
    if os.path.normcase(str(tmp_path / "src" / "Case.txt")) == os.path.normcase(
        str(tmp_path / "src" / "case.txt")
    ):
        pytest.skip("case-sensitive collision fixture unavailable")
    (tmp_path / "src" / "case.txt").write_text("two", encoding="utf-8")
    with pytest.raises(UnsafeWorkspaceError, match="collision"):
        validate_workspace(tmp_path, _spec(allowed_paths=["src", "manifest.txt"]))


def test_validate_workspace_symlink_policy_and_internal_target(tmp_path: Path) -> None:
    _workspace(tmp_path)
    outside = tmp_path.parent / "outside-workspace.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        os.symlink(outside, tmp_path / "src" / "escape.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are unavailable")
    with pytest.raises(UnsafeWorkspaceError, match="symlink is forbidden"):
        validate_workspace(tmp_path, _spec())
    (tmp_path / "src" / "escape.txt").unlink()

    os.symlink(tmp_path / "manifest.txt", tmp_path / "src" / "internal.txt")
    with pytest.raises(UnsafeWorkspaceError, match="symlink is forbidden"):
        validate_workspace(tmp_path, _spec())
    assert validate_workspace(
        tmp_path,
        _spec(symlinks="internal_only", allowed_paths=["src", "manifest.txt"]),
    )


def test_archive_extractors_accept_directories_and_regular_files(tmp_path: Path) -> None:
    zip_archive = tmp_path / "valid.zip"
    with zipfile.ZipFile(zip_archive, "w") as archive:
        archive.writestr("nested/", "")
        archive.writestr("nested/value.txt", "zip value")
    zip_destination = tmp_path / "zip-output"
    zip_destination.mkdir()
    safe_extract_zip(zip_archive, zip_destination, max_file_bytes=100, max_tree_bytes=200)
    assert (zip_destination / "nested/value.txt").read_text(encoding="utf-8") == "zip value"

    tar_archive = tmp_path / "valid.tar"
    with tarfile.open(tar_archive, "w") as archive:
        directory = tarfile.TarInfo("nested/")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        member = tarfile.TarInfo("nested/value.txt")
        payload = b"tar value"
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    tar_destination = tmp_path / "tar-output"
    tar_destination.mkdir()
    safe_extract_tar(tar_archive, tar_destination, max_file_bytes=100, max_tree_bytes=200)
    assert (tar_destination / "nested/value.txt").read_bytes() == b"tar value"


@pytest.mark.parametrize("value", ["", "../escape.txt", "folder//file.txt", "C:/drive.txt"])
def test_archive_path_and_target_helpers_fail_closed(value: str, tmp_path: Path) -> None:
    with pytest.raises(UnsafeWorkspaceError, match="unsafe archive path"):
        workspace_module._archive_path(value)  # pyright: ignore[reportPrivateUsage]
    if value == "":
        with pytest.raises(UnsafeWorkspaceError, match="escapes"):
            _safe_target(tmp_path, "../escape.txt")  # pyright: ignore[reportPrivateUsage]


def test_archive_helpers_enforce_per_file_and_tree_limits(tmp_path: Path) -> None:
    with pytest.raises(UnsafeWorkspaceError, match="entry exceeds"):
        _check_archive_size(-1, 0, 100, 100)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(UnsafeWorkspaceError, match="entry exceeds"):
        _check_archive_size(101, 0, 100, 200)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(UnsafeWorkspaceError, match="tree size"):
        _check_archive_size(60, 50, 100, 100)  # pyright: ignore[reportPrivateUsage]
    assert _check_archive_size(10, 20, 100, 100) == 30  # pyright: ignore[reportPrivateUsage]
    assert _permitted("src/file.py", ["src"], [])  # pyright: ignore[reportPrivateUsage]
    assert not _permitted("src/file.py", ["src"], ["src/file.py"])  # pyright: ignore[reportPrivateUsage]
    assert not _permitted("src/file.py", ["tests"], [])  # pyright: ignore[reportPrivateUsage]
    assert _within(("src", "file.py"), ("src",))  # pyright: ignore[reportPrivateUsage]
    assert not _within(("src",), ("src", "file.py"))  # pyright: ignore[reportPrivateUsage]


def test_zip_and_tar_extractors_reject_special_and_unsupported_members(tmp_path: Path) -> None:
    archive = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as target:
        target.writestr(info, "target")
    destination = tmp_path / "zip-output"
    destination.mkdir()
    with pytest.raises(UnsafeWorkspaceError, match="archive symlink"):
        safe_extract_zip(archive, destination, max_file_bytes=100, max_tree_bytes=100)

    tar_archive = tmp_path / "device.tar"
    with tarfile.open(tar_archive, "w") as target:
        member = tarfile.TarInfo("device")
        member.type = tarfile.CHRTYPE
        target.addfile(member)
    tar_destination = tmp_path / "tar-output"
    tar_destination.mkdir()
    with pytest.raises(UnsafeWorkspaceError, match="special entry"):
        safe_extract_tar(tar_archive, tar_destination, max_file_bytes=100, max_tree_bytes=100)

    fifo_archive = tmp_path / "fifo.tar"
    with tarfile.open(fifo_archive, "w") as target:
        member = tarfile.TarInfo("fifo")
        member.type = tarfile.FIFOTYPE
        target.addfile(member)
    with pytest.raises(UnsafeWorkspaceError, match="special entry"):
        safe_extract_tar(fifo_archive, tar_destination, max_file_bytes=100, max_tree_bytes=100)


def test_tar_extractor_rejects_unknown_member_and_unreadable_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "output"
    destination.mkdir()

    class Unsupported:
        name = "unknown"

        def issym(self) -> bool:
            return False

        def islnk(self) -> bool:
            return False

        def isdev(self) -> bool:
            return False

        def isfifo(self) -> bool:
            return False

        def isdir(self) -> bool:
            return False

        def isfile(self) -> bool:
            return False

    class OpenTar:
        def __enter__(self) -> OpenTar:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def __iter__(self) -> Any:
            return iter((Unsupported(),))

    def open_unsupported(*_args: object, **_kwargs: object) -> OpenTar:
        return OpenTar()

    monkeypatch.setattr(workspace_module.tarfile, "open", open_unsupported)
    with pytest.raises(UnsafeWorkspaceError, match="unsupported archive"):
        safe_extract_tar(
            tmp_path / "unsupported.tar", destination, max_file_bytes=100, max_tree_bytes=100
        )

    monkeypatch.undo()
    regular = tmp_path / "regular.tar"
    with tarfile.open(regular, "w") as target:
        member = tarfile.TarInfo("value")
        member.size = 1
        target.addfile(member, io.BytesIO(b"x"))
    original_extractfile = tarfile.TarFile.extractfile

    def unreadable(_self: tarfile.TarFile, _member: tarfile.TarInfo) -> None:
        return None

    monkeypatch.setattr(tarfile.TarFile, "extractfile", unreadable)
    with pytest.raises(UnsafeWorkspaceError, match="cannot be read"):
        safe_extract_tar(regular, destination, max_file_bytes=100, max_tree_bytes=100)
    monkeypatch.setattr(tarfile.TarFile, "extractfile", original_extractfile)


def _candidate(
    role: Literal[
        "controller-authority-candidate",
        "c8-capability-evidence-candidate",
        "hosted-rollback-proof-candidate",
    ],
    marker: str = "a",
) -> LocalActivationCandidateArtifact:
    return LocalActivationCandidateArtifact(
        role=role,
        artifact_digest="sha256:" + marker * 64,
        size_bytes=1,
        media_type="application/json",
    )


def _candidates() -> tuple[LocalActivationCandidateArtifact, ...]:
    return (
        _candidate("controller-authority-candidate", "a"),
        _candidate("c8-capability-evidence-candidate", "b"),
        _candidate("hosted-rollback-proof-candidate", "c"),
    )


def test_local_activation_preparation_rejects_bad_input_boundaries(tmp_path: Path) -> None:
    with pytest.raises(MainGraduationActivationPreparationError, match="output_file"):
        prepare_local_main_graduation_activation_draft(
            "draft.json",  # pyright: ignore[reportArgumentType]
            candidate_artifacts=_candidates(),  # type: ignore[arg-type]
        )
    with pytest.raises(MainGraduationActivationPreparationError, match="exactly three"):
        prepare_local_main_graduation_activation_draft(
            tmp_path / "draft.json", candidate_artifacts=_candidates()[:2]
        )
    with pytest.raises(MainGraduationActivationPreparationError, match="exact"):
        prepare_local_main_graduation_activation_draft(
            tmp_path / "draft.json",
            candidate_artifacts=(*_candidates()[:2], object()),  # type: ignore[arg-type]
        )


def test_local_activation_write_once_handles_publish_errors_and_races(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(MainGraduationActivationPreparationError, match="size bound"):
        activation_module._write_create_once(  # pyright: ignore[reportPrivateUsage]
            tmp_path / "draft.json", b"x" * (activation_module.MAX_LOCAL_DRAFT_BYTES + 1)
        )
    output_dir = tmp_path / "output-dir"
    output_dir.mkdir()
    with pytest.raises(MainGraduationActivationPreparationError, match="regular file"):
        activation_module._write_create_once(output_dir, b"payload")  # pyright: ignore[reportPrivateUsage]

    real_stat = activation_module.os.stat

    def fail_stat(*_args: Any, **_kwargs: Any) -> Never:
        raise OSError("stat failed")

    monkeypatch.setattr(
        activation_module.os,
        "stat",
        fail_stat,
    )
    with pytest.raises(MainGraduationActivationPreparationError, match="cannot be inspected"):
        activation_module._safe_existing_path(tmp_path, "test")  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(activation_module.os, "stat", real_stat)

    path = tmp_path / "publish-error.json"

    def fail_link(*_args: Any, **_kwargs: Any) -> Never:
        raise OSError("link failed")

    monkeypatch.setattr(
        activation_module.os,
        "link",
        fail_link,
    )
    with pytest.raises(MainGraduationActivationPreparationError, match="published"):
        activation_module._write_create_once(path, b"payload")  # pyright: ignore[reportPrivateUsage]

    winner = tmp_path / "race.json"
    original_link = activation_module.os.link

    def same_winner(source: Path, target: Path) -> None:
        target.write_bytes(source.read_bytes())
        raise FileExistsError

    monkeypatch.setattr(activation_module.os, "link", same_winner)
    assert activation_module._write_create_once(  # pyright: ignore[reportPrivateUsage]
        winner, b"payload"
    ) == activation_module._raw_digest(b"payload")  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(activation_module.os, "link", original_link)

    conflict = tmp_path / "conflict-race.json"

    def different_winner(source: Path, target: Path) -> None:
        del source
        target.write_bytes(b"different")
        raise FileExistsError

    monkeypatch.setattr(activation_module.os, "link", different_winner)
    with pytest.raises(MainGraduationActivationPreparationError, match="conflicting"):
        activation_module._write_create_once(conflict, b"payload")  # pyright: ignore[reportPrivateUsage]


def test_local_activation_path_reparse_guard_and_candidate_revalidation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class ExistingPath:
        parent = None

        def __init__(self, _value: object) -> None:
            self.parent = self

        def exists(self) -> bool:
            return True

        def is_symlink(self) -> bool:
            return False

    class Attributes:
        st_file_attributes = 0x400

    monkeypatch.setattr(activation_module, "Path", ExistingPath)

    def reparse_stat(*_args: Any, **_kwargs: Any) -> Attributes:
        return Attributes()

    monkeypatch.setattr(activation_module.os, "stat", reparse_stat)
    with pytest.raises(MainGraduationActivationPreparationError, match="reparse"):
        activation_module._safe_existing_path(tmp_path, "test")  # pyright: ignore[reportPrivateUsage]

    malformed = LocalActivationCandidateArtifact.model_construct(
        role="controller-authority-candidate",
        artifact_digest="not-a-digest",
        size_bytes=1,
        media_type="application/json",
    )
    with pytest.raises(MainGraduationActivationPreparationError, match="contract validation"):
        activation_module._revalidate_candidate(malformed)  # pyright: ignore[reportPrivateUsage]


def test_activation_service_constructor_and_private_load_boundaries() -> None:
    service, authority_ref, capability_ref, proof_ref = _service()
    assert service._read_durable_activation() is None  # pyright: ignore[reportPrivateUsage]
    assert service.activate(authority_ref, capability_ref, proof_ref).activation_digest.startswith(
        "sha256:"
    )

    with pytest.raises(ValueError, match="freshness_window"):
        MainGraduationActivationService(
            trust_root=service._trust_root,  # pyright: ignore[reportPrivateUsage]
            clock=service._clock,  # pyright: ignore[reportPrivateUsage]
            scheduler_watermark_reader=service._watermark_reader,  # pyright: ignore[reportPrivateUsage]
            ledger_service=service._ledger,  # pyright: ignore[reportPrivateUsage]
            freshness_window=timedelta(0),
        )

    with pytest.raises(MainGraduationActivationServiceError, match="exactly three"):
        service.activate(object(), capability_ref, proof_ref)  # type: ignore[arg-type]

    with pytest.raises(MainGraduationActivationServiceError, match="invalid"):
        activation_service_module._validate_ref(  # pyright: ignore[reportPrivateUsage]
            authority_ref.model_copy(update={"size_bytes": 0}),
            CONTROLLER_AUTHORITY_ROLE,
            CONTROLLER_AUTHORITY_MEDIA_TYPE,
        )
    with pytest.raises(MainGraduationActivationServiceError, match="lacks"):
        activation_service_module._load(  # pyright: ignore[reportPrivateUsage]
            cast(Any, object()),
            authority_ref,
            role=CONTROLLER_AUTHORITY_ROLE,
            media_type=CONTROLLER_AUTHORITY_MEDIA_TYPE,
            model=StrictModel,
            method_name="missing_loader",
        )


def test_activation_service_loader_and_watermark_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, authority_ref, _, _ = _service()

    class RaisingRoot:
        def load_verified_controller_authority(self, _reference: ArtifactRef) -> Any:
            raise RuntimeError("rejected")

    with pytest.raises(MainGraduationActivationServiceError, match="rejected"):
        activation_service_module._load(  # pyright: ignore[reportPrivateUsage]
            cast(Any, RaisingRoot()),
            authority_ref,
            role=CONTROLLER_AUTHORITY_ROLE,
            media_type=CONTROLLER_AUTHORITY_MEDIA_TYPE,
            model=cast(type[StrictModel], type(service._trust_root)),  # pyright: ignore[reportPrivateUsage]
            method_name="load_verified_controller_authority",
        )

    class WrongTypeRoot:
        def load_verified_controller_authority(self, _reference: ArtifactRef) -> StrictModel:
            return StrictModel()

    with pytest.raises(MainGraduationActivationServiceError, match="untyped"):
        activation_service_module._load(  # pyright: ignore[reportPrivateUsage]
            cast(Any, WrongTypeRoot()),
            authority_ref,
            role=CONTROLLER_AUTHORITY_ROLE,
            media_type=CONTROLLER_AUTHORITY_MEDIA_TYPE,
            model=cast(type[StrictModel], type(service._trust_root)),  # pyright: ignore[reportPrivateUsage]
            method_name="load_verified_controller_authority",
        )

    with pytest.raises(MainGraduationActivationServiceError, match="unavailable"):
        activation_service_module._watermark(object())  # pyright: ignore[reportPrivateUsage, reportArgumentType]

    class RaisingReader:
        def read_scheduler_sequence_watermark(self) -> Never:
            raise RuntimeError

    with pytest.raises(MainGraduationActivationServiceError, match="could not be read"):
        activation_service_module._watermark(  # pyright: ignore[reportPrivateUsage]
            RaisingReader()  # pyright: ignore[reportArgumentType]
        )

    class ValueReader:
        def __init__(self, value: object) -> None:
            self.value = value

        def read_scheduler_sequence_watermark(self) -> object:
            return self.value

    for value in (True, -1, "10"):
        reader = ValueReader(value)
        with pytest.raises(MainGraduationActivationServiceError, match="invalid"):
            activation_service_module._watermark(reader)  # pyright: ignore[reportPrivateUsage, reportArgumentType]

    class ZeroReader:
        def read_scheduler_sequence_watermark(self) -> int:
            return 0

    assert (
        activation_service_module._watermark(  # pyright: ignore[reportPrivateUsage]
            ZeroReader()
        )
        == 0
    )


class _DuplicateKeyMapping(Mapping[str, object]):
    def __iter__(self):
        return iter(("key", "key"))

    def __len__(self) -> int:
        return 2

    def __getitem__(self, key: str) -> object:
        del key
        return 1


class _CanonicalModel(BaseModel):
    value: int


def test_canonical_normalization_rejects_unsupported_and_duplicate_values() -> None:
    assert canonical_module._normalize(_CanonicalModel(value=3)) == {"value": 3}  # pyright: ignore[reportPrivateUsage]
    assert canonical_module._normalize((1, True, None)) == [1, True, None]  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(CanonicalizationError, match="keys"):
        canonical_module.canonical_bytes({1: "value"})
    with pytest.raises(CanonicalizationError, match="duplicate"):
        canonical_module.canonical_bytes(_DuplicateKeyMapping())
    with pytest.raises(CanonicalizationError, match="unsupported"):
        canonical_module.canonical_bytes(object())
    with pytest.raises(CanonicalizationError, match="unsupported"):
        canonical_module.canonical_bytes(b"bytes")


@pytest.mark.parametrize("error_type", [rfc8785.CanonicalizationError, rfc8785.FloatDomainError])
def test_canonical_bytes_wraps_provider_errors(
    monkeypatch: pytest.MonkeyPatch, error_type: type[Exception]
) -> None:
    def fail(_value: object) -> bytes:
        raise error_type("provider failure")

    monkeypatch.setattr(canonical_module.rfc8785, "dumps", fail)
    with pytest.raises(CanonicalizationError, match="provider failure"):
        canonical_module.canonical_bytes({"value": 1})


def test_canonical_file_and_source_tree_digests_cover_empty_and_nested_trees(
    tmp_path: Path,
) -> None:
    empty = canonical_module.source_tree_digest(tmp_path)
    data = tmp_path / "nested"
    data.mkdir()
    payload = data / "value.bin"
    payload.write_bytes(b"abcdef")
    assert canonical_module.file_digest(payload, chunk_size=2).startswith("sha256:")
    assert canonical_module.source_tree_digest(tmp_path) != empty


def test_canonical_normalization_rejects_non_nfc_strings() -> None:
    with pytest.raises(CanonicalizationError, match="NFC-normalized"):
        canonical_module.canonical_bytes("e\N{COMBINING ACUTE ACCENT}")


def test_source_tree_digest_records_only_internal_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("trusted\n", encoding="utf-8")
    internal = tmp_path / "internal-link"
    try:
        internal.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable")

    internal_digest = canonical_module.source_tree_digest(tmp_path, symlinks="internal_only")
    assert internal_digest.startswith("sha256:")

    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    escaping = tmp_path / "escaping-link"
    escaping.symlink_to(outside)
    with pytest.raises(CanonicalizationError, match="escapes tree"):
        canonical_module.source_tree_digest(tmp_path, symlinks="internal_only")


def test_source_tree_digest_rejects_collisions_and_special_files(tmp_path: Path) -> None:
    upper = tmp_path / "Case.txt"
    lower = tmp_path / "case.txt"
    upper.write_text("upper", encoding="utf-8")
    lower.write_text("lower", encoding="utf-8")
    if len(list(tmp_path.iterdir())) == 2:
        with pytest.raises(CanonicalizationError, match="collision"):
            canonical_module.source_tree_digest(tmp_path)
    else:
        pytest.skip("case-sensitive collision fixture unavailable")

    upper.unlink()
    lower.unlink()
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO fixtures are unavailable")
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)  # pyright: ignore[reportUnknownMemberType, reportAttributeAccessIssue]
    with pytest.raises(CanonicalizationError, match="unsupported file type"):
        canonical_module.source_tree_digest(tmp_path)
