"""Focused tests for the local-only C7 authority preparer."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.application.main_graduation_offline_identity import (
    C7WorkspaceIdentity,
)
from avo_correlate.domain.canonical import canonical_bytes
from scripts.prepare_avo0047_c7_authority import (
    C7AuthorityPreparationError,
    prepare_authority,
)

D = "sha256:" + "a" * 64
NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


class _Verifier:
    def __init__(self, _workspace: Path) -> None:
        self.observations = 0
        self.verifications = 0

    def observe(self) -> C7WorkspaceIdentity:
        self.observations += 1
        return C7WorkspaceIdentity(
            source_commit="b" * 40,
            source_tree="c" * 40,
            source_tree_digest=D,
            lockfile_digest=D,
            interpreter_digest=D,
            pytest_digest=D,
            plugin_set_digest=D,
            toolchain_digest=D,
            environment_identity_digest=D,
        )

    def verify(self, _authority: Any) -> None:
        self.verifications += 1


def _root(path: Path, value: dict[str, Any] | None = None) -> str:
    path.write_bytes(canonical_bytes(value or {"controller": "c7", "version": 1}))
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _prepare(tmp_path: Path, **updates: Any) -> tuple[Any, _Verifier, Path]:
    root = tmp_path / "controller-root.json"
    root_digest = (
        _root(root)
        if not root.exists()
        else "sha256:" + hashlib.sha256(root.read_bytes()).hexdigest()
    )
    verifier: _Verifier | None = None

    def factory(workspace: Path) -> _Verifier:
        nonlocal verifier
        verifier = _Verifier(workspace)
        return verifier

    values: dict[str, Any] = {
        "workspace": tmp_path / "workspace",
        "controller_root_file": root,
        "output_file": tmp_path / "authority.json",
        "expected_controller_root_artifact_digest": root_digest,
        "controller_authority_digest": D,
        "controller_authority_ref": "refs/avo/c7-controller",
        "operation_id": D,
        "issuer_identity": "offline-controller",
        "repository_digest": D,
        "protocol_digest": D,
        "configuration_digest": D,
        "policy_digest": D,
        "activation_digest": D,
        "normalized_report_schema_digest": D,
        "authorized_at": NOW,
        "ttl_seconds": 300,
        "verifier_factory": factory,
    }
    values.update(updates)
    return prepare_authority(**values), verifier, root


def test_preparer_builds_exact_47_nodes_and_canonical_create_once_draft(
    tmp_path: Path,
) -> None:
    draft, verifier, _root_file = _prepare(tmp_path)
    assert len(draft.authority.nodes) == 47
    assert draft.authority.authority_digest.startswith("sha256:")
    assert draft.artifact_digest.startswith("sha256:")
    assert draft.artifact_digest != draft.semantic_digest
    assert draft.artifact_path.read_bytes() == canonical_bytes(
        draft.authority.model_dump(mode="json")
    )
    assert verifier is not None
    assert verifier.observations == 1
    assert verifier.verifications == 1

    replay, _verifier, _root_file = _prepare(tmp_path)
    assert replay.artifact_digest == draft.artifact_digest
    assert replay.semantic_digest == draft.semantic_digest


def test_preparer_rejects_root_digest_duplicates_and_noncanonical_bytes(tmp_path: Path) -> None:
    root = tmp_path / "controller-root.json"
    expected = _root(root)
    with pytest.raises(C7AuthorityPreparationError, match="digest mismatch"):
        _prepare(tmp_path, expected_controller_root_artifact_digest=D)

    root.write_bytes(b'{"controller":"c7","controller":"other"}')
    with pytest.raises(C7AuthorityPreparationError, match="duplicate"):
        _prepare(tmp_path)

    root.write_bytes(b'{ "controller": "c7", "version": 1 }')
    with pytest.raises(C7AuthorityPreparationError, match="canonical"):
        _prepare(tmp_path, expected_controller_root_artifact_digest=expected)


def test_preparer_rejects_ttl_and_conflicting_existing_draft(tmp_path: Path) -> None:
    with pytest.raises(C7AuthorityPreparationError, match="ttl_seconds"):
        _prepare(tmp_path, ttl_seconds=301)
    with pytest.raises(C7AuthorityPreparationError, match="ttl_seconds"):
        _prepare(tmp_path, ttl_seconds=0)

    draft, _verifier, _root_file = _prepare(tmp_path)
    draft.artifact_path.write_bytes(b"tampered")
    with pytest.raises(C7AuthorityPreparationError, match="conflicting"):
        _prepare(tmp_path)


def test_preparer_rejects_symlinked_controller_root(tmp_path: Path) -> None:
    actual = tmp_path / "actual-root.json"
    digest = _root(actual)
    linked = tmp_path / "controller-root.json"
    try:
        linked.symlink_to(actual)
    except OSError:
        pytest.skip("symlink creation is unavailable on this Windows runner")
    with pytest.raises(C7AuthorityPreparationError, match="regular file"):
        _prepare(
            tmp_path,
            controller_root_file=linked,
            expected_controller_root_artifact_digest=digest,
        )
