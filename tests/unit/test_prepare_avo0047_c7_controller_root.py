"""Focused tests for local C7 controller-root preparation."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.application.c7_controller_root_preparation import (
    C7ControllerRootPreparationError,
    WorkspaceSourceIdentity,
    prepare_controller_root,
)
from avo_correlate.domain.canonical import canonical_bytes

DIGEST = "sha256:" + "a" * 64
NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def _identity(_workspace: Path) -> WorkspaceSourceIdentity:
    return WorkspaceSourceIdentity("b" * 40, "c" * 40, DIGEST)


def _prepare(tmp_path: Path, **updates: Any):
    values: dict[str, Any] = {
        "workspace": tmp_path,
        "output_file": tmp_path / "controller-root.json",
        "operation_id": DIGEST,
        "repository_digest": DIGEST,
        "issuer_identity": "offline-operator",
        "protocol_digest": DIGEST,
        "configuration_digest": DIGEST,
        "policy_digest": DIGEST,
        "activation_digest": DIGEST,
        "authorized_at": NOW,
        "ttl_seconds": 300,
        "nonce": DIGEST,
        "observer": _identity,
    }
    values.update(updates)
    return prepare_controller_root(**values)


def test_builds_typed_root_with_independent_source_identity_and_raw_pin(
    tmp_path: Path,
) -> None:
    artifact = _prepare(tmp_path)

    assert artifact.root.source_commit == "b" * 40
    assert artifact.root.source_tree == "c" * 40
    assert artifact.root.source_tree_digest == DIGEST
    assert artifact.root.controller_authority_digest.startswith("sha256:")
    assert artifact.raw_digest == (
        "sha256:" + hashlib.sha256(artifact.path.read_bytes()).hexdigest()
    )
    assert artifact.path.read_bytes() == canonical_bytes(artifact.root.model_dump(mode="json"))
    assert artifact.root.expires_at == NOW + timedelta(seconds=300)

    replay = _prepare(tmp_path)
    assert replay.raw_digest == artifact.raw_digest
    assert replay.controller_authority_digest == artifact.controller_authority_digest


def test_rejects_unbounded_or_naive_window(tmp_path: Path) -> None:
    with pytest.raises(C7ControllerRootPreparationError, match="timezone-aware"):
        _prepare(tmp_path, authorized_at=datetime(2026, 9, 1, 12, 0))
    with pytest.raises(C7ControllerRootPreparationError, match="ttl_seconds"):
        _prepare(tmp_path, ttl_seconds=7201)


def test_rejects_conflicting_output_and_symlinked_output(tmp_path: Path) -> None:
    artifact = _prepare(tmp_path)
    artifact.path.write_bytes(b"different")
    with pytest.raises(C7ControllerRootPreparationError, match="conflicting"):
        _prepare(tmp_path)

    actual = tmp_path / "actual.json"
    actual.write_bytes(b"not-used")
    linked = tmp_path / "linked.json"
    try:
        linked.symlink_to(actual)
    except OSError:
        pytest.skip("symlink creation is unavailable on this Windows runner")
    with pytest.raises(C7ControllerRootPreparationError, match="symlink"):
        _prepare(tmp_path, output_file=linked)


def test_observer_is_required_to_supply_source_facts(tmp_path: Path) -> None:
    def bad_observer(_workspace: Path) -> WorkspaceSourceIdentity:
        return WorkspaceSourceIdentity("not-a-commit", "c" * 40, DIGEST)

    with pytest.raises(C7ControllerRootPreparationError, match="schema validation"):
        _prepare(tmp_path, observer=bad_observer)
