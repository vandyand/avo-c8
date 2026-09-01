# pyright: reportPrivateUsage=false
"""Adversarial checks for the independent C7 workspace identity boundary."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from avo_correlate.application.main_graduation_offline_drill_service import (
    PinnedC7AuthorityVerifier,
)
from avo_correlate.application.main_graduation_offline_identity import (
    FROZEN_OFFLINE_EXECUTION_ARGV,
    C7WorkspaceIdentity,
    C7WorkspaceIdentityError,
    C7WorkspaceIdentityVerifier,
)
from avo_correlate.application.main_graduation_offline_pytest_executor import (
    OfflinePytestExecutionError,
    _node_identity,
    _pytest_node_id,
)
from avo_correlate.contracts.main_graduation_offline_drill import (
    FROZEN_OFFLINE_EXECUTION_NODE_IDS,
    FROZEN_OFFLINE_EXECUTION_PARAMETER_IDS,
)


def _authority(**updates: Any) -> Any:
    nodes = tuple(
        SimpleNamespace(node_id=node_id, parameter_id=parameter_id)
        for node_id, parameter_id in zip(
            FROZEN_OFFLINE_EXECUTION_NODE_IDS,
            FROZEN_OFFLINE_EXECUTION_PARAMETER_IDS,
            strict=True,
        )
    )
    values: dict[str, Any] = {
        "argv": FROZEN_OFFLINE_EXECUTION_ARGV,
        "nodes": nodes,
        "source_commit": "a" * 40,
        "source_tree": "b" * 40,
        "source_tree_digest": "sha256:" + "c" * 64,
        "lockfile_digest": "sha256:" + "d" * 64,
        "interpreter_digest": "sha256:" + "e" * 64,
        "pytest_digest": "sha256:" + "f" * 64,
        "plugin_set_digest": "sha256:" + "0" * 64,
        "toolchain_digest": "sha256:" + "1" * 64,
    }
    values.update(updates)
    return SimpleNamespace(**values)


def _observed() -> C7WorkspaceIdentity:
    return C7WorkspaceIdentity(
        source_commit="a" * 40,
        source_tree="b" * 40,
        source_tree_digest="sha256:" + "c" * 64,
        lockfile_digest="sha256:" + "d" * 64,
        interpreter_digest="sha256:" + "e" * 64,
        pytest_digest="sha256:" + "f" * 64,
        plugin_set_digest="sha256:" + "0" * 64,
        toolchain_digest="sha256:" + "1" * 64,
    )


def test_identity_verifier_rejects_argv_drift_before_observing_workspace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = C7WorkspaceIdentityVerifier(Path.cwd())
    monkeypatch.setattr(verifier, "observe", lambda: pytest.fail("workspace was observed"))
    authority = _authority(argv=("uv", "run", "pytest", "-q"))
    with pytest.raises(C7WorkspaceIdentityError, match="argv"):
        verifier.verify(authority)


def test_identity_verifier_rejects_frozen_node_drift() -> None:
    verifier = C7WorkspaceIdentityVerifier(Path.cwd())
    authority = _authority(
        nodes=(SimpleNamespace(node_id=FROZEN_OFFLINE_EXECUTION_NODE_IDS[0], parameter_id="wrong"),)
    )
    with pytest.raises(C7WorkspaceIdentityError, match="nodes"):
        verifier.verify(authority)


def test_identity_verifier_rejects_dirty_worktree_before_toolchain_probe(
    tmp_path: Path,
) -> None:
    def runner(argv: list[str], **_kwargs: Any) -> Any:
        if argv[1] == "rev-parse":
            return _completed(str(tmp_path))
        if argv[1] == "status":
            return _completed("1 .M file.py")
        return _completed("")

    verifier = C7WorkspaceIdentityVerifier(tmp_path, command_runner=runner)
    with pytest.raises(C7WorkspaceIdentityError, match="dirty"):
        verifier.observe()


def test_identity_verifier_rejects_any_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = C7WorkspaceIdentityVerifier(Path.cwd())
    monkeypatch.setattr(verifier, "observe", lambda: _observed())
    authority = _authority(lockfile_digest="sha256:" + "9" * 64)
    with pytest.raises(C7WorkspaceIdentityError, match="lockfile_digest"):
        verifier.verify(authority)


def test_real_pytest_junit_shape_requires_exact_repository_module() -> None:
    frozen = FROZEN_OFFLINE_EXECUTION_NODE_IDS[0]
    testcase = ET.Element(
        "testcase",
        {
            "classname": f"tests.unit.{frozen.split('::', 1)[0][:-3]}",
            "name": frozen.split("::", 1)[1],
        },
    )
    assert _node_identity(testcase, frozen) == frozen
    assert _pytest_node_id(frozen).startswith("tests/unit/")
    testcase.set("classname", "tests.other." + frozen.split("::", 1)[0][:-3])
    with pytest.raises(OfflinePytestExecutionError, match="identity"):
        _node_identity(testcase, frozen)


def test_controller_and_artifact_pins_are_required_externally() -> None:
    with pytest.raises(ValueError, match="artifact digest"):
        PinnedC7AuthorityVerifier("sha256:" + "a" * 64)
    with pytest.raises(ValueError, match="controller authority pin"):
        PinnedC7AuthorityVerifier("sha256:" + "a" * 64, "sha256:" + "b" * 64)


def _completed(stdout: str) -> Any:
    from subprocess import CompletedProcess

    return CompletedProcess([], 0, stdout=stdout, stderr="")
