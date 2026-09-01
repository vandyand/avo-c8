"""Offline inverse-composition boundary tests for C5."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from avo_correlate.adapters.git.main_composition import MainBaseSnapshot
from avo_correlate.adapters.git.main_rollback_composition import (
    MainRollbackCompositionAdapter,
    MainRollbackCompositionError,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.c4_coordinator_test_support import MAIN_OPERATION, REPOSITORY, git
from tests.unit.test_main_graduation_c4_completion_gates import _prepared_completion_fixture
from tests.unit.test_main_graduation_completion_filesystem import _completion_coordinator


class _Reader:
    def __init__(self, root: Path, commit: str, tree: str) -> None:
        self.root = root
        self.commit = commit
        self.tree = tree

    def fresh_main_base(self) -> MainBaseSnapshot:
        return MainBaseSnapshot(REPOSITORY, self.commit, self.tree)


def _adapter(
    root: Path,
    journal: object,
    reader: _Reader,
    *,
    policy_epoch: str | None = None,
) -> MainRollbackCompositionAdapter:
    return MainRollbackCompositionAdapter(
        root / "checkout",
        journal,  # type: ignore[arg-type]
        repository_digest=REPOSITORY,
        base_reader=reader,
        policy_epoch=policy_epoch or journal._policy_epoch,  # type: ignore[attr-defined]
    )


def _ready(tmp_path: Path) -> tuple[object, Path, object, object]:
    journal, provider, clock = _prepared_completion_fixture(tmp_path)
    completion = _completion_coordinator(journal, provider, clock).complete(
        MAIN_OPERATION,
        group_sha=provider.group_sha,
        pull_request_number=provider.pr_number,
    )
    assert completion.state == "completed", completion.reason
    package_value = journal.read_completion(MAIN_OPERATION)
    assert package_value is not None
    package = package_value[0]
    checkout = tmp_path / "checkout"
    subprocess.run(
        ["git", "update-ref", "refs/heads/main", provider.main_commit],
        cwd=checkout,
        check=True,
        capture_output=True,
    )
    return journal, checkout, provider, package


def test_inverse_composition_is_exact_and_does_not_move_main(tmp_path: Path) -> None:
    journal, checkout, provider, package = _ready(tmp_path)
    main_before = git(checkout, "rev-parse", "refs/heads/main")
    digest = canonical_digest(package)
    result = _adapter(
        tmp_path,
        journal,
        _Reader(checkout, provider.main_commit, provider.main_tree),
    ).compose(
        source_operation_id=MAIN_OPERATION,
        completion_package_digest=digest,
    )

    assert result.composition.source_operation_id == MAIN_OPERATION
    assert result.composition.inverse_tree == package.composition.base_tree
    assert result.candidate_parent_commit == provider.main_commit
    assert result.candidate_tree == package.composition.base_tree
    assert result.retention_ref == (
        f"refs/avo/main-rollback/{result.composition_id.removeprefix('sha256:')}"
    )
    assert git(checkout, "rev-parse", result.retention_ref) == result.candidate_commit
    assert git(checkout, "rev-parse", "refs/heads/main") == main_before
    assert journal.read_rollback_composition(result.composition_id) is not None


def test_inverse_requires_distinct_source_operation(tmp_path: Path) -> None:
    journal, _checkout, provider, package = _ready(tmp_path)
    with pytest.raises(MainRollbackCompositionError, match="provisional"):
        _adapter(
            tmp_path,
            journal,
            _Reader(_checkout, provider.main_commit, provider.main_tree),
        ).compose(
            rollback_operation_id=MAIN_OPERATION,
            source_operation_id=MAIN_OPERATION,
            completion_package_digest=canonical_digest(package),
        )


def test_inverse_rejects_wrong_completion_digest(tmp_path: Path) -> None:
    journal, _checkout, provider, _package = _ready(tmp_path)
    with pytest.raises(MainRollbackCompositionError, match="canonical digest"):
        _adapter(
            tmp_path,
            journal,
            _Reader(_checkout, provider.main_commit, provider.main_tree),
        ).compose(
            source_operation_id=MAIN_OPERATION,
            completion_package_digest="sha256:" + "f" * 64,
        )


def test_inverse_rejects_advanced_main_before_candidate_retention(tmp_path: Path) -> None:
    journal, checkout, _provider, package = _ready(tmp_path)
    subprocess.run(
        ["git", "commit", "--allow-empty", "-m", "advanced"],
        cwd=checkout,
        check=True,
        capture_output=True,
    )
    advanced = git(checkout, "rev-parse", "refs/heads/main")
    advanced_tree = git(checkout, "rev-parse", "refs/heads/main^{tree}")
    with pytest.raises(MainRollbackCompositionError, match="advanced"):
        _adapter(tmp_path, journal, _Reader(checkout, advanced, advanced_tree)).compose(
            source_operation_id=MAIN_OPERATION,
            completion_package_digest=canonical_digest(package),
        )
    assert git(checkout, "rev-parse", "refs/heads/main") == advanced
    assert not (checkout / ".git" / "refs" / "avo" / "main-rollback").exists()


def test_inverse_rejects_historical_policy_epoch(tmp_path: Path) -> None:
    journal, checkout, provider, package = _ready(tmp_path)
    with pytest.raises(MainRollbackCompositionError, match="policy epoch"):
        _adapter(
            tmp_path,
            journal,
            _Reader(checkout, provider.main_commit, provider.main_tree),
            policy_epoch="sha256:" + "e" * 64,
        ).compose(
            source_operation_id=MAIN_OPERATION,
            completion_package_digest=canonical_digest(package),
        )
    assert not (checkout / ".git" / "refs" / "avo" / "main-rollback").exists()
