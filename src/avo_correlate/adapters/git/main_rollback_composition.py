"""Offline inverse composition for protected-main rollback.

This adapter derives a rollback candidate from one durably completed main
graduation.  It only reads the protected-main snapshot and writes an isolated
object-retention ref under ``refs/avo/main-rollback``; in particular it never
updates ``refs/heads/main`` or any hosted ref.
"""

# The adapter intentionally delegates to the lower-level Git implementation's
# protected helpers; this module is the narrower rollback policy boundary.
# pyright: reportPrivateUsage=false

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from avo_correlate.adapters.artifacts.main_graduation_journal import MainGraduationJournal
from avo_correlate.adapters.git.main_composition import (
    MainBaseReader,
    MainBaseSnapshot,
    MainCompositionAdapter,
    MainCompositionError,
)
from avo_correlate.contracts.base import ArtifactRef, Sha256Digest
from avo_correlate.contracts.main_graduation import (
    MainCompletionPackage,
    MainRollbackCompositionArtifact,
    main_rollback_composition_id,
)
from avo_correlate.domain.canonical import canonical_digest

_ROLLBACK_RETENTION = re.compile(r"^refs/avo/main-rollback/[0-9a-f]{64}$")
_ROLLBACK_COMMIT_MESSAGE = "AVO protected-main rollback composition"
_AUTHOR_NAME = "AVO Main Rollback"
_AUTHOR_EMAIL = "avo-main-rollback@localhost"
_COMMIT_DATE = "2000-01-01T00:00:00+0000"


class MainRollbackCompositionError(RuntimeError):
    """A rollback source, inverse, or current-main fence is unsafe."""


@dataclass(frozen=True, slots=True)
class MainRollbackCompositionResult:
    """Exact inverse composition before a rollback attempt exists."""

    composition_id: Sha256Digest
    source_operation_id: Sha256Digest
    composition: MainRollbackCompositionArtifact
    composition_artifact: ArtifactRef
    candidate_commit: str
    candidate_tree: str
    candidate_parent_commit: str
    retention_ref: str

    @property
    def inverse_delta_digest(self) -> Sha256Digest:
        return self.composition.inverse_delta_digest

    @property
    def inverse_artifact_digest(self) -> Sha256Digest:
        return self.composition_artifact.digest


class MainRollbackCompositionAdapter:
    """Compute one exact reverse delta from a completed main result.

    The source completion is looked up by ``source_operation_id`` and checked
    against its canonical package digest; no mutable integration ref or
    caller-provided completion is accepted.  A final rollback operation is
    deliberately not known at this stage.
    """

    def __init__(
        self,
        root: Path,
        journal: MainGraduationJournal,
        *,
        repository_digest: str,
        base_reader: MainBaseReader,
        controller_config_digest: str | None = None,
        policy_epoch: str | None = None,
        command_timeout_seconds: int = 30,
    ) -> None:
        self._composition = MainCompositionAdapter(
            root,
            journal,
            repository_digest=repository_digest,
            base_reader=base_reader,
            controller_config_digest=controller_config_digest,
            policy_epoch=policy_epoch,
            command_timeout_seconds=command_timeout_seconds,
        )
        self.journal = journal
        self.repository_digest = repository_digest

    def compose(
        self,
        *,
        source_operation_id: Sha256Digest,
        completion_package_digest: Sha256Digest,
        rollback_operation_id: Sha256Digest | None = None,
    ) -> MainRollbackCompositionResult:
        try:
            if rollback_operation_id is not None:
                raise MainRollbackCompositionError(
                    "provisional rollback operation identity is rejected; compose without it"
                )
            package = self._load_source_completion(
                source_operation_id, completion_package_digest
            )
            if package.repository_digest != self.repository_digest:
                raise MainRollbackCompositionError("rollback repository differs from adapter")
            if package.plan.policy_epoch != self._composition.policy_epoch:
                raise MainRollbackCompositionError(
                    "source completion policy epoch differs from rollback authority"
                )

            current = self._composition.fresh_main_base()
            self._require_current_main(package, current)
            result_commit = package.reconciliation.main_commit
            result_tree = package.reconciliation.main_tree
            base_commit = package.composition.base_commit
            base_tree = package.composition.base_tree
            self._composition._verify_commit_tree(
                result_commit, result_tree, "completed main result"
            )
            self._composition._verify_commit_tree(base_commit, base_tree, "original main base")
            self._require_exact_parent(package, result_commit, base_commit)

            changed_paths, reverse_patch = self._composition._source_delta(
                result_commit, base_commit
            )
            self._require_inverse_paths(package, changed_paths)
            inverse_tree = self._composition._apply_delta(result_commit, reverse_patch)
            if inverse_tree != base_tree:
                raise MainRollbackCompositionError(
                    "inverse tree differs from the original main base tree"
                )

            candidate_commit = self._rollback_commit(result_commit, inverse_tree)
            self._composition._verify_candidate(
                candidate_commit, inverse_tree, result_commit
            )
            # Re-observe the protected base after all derived Git objects and
            # immediately before durable composition write.
            final = self._composition.fresh_main_base()
            if final.commit != current.commit or final.tree != current.tree:
                raise MainRollbackCompositionError("main changed during inverse composition")

            inverse_values: dict[str, Any] = {
                "schema_version": 1,
                "source_operation_id": source_operation_id,
                "completion_package_digest": completion_package_digest,
                "repository_digest": self.repository_digest,
                "target_ref": package.target_ref,
                "original_delta_digest": package.delta.delta_digest,
                "current_main_commit": current.commit,
                "current_main_tree": current.tree,
                "current_main_parent_commit": base_commit,
                "inverse_changed_paths": changed_paths,
                "inverse_tree": inverse_tree,
                "inverse_delta_digest": "sha256:" + "0" * 64,
                "policy_epoch": self._composition.policy_epoch,
                "candidate_commit": candidate_commit,
                "candidate_tree": inverse_tree,
                "candidate_parent_commit": result_commit,
                "deploy_performed": False,
            }
            probe = MainRollbackCompositionArtifact.model_construct(
                **inverse_values, composition_id="sha256:" + "0" * 64,
                retention_ref="refs/avo/main-rollback/" + "0" * 64,
            )
            inverse_values["inverse_delta_digest"] = canonical_digest(
                probe.model_dump(
                    exclude={"inverse_delta_digest", "composition_id", "retention_ref"},
                    mode="json",
                )
            )
            probe = MainRollbackCompositionArtifact.model_construct(
                **inverse_values,
                composition_id="sha256:" + "0" * 64,
                retention_ref="refs/avo/main-rollback/" + "0" * 64,
            )
            composition_id = main_rollback_composition_id(
                **probe.model_dump(exclude={"composition_id", "retention_ref"}, mode="json")
            )
            retention_ref = (
                f"refs/avo/main-rollback/{composition_id.removeprefix('sha256:')}"
            )
            self._retain_rollback_candidate(retention_ref, candidate_commit)
            inverse_values.update(
                {
                    "composition_id": composition_id,
                    "retention_ref": retention_ref,
                }
            )
            composition = MainRollbackCompositionArtifact.model_validate(inverse_values)
            artifact = self.journal.record_rollback_composition(composition)
            return MainRollbackCompositionResult(
                composition_id=composition_id,
                source_operation_id=source_operation_id,
                composition=composition,
                composition_artifact=artifact,
                candidate_commit=candidate_commit,
                candidate_tree=inverse_tree,
                candidate_parent_commit=result_commit,
                retention_ref=retention_ref,
            )
        except MainRollbackCompositionError:
            raise
        except (MainCompositionError, ValueError, TypeError, AttributeError) as exc:
            raise MainRollbackCompositionError("rollback inverse composition failed") from exc

    def _load_source_completion(
        self, source_operation_id: Sha256Digest, expected_digest: Sha256Digest
    ) -> MainCompletionPackage:
        loaded = self.journal.read_completion(source_operation_id)
        if loaded is None:
            raise MainRollbackCompositionError("source completion is not durably recorded")
        try:
            raw_package, artifact = loaded
            package = MainCompletionPackage.model_validate(
                cast(MainCompletionPackage, raw_package).model_dump(mode="json")
            )
            canonical = canonical_digest(package)
            if (
                package.operation_id != source_operation_id
                or canonical != expected_digest
                or artifact.digest != canonical
            ):
                raise MainRollbackCompositionError(
                    "source completion operation or canonical digest differs"
                )
        except MainRollbackCompositionError:
            raise
        except (AttributeError, TypeError, ValueError) as exc:
            raise MainRollbackCompositionError("source completion is malformed") from exc
        return package

    def _rollback_commit(self, parent: str, tree: str) -> str:
        env = self._composition._environment()
        env.update(
            {
                "GIT_AUTHOR_NAME": _AUTHOR_NAME,
                "GIT_AUTHOR_EMAIL": _AUTHOR_EMAIL,
                "GIT_COMMITTER_NAME": _AUTHOR_NAME,
                "GIT_COMMITTER_EMAIL": _AUTHOR_EMAIL,
                "GIT_AUTHOR_DATE": _COMMIT_DATE,
                "GIT_COMMITTER_DATE": _COMMIT_DATE,
            }
        )
        return self._composition._run(
            [
                "git",
                "-c",
                "i18n.commitEncoding=UTF-8",
                "-c",
                "commit.gpgSign=false",
                "-c",
                "tag.gpgSign=false",
                "commit-tree",
                tree,
                "-p",
                parent,
                "--no-gpg-sign",
            ],
            env=env,
            input_bytes=_ROLLBACK_COMMIT_MESSAGE.encode(),
        )

    @staticmethod
    def _require_current_main(
        package: MainCompletionPackage, current: MainBaseSnapshot
    ) -> None:
        if (
            current.commit != package.reconciliation.main_commit
            or current.tree != package.reconciliation.main_tree
        ):
            raise MainRollbackCompositionError(
                "current main is advanced, conflicting, or has a different tree"
            )
        if package.reconciliation.main_parents != [package.composition.base_commit]:
            raise MainRollbackCompositionError("completed main result is not one-parent")

    def _require_exact_parent(
        self, package: MainCompletionPackage, result_commit: str, base_commit: str
    ) -> None:
        _tree, parents = self._composition._commit_topology(result_commit)
        if parents != [base_commit] or package.reconciliation.main_parents != [base_commit]:
            raise MainRollbackCompositionError(
                "completed main result is not an exact sole-parent commit"
            )

    def _require_inverse_paths(
        self, package: MainCompletionPackage, changed_paths: list[str]
    ) -> None:
        expected = package.delta.changed_paths
        if changed_paths != expected:
            raise MainRollbackCompositionError("inverse changed paths differ from original delta")
        for path in changed_paths:
            if not self._composition._safe_path(path):
                raise MainRollbackCompositionError("inverse delta contains an unsafe path")

    def _retain_rollback_candidate(self, retention_ref: str, candidate_commit: str) -> None:
        if _ROLLBACK_RETENTION.fullmatch(retention_ref) is None:
            raise MainRollbackCompositionError(
                "rollback retention ref is outside controller namespace"
            )
        existing = self._composition._run_bytes(
            ["git", "rev-parse", "--verify", "--end-of-options", f"{retention_ref}^{{commit}}"],
            check=False,
        )
        if existing:
            if existing.decode("ascii", "strict").strip() != candidate_commit:
                raise MainRollbackCompositionError("rollback retention ref is conflicting")
            return
        try:
            self._composition._run(
                ["git", "update-ref", retention_ref, candidate_commit, "0" * len(candidate_commit)]
            )
        except MainCompositionError:
            observed = self._composition._run_bytes(
                ["git", "rev-parse", "--verify", "--end-of-options", f"{retention_ref}^{{commit}}"],
                check=False,
            )
            if not observed or observed.decode("ascii", "strict").strip() != candidate_commit:
                raise MainRollbackCompositionError(
                    "rollback retention publication was ambiguous or conflicting"
                ) from None
        observed = self._composition._git(
            "rev-parse", "--verify", "--end-of-options", f"{retention_ref}^{{commit}}"
        )
        if observed != candidate_commit:
            raise MainRollbackCompositionError("rollback retention ref does not retain candidate")


DeterministicMainRollbackCompositionAdapter = MainRollbackCompositionAdapter

__all__ = [
    "DeterministicMainRollbackCompositionAdapter",
    "MainRollbackCompositionAdapter",
    "MainRollbackCompositionError",
    "MainRollbackCompositionResult",
]
