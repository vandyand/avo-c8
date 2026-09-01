# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false
"""Run the authority-owned, hermetic offline AVO-004.7 C7 gate."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.application.c7_controller_root import (
    C7ControllerRootArtifact,
    C7ControllerRootError,
    load_controller_root,
)
from avo_correlate.application.main_graduation_offline_drill_service import (
    MainGraduationOfflineDrillService,
    PinnedC7AuthorityVerifier,
)
from avo_correlate.application.main_graduation_offline_pytest_executor import HermeticPytestExecutor
from avo_correlate.contracts.main_graduation_offline_drill import (
    MainGraduationOfflineExecutionAuthority,
)
from avo_correlate.domain.canonical import canonical_bytes, file_digest


class _AuthorityClock:
    """Local OS UTC wall clock for freshness inside an authenticated window.

    This clock is not a cryptographic time source and does not authenticate a
    controller root; the loaded, pinned root supplies that authority.
    """

    def now(self) -> datetime:
        return datetime.now(UTC)


def _reject_conflicting_root(root: Path) -> None:
    if not root.exists():
        return
    files = [path for path in root.rglob("*") if path.is_file()]
    known = {"artifacts", "main-graduation-offline-drill-v1"}
    if files and any(path.relative_to(root).parts[0] not in known for path in files):
        raise RuntimeError("refusing nonempty existing conflicting C7 root")


def _strict_object(raw: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("authority JSON contains duplicate key")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise ValueError("authority JSON must be canonical")
    return value


def _load_authority(
    path: Path, expected_artifact_digest: str
) -> MainGraduationOfflineExecutionAuthority:
    if not expected_artifact_digest.startswith("sha256:"):
        raise RuntimeError("c7_authority_digest_mismatch")
    try:
        if not path.is_file() or path.is_symlink():
            raise ValueError("authority file is not a regular file")
        raw = path.read_bytes()
        if file_digest(path) != expected_artifact_digest:
            raise ValueError("authority artifact digest mismatch")
        authority = MainGraduationOfflineExecutionAuthority.model_validate(_strict_object(raw))
    except Exception as exc:
        raise RuntimeError("c7_authority_digest_mismatch") from exc
    return authority


def _load_controller_root(
    path: Path, expected_raw_digest: str
) -> C7ControllerRootArtifact:
    """Load the typed controller root using only its out-of-band raw pin."""
    try:
        return load_controller_root(path, expected_raw_digest)
    except (C7ControllerRootError, AttributeError, TypeError) as exc:
        raise RuntimeError("c7_controller_root_mismatch") from exc


def _match_controller_root(
    authority: MainGraduationOfflineExecutionAuthority,
    controller: C7ControllerRootArtifact,
) -> None:
    root = controller.root
    bindings = (
        ("operation_id", authority.operation_id, root.operation_id),
        ("repository_digest", authority.repository_digest, root.repository_digest),
        ("target_ref", authority.target_ref, root.target_ref),
        ("issuer_identity", authority.issuer_identity, root.issuer_identity),
        ("source_commit", authority.source_commit, root.source_commit),
        ("source_tree", authority.source_tree, root.source_tree),
        ("source_tree_digest", authority.source_tree_digest, root.source_tree_digest),
        ("protocol_digest", authority.protocol_digest, root.protocol_digest),
        ("configuration_digest", authority.configuration_digest, root.configuration_digest),
        ("policy_digest", authority.policy_digest, root.policy_digest),
        ("activation_digest", authority.activation_digest, root.activation_digest),
        (
            "controller_authority_digest",
            authority.controller_authority_digest,
            root.controller_authority_digest,
        ),
        ("controller_authority_ref", authority.controller_authority_ref, controller.raw_digest),
    )
    if any(supplied != expected for _, supplied, expected in bindings):
        raise RuntimeError("c7_controller_authority_mismatch")
    if not root.authorized_at <= authority.authorized_at <= authority.expires_at <= root.expires_at:
        raise RuntimeError("c7_controller_authority_window_mismatch")


def run(
    root: Path,
    authority_file: Path | None = None,
    expected_authority_artifact_digest: str | None = None,
    workspace: Path | None = None,
    state_root: Path | None = None,
    *,
    controller_root_file: Path | None = None,
    expected_controller_root_raw_digest: str | None = None,
    # Naming used by the preparation script is retained as an explicit alias;
    # both values, when supplied, must be the same out-of-band raw pin.
    expected_controller_root_artifact_digest: str | None = None,
) -> dict[str, Any]:
    """Execute only with a typed, raw-pinned controller root and workspace."""
    target_root = state_root or root
    _reject_conflicting_root(target_root)
    raw_digest = expected_controller_root_raw_digest
    if raw_digest is None:
        raw_digest = expected_controller_root_artifact_digest
    elif (
        expected_controller_root_artifact_digest is not None
        and expected_controller_root_artifact_digest != raw_digest
    ):
        raise RuntimeError("c7_controller_root_mismatch")
    if (
        authority_file is None
        or expected_authority_artifact_digest is None
        or workspace is None
        or controller_root_file is None
        or raw_digest is None
    ):
        raise RuntimeError("c7_authority_executor_unavailable")
    controller = _load_controller_root(controller_root_file, raw_digest)
    authority = _load_authority(authority_file, expected_authority_artifact_digest)
    _match_controller_root(authority, controller)
    clock = _AuthorityClock()
    now = clock.now()
    if not controller.root.authorized_at <= now < controller.root.expires_at:
        raise RuntimeError("c7_controller_authority_window_mismatch")
    if not authority.authorized_at <= now < authority.expires_at:
        raise RuntimeError("c7_controller_authority_window_mismatch")
    verifier = PinnedC7AuthorityVerifier(
        authority.authority_digest,
        expected_authority_artifact_digest,
        controller_authority_digest=controller.controller_authority_digest,
        controller_authority_ref=controller.controller_authority_ref,
    )
    store_root = target_root / "artifacts"
    executor = HermeticPytestExecutor(
        workspace, FilesystemArtifactStore(store_root, clock=clock.now), clock=clock.now
    )
    service = MainGraduationOfflineDrillService(
        target_root, executor, authority=authority, clock=clock, authority_verifier=verifier
    )
    run_result = service.run()
    if run_result.result is None:
        raise RuntimeError("c7_execution_incomplete")
    result = run_result.result
    return {
        "status": run_result.status,
        "operation_id": result.operation_id,
        "authority_digest": authority.authority_digest,
        "plan_digest": result.plan_digest,
        "report_digest": result.execution_report_digest,
        "result_digest": result.result_digest,
        "case_count": len(result.cases),
        "deploy_performed": result.deploy_performed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authority-file", type=Path)
    parser.add_argument("--expected-authority-artifact-digest")
    parser.add_argument("--controller-root-file", type=Path)
    parser.add_argument(
        "--expected-controller-root-raw-digest",
        "--expected-controller-root-artifact-digest",
        "--expected-controller-root-digest",
        dest="expected_controller_root_raw_digest",
    )
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--root", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.state_root is None and args.root is None:
            raise RuntimeError("c7_authority_executor_unavailable")
        state_root = args.state_root or args.root
        output = run(
            state_root,
            args.authority_file,
            args.expected_authority_artifact_digest,
            args.workspace,
            state_root,
            controller_root_file=args.controller_root_file,
            expected_controller_root_raw_digest=args.expected_controller_root_raw_digest,
        )
    except (RuntimeError, OSError, ValueError) as exc:
        print(str(exc))
        return 2
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
