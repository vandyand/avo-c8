# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false
"""Run the authority-owned, hermetic offline AVO-004.7 C7 gate."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.application.main_graduation_offline_drill_service import (
    MainGraduationOfflineDrillService,
    PinnedC7AuthorityVerifier,
)
from avo_correlate.application.main_graduation_offline_pytest_executor import HermeticPytestExecutor
from avo_correlate.contracts.main_graduation_offline_drill import (
    MainGraduationOfflineExecutionAuthority,
)
from avo_correlate.domain.canonical import canonical_bytes


class _AuthorityClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


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


def _load_authority(path: Path, expected_digest: str) -> MainGraduationOfflineExecutionAuthority:
    if not expected_digest.startswith("sha256:"):
        raise RuntimeError("c7_authority_digest_mismatch")
    try:
        authority = MainGraduationOfflineExecutionAuthority.model_validate(
            _strict_object(path.read_bytes())
        )
    except Exception as exc:
        raise RuntimeError("c7_authority_digest_mismatch") from exc
    if authority.authority_digest != expected_digest:
        raise RuntimeError("c7_authority_digest_mismatch")
    return authority


def run(
    root: Path,
    authority_file: Path | None = None,
    expected_authority_digest: str | None = None,
    workspace: Path | None = None,
    state_root: Path | None = None,
) -> dict[str, Any]:
    """Execute only with an explicit controller authority and workspace."""
    target_root = state_root or root
    _reject_conflicting_root(target_root)
    if authority_file is None or expected_authority_digest is None or workspace is None:
        raise RuntimeError("c7_authority_executor_unavailable")
    authority = _load_authority(authority_file, expected_authority_digest)
    clock = _AuthorityClock(authority.authorized_at)
    verifier = PinnedC7AuthorityVerifier(authority.authority_digest)
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
    parser.add_argument("--expected-authority-digest")
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
            args.expected_authority_digest,
            args.workspace,
            state_root,
        )
    except (RuntimeError, OSError, ValueError) as exc:
        print(str(exc))
        return 2
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
