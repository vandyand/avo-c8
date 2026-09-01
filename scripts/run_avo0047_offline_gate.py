# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false

"""Run the deterministic, offline-only AVO-004.7 C7 gate.

The output is a compact redacted summary.  It contains no filesystem path,
timestamp, provider identity, credential, or host information.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from avo_correlate.application.main_graduation_offline_drill_service import (
    MainGraduationOfflineDrillService,
)


def _reject_conflicting_root(root: Path) -> None:
    if not root.exists():
        return
    files = [path for path in root.rglob("*") if path.is_file()]
    if not files:
        return
    known = {"artifacts", "main-graduation-offline-drill-v1"}
    if any(path.relative_to(root).parts[0] not in known for path in files):
        raise RuntimeError("refusing nonempty existing conflicting C7 root")


def run(root: Path) -> dict[str, Any]:
    """Run/replay C7 and return a stable, machine-readable summary."""
    _reject_conflicting_root(root)
    execution = MainGraduationOfflineDrillService(root).run()
    result = execution.result
    return {
        "schema_version": 1,
        "status": execution.status,
        "operation_id": execution.plan.operation_id,
        "plan_digest": execution.plan.plan_digest,
        "result_digest": result.result_digest if result is not None else None,
        "case_count": len(execution.cases),
        "vector_count": sum(len(case.vectors) for case in execution.plan.cases),
        "pending_case_vectors": [list(item) for item in execution.pending_case_vectors],
        "deploy_performed": False,
        "main_before_commit": execution.plan.main_before_commit,
        "main_after_commit": execution.plan.main_before_commit,
        "aggregate_result": result.result_digest if result is not None else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(".avo-runtime") / "avo0047-offline-gate",
        help="journal/artifact root (default: .avo-runtime/avo0047-offline-gate)",
    )
    args = parser.parse_args()
    print(json.dumps(run(args.root), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
