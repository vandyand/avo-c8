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
    """Fail closed until an authority-owned executor/manifest is available."""
    _reject_conflicting_root(root)
    raise RuntimeError("c7_authority_executor_unavailable")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(".avo-runtime") / "avo0047-offline-gate",
        help="journal/artifact root (default: .avo-runtime/avo0047-offline-gate)",
    )
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.root), sort_keys=True, separators=(",", ":")))
    except RuntimeError as exc:
        print(str(exc))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
