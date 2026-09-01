"""Prepare a raw-pinned, local-only C7 controller root.

The command observes a clean local Git worktree and publishes one canonical
root.  It does not execute the C7 gate, tests, or any hosted/provider call.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from avo_correlate.application.c7_controller_root_preparation import (
    C7ControllerRootPreparationError,
    prepare_controller_root,
)


def _parse_datetime(raw: str) -> datetime:
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timestamp must be ISO-8601") from exc
    if value.tzinfo is None or value.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp must include a timezone")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output-file", type=Path, required=True)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--repository-digest", required=True)
    parser.add_argument("--issuer-identity", required=True)
    parser.add_argument("--protocol-digest", required=True)
    parser.add_argument("--configuration-digest", required=True)
    parser.add_argument("--policy-digest", required=True)
    parser.add_argument("--activation-digest", required=True)
    parser.add_argument("--authorized-at", type=_parse_datetime, required=True)
    parser.add_argument("--ttl-seconds", type=int, required=True)
    parser.add_argument("--nonce", required=True)
    args = parser.parse_args(argv)
    try:
        artifact = prepare_controller_root(
            args.workspace,
            args.output_file,
            operation_id=args.operation_id,
            repository_digest=args.repository_digest,
            issuer_identity=args.issuer_identity,
            protocol_digest=args.protocol_digest,
            configuration_digest=args.configuration_digest,
            policy_digest=args.policy_digest,
            activation_digest=args.activation_digest,
            authorized_at=args.authorized_at,
            ttl_seconds=args.ttl_seconds,
            nonce=args.nonce,
        )
    except (C7ControllerRootPreparationError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    semantic = artifact.controller_authority_digest
    raw = artifact.raw_digest
    print(
        json.dumps(
            {
                "status": "controller-root-created",
                "controller_root_file": str(artifact.path),
                "raw_sha256": raw,
                "raw_digest": raw,
                "controller_root_raw_digest": raw,
                "semantic_digest": semantic,
                "controller_authority_digest": semantic,
                "tests_executed": False,
                "self_approved": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
