# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportUnusedVariable=false
"""Prepare a local-only C8 hosted-main rollback proof.

The inputs are recorded JSON artifacts.  This command never constructs a
provider, opens a network transport, executes a rollback, or activates the
ledger; its output is explicitly suitable only for a later activation step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from avo_correlate.application.main_graduation_hosted_rollback import (
    HostedRollbackProofPreparationError,
    prepare_hosted_rollback_proof,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation import MainRollbackCompletionPackage
from avo_correlate.contracts.main_graduation_ledger import MainLedgerControllerAuthority
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HostedRollbackProofPreparationError(
            f"recorded artifact cannot be read: {path}"
        ) from exc


def _artifact(path: Path, role: str, media_type: str) -> ArtifactRef:
    try:
        data = path.read_bytes()
        timestamp = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    except OSError as exc:
        raise HostedRollbackProofPreparationError(
            f"recorded artifact cannot be read: {path}"
        ) from exc
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    return ArtifactRef(
        digest=digest,
        size_bytes=len(data),
        media_type=media_type,
        role=role,
        created_at=timestamp,
    )


class _RecordedAuthorityVerifier:
    """Fixture verifier for this local preparation command.

    The command accepts only a parsed, self-consistent package and authority;
    the production activation path must supply its independently rooted
    verifier.  Returning a literal bool here keeps the boundary explicit and
    prevents a DTO or caller assertion from being treated as verification.
    """

    def verify_hosted_rollback(
        self,
        authority: MainLedgerControllerAuthority,
        package: MainRollbackCompletionPackage,
    ) -> bool:
        return (
            authority.repository_digest == package.repository_digest
            and authority.target_ref == package.target_ref
            and authority.controller_config_digest
            == package.attempt_authority.controller_config_digest
            and authority.policy_epoch == package.attempt_authority.policy_epoch
        )


def _reader(path: Path):
    def read(operation_id: str):
        package = MainRollbackCompletionPackage.model_validate(_read_json(path))
        if package.operation_id != operation_id:
            return None
        return package, _artifact(
            path,
            "main-graduation-rollback-completion",
            "application/vnd.avo.main-graduation-rollback-completion+json",
        )

    return read


def _authority_reader(path: Path):
    def read():
        raw = path.read_bytes()
        authority = MainLedgerControllerAuthority.model_validate(
            json.loads(raw.decode("utf-8"))
        )
        if canonical_bytes(authority) != raw:
            raise HostedRollbackProofPreparationError(
                "controller authority artifact is not canonical JSON"
            )
        # Include an artifact ref so the preparer also exercises a durable
        # authority artifact boundary.  The semantic authority digest is the
        # content identity of this record.
        return authority, ArtifactRef(
            digest=canonical_digest(authority),
            size_bytes=len(canonical_bytes(authority)),
            media_type="application/vnd.avo.main-ledger-controller-authority+json",
            role="main-ledger-controller-authority",
            created_at=datetime.fromtimestamp(path.stat().st_mtime, tz=UTC),
        )

    return read


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--completion-file", type=Path, required=True)
    parser.add_argument("--controller-authority-file", type=Path, required=True)
    parser.add_argument("--output-file", type=Path, required=True)
    parser.add_argument("--operation-id", required=True)
    args = parser.parse_args(argv)
    try:
        prepared = prepare_hosted_rollback_proof(
            args.output_file,
            operation_id=args.operation_id,
            completion_reader=_reader(args.completion_file),
            controller_authority_reader=_authority_reader(args.controller_authority_file),
            authority_verifier=_RecordedAuthorityVerifier(),
        )
    except (HostedRollbackProofPreparationError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "hosted-main-rollback-proof-prepared",
                "proof_file": str(prepared.path),
                "proof_artifact_digest": prepared.proof.proof_artifact_digest,
                "proof_digest": prepared.proof.proof_digest,
                "artifact_digest": prepared.artifact_ref.digest,
                "prepared_only": True,
                "hosted_drill_executed": False,
                "ledger_activated": False,
                "provider_calls": 0,
                "deploy_performed": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
