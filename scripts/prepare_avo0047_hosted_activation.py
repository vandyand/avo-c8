"""Prepare a local, non-consumable AVO-004.7 activation candidate inventory.

This command never authenticates an authority, evaluates provider evidence,
contacts a provider, or activates a ledger. It records only canonical local
file identities for a future service-owned provider/CAS trust root to re-read
and verify. Its output is intentionally incompatible with
``MainLedgerActivation``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from avo_correlate.application.main_graduation_activation import (
    LocalActivationCandidateArtifact,
    MainGraduationActivationPreparationError,
    PreparedLocalMainLedgerActivationDraft,
    prepare_local_main_graduation_activation_draft,
)
from avo_correlate.domain.canonical import canonical_bytes

MAX_INPUT_BYTES = 8 * 1024 * 1024
_CANDIDATE_SPECS = (
    (
        "controller-authority-candidate",
        "application/vnd.avo.main-ledger-controller-authority+json",
    ),
    (
        "c8-capability-evidence-candidate",
        "application/vnd.avo.main-ledger-c8-capability-evidence+json",
    ),
    (
        "hosted-rollback-proof-candidate",
        "application/vnd.avo.main-ledger-hosted-rollback-proof+json",
    ),
)


class HostedActivationPreparationError(RuntimeError):
    """The command-line inputs cannot produce a safe local draft."""


def _json_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HostedActivationPreparationError("input JSON contains duplicate keys")
        result[key] = value
    return result


def _load_candidate(
    path: Path, *, role: str, media_type: str
) -> LocalActivationCandidateArtifact:
    try:
        if path.is_symlink() or not path.is_file():
            raise HostedActivationPreparationError(f"input record must be a regular file: {path}")
        data = path.read_bytes()
    except OSError as exc:
        raise HostedActivationPreparationError(f"input record cannot be read: {path}") from exc
    if len(data) > MAX_INPUT_BYTES:
        raise HostedActivationPreparationError("input record exceeds size bound")
    try:
        values = json.loads(data, object_pairs_hook=_json_object_pairs)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HostedActivationPreparationError(f"input record is not valid JSON: {path}") from exc
    if not isinstance(values, dict):
        raise HostedActivationPreparationError(f"input record must be a JSON object: {path}")
    try:
        if canonical_bytes(values) != data:
            raise HostedActivationPreparationError(
                f"input record is not canonical JSON: {path}"
            )
        return LocalActivationCandidateArtifact.model_validate(
            {
                "role": role,
                "artifact_digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
                "media_type": media_type,
            }
        )
    except HostedActivationPreparationError:
        raise
    except (TypeError, ValueError) as exc:
        raise HostedActivationPreparationError(
            f"input record cannot be inventoried: {path}"
        ) from exc


def prepare_local_activation_draft_from_files(
    controller_authority_file: Path,
    capability_evidence_file: Path,
    hosted_rollback_proof_file: Path,
    output_file: Path,
) -> PreparedLocalMainLedgerActivationDraft:
    """Inventory three canonical local files without authenticating their claims."""
    paths = (
        controller_authority_file,
        capability_evidence_file,
        hosted_rollback_proof_file,
    )
    candidates = tuple(
        _load_candidate(path, role=role, media_type=media_type)
        for path, (role, media_type) in zip(paths, _CANDIDATE_SPECS, strict=True)
    )
    try:
        return prepare_local_main_graduation_activation_draft(
            output_file, candidate_artifacts=candidates
        )
    except MainGraduationActivationPreparationError as exc:
        raise HostedActivationPreparationError(str(exc)) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-authority-file", type=Path, required=True)
    parser.add_argument("--capability-evidence-file", type=Path, required=True)
    parser.add_argument("--hosted-rollback-proof-file", type=Path, required=True)
    parser.add_argument("--output-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        draft = prepare_local_activation_draft_from_files(
            args.controller_authority_file,
            args.capability_evidence_file,
            args.hosted_rollback_proof_file,
            args.output_file,
        )
    except (HostedActivationPreparationError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "local-activation-preparation-draft-prepared",
                "prepared_only": True,
                "activation_consumable": False,
                "rooted_verification": False,
                "ledger_activated": False,
                "provider_calls": 0,
                "draft_file": str(draft.artifact_path),
                "draft_digest": draft.semantic_digest,
                "draft_artifact_digest": draft.artifact_digest,
                "candidate_artifact_count": len(draft.draft.candidate_artifacts),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
