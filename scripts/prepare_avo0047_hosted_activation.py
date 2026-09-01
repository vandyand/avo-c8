# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false
"""Prepare a local-only AVO-004.7 hosted-ledger activation draft.

The input records are authenticated only by injected controller verifiers.  A
CLI invocation therefore has to name local verifier callables explicitly; a
JSON record, digest, or boolean is never treated as proof of capability.  The
command writes a canonical draft and reports that no ledger activation or
provider call occurred.
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from avo_correlate.application.main_graduation_activation import (
    MainGraduationActivationPreparationError,
    PreparedMainGraduationActivation,
    prepare_main_graduation_activation,
)
from avo_correlate.contracts.main_graduation_ledger import (
    MainLedgerC8CapabilityEvidence,
    MainLedgerControllerAuthority,
    MainLedgerHostedRollbackProof,
)
from avo_correlate.domain.canonical import canonical_bytes

MAX_INPUT_BYTES = 8 * 1024 * 1024


class HostedActivationPreparationError(RuntimeError):
    """The command-line inputs cannot produce a safe local draft."""


def _parse_datetime(raw: str) -> datetime:
    try:
        result = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timestamp must be ISO-8601") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp must include a timezone")
    return result


def _json_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HostedActivationPreparationError("input JSON contains duplicate keys")
        result[key] = value
    return result


def _load_record(path: Path, model_type: Any) -> Any:
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
        return model_type.model_validate(values)
    except HostedActivationPreparationError:
        raise
    except (TypeError, ValueError) as exc:
        raise HostedActivationPreparationError(
            f"input record failed contract validation: {path}"
        ) from exc


def _load_verifier(spec: str, label: str) -> Callable[[Any], object]:
    module_name, separator, attribute = spec.partition(":")
    if not separator or not module_name or not attribute:
        raise HostedActivationPreparationError(
            f"{label} verifier must use module:callable syntax"
        )
    try:
        candidate = getattr(importlib.import_module(module_name), attribute)
    except (ImportError, AttributeError) as exc:
        raise HostedActivationPreparationError(f"{label} verifier cannot be loaded") from exc
    if not callable(candidate):
        raise HostedActivationPreparationError(f"{label} verifier is not callable")
    return candidate


def prepare_hosted_activation_from_files(
    controller_authority_file: Path,
    capability_evidence_file: Path,
    hosted_rollback_proof_file: Path,
    output_file: Path,
    *,
    freshness_cutoff: datetime,
    activated_at: datetime,
    scheduler_sequence_watermark: int,
    authority_verifier: Callable[[Any], object],
    capability_verifier: Callable[[Any], object],
    rollback_verifier: Callable[[Any], object],
) -> PreparedMainGraduationActivation:
    """Load canonical typed records and delegate to the fail-closed builder."""
    authority = _load_record(controller_authority_file, MainLedgerControllerAuthority)
    capability = _load_record(capability_evidence_file, MainLedgerC8CapabilityEvidence)
    proof = _load_record(hosted_rollback_proof_file, MainLedgerHostedRollbackProof)
    try:
        return prepare_main_graduation_activation(
            output_file,
            controller_authority=authority,
            c8_capability_evidence=capability,
            hosted_rollback_proof=proof,
            freshness_cutoff=freshness_cutoff,
            activated_at=activated_at,
            scheduler_sequence_watermark=scheduler_sequence_watermark,
            authority_verifier=authority_verifier,
            capability_verifier=capability_verifier,
            rollback_verifier=rollback_verifier,
        )
    except MainGraduationActivationPreparationError as exc:
        raise HostedActivationPreparationError(str(exc)) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-authority-file", type=Path, required=True)
    parser.add_argument("--capability-evidence-file", type=Path, required=True)
    parser.add_argument("--hosted-rollback-proof-file", type=Path, required=True)
    parser.add_argument("--output-file", type=Path, required=True)
    parser.add_argument("--freshness-cutoff", type=_parse_datetime, required=True)
    parser.add_argument("--activated-at", type=_parse_datetime, required=True)
    parser.add_argument("--scheduler-sequence-watermark", type=int, required=True)
    parser.add_argument("--authority-verifier", required=True, metavar="MODULE:CALLABLE")
    parser.add_argument("--capability-verifier", required=True, metavar="MODULE:CALLABLE")
    parser.add_argument("--rollback-verifier", required=True, metavar="MODULE:CALLABLE")
    args = parser.parse_args(argv)
    try:
        draft = prepare_hosted_activation_from_files(
            args.controller_authority_file,
            args.capability_evidence_file,
            args.hosted_rollback_proof_file,
            args.output_file,
            freshness_cutoff=args.freshness_cutoff,
            activated_at=args.activated_at,
            scheduler_sequence_watermark=args.scheduler_sequence_watermark,
            authority_verifier=_load_verifier(args.authority_verifier, "controller authority"),
            capability_verifier=_load_verifier(args.capability_verifier, "C8 capability"),
            rollback_verifier=_load_verifier(args.rollback_verifier, "hosted rollback"),
        )
    except (HostedActivationPreparationError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "prepared",
                "prepared_only": True,
                "ledger_activated": False,
                "provider_calls": 0,
                "activation_file": str(draft.artifact_path),
                "activation_digest": draft.semantic_digest,
                "activation_artifact_digest": draft.artifact_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
