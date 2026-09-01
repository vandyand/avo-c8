# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false
"""Prepare a controller-bound, local-only C7 execution authority draft.

This command only observes the committed workspace and writes one canonical
authority artifact.  It deliberately does not invoke pytest, the C7 service,
or any hosted/provider API.  The controller-root document and all authority
configuration digests are supplied by the caller; this script never invents
or self-approves them.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

from avo_correlate.application.main_graduation_offline_identity import (
    FROZEN_OFFLINE_EXECUTION_ARGV,
    C7WorkspaceIdentity,
    C7WorkspaceIdentityError,
    C7WorkspaceIdentityVerifier,
)
from avo_correlate.contracts.main_graduation_offline_drill import (
    FROZEN_OFFLINE_DRILL_CASE_IDS,
    FROZEN_OFFLINE_DRILL_VECTOR_IDS,
    FROZEN_OFFLINE_EXECUTION_NODE_IDS,
    FROZEN_OFFLINE_EXECUTION_PARAMETER_IDS,
    MainGraduationOfflineExecutionAuthority,
    MainGraduationOfflineExecutionNodeSpec,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest, file_digest

# C7 preparation should be short-lived.  Five minutes matches the existing
# controller authorization default, while the lower bound prevents a caller
# from creating an immediately unusable draft.
MIN_TTL_SECONDS = 1
MAX_TTL_SECONDS = 5 * 60
MAX_CONTROLLER_ROOT_BYTES = 8 * 1024 * 1024
MAX_AUTHORITY_BYTES = 8 * 1024 * 1024


class C7AuthorityPreparationError(RuntimeError):
    """The local preparation inputs cannot produce a safe authority draft."""


class C7AuthorityDraft:
    """The prepared authority and its canonical raw artifact identity."""

    def __init__(
        self,
        authority: MainGraduationOfflineExecutionAuthority,
        artifact_path: Path,
        artifact_digest: str,
    ) -> None:
        self.authority = authority
        self.artifact_path = artifact_path
        self.artifact_digest = artifact_digest

    @property
    def semantic_digest(self) -> str:
        return self.authority.authority_digest


def _strict_canonical_object(path: Path, *, max_bytes: int) -> tuple[dict[str, Any], bytes]:
    """Read one regular canonical JSON object, rejecting duplicate keys."""
    if path.is_symlink() or not path.is_file():
        raise C7AuthorityPreparationError("controller root must be a regular file")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise C7AuthorityPreparationError("controller root is unreadable") from exc
    if len(raw) > max_bytes:
        raise C7AuthorityPreparationError("controller root exceeds size bound")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise C7AuthorityPreparationError("controller root contains duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except C7AuthorityPreparationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise C7AuthorityPreparationError("controller root is invalid JSON") from exc
    if not isinstance(value, dict):
        raise C7AuthorityPreparationError("controller root must be a JSON object")
    try:
        if canonical_bytes(value) != raw:
            raise C7AuthorityPreparationError("controller root is not canonical")
    except ValueError as exc:
        raise C7AuthorityPreparationError("controller root is not canonical") from exc
    return cast(dict[str, Any], value), raw


def _validate_digest(value: str, label: str) -> None:
    if len(value) != 71 or not value.startswith("sha256:"):
        raise C7AuthorityPreparationError(f"{label} must be a sha256 digest")
    if any(char not in "0123456789abcdef" for char in value[7:]):
        raise C7AuthorityPreparationError(f"{label} must be a sha256 digest")


def _safe_existing_path(path: Path, label: str) -> Path:
    """Resolve a path while refusing an existing symlink in its chain."""
    path = Path(path)
    current = path
    missing: list[Path] = []
    while not current.exists() and not current.is_symlink():
        missing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    if current.is_symlink():
        raise C7AuthorityPreparationError(f"{label} path cannot contain a symlink")
    return path


def _write_create_once(path: Path, data: bytes) -> str:
    """Publish canonical bytes atomically, replaying only an identical winner."""
    if len(data) > MAX_AUTHORITY_BYTES:
        raise C7AuthorityPreparationError("authority artifact exceeds size bound")
    _safe_existing_path(path.parent, "authority output parent")
    path.parent.mkdir(parents=True, exist_ok=True)
    _safe_existing_path(path, "authority output")
    expected = file_digest_from_bytes(data)

    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise C7AuthorityPreparationError("authority output must be a regular file")
        try:
            existing = path.read_bytes()
        except OSError as exc:
            raise C7AuthorityPreparationError("authority output is unreadable") from exc
        if existing != data:
            raise C7AuthorityPreparationError("conflicting authority draft already exists")
        return expected

    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", suffix=".partial", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            # A hard-link is create-once: it never replaces a concurrent winner.
            os.link(temporary, path)
        except FileExistsError:
            if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                raise C7AuthorityPreparationError(
                    "conflicting authority draft already exists"
                ) from None
        return expected
    except OSError as exc:
        raise C7AuthorityPreparationError("authority draft could not be published") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def file_digest_from_bytes(data: bytes) -> str:
    """Return the same sha256 wire form as :func:`file_digest`."""
    import hashlib

    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _frozen_nodes() -> tuple[MainGraduationOfflineExecutionNodeSpec, ...]:
    nodes: list[MainGraduationOfflineExecutionNodeSpec] = []
    node_index = 0
    for case_id in FROZEN_OFFLINE_DRILL_CASE_IDS:
        for vector_id in FROZEN_OFFLINE_DRILL_VECTOR_IDS[case_id]:
            if node_index >= len(FROZEN_OFFLINE_EXECUTION_NODE_IDS):
                raise C7AuthorityPreparationError("frozen C7 node matrix is inconsistent")
            expected_outcome = (
                "replayed"
                if case_id == "replay-idempotence"
                else "passed"
                if (case_id, vector_id)
                in {
                    ("crash-boundary-matrix", "after-hold-success"),
                    ("admission-group-identity", "admission-success"),
                }
                else "reconciliation_required"
            )
            expected_state = (
                "replayed_read_only"
                if case_id == "replay-idempotence"
                else "completed"
                if (case_id, vector_id)
                in {
                    ("crash-boundary-matrix", "after-hold-success"),
                    ("admission-group-identity", "admission-success"),
                }
                else "failed_closed"
            )
            nodes.append(
                MainGraduationOfflineExecutionNodeSpec(
                    node_id=FROZEN_OFFLINE_EXECUTION_NODE_IDS[node_index],
                    parameter_id=FROZEN_OFFLINE_EXECUTION_PARAMETER_IDS[node_index],
                    case_id=case_id,
                    vector_id=vector_id,
                    expected_outcome=expected_outcome,
                    expected_state=expected_state,
                )
            )
            node_index += 1
    if node_index != 47 or node_index != len(FROZEN_OFFLINE_EXECUTION_NODE_IDS):
        raise C7AuthorityPreparationError("frozen C7 node matrix is not exactly 47 nodes")
    return tuple(nodes)


def _authority_values(
    identity: C7WorkspaceIdentity,
    *,
    operation_id: str,
    controller_authority_digest: str,
    controller_authority_ref: str,
    issuer_identity: str,
    repository_digest: str,
    protocol_digest: str,
    configuration_digest: str,
    policy_digest: str,
    activation_digest: str,
    normalized_report_schema_digest: str,
    authorized_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    nodes = _frozen_nodes()
    values: dict[str, Any] = {
        "operation_id": operation_id,
        "controller_authority_digest": controller_authority_digest,
        "controller_authority_ref": controller_authority_ref,
        "issuer_identity": issuer_identity,
        "repository_digest": repository_digest,
        "target_ref": "refs/heads/main",
        "source_commit": identity.source_commit,
        "source_tree": identity.source_tree,
        "source_tree_digest": identity.source_tree_digest,
        "protocol_digest": protocol_digest,
        "configuration_digest": configuration_digest,
        "policy_digest": policy_digest,
        "activation_digest": activation_digest,
        "lockfile_digest": identity.lockfile_digest,
        "interpreter_digest": identity.interpreter_digest,
        "pytest_digest": identity.pytest_digest,
        "plugin_set_digest": identity.plugin_set_digest,
        "toolchain_digest": identity.toolchain_digest,
        "environment_identity_digest": identity.environment_identity_digest,
        "argv": FROZEN_OFFLINE_EXECUTION_ARGV,
        "normalized_report_schema_digest": normalized_report_schema_digest,
        "normalized_report_media_type": "application/vnd.avo.c7.execution-report+json",
        "authorized_at": authorized_at,
        "expires_at": expires_at,
        "nodes": nodes,
    }
    # The contract's digest excludes itself.  model_construct lets us compute
    # the digest before the contract's strict self-validation runs.
    stub = MainGraduationOfflineExecutionAuthority.model_construct(
        **values, authority_digest="sha256:" + "0" * 64
    )
    values["authority_digest"] = canonical_digest(
        {
            "domain": "avo-004.7-c7/offline-execution-authority/v1",
            "value": stub.model_dump(exclude={"authority_digest"}, mode="json"),
        }
    )
    return values


def prepare_authority(
    workspace: Path,
    controller_root_file: Path,
    output_file: Path,
    *,
    expected_controller_root_artifact_digest: str,
    controller_authority_digest: str,
    controller_authority_ref: str,
    operation_id: str,
    issuer_identity: str,
    repository_digest: str,
    protocol_digest: str,
    configuration_digest: str,
    policy_digest: str,
    activation_digest: str,
    normalized_report_schema_digest: str,
    authorized_at: datetime,
    ttl_seconds: int,
    verifier_factory: Callable[[Path], C7WorkspaceIdentityVerifier] | None = None,
) -> C7AuthorityDraft:
    """Observe a clean workspace and publish one controller-bound authority draft."""
    _safe_existing_path(workspace, "workspace")
    root_value, root_raw = _strict_canonical_object(
        controller_root_file, max_bytes=MAX_CONTROLLER_ROOT_BYTES
    )
    del root_value  # Presence, canonicality, and raw identity are the boundary here.
    actual_root_digest = file_digest(controller_root_file)
    if actual_root_digest != expected_controller_root_artifact_digest:
        raise C7AuthorityPreparationError("controller root artifact digest mismatch")
    _validate_digest(expected_controller_root_artifact_digest, "controller root artifact digest")
    if (
        not controller_authority_ref.strip()
        or controller_authority_ref != controller_authority_ref.strip()
    ):
        raise C7AuthorityPreparationError("controller authority ref is required")
    if authorized_at.tzinfo is None:
        raise C7AuthorityPreparationError("authorized_at must be timezone-aware")
    if not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
        raise C7AuthorityPreparationError(
            f"ttl_seconds must be between {MIN_TTL_SECONDS} and {MAX_TTL_SECONDS}"
        )
    expires_at = authorized_at + timedelta(seconds=ttl_seconds)
    if expires_at <= authorized_at:
        raise C7AuthorityPreparationError("authority expiry must follow authorization")
    for label, value in (
        ("operation_id", operation_id),
        ("controller root artifact digest", expected_controller_root_artifact_digest),
        ("controller_authority_digest", controller_authority_digest),
        ("repository_digest", repository_digest),
        ("protocol_digest", protocol_digest),
        ("configuration_digest", configuration_digest),
        ("policy_digest", policy_digest),
        ("activation_digest", activation_digest),
        ("normalized_report_schema_digest", normalized_report_schema_digest),
    ):
        _validate_digest(value, label)

    verifier = (verifier_factory or C7WorkspaceIdentityVerifier)(workspace)
    try:
        identity = verifier.observe()
    except C7WorkspaceIdentityError as exc:
        raise C7AuthorityPreparationError(str(exc)) from exc
    values = _authority_values(
        identity,
        operation_id=operation_id,
        controller_authority_digest=controller_authority_digest,
        controller_authority_ref=controller_authority_ref,
        issuer_identity=issuer_identity,
        repository_digest=repository_digest,
        protocol_digest=protocol_digest,
        configuration_digest=configuration_digest,
        policy_digest=policy_digest,
        activation_digest=activation_digest,
        normalized_report_schema_digest=normalized_report_schema_digest,
        authorized_at=authorized_at,
        expires_at=expires_at,
    )
    try:
        authority = MainGraduationOfflineExecutionAuthority.model_validate(values)
        # The verifier is called after construction so identity is both
        # independently observed and exact-matched against the authority.
        verifier.verify(authority)
    except (C7WorkspaceIdentityError, ValueError) as exc:
        raise C7AuthorityPreparationError(
            "authority identity or contract validation failed"
        ) from exc
    # Keep this explicit so a future edit cannot accidentally stop checking the
    # controller-root bytes before authority publication.
    if file_digest(controller_root_file) != file_digest_from_bytes(root_raw):
        raise C7AuthorityPreparationError("controller root changed during preparation")
    data = canonical_bytes(authority.model_dump(mode="json"))
    artifact_digest = _write_create_once(output_file, data)
    return C7AuthorityDraft(authority, output_file, artifact_digest)


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
    parser.add_argument("--controller-root-file", type=Path, required=True)
    parser.add_argument(
        "--expected-controller-root-artifact-digest",
        "--expected-controller-root-raw-digest",
        "--expected-controller-root-digest",
        dest="expected_controller_root_artifact_digest",
        required=True,
    )
    parser.add_argument(
        "--controller-authority-digest",
        "--controller-authority-semantic-digest",
        required=True,
    )
    parser.add_argument("--controller-authority-ref", required=True)
    parser.add_argument(
        "--output-file",
        "--authority-file",
        "--draft-authority-file",
        dest="output_file",
        type=Path,
        required=True,
    )
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--issuer-identity", required=True)
    for name in (
        "repository-digest",
        "protocol-digest",
        "configuration-digest",
        "policy-digest",
        "activation-digest",
        "normalized-report-schema-digest",
    ):
        parser.add_argument(f"--{name}", dest=name.replace("-", "_"), required=True)
    parser.add_argument("--authorized-at", type=_parse_datetime, required=True)
    parser.add_argument("--ttl-seconds", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        draft = prepare_authority(
            args.workspace,
            args.controller_root_file,
            args.output_file,
            expected_controller_root_artifact_digest=args.expected_controller_root_artifact_digest,
            controller_authority_digest=args.controller_authority_digest,
            controller_authority_ref=args.controller_authority_ref,
            operation_id=args.operation_id,
            issuer_identity=args.issuer_identity,
            repository_digest=args.repository_digest,
            protocol_digest=args.protocol_digest,
            configuration_digest=args.configuration_digest,
            policy_digest=args.policy_digest,
            activation_digest=args.activation_digest,
            normalized_report_schema_digest=args.normalized_report_schema_digest,
            authorized_at=args.authorized_at,
            ttl_seconds=args.ttl_seconds,
        )
    except (C7AuthorityPreparationError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "draft-created",
                "authority_file": str(draft.artifact_path),
                "authority_digest": draft.semantic_digest,
                "semantic_authority_digest": draft.semantic_digest,
                "authority_artifact_digest": draft.artifact_digest,
                "raw_artifact_digest": draft.artifact_digest,
                "controller_root_raw_digest": args.expected_controller_root_artifact_digest,
                "controller_authority_digest": draft.authority.controller_authority_digest,
                "controller_authority_ref": draft.authority.controller_authority_ref,
                "node_count": len(draft.authority.nodes),
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
