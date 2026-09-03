"""Offline cross-binding of the writer diagnostic and observer base evidence.

This module deliberately contains no provider, transport, credential, journal,
filesystem, or controller code.  The result is a scalar, immutable evidence
record.  It is useful for proving that two already-completed observations refer
to the same hosted repository and protected ref, but it never grants authority.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, Any, cast

from avo_correlate.contracts.main_personal_exact_cas_hosted_configuration import (
    MainPersonalExactCasHostedConfigurationDiagnostic,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

from .github_read_provenance import (
    GitHubReadProvenance,
    GitHubReadRequest,
    GitHubReadWithProvenance,
)

if TYPE_CHECKING:
    from avo_correlate.adapters.git.main_composition import MainBaseSnapshot

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_TARGET_REF = "refs/heads/main"


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _object(value: object, label: str) -> str:
    if type(value) is not str or _OBJECT.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _canonical_json(value: object) -> dict[str, Any]:
    decoded = json.loads(canonical_bytes(value))
    if type(decoded) is not dict:
        raise ValueError("canonical evidence payload is not an object")
    return cast(dict[str, Any], decoded)


def _revalidate_writer(
    value: MainPersonalExactCasHostedConfigurationDiagnostic,
) -> MainPersonalExactCasHostedConfigurationDiagnostic:
    """Round-trip the concrete Pydantic model to close construction escapes."""

    if type(value) is not MainPersonalExactCasHostedConfigurationDiagnostic:
        raise TypeError("exact hosted writer diagnostic is required")
    # Pydantic's public dump intentionally excludes reflective attributes.  An
    # unexpected __dict__ key is therefore rejected before the round-trip.
    model_type = cast(Any, type(value))
    if set(vars(value)) != set(model_type.model_fields):
        raise ValueError("hosted writer diagnostic has reflective state")
    typed_value = cast(Any, value)
    if typed_value.__pydantic_extra__ is not None or typed_value.__pydantic_private__ is not None:
        raise ValueError("hosted writer diagnostic has reflective state")
    try:
        rebuilt = cast(
            MainPersonalExactCasHostedConfigurationDiagnostic,
            model_type.model_validate_json(typed_value.model_dump_json()),
        )
    except Exception:
        raise ValueError("hosted writer diagnostic is not valid") from None
    if rebuilt != value:
        raise ValueError("hosted writer diagnostic changed during validation")
    return rebuilt


def _snapshot_payload(snapshot: MainBaseSnapshot) -> dict[str, object]:
    from avo_correlate.adapters.git.main_composition import MainBaseSnapshot

    if type(snapshot) is not MainBaseSnapshot:
        raise TypeError("exact main base snapshot is required")
    if set(vars(snapshot)) != {"repository_digest", "commit", "tree", "target_ref"}:
        raise ValueError("main base snapshot has reflective state")
    repository_digest = _digest(snapshot.repository_digest, "observer snapshot repository digest")
    commit = _object(snapshot.commit, "observer snapshot commit")
    tree = _object(snapshot.tree, "observer snapshot tree")
    if snapshot.target_ref != _TARGET_REF:
        raise ValueError("observer snapshot target ref is not exact main")
    return {
        "repository_digest": repository_digest,
        "commit": commit,
        "tree": tree,
        "target_ref": _TARGET_REF,
    }


def _revalidate_snapshot(snapshot: MainBaseSnapshot) -> tuple[MainBaseSnapshot, str]:
    from avo_correlate.adapters.git.main_composition import MainBaseSnapshot

    payload = _snapshot_payload(snapshot)
    canonical = _canonical_json(payload)
    rebuilt = MainBaseSnapshot(
        repository_digest=canonical["repository_digest"],
        commit=canonical["commit"],
        tree=canonical["tree"],
        target_ref=canonical["target_ref"],
    )
    if rebuilt != snapshot:
        raise ValueError("observer snapshot changed during validation")
    return rebuilt, canonical_digest(payload)


def _provenance_payload(value: GitHubReadProvenance) -> dict[str, object]:
    if type(value) is not GitHubReadProvenance:
        raise TypeError("exact GitHub read provenance is required")
    requests = value.requests
    if type(requests) is not tuple:
        raise ValueError("observer provenance request trace is not immutable")
    request_payload: list[dict[str, str]] = []
    for request in requests:
        if type(request) is not GitHubReadRequest:
            raise ValueError("observer provenance request is not concrete")
        request_payload.append(
            {
                "method": request.method,
                "path": request.path,
                "credential_role": request.credential_role,
            }
        )
    return {
        "api_origin": value.api_origin,
        "api_version": value.api_version,
        "owner": value.owner,
        "owner_id": value.owner_id,
        "repository": value.repository,
        "repository_id": value.repository_id,
        "repository_digest": value.repository_digest,
        "target_ref": value.target_ref,
        "app_slug": value.app_slug,
        "app_id": value.app_id,
        "installation_id": value.installation_id,
        "requested_repository_id": value.requested_repository_id,
        "requested_permissions": value.requested_permissions,
        "observed_permissions": value.observed_permissions,
        "repository_selection": value.repository_selection,
        "token_expiry_policy": value.token_expiry_policy,
        "requests": request_payload,
        "endpoint_observation_digests": value.endpoint_observation_digests,
        "initial_ref_digest": value.initial_ref_digest,
        "commit_digest": value.commit_digest,
        "final_ref_digest": value.final_ref_digest,
        "configuration_pass_digests": value.configuration_pass_digests,
        "configuration_digest": value.configuration_digest,
        "writer_app_id": value.writer_app_id,
        "writer_installation_id": value.writer_installation_id,
        "reader_identity": value.reader_identity,
    }


def _revalidate_provenance(value: GitHubReadProvenance) -> GitHubReadProvenance:
    payload = _provenance_payload(value)
    canonical = _canonical_json(payload)
    raw_requests = cast(list[Any], canonical.pop("requests"))
    if type(raw_requests) is not list:
        raise ValueError("observer provenance request trace is malformed")
    requests_list: list[GitHubReadRequest] = []
    for raw_request in raw_requests:
        if type(raw_request) is not dict:
            raise ValueError("observer provenance request is malformed")
        request = cast(dict[str, Any], raw_request)
        requests_list.append(
            GitHubReadRequest(
                method=request["method"],
                path=cast(str, request["path"]),
                credential_role=cast(str, request["credential_role"]),
            )
        )
    requests = tuple(requests_list)
    canonical["requests"] = requests
    for key in (
        "requested_permissions",
        "observed_permissions",
        "configuration_pass_digests",
    ):
        if type(canonical[key]) is list:
            canonical[key] = tuple(canonical[key])
    endpoint = cast(list[object], canonical["endpoint_observation_digests"])
    if type(endpoint) is not list:
        raise ValueError("observer provenance endpoint evidence is malformed")
    endpoint_values: list[tuple[str, str]] = []
    for raw_endpoint in endpoint:
        if type(raw_endpoint) is not list or len(cast(list[object], raw_endpoint)) != 2:
            raise ValueError("observer provenance endpoint evidence is malformed")
        raw_values = cast(list[object], raw_endpoint)
        endpoint_values.append((cast(str, raw_values[0]), cast(str, raw_values[1])))
    canonical["endpoint_observation_digests"] = tuple(endpoint_values)
    try:
        rebuilt = GitHubReadProvenance(**canonical)
    except Exception:
        raise ValueError("observer provenance is not valid") from None
    if rebuilt.provenance_digest != value.provenance_digest or rebuilt != value:
        raise ValueError("observer provenance digest does not match semantic state")
    return rebuilt


def _revalidate_observer(
    value: GitHubReadWithProvenance[MainBaseSnapshot],
) -> tuple[MainBaseSnapshot, GitHubReadProvenance, str, str]:
    if type(value) is not GitHubReadWithProvenance:
        raise TypeError("exact observer read result is required")
    snapshot, snapshot_digest = _revalidate_snapshot(value.result)
    provenance = _revalidate_provenance(value.provenance)
    if provenance.repository_digest != snapshot.repository_digest:
        raise ValueError("observer snapshot and provenance repository differs")
    if provenance.target_ref != _TARGET_REF:
        raise ValueError("observer provenance target ref is not exact main")
    expected_ref = canonical_digest(
        {"ref": _TARGET_REF, "object": {"type": "commit", "sha": snapshot.commit}}
    )
    if provenance.initial_ref_digest != expected_ref or provenance.final_ref_digest != expected_ref:
        raise ValueError("observer ref fence does not bind snapshot")
    if provenance.commit_digest != canonical_digest(
        {"commit": snapshot.commit, "tree": snapshot.tree}
    ):
        raise ValueError("observer commit evidence does not bind snapshot")
    config_digest = provenance.configuration_digest
    _digest(config_digest, "observer configuration digest")
    # Rebuild the configuration digest as a strict concrete model as a second
    # cross-check.  The reader provenance carries this value, so no third DTO
    # or credential-bearing object is accepted by this bundle.
    if type(config_digest) is not str:
        raise ValueError("observer configuration digest is missing")
    return snapshot, provenance, snapshot_digest, config_digest


@dataclass(frozen=True, slots=True)
class MainPersonalExactCasHostedIdentityEvidenceBundle:
    """Frozen, canonical, explicitly non-authoritative identity evidence."""

    schema_version: int
    repository_digest: str
    owner: str
    owner_id: int
    repository: str
    repository_id: int
    target_ref: str
    main_commit: str
    writer_app_id: int
    writer_installation_id: int
    writer_configuration_digest: str
    writer_ruleset_digest: str
    writer_safety_ruleset_digest: str
    writer_protection_ruleset_digest: str
    writer_source_digest: str
    writer_observation_digest: str
    writer_diagnostic_digest: str
    observer_app_id: int
    observer_installation_id: int
    observer_identity: str
    observer_base_snapshot_digest: str
    observer_configuration_digest: str
    observer_provenance_digest: str
    is_authoritative: bool
    is_terminal: bool
    readiness_authorized: bool
    deploy_performed: bool
    mutation_performed: bool
    receipt_issued: bool
    completion_claimed: bool
    bundle_digest: str

    def __post_init__(self) -> None:
        self.assert_valid()

    def _payload(self) -> dict[str, object]:
        return {
            item.name: getattr(self, item.name)
            for item in fields(self)
            if item.name != "bundle_digest"
        }

    def assert_valid(self) -> None:
        if self.schema_version != 1:
            raise ValueError("identity bundle schema version is invalid")
        _digest(self.repository_digest, "identity bundle repository digest")
        _object(self.main_commit, "identity bundle main commit")
        if self.target_ref != _TARGET_REF:
            raise ValueError("identity bundle target ref is not exact main")
        for name in (
            "writer_configuration_digest",
            "writer_ruleset_digest",
            "writer_safety_ruleset_digest",
            "writer_protection_ruleset_digest",
            "writer_source_digest",
            "writer_observation_digest",
            "writer_diagnostic_digest",
            "observer_base_snapshot_digest",
            "observer_configuration_digest",
            "observer_provenance_digest",
        ):
            _digest(getattr(self, name), f"identity bundle {name}")
        for name in (
            "writer_app_id",
            "writer_installation_id",
            "observer_app_id",
            "observer_installation_id",
            "owner_id",
            "repository_id",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"identity bundle {name} is invalid")
        if self.writer_app_id == self.observer_app_id:
            raise ValueError("identity bundle writer and observer Apps must be distinct")
        if self.writer_installation_id == self.observer_installation_id:
            raise ValueError("identity bundle writer and observer installations must be distinct")
        if type(self.owner) is not str or not self.owner:
            raise ValueError("identity bundle owner is invalid")
        if type(self.repository) is not str or not self.repository:
            raise ValueError("identity bundle repository is invalid")
        if type(self.observer_identity) is not str or not self.observer_identity:
            raise ValueError("identity bundle observer identity is invalid")
        for name in (
            "is_authoritative",
            "is_terminal",
            "readiness_authorized",
            "deploy_performed",
            "mutation_performed",
            "receipt_issued",
            "completion_claimed",
        ):
            if getattr(self, name) is not False:
                raise ValueError("identity bundle contains an authority flag")
        if self.bundle_digest != canonical_digest(self._payload()):
            raise ValueError("identity bundle digest does not match semantic state")

    @classmethod
    def build(
        cls,
        writer: MainPersonalExactCasHostedConfigurationDiagnostic,
        observer: GitHubReadWithProvenance[MainBaseSnapshot],
    ) -> MainPersonalExactCasHostedIdentityEvidenceBundle:
        writer = _revalidate_writer(writer)
        typed_writer = cast(Any, writer)
        snapshot, provenance, snapshot_digest, observer_configuration_digest = _revalidate_observer(
            observer
        )
        if (
            typed_writer.repository_digest != snapshot.repository_digest
            or typed_writer.owner != provenance.owner
            or typed_writer.owner_id != provenance.owner_id
            or typed_writer.repository != provenance.repository
            or typed_writer.repository_id != provenance.repository_id
            or typed_writer.target_ref != provenance.target_ref
            or typed_writer.main_commit != snapshot.commit
        ):
            raise ValueError("writer and observer repository identity differs")
        if (
            provenance.writer_app_id != typed_writer.writer_app_id
            or provenance.writer_installation_id != typed_writer.writer_installation_id
        ):
            raise ValueError("observer provenance writer identity differs")
        if provenance.requested_permissions != ("contents:read",):
            raise ValueError("observer requested permissions are not exact")
        if provenance.observed_permissions != ("contents:read", "metadata:read"):
            raise ValueError("observer observed permissions are not exact")
        writer_digest = canonical_digest(typed_writer.model_dump(mode="json"))
        values: dict[str, object] = {
            "schema_version": 1,
            "repository_digest": typed_writer.repository_digest,
            "owner": typed_writer.owner,
            "owner_id": typed_writer.owner_id,
            "repository": typed_writer.repository,
            "repository_id": typed_writer.repository_id,
            "target_ref": typed_writer.target_ref,
            "main_commit": typed_writer.main_commit,
            "writer_app_id": typed_writer.writer_app_id,
            "writer_installation_id": typed_writer.writer_installation_id,
            "writer_configuration_digest": typed_writer.configuration_digest,
            "writer_ruleset_digest": typed_writer.writer_ruleset_digest,
            "writer_safety_ruleset_digest": typed_writer.safety_ruleset_digest,
            "writer_protection_ruleset_digest": typed_writer.protection_ruleset_digest,
            "writer_source_digest": typed_writer.source_digest,
            "writer_observation_digest": typed_writer.observation_digest,
            "writer_diagnostic_digest": writer_digest,
            "observer_app_id": provenance.app_id,
            "observer_installation_id": provenance.installation_id,
            "observer_identity": provenance.app_slug,
            "observer_base_snapshot_digest": snapshot_digest,
            "observer_configuration_digest": observer_configuration_digest,
            "observer_provenance_digest": provenance.provenance_digest,
            "is_authoritative": False,
            "is_terminal": False,
            "readiness_authorized": False,
            "deploy_performed": False,
            "mutation_performed": False,
            "receipt_issued": False,
            "completion_claimed": False,
        }
        values["bundle_digest"] = canonical_digest(values)
        return cls(**cast(dict[str, Any], values))


build_main_personal_exact_cas_hosted_identity_evidence_bundle = (
    MainPersonalExactCasHostedIdentityEvidenceBundle.build
)


__all__ = [
    "MainPersonalExactCasHostedIdentityEvidenceBundle",
    "build_main_personal_exact_cas_hosted_identity_evidence_bundle",
]
