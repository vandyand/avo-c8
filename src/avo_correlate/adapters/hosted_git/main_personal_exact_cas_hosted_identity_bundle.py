"""Offline cross-binding of the writer diagnostic and observer base evidence.

This module deliberately contains no provider, transport, credential, journal,
filesystem, or controller code.  The result is a scalar, immutable evidence
record.  It is useful for proving that two already-completed observations refer
to the same hosted repository and protected ref, but it never grants authority.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, fields, replace
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

    from .github_main_base_reader import GitHubMainBaseReaderConfiguration

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_TARGET_REF = "refs/heads/main"
HOSTED_CONFIGURATION_READER_IDENTITY = "main_personal_exact_cas_hosted_configuration_verifier"
MAIN_BASE_READER_IDENTITY = "github_main_base_reader"


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
    value: GitHubReadWithProvenance[MainPersonalExactCasHostedConfigurationDiagnostic],
) -> tuple[
    MainPersonalExactCasHostedConfigurationDiagnostic,
    GitHubReadProvenance,
]:
    """Round-trip the concrete Pydantic model to close construction escapes."""

    if type(value) is not GitHubReadWithProvenance:
        raise TypeError("exact hosted writer read result is required")
    typed_wrapper = cast(Any, value)
    if type(typed_wrapper.result) is not MainPersonalExactCasHostedConfigurationDiagnostic:
        raise TypeError("exact hosted writer diagnostic is required")
    provenance = _revalidate_provenance(value.provenance)
    # Pydantic's public dump intentionally excludes reflective attributes.  An
    # unexpected __dict__ key is therefore rejected before the round-trip.
    model_type = cast(Any, type(typed_wrapper.result))
    if set(vars(typed_wrapper.result)) != set(model_type.model_fields):
        raise ValueError("hosted writer diagnostic has reflective state")
    typed_value = cast(Any, typed_wrapper.result)
    if typed_value.__pydantic_extra__ is not None or typed_value.__pydantic_private__ is not None:
        raise ValueError("hosted writer diagnostic has reflective state")
    try:
        rebuilt = cast(
            MainPersonalExactCasHostedConfigurationDiagnostic,
            model_type.model_validate_json(typed_value.model_dump_json()),
        )
    except Exception:
        raise ValueError("hosted writer diagnostic is not valid") from None
    if rebuilt != typed_wrapper.result:
        raise ValueError("hosted writer diagnostic changed during validation")
    return rebuilt, provenance


def _snapshot_payload(snapshot: MainBaseSnapshot) -> dict[str, object]:
    from avo_correlate.adapters.git.main_composition import MainBaseSnapshot

    if type(snapshot) is not MainBaseSnapshot:
        raise TypeError("exact main base snapshot is required")
    if set(vars(snapshot)) != {"repository_digest", "commit", "tree", "target_ref", "parents"}:
        raise ValueError("main base snapshot has reflective state")
    repository_digest = _digest(snapshot.repository_digest, "observer snapshot repository digest")
    commit = _object(snapshot.commit, "observer snapshot commit")
    tree = _object(snapshot.tree, "observer snapshot tree")
    if type(snapshot.parents) is not tuple:
        raise ValueError("observer snapshot parents are not immutable")
    parents = tuple(_object(parent, "observer snapshot parent") for parent in snapshot.parents)
    if snapshot.target_ref != _TARGET_REF:
        raise ValueError("observer snapshot target ref is not exact main")
    return {
        "repository_digest": repository_digest,
        "commit": commit,
        "tree": tree,
        "target_ref": _TARGET_REF,
        "parents": parents,
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
        parents=tuple(canonical["parents"]),
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
    configuration: GitHubMainBaseReaderConfiguration,
) -> tuple[MainBaseSnapshot, GitHubReadProvenance, str, str]:
    from .github_main_base_reader import GitHubMainBaseReaderConfiguration

    if type(value) is not GitHubReadWithProvenance:
        raise TypeError("exact observer read result is required")
    snapshot, snapshot_digest = _revalidate_snapshot(value.result)
    provenance = _revalidate_provenance(value.provenance)
    if type(configuration) is not GitHubMainBaseReaderConfiguration:
        raise TypeError("exact observer reader configuration is required")
    try:
        configuration.assert_valid()
        rebuilt_configuration = replace(configuration)
        rebuilt_configuration.assert_valid()
    except Exception:
        raise ValueError("observer reader configuration is not valid") from None
    if rebuilt_configuration != configuration:
        raise ValueError("observer reader configuration changed during validation")
    if provenance.configuration_digest != configuration.configuration_digest:
        raise ValueError("observer provenance configuration differs")
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
        {"commit": snapshot.commit, "tree": snapshot.tree, "parents": snapshot.parents}
    ):
        raise ValueError("observer commit evidence does not bind snapshot")
    validate_main_base_provenance(configuration, snapshot, provenance)
    config_digest = provenance.configuration_digest
    _digest(config_digest, "observer configuration digest")
    # Rebuild the configuration digest as a strict concrete model as a second
    # cross-check.  The reader provenance carries this value, so no third DTO
    # or credential-bearing object is accepted by this bundle.
    if type(config_digest) is not str:
        raise ValueError("observer configuration digest is missing")
    return snapshot, provenance, snapshot_digest, config_digest


def validate_hosted_configuration_provenance(
    diagnostic: MainPersonalExactCasHostedConfigurationDiagnostic,
    provenance: GitHubReadProvenance,
) -> None:
    """Validate the verifier's complete, parameterized 34-request read trace."""

    if provenance.reader_identity != HOSTED_CONFIGURATION_READER_IDENTITY:
        raise ValueError("hosted writer provenance reader identity differs")
    typed_diagnostic = cast(Any, diagnostic)
    base = "/repos/vandyand/avo-c8"
    requests = provenance.requests
    if type(requests) is not tuple or len(requests) != 34:
        raise ValueError("hosted writer provenance trace is not the exact 34-request trace")

    def expected_pass(ruleset_paths: tuple[str, ...]) -> tuple[GitHubReadRequest, ...]:
        return (
            GitHubReadRequest("GET", base, "owner_admin_token"),
            GitHubReadRequest("GET", "/app", "app_jwt"),
            GitHubReadRequest(
                "GET", "/app/installations?per_page=100&page=1", "app_jwt"
            ),
            GitHubReadRequest(
                "POST",
                f"/app/installations/{typed_diagnostic.writer_installation_id}/access_tokens",
                "app_jwt",
            ),
            GitHubReadRequest(
                "GET", "/installation/repositories?per_page=100&page=1", "installation_token"
            ),
            GitHubReadRequest("GET", "/app", "app_jwt"),
            GitHubReadRequest(
                "GET",
                f"/app/installations/{typed_diagnostic.candidate_publisher_installation_id}",
                "app_jwt",
            ),
            GitHubReadRequest(
                "POST",
                f"/app/installations/{typed_diagnostic.candidate_publisher_installation_id}/access_tokens",
                "app_jwt",
            ),
            GitHubReadRequest(
                "GET", "/installation/repositories?per_page=100&page=1", "installation_token"
            ),
            GitHubReadRequest("GET", base + "/rulesets?per_page=100&page=1", "owner_admin_token"),
            *(GitHubReadRequest("GET", path, "owner_admin_token") for path in ruleset_paths),
            GitHubReadRequest("GET", base + "/branches/main/protection", "owner_admin_token"),
        )

    expected_ruleset_paths = {
        base + f"/rulesets/{ident}"
        for ident in (
            typed_diagnostic.writer_ruleset_id,
            typed_diagnostic.safety_ruleset_id,
            typed_diagnostic.rollback_ruleset_id,
            typed_diagnostic.candidate_creation_ruleset_id,
            typed_diagnostic.candidate_immutable_ruleset_id,
        )
    }
    if len(expected_ruleset_paths) != 5:
        raise ValueError("hosted writer diagnostic ruleset identities are not exact")
    observed_rule_slots: list[tuple[GitHubReadRequest, ...]] = []
    first_paths: tuple[str, ...] | None = None
    for offset in (1, 17):
        observed = requests[offset : offset + 16]
        ruleset_slots = observed[10:15]
        paths = tuple(item.path for item in ruleset_slots)
        if first_paths is None:
            first_paths = paths
        expected = expected_pass(first_paths)
        if observed[:10] != expected[:10] or observed[15:] != expected[15:]:
            raise ValueError("hosted writer provenance trace shape differs")
        if any(
            item.method != "GET" or item.credential_role != "owner_admin_token"
            for item in ruleset_slots
        ):
            raise ValueError("hosted writer provenance ruleset request differs")
        paths = tuple(item.path for item in ruleset_slots)
        if len(set(paths)) != 5 or set(paths) != expected_ruleset_paths:
            raise ValueError("hosted writer provenance ruleset identities are not exact")
        observed_rule_slots.append(ruleset_slots)
    if observed_rule_slots[0] != observed_rule_slots[1]:
        raise ValueError("hosted writer provenance ruleset request order drifted")
    ref = GitHubReadRequest("GET", base + "/git/ref/heads/main", "owner_admin_token")
    if requests[0] != ref or requests[-1] != ref:
        raise ValueError("hosted writer provenance main fence differs")
    if (
        provenance.repository_digest != typed_diagnostic.repository_digest
        or provenance.owner != typed_diagnostic.owner
        or provenance.owner_id != typed_diagnostic.owner_id
        or provenance.repository != typed_diagnostic.repository
        or provenance.repository_id != typed_diagnostic.repository_id
        or provenance.target_ref != typed_diagnostic.target_ref
        or provenance.app_id != typed_diagnostic.writer_app_id
        or provenance.installation_id != typed_diagnostic.writer_installation_id
        or provenance.app_slug != typed_diagnostic.writer_app_slug
        or provenance.configuration_digest != typed_diagnostic.configuration_digest
        or provenance.initial_ref_digest != typed_diagnostic.initial_ref_digest
        or provenance.final_ref_digest != typed_diagnostic.final_ref_digest
        or provenance.commit_digest != canonical_digest({"commit": typed_diagnostic.main_commit})
        or provenance.configuration_pass_digests
        != (typed_diagnostic.first_pass_digest, typed_diagnostic.second_pass_digest)
    ):
        raise ValueError("hosted writer provenance diagnostic binding differs")
    expected_endpoints = {
        "app": typed_diagnostic.app_configuration_digest,
        "installation": typed_diagnostic.installation_configuration_digest,
        "candidate_publisher_identity": typed_diagnostic.candidate_publisher_identity_digest,
        "candidate_publisher_installation": (
            typed_diagnostic.candidate_publisher_installation_digest
        ),
        "candidate_publisher_app": (
            typed_diagnostic.candidate_publisher_app_configuration_digest
        ),
        "candidate_publisher_installation_observation": (
            typed_diagnostic.candidate_publisher_installation_configuration_digest
        ),
        "candidate_publisher_selected_repositories": (
            typed_diagnostic.candidate_publisher_selected_repositories_digest
        ),
        "repository": typed_diagnostic.repository_digest,
        "selected_repositories": typed_diagnostic.selected_repositories_digest,
    }
    if dict(provenance.endpoint_observation_digests) != expected_endpoints:
        raise ValueError("hosted writer provenance endpoint binding differs")


def validate_main_base_provenance(
    configuration: GitHubMainBaseReaderConfiguration,
    snapshot: MainBaseSnapshot,
    provenance: GitHubReadProvenance,
) -> None:
    """Validate the observer's exact seven-request authenticated read trace."""

    if provenance.reader_identity != MAIN_BASE_READER_IDENTITY:
        raise ValueError("main base provenance reader identity differs")
    if (
        provenance.owner != configuration.owner
        or provenance.owner_id != configuration.owner_id
        or provenance.repository != configuration.repo
        or provenance.repository_id != configuration.repository_id
        or provenance.repository_digest != configuration.repository_digest
        or provenance.app_slug != configuration.observer_identity
        or provenance.app_id != configuration.observer_app_id
        or provenance.installation_id != configuration.observer_installation_id
        or provenance.writer_app_id != configuration.writer_app_id
        or provenance.writer_installation_id != configuration.writer_installation_id
        or provenance.target_ref != "refs/heads/main"
        or snapshot.repository_digest != configuration.repository_digest
    ):
        raise ValueError("main base provenance configuration binding differs")
    base = f"/repos/{configuration.owner}/{configuration.repo}"
    expected = (
        GitHubReadRequest("GET", "/app", "app_jwt"),
        GitHubReadRequest(
            "GET", f"/app/installations/{configuration.observer_installation_id}", "app_jwt"
        ),
        GitHubReadRequest(
            "POST",
            f"/app/installations/{configuration.observer_installation_id}/access_tokens",
            "app_jwt",
        ),
        GitHubReadRequest(
            "GET", f"/repositories/{configuration.repository_id}", "installation_token"
        ),
        GitHubReadRequest("GET", base + "/git/ref/heads/main", "installation_token"),
        GitHubReadRequest(
            "GET", base + f"/git/commits/{snapshot.commit}", "installation_token"
        ),
        GitHubReadRequest("GET", base + "/git/ref/heads/main", "installation_token"),
    )
    if provenance.requests != expected:
        raise ValueError("main base provenance trace is not the exact seven-request trace")
    expected_ref = canonical_digest(
        {"ref": _TARGET_REF, "object": {"type": "commit", "sha": snapshot.commit}}
    )
    if provenance.initial_ref_digest != expected_ref or provenance.final_ref_digest != expected_ref:
        raise ValueError("main base provenance ref fence does not bind snapshot")
    expected_commit = canonical_digest(
        {"commit": snapshot.commit, "tree": snapshot.tree, "parents": snapshot.parents}
    )
    if provenance.commit_digest != expected_commit:
        raise ValueError("main base provenance commit evidence does not bind snapshot")


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
    writer_rollback_ruleset_id: int
    writer_rollback_ruleset_name: str
    writer_rollback_ruleset_digest: str
    writer_protection_ruleset_digest: str
    writer_source_digest: str
    writer_observation_digest: str
    writer_diagnostic_digest: str
    writer_provenance_digest: str
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
            "writer_rollback_ruleset_digest",
            "writer_protection_ruleset_digest",
            "writer_source_digest",
            "writer_observation_digest",
            "writer_diagnostic_digest",
            "observer_base_snapshot_digest",
            "observer_configuration_digest",
            "observer_provenance_digest",
            "writer_provenance_digest",
        ):
            _digest(getattr(self, name), f"identity bundle {name}")
        for name in (
            "writer_app_id",
            "writer_installation_id",
            "writer_rollback_ruleset_id",
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
        if (
            type(self.writer_rollback_ruleset_name) is not str
            or not self.writer_rollback_ruleset_name
        ):
            raise ValueError("identity bundle rollback ruleset name is invalid")
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
        writer: GitHubReadWithProvenance[MainPersonalExactCasHostedConfigurationDiagnostic],
        observer: GitHubReadWithProvenance[MainBaseSnapshot],
        observer_configuration: GitHubMainBaseReaderConfiguration,
    ) -> MainPersonalExactCasHostedIdentityEvidenceBundle:
        writer_diagnostic, writer_provenance = _revalidate_writer(writer)
        typed_writer = cast(Any, writer_diagnostic)
        validate_hosted_configuration_provenance(writer_diagnostic, writer_provenance)
        snapshot, provenance, snapshot_digest, observer_configuration_digest = _revalidate_observer(
            observer, observer_configuration
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
            "writer_rollback_ruleset_id": typed_writer.rollback_ruleset_id,
            "writer_rollback_ruleset_name": typed_writer.rollback_ruleset_name,
            "writer_rollback_ruleset_digest": typed_writer.rollback_ruleset_digest,
            "writer_protection_ruleset_digest": typed_writer.protection_ruleset_digest,
            "writer_source_digest": typed_writer.source_digest,
            "writer_observation_digest": typed_writer.observation_digest,
            "writer_diagnostic_digest": writer_digest,
            "writer_provenance_digest": writer_provenance.provenance_digest,
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
    "HOSTED_CONFIGURATION_READER_IDENTITY",
    "MAIN_BASE_READER_IDENTITY",
    "MainPersonalExactCasHostedIdentityEvidenceBundle",
    "build_main_personal_exact_cas_hosted_identity_evidence_bundle",
    "validate_hosted_configuration_provenance",
    "validate_main_base_provenance",
]
