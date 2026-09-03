"""Strict, non-authoritative root for one personal exact-CAS composition."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, cast

from pydantic import StrictInt, field_validator, model_validator

from avo_correlate.contracts.base import (
    ArtifactRef,
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.contracts.main_personal_exact_cas import (
    CandidateRef,
    GitObject,
    MainRef,
    personal_cas_claim_digest,
    personal_cas_operation_id,
)
from avo_correlate.domain.canonical import canonical_digest


class MainPersonalExactCasControllerComposition(StrictModel):
    """Immutable evidence root; it is not an authority or readiness grant.

    The root intentionally records a forward operation only.  Rollback has a
    separate operation and must not reuse this identity or its source.
    """

    schema_version: Literal[1] = 1
    operation_kind: Literal["forward"] = "forward"
    operation_id: Sha256Digest
    activation_digest: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"
    hosted_identity_root_artifact: ArtifactRef
    hosted_identity_bundle_digest: Sha256Digest
    activation_artifact: ArtifactRef
    source_operation_id: Sha256Digest
    source_plan_digest: Sha256Digest
    source_plan_artifact: ArtifactRef
    source_package_digest: Sha256Digest
    source_package_artifact: ArtifactRef
    source_composition_digest: Sha256Digest
    source_composition_artifact: ArtifactRef
    source_composition_proof_artifact: ArtifactRef
    base_commit: GitObject
    base_tree: GitObject
    candidate_commit: GitObject
    candidate_tree: GitObject
    candidate_ref: CandidateRef
    candidate_parents: tuple[GitObject, ...]
    writer_app_id: StrictInt
    writer_installation_id: StrictInt
    writer_identity: NonEmptyString
    writer_configuration_digest: Sha256Digest
    observer_configuration_digest: Sha256Digest
    protection_ruleset_digest: Sha256Digest
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    lease_artifact: ArtifactRef
    lease_expires_at: datetime
    claim_nonce: NonEmptyString
    claim_digest: Sha256Digest
    policy_digest: Sha256Digest
    protocol_digest: Sha256Digest
    fresh_activation_required: Literal[True] = True
    activation_authority_sufficient: Literal[False] = False
    is_authoritative: Literal[False] = False
    is_terminal: Literal[False] = False
    readiness_authorized: Literal[False] = False
    mutation_performed: Literal[False] = False
    receipt_issued: Literal[False] = False
    completion_claimed: Literal[False] = False
    deploy_performed: Literal[False] = False
    root_digest: Sha256Digest

    _aware_lease_expires_at = field_validator("lease_expires_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_root(self) -> MainPersonalExactCasControllerComposition:
        if self.target_ref != "refs/heads/main" or self.operation_kind != "forward":
            raise ValueError("composition root target is not exact forward main")
        if self.hosted_identity_root_artifact.role != (
            "main-personal-exact-cas-hosted-identity-root"
        ) or self.hosted_identity_root_artifact.media_type != (
            "application/vnd.avo.main-personal-exact-cas-hosted-identity-root+json"
        ):
            raise ValueError("hosted identity root artifact is not exact")
        if not self.candidate_ref.startswith("refs/heads/avo/candidate/"):
            raise ValueError("composition root candidate ref is not forward-only")
        if self.candidate_parents != (self.base_commit,):
            raise ValueError("composition root candidate topology differs")
        if self.lease_artifact.role != "main-graduation-lease-evidence-record" or (
            self.lease_artifact.media_type
            != "application/vnd.avo.main-graduation-lease-evidence-record+json"
        ):
            raise ValueError("composition root lease artifact is not exact")
        if self.writer_app_id <= 0 or self.writer_installation_id <= 0:
            raise ValueError("composition root writer identity is invalid")
        if self.activation_authority_sufficient is not False or not self.fresh_activation_required:
            raise ValueError("fresh activation requirement was weakened")
        if self.claim_digest != personal_cas_claim_digest(
            operation_id=self.operation_id,
            lease_identity=self.lease_identity,
            lease_digest=self.lease_digest,
            lease_expires_at=self.lease_expires_at,
            claim_nonce=self.claim_nonce,
        ):
            raise ValueError("composition root claim digest differs")
        expected_operation = personal_cas_operation_id(
            activation_digest=self.activation_digest,
            repository_digest=self.repository_digest,
            target_ref=self.target_ref,
            source_operation_id=self.source_operation_id,
            source_plan_digest=self.source_plan_digest,
            source_composition_digest=self.source_composition_digest,
            base_commit=self.base_commit,
            base_tree=self.base_tree,
            candidate_commit=self.candidate_commit,
            candidate_tree=self.candidate_tree,
            candidate_ref=self.candidate_ref,
            candidate_parents=self.candidate_parents,
            protection_ruleset_digest=self.protection_ruleset_digest,
            writer_app_id=self.writer_app_id,
            writer_installation_id=self.writer_installation_id,
            writer_identity=self.writer_identity,
            lease_identity=self.lease_identity,
            lease_digest=self.lease_digest,
            lease_expires_at=self.lease_expires_at,
            claim_nonce=self.claim_nonce,
        )
        if self.operation_id != expected_operation:
            raise ValueError("composition root operation identity differs")
        if self.root_digest != canonical_digest(
            self.model_dump(exclude={"root_digest"}, mode="json")
        ):
            raise ValueError("composition root digest differs")
        return self

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasControllerComposition:
        values = dict(values)
        values.setdefault("operation_kind", "forward")
        values.setdefault("fresh_activation_required", True)
        values.setdefault("activation_authority_sufficient", False)
        for name in (
            "is_authoritative",
            "is_terminal",
            "readiness_authorized",
            "mutation_performed",
            "receipt_issued",
            "completion_claimed",
            "deploy_performed",
        ):
            values.setdefault(name, False)
        probe = cast(
            MainPersonalExactCasControllerComposition,
            cast(Any, cls).model_construct(**dict(values, root_digest="sha256:" + "0" * 64)),
        )
        return cls.model_validate(
            dict(
                values,
                root_digest=canonical_digest(
                    probe.model_dump(exclude={"root_digest"}, mode="json")
                ),
            )
        )


__all__ = ["MainPersonalExactCasControllerComposition"]
