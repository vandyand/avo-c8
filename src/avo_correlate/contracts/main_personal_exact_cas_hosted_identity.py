"""Strict root contract for the offline hosted identity evidence journal."""

# The journal deliberately reparses dynamically selected concrete children;
# runtime exact-type checks below are the contract boundary.
# pyright: reportUnknownArgumentType=false, reportUnknownVariableType=false, reportArgumentType=false

from __future__ import annotations

from typing import Literal

from pydantic import model_validator

from avo_correlate.contracts.base import ArtifactRef, Sha256Digest, StrictModel

_ROLES_MEDIA = {
    "writer_diagnostic_artifact": (
        "main-personal-exact-cas-hosted-configuration-diagnostic",
        "application/vnd.avo.main-personal-exact-cas-hosted-configuration-diagnostic+json",
    ),
    "writer_provenance_artifact": (
        "github-read-provenance",
        "application/vnd.avo.github-read-provenance+json",
    ),
    "observer_snapshot_artifact": (
        "main-base-snapshot",
        "application/vnd.avo.main-base-snapshot+json",
    ),
    "observer_provenance_artifact": (
        "github-read-provenance",
        "application/vnd.avo.github-read-provenance+json",
    ),
    "observer_configuration_artifact": (
        "github-main-base-reader-configuration",
        "application/vnd.avo.github-main-base-reader-configuration+json",
    ),
}


class MainPersonalExactCasHostedIdentityEvidenceRoot(StrictModel):
    """The singleton, non-authoritative root binding five sanitized leaves."""

    schema_version: Literal[1] = 1
    writer_diagnostic_artifact: ArtifactRef
    writer_provenance_artifact: ArtifactRef
    observer_snapshot_artifact: ArtifactRef
    observer_provenance_artifact: ArtifactRef
    observer_configuration_artifact: ArtifactRef
    bundle_digest: Sha256Digest
    is_authoritative: Literal[False] = False
    is_terminal: Literal[False] = False
    readiness_authorized: Literal[False] = False
    deploy_performed: Literal[False] = False
    mutation_performed: Literal[False] = False
    receipt_issued: Literal[False] = False
    completion_claimed: Literal[False] = False
    root_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_root(self) -> MainPersonalExactCasHostedIdentityEvidenceRoot:
        for name, (role, media_type) in _ROLES_MEDIA.items():
            reference = getattr(self, name)
            if type(reference) is not ArtifactRef:
                raise ValueError(f"{name} must be an exact ArtifactRef")
            if reference.role != role or reference.media_type != media_type:
                raise ValueError(f"{name} role or media type differs")
        if any(
            getattr(self, name) is not False
            for name in (
                "is_authoritative",
                "is_terminal",
                "readiness_authorized",
                "deploy_performed",
                "mutation_performed",
                "receipt_issued",
                "completion_claimed",
            )
        ):
            raise ValueError("hosted identity root contains an authority flag")
        if self.root_digest != self.expected_root_digest():
            raise ValueError("hosted identity root digest does not match semantic state")
        return self

    def _digest_values(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "writer_diagnostic_artifact": self.writer_diagnostic_artifact,
            "writer_provenance_artifact": self.writer_provenance_artifact,
            "observer_snapshot_artifact": self.observer_snapshot_artifact,
            "observer_provenance_artifact": self.observer_provenance_artifact,
            "observer_configuration_artifact": self.observer_configuration_artifact,
            "bundle_digest": self.bundle_digest,
            "is_authoritative": False,
            "is_terminal": False,
            "readiness_authorized": False,
            "deploy_performed": False,
            "mutation_performed": False,
            "receipt_issued": False,
            "completion_claimed": False,
        }

    def expected_root_digest(self) -> str:
        from avo_correlate.domain.canonical import canonical_digest

        return canonical_digest(self._digest_values())

    @classmethod
    def build(
        cls,
        *,
        writer_diagnostic_artifact: ArtifactRef,
        writer_provenance_artifact: ArtifactRef,
        observer_snapshot_artifact: ArtifactRef,
        observer_provenance_artifact: ArtifactRef,
        observer_configuration_artifact: ArtifactRef,
        bundle_digest: Sha256Digest,
    ) -> MainPersonalExactCasHostedIdentityEvidenceRoot:
        from avo_correlate.domain.canonical import canonical_digest

        values: dict[str, object] = {
            "schema_version": 1,
            "writer_diagnostic_artifact": writer_diagnostic_artifact,
            "writer_provenance_artifact": writer_provenance_artifact,
            "observer_snapshot_artifact": observer_snapshot_artifact,
            "observer_provenance_artifact": observer_provenance_artifact,
            "observer_configuration_artifact": observer_configuration_artifact,
            "bundle_digest": bundle_digest,
            "is_authoritative": False,
            "is_terminal": False,
            "readiness_authorized": False,
            "deploy_performed": False,
            "mutation_performed": False,
            "receipt_issued": False,
            "completion_claimed": False,
        }
        values["root_digest"] = canonical_digest(values)
        return cls(**values)


# Names used by callers that describe the root as a journal record.
MainPersonalExactCasHostedIdentityJournalRoot = MainPersonalExactCasHostedIdentityEvidenceRoot
MainPersonalExactCasHostedIdentityJournalRecord = MainPersonalExactCasHostedIdentityEvidenceRoot
MainPersonalExactCasHostedIdentityEvidenceRecord = MainPersonalExactCasHostedIdentityEvidenceRoot
MainPersonalExactCasHostedIdentityEvidenceBundleRoot = (
    MainPersonalExactCasHostedIdentityEvidenceRoot
)

__all__ = [
    "MainPersonalExactCasHostedIdentityEvidenceBundleRoot",
    "MainPersonalExactCasHostedIdentityEvidenceRecord",
    "MainPersonalExactCasHostedIdentityEvidenceRoot",
    "MainPersonalExactCasHostedIdentityJournalRecord",
    "MainPersonalExactCasHostedIdentityJournalRoot",
]
