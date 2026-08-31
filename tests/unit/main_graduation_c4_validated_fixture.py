"""Filesystem foundation for a model-validated C4 completion fixture.

This deliberately starts with the upstream campaign package (which is itself
round-trip validated) and builds the main-graduation C2 records with ordinary
Pydantic constructors.  It is kept separate from the historical construct-
based journal coverage fixture.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from avo_correlate.adapters.artifacts.main_graduation_journal import MainGraduationJournal
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation import (
    MainCompositionArtifact,
    MainCompositionProof,
    MainDeltaManifest,
    MainGraduationPlan,
    MainReleaseIssuerBinding,
    MainSourcePackageBinding,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from avo_correlate.contracts.promotion_policy import path_manifest_digest
from tests.unit.test_rollback_bundle_authority import _complete_package

NOW = datetime(2026, 1, 1, tzinfo=UTC)
MAIN_OPERATION = "sha256:" + "1" * 64
REPOSITORY = "sha256:" + "a" * 64
BASE = "a" * 40
HEAD = "c" * 40
TREE = "b" * 40


def _source(root: Path) -> MainSourcePackageBinding:
    package, evidence_bytes, evidence_ref = _complete_package()
    store = MainGraduationJournal(root)._store
    package_bytes = canonical_bytes(package)
    package_ref = ArtifactRef(
        digest=canonical_digest(package),
        size_bytes=len(package_bytes),
        media_type="application/vnd.avo.integration-campaign+json",
        role="integration-campaign-package",
        created_at=NOW,
    )
    store.put_bytes(package_bytes, media_type=package_ref.media_type, role=package_ref.role, max_bytes=2_000_000)
    store.put_bytes(evidence_bytes, media_type=evidence_ref.media_type, role=evidence_ref.role, max_bytes=2_000_000)
    store.put_bytes(canonical_bytes(package.lease_evidence), media_type=package.lease_evidence_artifact.media_type, role=package.lease_evidence_artifact.role, max_bytes=2_000_000)
    return MainSourcePackageBinding.model_validate(
        {
            "operation_id": MAIN_OPERATION,
            "source_operation_id": package.intent.operation_id,
            "repository_digest": REPOSITORY,
            "target_ref": "refs/heads/main",
            "package_digest": package_ref.digest,
            "package_artifact": package_ref,
            "child_artifacts": [evidence_ref, package.lease_evidence_artifact],
            "source_result_commit": package.reconciliation.target_head_commit,
            "source_result_tree": package.reconciliation.target_head_tree,
            "source_result_parent": package.reconciliation.target_first_parent,
            "source_issuer": "controller",
        }
    )


@pytest.mark.xfail(
    strict=True,
    reason="validated upstream factory emits application/json evidence; main journal requires application/vnd.avo.* child media",
)
def test_validated_c2_records_materialize_and_reload(tmp_path: Path) -> None:
    source = _source(tmp_path)
    issuer_values = {
        "operation_id": MAIN_OPERATION,
        "repository_digest": REPOSITORY,
        "target_ref": "refs/heads/main",
        "controller_config_digest": "sha256:" + "2" * 64,
        "issuer_id": "isolated-release",
        "app_id": 9001,
        "isolation_digest": "sha256:" + "1" * 64,
        "issuer_domain": "isolated-release-check",
        "trusted_source_issuer": source.source_issuer,
        "trusted_source_domain": source.source_domain,
    }
    issuer_probe = MainReleaseIssuerBinding.model_construct(
        **issuer_values, binding_digest="sha256:" + "0" * 64
    )
    issuer = MainReleaseIssuerBinding.model_validate(
        issuer_values
        | {
            "binding_digest": canonical_digest(
                issuer_probe.model_dump(exclude={"binding_digest"}, mode="json")
            )
        }
    )
    paths = ["src/feature.py"]
    delta_values = {
        "repository_digest": REPOSITORY, "target_ref": "refs/heads/main", "operation_id": MAIN_OPERATION,
        "package_digest": source.package_digest, "source_result_commit": HEAD, "source_result_parent": BASE,
        "source_result_tree": TREE, "changed_paths": paths, "path_manifest_digest": path_manifest_digest(paths),
        "ordinary_risk_digest": canonical_digest({"ordinary_risk": "ordinary", "changed_paths": paths, "path_manifest_digest": path_manifest_digest(paths)}),
    }
    delta_probe = MainDeltaManifest.model_construct(**delta_values, delta_digest="sha256:" + "0" * 64)
    delta = MainDeltaManifest.model_validate(delta_values | {"delta_digest": canonical_digest(delta_probe.model_dump(exclude={"delta_digest"}, mode="json"))})
    composition_values = {
        "repository_digest": REPOSITORY, "target_ref": "refs/heads/main", "operation_id": MAIN_OPERATION,
        "package_digest": source.package_digest, "delta_digest": delta.delta_digest, "base_commit": BASE,
        "base_tree": TREE, "candidate_commit": HEAD, "candidate_tree": TREE, "candidate_parent_commit": BASE,
        "candidate_ref": "refs/heads/avo/candidate/" + "1" * 64, "retention_ref": "refs/avo/main-composition/" + "1" * 64,
    }
    composition_probe = MainCompositionArtifact.model_construct(**composition_values, composition_digest="sha256:" + "0" * 64)
    composition = MainCompositionArtifact.model_validate(composition_values | {"composition_digest": canonical_digest(composition_probe.model_dump(exclude={"composition_digest"}, mode="json"))})
    proof_values = {
        "repository_digest": REPOSITORY, "target_ref": "refs/heads/main", "operation_id": MAIN_OPERATION,
        "source_operation_id": source.source_operation_id, "package_digest": source.package_digest,
        "source_result_commit": HEAD, "source_result_parent": BASE, "source_result_tree": TREE,
        "delta_digest": delta.delta_digest, "path_manifest_digest": delta.path_manifest_digest,
        "ordinary_risk_digest": delta.ordinary_risk_digest, "composition_digest": composition.composition_digest,
        "base_commit": BASE, "base_tree": TREE, "candidate_commit": HEAD, "candidate_tree": TREE,
        "candidate_parent_commit": BASE, "candidate_ref": composition.candidate_ref, "retention_ref": composition.retention_ref,
        "controller_config_digest": issuer.controller_config_digest, "policy_epoch": issuer.controller_config_digest,
        "source_issuer": source.source_issuer, "source_domain": source.source_domain,
        "verifier_identity": "avo_correlate.adapters.git.main_composition.MainCompositionAdapter", "verifier_version": "1",
        "base_observer_identity": "avo_correlate.adapters.git.main_composition.MainBaseReader", "git_root_digest": REPOSITORY,
    }
    proof_probe = MainCompositionProof.model_construct(**proof_values, proof_digest="sha256:" + "0" * 64)
    proof = MainCompositionProof.model_validate(proof_values | {"proof_digest": canonical_digest(proof_probe.model_dump(exclude={"proof_digest"}, mode="json"))})
    proof_ref = ArtifactRef(digest=canonical_digest(proof), size_bytes=len(canonical_bytes(proof)), media_type="application/vnd.avo.main-graduation-composition-proof+json", role="main-graduation-composition-proof", created_at=NOW)
    journal = MainGraduationJournal(tmp_path, release_issuer_binding=issuer)
    journal.record_release_issuer_binding(issuer)
    journal.record_source_package(source)
    journal.record_delta(delta)
    journal.record_composition(composition)
    journal._record("composition-proof", proof)
    plan = MainGraduationPlan.model_validate({"operation_id": MAIN_OPERATION, "repository_digest": REPOSITORY, "target_ref": "refs/heads/main", "package": source, "delta": delta, "composition": composition, "composition_proof": proof, "composition_proof_artifact": proof_ref, "policy_epoch": issuer.controller_config_digest, "controller_config_digest": issuer.controller_config_digest, "release_issuer_binding": issuer, "evidence_artifacts": [source.package_artifact, *source.child_artifacts]})
    journal.record_plan(plan)
    fresh = MainGraduationJournal(tmp_path, release_issuer_binding=issuer).read_plan(MAIN_OPERATION)
    assert fresh is not None and fresh[0] == plan
