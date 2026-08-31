"""Filesystem foundation for a model-validated C4 completion fixture.

This deliberately starts with the upstream campaign package (which is itself
round-trip validated) and builds the main-graduation C2 records with ordinary
Pydantic constructors.  It is kept separate from the historical construct-
based journal coverage fixture.
"""

import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.main_graduation_journal import MainGraduationJournal
from avo_correlate.adapters.git.main_composition import MainBaseSnapshot, MainCompositionAdapter
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
from avo_correlate.contracts.integration_promotion import (
    IntegrationPromotionIntent,
    integration_operation_id,
)
from avo_correlate.contracts.main_graduation import (
    MainGraduationPlan,
    MainReleaseIssuerBinding,
    MainSourcePackageBinding,
)
from avo_correlate.contracts.promotion_bundle import promotion_bundle_digest
from avo_correlate.contracts.promotion_policy import RiskClass, path_manifest_digest
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit import test_rollback_bundle_authority

_complete_package_factory: Callable[
    [], tuple[IntegrationCampaignEvidencePackage, bytes, ArtifactRef]
] = test_rollback_bundle_authority._complete_package  # pyright: ignore[reportPrivateUsage]

NOW = datetime(2026, 1, 1, tzinfo=UTC)
MAIN_OPERATION = "sha256:" + "1" * 64
REPOSITORY = "sha256:" + "a" * 64


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def _checkout(root: Path) -> tuple[Path, MainBaseSnapshot, str, str]:
    checkout = root / "checkout"
    checkout.mkdir(parents=True)
    _git(checkout, "init", "--initial-branch=main")
    _git(checkout, "config", "user.email", "avo-fixture@example.invalid")
    _git(checkout, "config", "user.name", "AVO fixture")
    _git(checkout, "commit", "--allow-empty", "-m", "base")
    base = _git(checkout, "rev-parse", "HEAD")
    base_tree = _git(checkout, "rev-parse", "HEAD^{tree}")
    source = checkout / "src" / "x.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 1\n", encoding="utf-8")
    _git(checkout, "add", "src/x.py")
    _git(checkout, "commit", "-m", "source")
    result = _git(checkout, "rev-parse", "HEAD")
    result_tree = _git(checkout, "rev-parse", "HEAD^{tree}")
    return checkout, MainBaseSnapshot(REPOSITORY, base, base_tree), result, result_tree


def _source(root: Path) -> MainSourcePackageBinding:
    package: IntegrationCampaignEvidencePackage
    evidence_bytes: bytes
    evidence_ref: ArtifactRef
    package, evidence_bytes, evidence_ref = _complete_package_factory()
    # The upstream rollback fixture intentionally uses generic JSON for its
    # publication evidence.  Main graduation only accepts typed AVO child
    # media, so rebuild the package and that child reference through the
    # normal validator after assigning its canonical allowlisted media type.
    evidence_ref = ArtifactRef.model_validate(
        evidence_ref.model_dump(mode="json")
        | {"media_type": "application/vnd.avo.integration-campaign-publication+json"}
    )
    package = IntegrationCampaignEvidencePackage.model_validate(
        package.model_dump(mode="json")
        | {"evidence_artifacts": [evidence_ref.model_dump(mode="json")]}
    )
    _checkout_path, base, result, result_tree = _checkout(root)
    bundle = package.bundle
    paths = ["src/x.py"]
    request = bundle.request.model_copy(
        update={
            "changed_paths": paths,
            "path_manifest_attestation": bundle.request.path_manifest_attestation.model_copy(
                update={"path_manifest_digest": path_manifest_digest(paths)}
            ),
        }
    )
    bundle = type(bundle).model_validate(
        bundle.model_dump(mode="json")
        | {
            "snapshot": bundle.snapshot.model_dump(mode="json")
            | {"commit": base.commit, "tree": base.tree},
            "comparison": bundle.comparison.model_dump(mode="json") | {"changed_paths": paths},
            "request": request.model_dump(mode="json"),
            "decision": bundle.decision.model_dump(mode="json")
            | {"risk_class": RiskClass.ORDINARY.value},
        }
    )
    bundle_digest = promotion_bundle_digest(bundle)
    intent_data = package.intent.model_dump(mode="json")
    intent_data.update(
        {
            "bundle_digest": bundle_digest,
            "base_commit": base.commit,
            "base_tree": base.tree,
            "target_base_commit": base.commit,
            "target_base_tree": base.tree,
            "candidate_tree": result_tree,
            "candidate_head_tree": result_tree,
            "synthetic_merge_tree": result_tree,
        }
    )
    identity = {
        key: str(intent_data[key])
        for key in (
            "repository_digest",
            "pull_request_number",
            "candidate_ref",
            "target_ref",
            "base_commit",
            "candidate_commit",
            "candidate_head_commit",
            "target_base_commit",
            "synthetic_merge_commit",
            "bundle_digest",
            "candidate_digest",
            "publication_evidence_digest",
            "provider_identity",
            "provider_api_version",
            "merge_method",
        )
    }
    operation_id = integration_operation_id(**identity)
    lease = package.lease_evidence.model_copy(update={"operation_id": operation_id})
    lease = lease.model_copy(
        update={"digest": canonical_digest(lease.model_dump(exclude={"digest"}, mode="json"))}
    )
    intent_data.update({"operation_id": operation_id, "controller_lease_digest": lease.digest})
    intent = IntegrationPromotionIntent.model_validate(intent_data)
    intent_digest = canonical_digest(intent)
    observation = package.observation.model_copy(
        update={
            "base_commit": base.commit,
            "base_tree": base.tree,
            "candidate_tree": result_tree,
            "synthetic_merge_tree": result_tree,
        }
    )
    reconciliation = package.reconciliation.model_copy(
        update={
            "merge_commit": result,
            "target_head_commit": result,
            "target_head_tree": result_tree,
            "target_first_parent": base.commit,
            "target_parents": [base.commit],
        }
    )
    merge_result = package.merge_result.model_copy(
        update={
            "result_commit": result,
            "result_tree": result_tree,
            "first_parent_commit": base.commit,
        }
    )
    receipt = package.receipt.model_copy(
        update={
            "operation_id": operation_id,
            "intent_digest": intent_digest,
            "bundle_digest": bundle_digest,
            "expected_candidate_tree": result_tree,
            "expected_base_commit": base.commit,
            "applied_result_commit": result,
            "applied_result_tree": result_tree,
            "applied_result_parent_commit": base.commit,
            "observed_base_commit": base.commit,
            "observed_head_commit": result,
            "observed_head_tree": result_tree,
            "observation_digest": canonical_digest(reconciliation),
        }
    )
    receipt_digest = canonical_digest(receipt)
    report = package.report.model_copy(
        update={
            "operation_id": operation_id,
            "intent_digest": intent_digest,
            "receipt_digest": receipt_digest,
        }
    )
    publication = package.publication.model_copy(
        update={"base_commit": base.commit, "base_tree": base.tree, "candidate_tree": result_tree}
    )
    lease_ref = ArtifactRef(
        digest=canonical_digest(lease),
        size_bytes=len(canonical_bytes(lease)),
        media_type="application/vnd.avo.integration-promotion+json",
        role="promotion-lease-evidence",
        created_at=lease.acquired_at,
    )
    package = IntegrationCampaignEvidencePackage.model_validate(
        package.model_dump(mode="json")
        | {
            "bundle": bundle.model_dump(mode="json"),
            "bundle_digest": bundle_digest,
            "intent": intent.model_dump(mode="json"),
            "intent_digest": intent_digest,
            "observation": observation.model_dump(mode="json"),
            "merge_result": merge_result.model_dump(mode="json"),
            "reconciliation": reconciliation.model_dump(mode="json"),
            "receipt": receipt.model_dump(mode="json"),
            "receipt_digest": receipt_digest,
            "report": report.model_dump(mode="json"),
            "publication": publication.model_dump(mode="json"),
            "lease_evidence": lease.model_dump(mode="json"),
            "lease_evidence_artifact": lease_ref.model_dump(mode="json"),
            "campaign_marker_digest": canonical_digest(
                {
                    "operation_id": operation_id,
                    "bundle_digest": bundle_digest,
                    "repository_digest": intent.repository_digest,
                    "pull_request_number": intent.pull_request_number,
                    "candidate_ref": intent.candidate_ref,
                    "candidate_commit": intent.candidate_commit,
                    "target_ref": intent.target_ref,
                    "base_commit": intent.base_commit,
                }
            ),
            "main_before_commit": base.commit,
            "main_after_commit": base.commit,
        }
    )
    store = FilesystemArtifactStore(root / "artifacts")
    package_bytes = canonical_bytes(package)
    package_ref = ArtifactRef(
        digest=canonical_digest(package),
        size_bytes=len(package_bytes),
        media_type="application/vnd.avo.integration-campaign+json",
        role="integration-campaign-package",
        created_at=NOW,
    )
    store.put_bytes(
        package_bytes, media_type=package_ref.media_type, role=package_ref.role, max_bytes=2_000_000
    )
    store.put_bytes(
        evidence_bytes,
        media_type=evidence_ref.media_type,
        role=evidence_ref.role,
        max_bytes=2_000_000,
    )
    store.put_bytes(
        canonical_bytes(package.lease_evidence),
        media_type=package.lease_evidence_artifact.media_type,
        role=package.lease_evidence_artifact.role,
        max_bytes=2_000_000,
    )
    return MainSourcePackageBinding.model_validate(
        {
            "operation_id": MAIN_OPERATION,
            "source_operation_id": package.intent.operation_id,
            "repository_digest": REPOSITORY,
            "target_ref": "refs/heads/main",
            "package_digest": package_ref.digest,
            "package_artifact": package_ref,
            "child_artifacts": [evidence_ref, package.lease_evidence_artifact],
            "source_result_commit": result,
            "source_result_tree": result_tree,
            "source_result_parent": base.commit,
            "source_issuer": "controller",
        }
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
    issuer = MainReleaseIssuerBinding.model_validate(
        issuer_values | {"binding_digest": canonical_digest(issuer_values | {"schema_version": 1})}
    )
    policy_epoch = canonical_digest(
        {"controller_config_digest": issuer.controller_config_digest, "main_policy": "ordinary"}
    )

    class Reader:
        def fresh_main_base(self) -> MainBaseSnapshot:
            return MainBaseSnapshot(
                REPOSITORY,
                source.source_result_parent,
                _git(tmp_path / "checkout", "rev-parse", f"{source.source_result_parent}^{{tree}}"),
            )

    journal = MainGraduationJournal(
        tmp_path,
        release_issuer_binding=issuer,
        composition_root=tmp_path / "checkout",
        repository_digest=REPOSITORY,
        base_reader=Reader(),
    )
    journal.record_release_issuer_binding(issuer)
    journal.record_source_package(source)
    composition = MainCompositionAdapter(
        tmp_path / "checkout",
        journal,
        repository_digest=REPOSITORY,
        base_reader=Reader(),
        controller_config_digest=issuer.controller_config_digest,
        policy_epoch=policy_epoch,
    ).compose(source)
    plan = MainGraduationPlan.model_validate(
        {
            "operation_id": MAIN_OPERATION,
            "repository_digest": REPOSITORY,
            "target_ref": "refs/heads/main",
            "package": source,
            "delta": composition.delta,
            "composition": composition.composition,
            "composition_proof": composition.proof,
            "composition_proof_artifact": composition.proof_artifact,
            "policy_epoch": policy_epoch,
            "controller_config_digest": issuer.controller_config_digest,
            "release_issuer_binding": issuer,
            "evidence_artifacts": [source.package_artifact, *source.child_artifacts],
        }
    )
    journal.record_plan(plan)
    fresh = MainGraduationJournal(tmp_path, release_issuer_binding=issuer).read_plan(MAIN_OPERATION)
    assert fresh is not None and fresh[0] == plan
