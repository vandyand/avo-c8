# ruff: noqa: E501
# pyright: reportPrivateUsage=false
from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from avo_correlate.adapters.artifacts import (
    CandidatePublicationAuthorityResolutionError,
    CandidatePublicationJournalError,
    CandidatePublicationRecordConflictError,
    MainGraduationJournal,
    MainPersonalExactCasCandidatePublicationAuthorityJournal,
    MainPersonalExactCasCandidatePublicationAuthorityResolver,
    MainPersonalExactCasCandidatePublicationJournal,
    MainPersonalExactCasControllerCompositionJournal,
    MainPersonalExactCasHostedIdentityJournal,
)
from avo_correlate.adapters.artifacts import (
    main_personal_exact_cas_candidate_publication_authority as authority_module,
)
from avo_correlate.adapters.artifacts import (
    main_personal_exact_cas_candidate_publication_journal as journal_module,
)
from avo_correlate.adapters.artifacts.durable_backend_gate import DurableBackendQualification
from avo_correlate.adapters.hosted_git import (
    GitHubCandidatePublisherConfiguration,
    GitHubCandidatePublisherCredentials,
    MainPersonalExactCasCandidatePublicationController,
)
from avo_correlate.adapters.hosted_git.github import (
    GitHubRejected,
    GitHubTransportError,
    JsonBody,
    JsonValue,
)
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_candidate_publisher import (
    _CandidateRefTransport,  # pyright: ignore[reportPrivateUsage]
)
from avo_correlate.contracts import (
    ArtifactRef,
    MainPersonalExactCasCandidatePublicationAuthorityRoot,
    MainPersonalExactCasCandidatePublicationDispatchStarted,
    MainPersonalExactCasCandidatePublicationIntent,
    MainPersonalExactCasCandidatePublicationReconciliation,
    MainPersonalExactCasCandidatePublicationResponseEvidence,
    candidate_publication_request_digest,
)
from avo_correlate.contracts.main_graduation import MainPreparationAuthorization
from avo_correlate.contracts.main_personal_exact_cas_hosted_identity import (
    MainPersonalExactCasHostedIdentityEvidenceRoot,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_main_personal_exact_cas_controller_composition import (  # pyright: ignore[reportPrivateUsage]
    _root,  # pyright: ignore[reportPrivateUsage]
)


def _noop_fsync(_path: Path) -> None:
    pass


def _intent(
    configuration_digest: str = "sha256:" + "5" * 64,
) -> MainPersonalExactCasCandidatePublicationIntent:
    return MainPersonalExactCasCandidatePublicationIntent.build(
        operation_id="sha256:" + "1" * 64,
        repository_digest="sha256:" + "2" * 64,
        repository_id=1354880741,
        candidate_ref="refs/heads/avo/candidate/" + "1" * 64,
        base_commit="0" * 40,
        candidate_commit="1" * 40,
        candidate_tree="2" * 40,
        candidate_parents=("0" * 40,),
        source_composition_digest="sha256:" + "3" * 64,
        verified_policy_digest="sha256:" + "4" * 64,
        configuration_digest=configuration_digest,
        publisher_app_id=77,
        publisher_installation_id=88,
        publisher_identity="avo-c8-candidate-publisher-vandyand",
        intent_created_at=datetime.now(UTC),
    )


def _authority_root() -> MainPersonalExactCasCandidatePublicationAuthorityRoot:
    now = datetime.now(UTC) + timedelta(hours=1)

    def ref(digest: str, role: str, media_type: str) -> ArtifactRef:
        return ArtifactRef(
            digest=digest,
            size_bytes=1,
            role=role,
            media_type=media_type,
            created_at=now,
        )

    composition = ref(
        "sha256:" + "2" * 64,
        "main-graduation-composition",
        "application/vnd.avo.main-graduation-composition+json",
    )
    preparation = ref(
        "sha256:" + "3" * 64,
        "main-graduation-preparation-authorization",
        "application/vnd.avo.main-graduation-preparation-authorization+json",
    )
    identity = ref(
        "sha256:" + "4" * 64,
        "main-personal-exact-cas-hosted-identity-root",
        "application/vnd.avo.main-personal-exact-cas-hosted-identity-root+json",
    )
    policy = ref(
        "sha256:" + "5" * 64,
        "main-personal-exact-cas-hosted-configuration-diagnostic",
        "application/vnd.avo.main-personal-exact-cas-hosted-configuration-diagnostic+json",
    )
    policy_digests = tuple("sha256:" + digit * 64 for digit in "bcdef")
    policy_digest = canonical_digest(
        {
            "writer_ruleset": policy_digests[0],
            "safety_ruleset": policy_digests[1],
            "rollback_ruleset": policy_digests[2],
            "candidate_creation_ruleset": policy_digests[3],
            "candidate_immutable_ruleset": policy_digests[4],
        }
    )
    return MainPersonalExactCasCandidatePublicationAuthorityRoot.build(
        operation_id="sha256:" + "1" * 64,
        repository_digest="sha256:" + "6" * 64,
        candidate_ref="refs/heads/avo/candidate/" + "1" * 64,
        base_commit="0" * 40,
        base_tree="a" * 40,
        candidate_commit="1" * 40,
        candidate_tree="b" * 40,
        candidate_parents=("0" * 40,),
        lease_identity="lease-1",
        lease_digest="sha256:" + "7" * 64,
        lease_expires_at=now,
        configuration_digest="sha256:" + "8" * 64,
        publisher_app_id=77,
        publisher_installation_id=88,
        publisher_identity="avo-c8-candidate-publisher-vandyand",
        owner_id=99,
        composition_digest=composition.digest,
        composition_artifact=composition,
        preparation_authorization_record_digest=preparation.digest,
        preparation_authorization_digest="sha256:" + "f" * 64,
        preparation_authorization_artifact=preparation,
        hosted_identity_root_digest=identity.digest,
        hosted_identity_root_artifact=identity,
        hosted_identity_bundle_digest="sha256:" + "9" * 64,
        candidate_policy_digest=policy_digest,
        candidate_policy_artifact=policy,
        candidate_policy_ruleset_digests=policy_digests,
    )


def _publisher(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    _CandidateRefTransport,
    MainPersonalExactCasCandidatePublicationIntent,
    MainPersonalExactCasCandidatePublicationDispatchStarted,
    list[tuple[str, str, JsonBody | None, Mapping[str, str]]],
]:
    config = GitHubCandidatePublisherConfiguration(app_id=77, installation_id=88)
    intent = _intent(config.configuration_digest)
    marker = MainPersonalExactCasCandidatePublicationDispatchStarted.build(
        operation_id=intent.operation_id,
        candidate_ref=intent.candidate_ref,
        intent_digest=intent.intent_digest,
        configuration_digest=config.configuration_digest,
        started_at=datetime.now(UTC),
    )
    calls: list[tuple[str, str, JsonBody | None, Mapping[str, str]]] = []

    class FakeTransport:
        def __init__(self, **_: object) -> None:
            pass

        def __call__(
            self,
            method: str,
            url: str,
            body: JsonBody | None,
            headers: Mapping[str, str],
        ) -> tuple[int, JsonValue]:
            path = url.removeprefix("https://api.github.com")
            calls.append((method, path, body, headers))
            repo: dict[str, JsonValue] = {"id": 1354880741, "name": "avo-c8", "full_name": "vandyand/avo-c8", "owner": {"login": "vandyand"}}
            if path == "/app":
                return 200, {"id": 77, "slug": "avo-c8-candidate-publisher-vandyand", "name": "avo-c8-candidate-publisher-vandyand", "permissions": {"contents": "write", "metadata": "read"}, "events": [], "owner": {"login": "vandyand"}}
            if path == "/app/installations/88":
                return 200, {"id": 88, "app_id": 77, "app_slug": "avo-c8-candidate-publisher-vandyand", "repository_selection": "selected", "account": {"login": "vandyand"}}
            if path.endswith("/access_tokens"):
                return 201, {"token": "iat-secret", "permissions": {"contents": "write", "metadata": "read"}, "repository_selection": "selected", "repositories": [repo], "expires_at": (datetime.now(UTC) + timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ")}
            if path == "/repositories/1354880741":
                return 200, repo
            request = body if isinstance(body, dict) else {}
            return 201, {"ref": request.get("ref"), "object": {"type": "commit", "sha": request.get("sha")}}

    monkeypatch.setattr("avo_correlate.adapters.hosted_git.main_personal_exact_cas_candidate_publisher.GitHubJsonTransport", FakeTransport)
    return _CandidateRefTransport(config, GitHubCandidatePublisherCredentials("jwt-secret")), intent, marker, calls  # pyright: ignore[reportPrivateUsage]


def test_publisher_has_one_exact_post_and_redacts_credentials(monkeypatch: pytest.MonkeyPatch):
    publisher, intent, marker, calls = _publisher(monkeypatch)
    evidence = publisher._create(intent, marker)  # pyright: ignore[reportPrivateUsage]
    assert evidence.response_status == 201
    assert evidence.response_ref == intent.candidate_ref
    assert [(method, path) for method, path, _, _ in calls] == [
        ("GET", "/app"),
        ("GET", "/app/installations/88"),
        ("POST", "/app/installations/88/access_tokens"),
        ("GET", "/repositories/1354880741"),
        ("POST", "/repos/vandyand/avo-c8/git/refs"),
    ]
    assert calls[-1][2] == {"ref": intent.candidate_ref, "sha": intent.candidate_commit}
    assert "jwt-secret" not in repr(publisher)
    assert "iat-secret" not in evidence.model_dump_json()


def test_input_configuration_and_request_digest_are_exact(monkeypatch: pytest.MonkeyPatch):
    publisher, intent, marker, _ = _publisher(monkeypatch)
    wrong_marker = marker.model_copy(update={"configuration_digest": "sha256:" + "9" * 64})
    with pytest.raises(ValueError):
        publisher._create(intent, wrong_marker)  # pyright: ignore[reportPrivateUsage]
    assert intent.configuration_digest == publisher.configuration_digest
    assert intent.intent_digest.startswith("sha256:")
    assert candidate_publication_request_digest(
        repository_digest=intent.repository_digest,
        repository_id=intent.repository_id,
        candidate_ref=intent.candidate_ref,
        candidate_commit=intent.candidate_commit,
    ).startswith("sha256:")


def test_present_public_or_webhook_flags_are_fail_closed(monkeypatch: pytest.MonkeyPatch):
    publisher, _, _, _ = _publisher(monkeypatch)
    with pytest.raises(ValueError):
        publisher._verify_app(  # pyright: ignore[reportPrivateUsage]
            {
                "id": 77,
                "slug": "avo-c8-candidate-publisher-vandyand",
                "name": "avo-c8-candidate-publisher-vandyand",
                "permissions": {"contents": "write", "metadata": "read"},
                "events": [],
                "public": True,
                "owner": {"login": "vandyand"},
            }
        )


class _TestAuthority:
    def __init__(self, *_: object, **__: object) -> None:
        pass

    def verify_intent(self, _: object) -> bool:
        return True

    def verify_response_evidence(self, *_: object) -> bool:
        return True

    def verify_reconciliation(self, *_: object) -> bool:
        return True


def test_journal_owns_dispatch_once_and_reopens_canonical_record(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def qualified(root: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=tmp_path if root == tmp_path else root.resolve(),
            qualified=True,
            reason="test-qualified",
            filesystem_type="ext4",
            mount_id=1,
            device="8:1",
        )

    monkeypatch.setattr(
        "avo_correlate.adapters.artifacts.main_personal_exact_cas_candidate_publication_journal.require_durable_backend",
        qualified,
    )
    monkeypatch.setattr(
        "avo_correlate.adapters.artifacts.main_personal_exact_cas_candidate_publication_journal._fsync_directory",
        _noop_fsync,
    )
    monkeypatch.setattr(
        "avo_correlate.adapters.artifacts.main_personal_exact_cas_candidate_publication_journal._CandidatePublicationAuthorityRoot",
        _TestAuthority,
    )
    config = GitHubCandidatePublisherConfiguration(app_id=77, installation_id=88)
    intent = _intent(config.configuration_digest)
    marker = MainPersonalExactCasCandidatePublicationDispatchStarted.build(
        operation_id=intent.operation_id,
        candidate_ref=intent.candidate_ref,
        intent_digest=intent.intent_digest,
        configuration_digest=intent.configuration_digest,
        started_at=datetime.now(UTC),
    )
    journal = MainPersonalExactCasCandidatePublicationJournal(
        tmp_path,
        approved_composition=_root(),
        configuration_digest=config.configuration_digest,
        publisher_app_id=77,
        publisher_installation_id=88,
    )
    journal.record_intent(intent)
    _, first = journal.claim_dispatch_started(marker)
    _, second = journal.claim_dispatch_started(marker)
    assert first is True
    assert second is False
    later_marker = MainPersonalExactCasCandidatePublicationDispatchStarted.build(
        operation_id=intent.operation_id,
        candidate_ref=intent.candidate_ref,
        intent_digest=intent.intent_digest,
        configuration_digest=intent.configuration_digest,
        started_at=marker.started_at + timedelta(seconds=30),
    )
    _, race_loser = journal.claim_dispatch_started(later_marker)
    assert race_loser is False
    reopened = MainPersonalExactCasCandidatePublicationJournal(
        tmp_path,
        approved_composition=_root(),
        configuration_digest=config.configuration_digest,
        publisher_app_id=77,
        publisher_installation_id=88,
    )
    loaded = reopened.read_intent(intent.operation_id)
    assert loaded is not None and loaded[0] == intent


def test_journal_fails_closed_without_controller_verifier(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def qualified(root: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=tmp_path if root == tmp_path else root.resolve(),
            qualified=True,
            reason="test-qualified",
            filesystem_type="ext4",
            mount_id=1,
            device="8:1",
        )

    monkeypatch.setattr(
        "avo_correlate.adapters.artifacts.main_personal_exact_cas_candidate_publication_journal.require_durable_backend",
        qualified,
    )
    config = GitHubCandidatePublisherConfiguration(app_id=77, installation_id=88)
    with pytest.raises(ValueError, match="authority root is not provisioned"):
        MainPersonalExactCasCandidatePublicationJournal(
            tmp_path,
            approved_composition=_root(),
            configuration_digest=config.configuration_digest,
            publisher_app_id=77,
            publisher_installation_id=88,
        )


def test_raw_transport_is_module_private_and_package_has_no_mutation_alias() -> None:
    import avo_correlate.adapters.hosted_git as package
    import avo_correlate.adapters.hosted_git.main_personal_exact_cas_candidate_publisher as module

    assert not hasattr(module, "__all__")
    assert "GitHubCandidatePublisher" not in module.__dict__
    assert not hasattr(package, "GitHubCandidateRefPublisher")


def test_controller_boundary_is_fail_closed_until_authority_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = GitHubCandidatePublisherConfiguration(app_id=77, installation_id=88)
    with pytest.raises(ValueError, match="authority root is not provisioned"):
        MainPersonalExactCasCandidatePublicationController(
            tmp_path,
            configuration=config,
            credentials=GitHubCandidatePublisherCredentials("jwt-secret"),
            approved_composition=_root(),
        )


def test_authority_root_binds_exact_refs_and_rejects_tampering() -> None:
    root = _authority_root()
    assert root.dependencies_bound is True
    assert root.candidate_publication_authorized is False
    assert root.offline_only is True
    assert root.is_authoritative is False
    assert root.receipt_issued is False
    assert root.mutation_performed is False
    tampered = root.model_copy(update={"owner_id": root.owner_id + 1})
    with pytest.raises(ValueError):
        MainPersonalExactCasCandidatePublicationAuthorityRoot.model_validate_json(
            canonical_bytes(tampered)
        )
    created_at_tampered = root.preparation_authorization_artifact.model_copy(
        update={"created_at": root.preparation_authorization_artifact.created_at + timedelta(seconds=1)}
    )
    with pytest.raises(ValueError):
        MainPersonalExactCasCandidatePublicationAuthorityRoot.model_validate_json(
            canonical_bytes(
                root.model_copy(
                    update={"preparation_authorization_artifact": created_at_tampered}
                )
            )
        )


def test_authority_resolver_rejects_protocol_or_dto_dependencies() -> None:
    configuration = GitHubCandidatePublisherConfiguration(
        app_id=77, installation_id=88, owner_id=99
    )
    with pytest.raises(TypeError):
        MainPersonalExactCasCandidatePublicationAuthorityResolver(
            composition_journal=object(),  # type: ignore[arg-type]
            graduation_journal=object(),  # type: ignore[arg-type]
            hosted_identity_journal=object(),  # type: ignore[arg-type]
            configuration=configuration,
        )


def test_resolver_uses_real_concrete_journals_and_fails_closed_without_closure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def qualified(path: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=path.resolve(),
            qualified=True,
            reason="test-qualified",
            filesystem_type="ext4",
            mount_id=1,
            device="8:1",
        )

    monkeypatch.setattr(
        "avo_correlate.adapters.artifacts.main_personal_exact_cas_controller_composition.require_durable_backend",
        qualified,
    )
    monkeypatch.setattr(
        "avo_correlate.adapters.artifacts.main_personal_exact_cas_hosted_identity_journal.require_durable_backend",
        qualified,
    )
    monkeypatch.setattr(
        "avo_correlate.adapters.artifacts.main_personal_exact_cas_controller_composition._fsync_directory",
        _noop_fsync,
    )
    monkeypatch.setattr(
        "avo_correlate.adapters.artifacts.main_personal_exact_cas_hosted_identity_journal._fsync_directory",
        _noop_fsync,
    )
    composition = MainPersonalExactCasControllerCompositionJournal(tmp_path / "composition")
    graduation = MainGraduationJournal(tmp_path / "graduation")
    identity = MainPersonalExactCasHostedIdentityJournal(tmp_path / "identity")
    configuration = GitHubCandidatePublisherConfiguration(
        app_id=77, installation_id=88, owner_id=99
    )
    resolver = MainPersonalExactCasCandidatePublicationAuthorityResolver(
        composition_journal=composition,
        graduation_journal=graduation,
        hosted_identity_journal=identity,
        configuration=configuration,
    )
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        resolver.resolve("sha256:" + "1" * 64)


def test_authority_journal_reopens_and_rejects_tampered_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _authority_root()
    resolver = object.__new__(MainPersonalExactCasCandidatePublicationAuthorityResolver)
    current = [root]

    def resolve_current(
        _self: MainPersonalExactCasCandidatePublicationAuthorityResolver,
        _operation_id: str,
    ) -> MainPersonalExactCasCandidatePublicationAuthorityRoot:
        return current[0]

    def qualified(path: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=path.resolve(),
            qualified=True,
            reason="test-qualified",
            filesystem_type="ext4",
            mount_id=1,
            device="8:1",
        )

    monkeypatch.setattr(
        MainPersonalExactCasCandidatePublicationAuthorityResolver,
        "resolve",
        resolve_current,
    )
    monkeypatch.setattr(
        "avo_correlate.adapters.artifacts.main_personal_exact_cas_candidate_publication_authority.require_durable_backend",
        qualified,
    )
    monkeypatch.setattr(
        "avo_correlate.adapters.artifacts.main_personal_exact_cas_candidate_publication_authority._fsync_directory",
        _noop_fsync,
    )
    journal = MainPersonalExactCasCandidatePublicationAuthorityJournal(
        tmp_path, resolver=resolver
    )
    assert journal.bind(root.operation_id) == root
    assert journal.bind(root.operation_id) == root
    reopened = MainPersonalExactCasCandidatePublicationAuthorityJournal(
        tmp_path, resolver=resolver
    )
    assert reopened.read(root.operation_id) == root
    path = reopened._path(root.operation_id)  # pyright: ignore[reportPrivateUsage]
    path.write_bytes(b" " + canonical_bytes(root))
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        reopened.read(root.operation_id)
    path.write_bytes(canonical_bytes(root))
    different = MainPersonalExactCasCandidatePublicationAuthorityRoot.build(
        **(root.model_dump() | {"owner_id": root.owner_id + 1})
    )
    current[0] = different
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        reopened.read(root.operation_id)
    current[0] = root
    tampered = root.model_copy(update={"owner_id": root.owner_id + 1})
    journal._path(root.operation_id).write_bytes(canonical_bytes(tampered))  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        reopened.read(root.operation_id)
    reopened.close()
    reopened.close()
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        reopened.read(root.operation_id)


def test_operation_and_leaf_mount_device_fences(monkeypatch: pytest.MonkeyPatch) -> None:
    from avo_correlate.adapters.artifacts import (
        main_personal_exact_cas_candidate_publication_authority as authority_module,
    )

    class Stat:
        def __init__(self, device: int) -> None:
            self.st_dev = device

    devices = {1: Stat(7), 2: Stat(7)}
    mounts = {1: 11, 2: 11}
    def fake_fstat(descriptor: int) -> os.stat_result:
        return cast(os.stat_result, devices[descriptor])

    def fake_mount_id(descriptor: int) -> int:
        return mounts[descriptor]

    monkeypatch.setattr(authority_module.os, "fstat", fake_fstat)
    monkeypatch.setattr(authority_module, "_fd_mount_id", fake_mount_id)
    authority_module._compare_directory_mount(1, 2)  # pyright: ignore[reportPrivateUsage]
    devices[2] = Stat(8)
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        authority_module._compare_directory_mount(1, 2)  # pyright: ignore[reportPrivateUsage]
    devices[2] = Stat(7)
    mounts[2] = 12
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        authority_module._compare_directory_mount(1, 2)  # pyright: ignore[reportPrivateUsage]
    mounts[2] = 11
    devices[2] = Stat(8)
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        authority_module._compare_leaf_mount(1, 2)  # pyright: ignore[reportPrivateUsage]


def _publication_journal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[
    MainPersonalExactCasCandidatePublicationJournal,
    MainPersonalExactCasCandidatePublicationIntent,
    MainPersonalExactCasCandidatePublicationDispatchStarted,
]:
    def qualified(path: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=path.resolve(),
            qualified=True,
            reason="test-qualified",
            filesystem_type="ext4",
            mount_id=1,
            device="8:1",
        )

    monkeypatch.setattr(journal_module, "require_durable_backend", qualified)
    monkeypatch.setattr(journal_module, "_fsync_directory", _noop_fsync)
    monkeypatch.setattr(journal_module, "_CandidatePublicationAuthorityRoot", _TestAuthority)
    config = GitHubCandidatePublisherConfiguration(app_id=77, installation_id=88)
    journal = MainPersonalExactCasCandidatePublicationJournal(
        tmp_path,
        approved_composition=_root(),
        configuration_digest=config.configuration_digest,
        publisher_app_id=77,
        publisher_installation_id=88,
    )
    intent = _intent(config.configuration_digest)
    marker = MainPersonalExactCasCandidatePublicationDispatchStarted.build(
        operation_id=intent.operation_id,
        candidate_ref=intent.candidate_ref,
        intent_digest=intent.intent_digest,
        configuration_digest=intent.configuration_digest,
        started_at=datetime.now(UTC),
    )
    journal.record_intent(intent)
    journal.claim_dispatch_started(marker)
    return journal, intent, marker


def test_publication_journal_round_trips_response_and_reconciliation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, intent, marker = _publication_journal(monkeypatch, tmp_path)
    publisher, _, _, _ = _publisher(monkeypatch)
    evidence = publisher._create(intent, marker)  # pyright: ignore[reportPrivateUsage]
    evidence_ref = journal.record_response_evidence(evidence)
    loaded_evidence = journal.read_response_evidence(intent.operation_id)
    assert loaded_evidence is not None and loaded_evidence[0] == evidence
    assert loaded_evidence[1] == evidence_ref
    reconciliation = MainPersonalExactCasCandidatePublicationReconciliation.build(
        operation_id=intent.operation_id,
        repository_digest=intent.repository_digest,
        candidate_ref=intent.candidate_ref,
        candidate_commit=intent.candidate_commit,
        candidate_tree=intent.candidate_tree,
        candidate_parents=intent.candidate_parents,
        initial_ref_digest="sha256:" + "a" * 64,
        final_ref_digest="sha256:" + "a" * 64,
        response_evidence_digest=evidence.evidence_digest,
        observer_provenance_digest="sha256:" + "b" * 64,
        observed_at=datetime.now(UTC),
    )
    reconciliation_ref = journal.record_reconciliation(reconciliation)
    loaded_reconciliation = journal.read_reconciliation(reconciliation.reconciliation_digest)
    assert loaded_reconciliation is not None and loaded_reconciliation[0] == reconciliation
    assert loaded_reconciliation[1] == reconciliation_ref


def test_publication_journal_rejects_conflicts_and_malformed_indexes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, intent, marker = _publication_journal(monkeypatch, tmp_path)
    publisher, _, _, _ = _publisher(monkeypatch)
    evidence = publisher._create(intent, marker)  # pyright: ignore[reportPrivateUsage]
    journal.record_response_evidence(evidence)
    changed = MainPersonalExactCasCandidatePublicationResponseEvidence.build(
        **(evidence.model_dump(exclude={"evidence_digest"}) | {"response_metadata": {"x": "y"}})
    )
    with pytest.raises(CandidatePublicationRecordConflictError):
        journal.record_response_evidence(changed)
    index = journal._index_path(  # pyright: ignore[reportPrivateUsage]
        "response-evidence", intent.operation_id
    )
    index.write_bytes(b"not-json")
    with pytest.raises(CandidatePublicationJournalError):
        journal.read_response_evidence(intent.operation_id)
    with pytest.raises(CandidatePublicationJournalError):
        journal._index_path("unknown", intent.operation_id)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(CandidatePublicationJournalError):
        journal._index_path("intent", "not-a-digest")  # pyright: ignore[reportPrivateUsage]


def test_publication_journal_scope_and_verifier_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, intent, marker = _publication_journal(monkeypatch, tmp_path)
    wrong_marker = marker.model_copy(update={"candidate_ref": "refs/heads/main"})
    with pytest.raises(CandidatePublicationJournalError):
        journal.claim_dispatch_started(wrong_marker)
    class RejectingAuthority:
        def verify_intent(self, *_: object) -> bool:
            return False

    cast(Any, journal)._authority = RejectingAuthority()
    with pytest.raises(CandidatePublicationJournalError):
        journal.record_intent(intent)


def test_authority_filesystem_guards_cover_invalid_layout_and_bounds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    good = authority_module._prepare(tmp_path / "nested")  # pyright: ignore[reportPrivateUsage]
    assert good.is_dir()
    regular = tmp_path / "regular"
    regular.mkdir()
    def fake_is_symlink(value: Path) -> bool:
        return value == regular

    monkeypatch.setattr(authority_module.Path, "is_symlink", fake_is_symlink)
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        authority_module._prepare(regular)  # pyright: ignore[reportPrivateUsage]
    monkeypatch.undo()
    regular_file = tmp_path / "regular-file"
    regular_file.write_bytes(b"data")
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        authority_module._directory_identity(regular_file)  # pyright: ignore[reportPrivateUsage]
    qualified = DurableBackendQualification(
        root=tmp_path,
        qualified=True,
        reason="test-qualified",
        filesystem_type="ext4",
        mount_id=1,
        device="8:1",
    )
    assert authority_module._supports_descriptor_backend(qualified) is False  # pyright: ignore[reportPrivateUsage]
    authority_module._same_backend(qualified, qualified)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        authority_module._same_backend(qualified, qualified.__class__(  # pyright: ignore[reportPrivateUsage]
            root=tmp_path,
            qualified=True,
            reason="test-qualified",
            filesystem_type="ext4",
            mount_id=2,
            device="8:1",
        ))
    descriptor = os.open(regular_file, os.O_RDONLY)
    try:
        assert authority_module._read_bounded(descriptor, 10) == b"data"  # pyright: ignore[reportPrivateUsage]
    finally:
        os.close(descriptor)
    descriptor = os.open(regular_file, os.O_RDONLY)
    try:
        with pytest.raises(ValueError, match="too large"):
            authority_module._read_bounded(descriptor, 2)  # pyright: ignore[reportPrivateUsage]
    finally:
        os.close(descriptor)
    def fake_write(_fd: int, data: bytes) -> int:
        return len(data)

    monkeypatch.setattr(authority_module.os, "write", fake_write)
    authority_module._write_all(1, b"payload")  # pyright: ignore[reportPrivateUsage]


def test_authority_descriptor_and_reference_helpers_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    directory = tmp_path / "directory"
    directory.mkdir()
    child = directory / "child"
    child.mkdir()
    file_path = directory / "file"
    file_path.write_bytes(b"data")
    def fake_open(*_: object, **__: object) -> int:
        return 11

    def fake_fstat(_: int) -> os.stat_result:
        return os.stat_result((stat.S_IFDIR | 0o700, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    def fake_mount(_: int) -> int:
        return 1

    def fake_close(_: int) -> None:
        pass

    monkeypatch.setattr(authority_module.os, "open", fake_open)
    monkeypatch.setattr(authority_module.os, "fstat", fake_fstat)
    monkeypatch.setattr(authority_module.os, "close", fake_close)
    monkeypatch.setattr(authority_module, "_fd_mount_id", fake_mount)
    descriptor = authority_module._open_directory(directory)  # pyright: ignore[reportPrivateUsage]
    child_descriptor = authority_module._open_dir_at(  # pyright: ignore[reportPrivateUsage]
        descriptor, "child", create=False
    )
    authority_module._compare_directory_identity(descriptor, descriptor)  # pyright: ignore[reportPrivateUsage]
    authority_module._compare_directory_mount(descriptor, child_descriptor)  # pyright: ignore[reportPrivateUsage]
    monkeypatch.undo()
    file_descriptor = os.open(file_path, os.O_RDONLY)
    try:
        authority_module._check_regular(file_descriptor)  # pyright: ignore[reportPrivateUsage]
        def fake_directory_stat(_: int) -> os.stat_result:
            return os.stat_result((stat.S_IFDIR | 0o700, 0, 0, 0, 0, 0, 0, 0, 0, 0))

        monkeypatch.setattr(authority_module.os, "fstat", fake_directory_stat)
        with pytest.raises(ValueError, match="regular"):
            authority_module._check_regular(file_descriptor)  # pyright: ignore[reportPrivateUsage]
    finally:
        os.close(file_descriptor)
    value = _authority_root()
    raw = canonical_bytes(value)
    reference = ArtifactRef(
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        role="root",
        media_type="root",
        created_at=datetime.now(UTC),
    )
    authority_module._require_record_ref(reference, value, "root", "root")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError):
        authority_module._require_record_ref(reference.model_copy(update={"size_bytes": 1}), value, "root", "root")  # pyright: ignore[reportPrivateUsage]
    assert authority_module._artifact_matches(reference, reference)  # pyright: ignore[reportPrivateUsage]
    assert not authority_module._artifact_matches(  # pyright: ignore[reportPrivateUsage]
        reference, reference.model_copy(update={"created_at": reference.created_at + timedelta(seconds=1)})
    )
    monkeypatch.setattr(authority_module.sys, "platform", "linux")
    monkeypatch.setattr(authority_module.os, "O_NOFOLLOW", 0, raising=False)
    monkeypatch.setattr(authority_module.os, "O_DIRECTORY", 0, raising=False)
    assert authority_module._supports_descriptor_backend(object()) is True  # pyright: ignore[reportPrivateUsage]


def test_authority_journal_descriptor_paths_recheck_and_fsync_boundaries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _authority_root()
    journal = cast(Any, object.__new__(MainPersonalExactCasCandidatePublicationAuthorityJournal))
    journal._closed = False
    journal._descriptor_mode = True
    journal._root_fd = 10
    journal._index_fd = 11
    journal._root = tmp_path
    journal._indexes = tmp_path / "index"
    journal._root_identity = (1, 2)
    journal._index_identity = (1, 2)
    qualification = SimpleNamespace(qualified=True, mount_id=1, device="8:1")
    journal._qualification = qualification

    def fake_resolve(_: str) -> MainPersonalExactCasCandidatePublicationAuthorityRoot:
        return root

    journal._resolver = SimpleNamespace(resolve=fake_resolve)
    journal._indexes.mkdir()

    def fake_open(*_: object, **__: object) -> int:
        return 40

    def fake_close(_: int) -> None:
        pass

    def fake_mkdir(*_: object, **__: object) -> None:
        pass

    monkeypatch.setattr(authority_module.os, "open", fake_open)
    monkeypatch.setattr(authority_module.os, "close", fake_close)
    monkeypatch.setattr(authority_module.os, "mkdir", fake_mkdir)
    def fake_fsync(_: int) -> None:
        pass

    def fake_open_directory(_: Path) -> int:
        return 20

    def fake_open_dir_at(*_: object, **__: object) -> int:
        return 21

    def fake_compare(*_: object) -> None:
        pass

    def fake_identity(_: Path) -> tuple[int, int]:
        return 1, 2

    def fake_fsync_directory(_: Path) -> None:
        pass

    def fake_qualification(_: Path) -> Any:
        return qualification

    monkeypatch.setattr(authority_module.os, "fsync", fake_fsync)
    monkeypatch.setattr(authority_module, "_open_directory", fake_open_directory)
    monkeypatch.setattr(authority_module, "_open_dir_at", fake_open_dir_at)
    monkeypatch.setattr(authority_module, "_compare_directory_identity", fake_compare)
    monkeypatch.setattr(authority_module, "_compare_directory_mount", fake_compare)
    monkeypatch.setattr(authority_module, "_compare_leaf_mount", fake_compare)
    monkeypatch.setattr(authority_module, "_directory_identity", fake_identity)
    monkeypatch.setattr(authority_module, "_fsync_directory", fake_fsync_directory)
    monkeypatch.setattr(authority_module, "require_durable_backend", fake_qualification)
    journal._verify_retained_directories()
    descriptor, operation_descriptor, _ = journal._open_record(root.operation_id, write=True)
    assert (descriptor, operation_descriptor) == (40, 21)
    def fake_open_record(*_: object, **__: object) -> tuple[int, int, Path]:
        return 40, 21, journal._path(root.operation_id)

    def fake_check_regular(_: int) -> None:
        pass

    def fake_read_bounded(*_: object) -> bytes:
        return canonical_bytes(root)

    monkeypatch.setattr(journal, "_open_record", fake_open_record)
    monkeypatch.setattr(authority_module, "_check_regular", fake_check_regular)
    monkeypatch.setattr(authority_module, "_read_bounded", fake_read_bounded)
    assert journal.read(root.operation_id) == root
    def fake_write_all(*_: object) -> None:
        pass

    monkeypatch.setattr(authority_module, "_write_all", fake_write_all)
    assert journal.bind(root.operation_id) == root


def test_publication_journal_descriptor_index_paths_are_bounded_and_durable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal = cast(Any, object.__new__(MainPersonalExactCasCandidatePublicationJournal))
    journal._descriptor_mode = True
    journal._root_fd = 10
    journal._index_fd = 11
    journal._max = 1024
    journal._qualification = SimpleNamespace(mount_id=1, device="8:1")
    journal._indexes = tmp_path / "indexes"
    journal._indexes.mkdir()

    def fake_open(*_: object, **__: object) -> int:
        return 20

    def fake_close(_: int) -> None:
        pass

    def fake_fsync(_: int) -> None:
        pass

    def fake_check_descriptors() -> None:
        pass

    def fake_open_dir_at(*_: object, **__: object) -> int:
        return 21

    def fake_check_regular(_: int) -> None:
        pass

    def fake_read_bounded(*_: object) -> bytes:
        return b"{}"

    def fake_write_all(*_: object) -> None:
        pass

    monkeypatch.setattr(journal, "_check_descriptors", fake_check_descriptors)
    monkeypatch.setattr(journal_module, "_open_dir_at", fake_open_dir_at)
    monkeypatch.setattr(journal_module, "_check_regular", fake_check_regular)
    monkeypatch.setattr(journal_module, "_read_bounded", fake_read_bounded)
    monkeypatch.setattr(journal_module, "_write_all", fake_write_all)
    monkeypatch.setattr(journal_module.os, "open", fake_open)
    monkeypatch.setattr(journal_module.os, "close", fake_close)
    monkeypatch.setattr(journal_module.os, "fsync", fake_fsync)
    index = journal._indexes / "intent" / "record.json"
    assert journal._read_index(index, "intent") == b"{}"
    journal._write_index(index, "intent", b"{}")
    assert journal._index_exists(index, "intent") is True
    assert journal._index_exists(index, "intent") is True


def test_publication_authority_guard_and_verifier_bindings_are_exercised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = GitHubCandidatePublisherConfiguration(app_id=77, installation_id=88)
    with pytest.raises(ValueError, match="approved composition"):
        journal_module._CandidatePublicationAuthorityRoot(  # pyright: ignore[reportPrivateUsage]
            cast(Any, object()), configuration_digest=config.configuration_digest,
            publisher_app_id=77, publisher_installation_id=88,
        )
    with pytest.raises(ValueError, match="identity"):
        journal_module._CandidatePublicationAuthorityRoot(  # pyright: ignore[reportPrivateUsage]
            _root(), configuration_digest="bad",
            publisher_app_id=77, publisher_installation_id=88,
        )
    intent = _intent(config.configuration_digest)
    composition = SimpleNamespace(
        operation_id=intent.operation_id,
        repository_digest=intent.repository_digest,
        candidate_ref=intent.candidate_ref,
        base_commit=intent.base_commit,
        candidate_commit=intent.candidate_commit,
        candidate_tree=intent.candidate_tree,
        candidate_parents=intent.candidate_parents,
        source_composition_digest=intent.source_composition_digest,
        policy_digest=intent.verified_policy_digest,
    )
    authority = cast(Any, object.__new__(journal_module._CandidatePublicationAuthorityRoot))  # pyright: ignore[reportPrivateUsage]
    authority._composition = composition
    authority._configuration_digest = config.configuration_digest
    authority._app_id = config.app_id
    authority._installation_id = config.installation_id
    assert authority.verify_intent(intent) is True
    with pytest.raises(ValueError, match="intent"):
        authority.verify_intent(intent.model_copy(update={"candidate_ref": "refs/heads/main"}))
    publisher, intent, marker, _ = _publisher(monkeypatch)
    evidence = publisher._create(intent, marker)  # pyright: ignore[reportPrivateUsage]
    assert authority.verify_response_evidence(evidence, intent, marker) is True
    with pytest.raises(ValueError, match="response"):
        authority.verify_response_evidence(
            evidence.model_copy(update={"repository_digest": "sha256:" + "a" * 64}),
            intent,
            marker,
        )
    reconciliation = MainPersonalExactCasCandidatePublicationReconciliation.build(
        operation_id=intent.operation_id,
        repository_digest=intent.repository_digest,
        candidate_ref=intent.candidate_ref,
        candidate_commit=intent.candidate_commit,
        candidate_tree=intent.candidate_tree,
        candidate_parents=intent.candidate_parents,
        initial_ref_digest="sha256:" + "a" * 64,
        final_ref_digest="sha256:" + "a" * 64,
        response_evidence_digest=evidence.evidence_digest,
        observer_provenance_digest="sha256:" + "b" * 64,
        observed_at=datetime.now(UTC),
    )
    assert authority.verify_reconciliation(reconciliation, intent, marker) is True
    with pytest.raises(ValueError, match="reconciliation"):
        authority.verify_reconciliation(
            reconciliation.model_copy(update={"candidate_tree": "a" * 40}), intent, marker
        )


def test_publication_journal_bounds_and_raw_record_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="max_record_bytes"):
        MainPersonalExactCasCandidatePublicationJournal(
            tmp_path, approved_composition=_root(), configuration_digest="sha256:" + "a" * 64,
            publisher_app_id=77, publisher_installation_id=88, max_record_bytes=0,
        )
    journal, intent, _ = _publication_journal(monkeypatch, tmp_path)
    with pytest.raises(TypeError):
        journal._record("intent", intent.operation_id, cast(Any, object()))  # pyright: ignore[reportPrivateUsage]
    journal._max = 1  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(CandidatePublicationJournalError, match="invalid intent"):
        journal._record("intent", intent.operation_id, intent)  # pyright: ignore[reportPrivateUsage]


def test_publication_journal_rejects_noncanonical_artifacts_and_backend_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, intent, _ = _publication_journal(monkeypatch, tmp_path)
    assert journal.root == tmp_path.resolve()
    assert journal.artifact_store.root == tmp_path.resolve() / "artifacts"
    assert journal.backend_qualification.qualified is True
    index = journal._index_path("intent", intent.operation_id)  # pyright: ignore[reportPrivateUsage]
    reference = journal._read_reference(index, "intent")  # pyright: ignore[reportPrivateUsage]
    artifact = journal.artifact_store.path_for_digest(reference.digest)
    artifact.write_text(json.dumps(intent.model_dump(mode="json")), encoding="utf-8")
    with pytest.raises(CandidatePublicationJournalError, match="malformed intent"):
        journal.read_intent(intent.operation_id)
    index.write_bytes(b"{}")
    with pytest.raises(CandidatePublicationJournalError, match="malformed intent"):
        journal.read_intent(intent.operation_id)
    journal._max = 1  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(CandidatePublicationJournalError, match="invalid intent"):
        journal.record_intent(intent)
    def mismatched(_: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=tmp_path.resolve(), qualified=True, reason="test-qualified",
            filesystem_type="ext4", mount_id=2, device="8:1"
        )
    monkeypatch.setattr(journal_module, "require_durable_backend", mismatched)
    with pytest.raises(CandidatePublicationJournalError, match="backend"):
        journal._same_backend(tmp_path, "index directory")  # pyright: ignore[reportPrivateUsage]


def test_publication_journal_verifier_and_descriptor_fences_reject_tampering(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, intent, marker = _publication_journal(monkeypatch, tmp_path)
    wrong = intent.model_copy(update={"candidate_ref": "refs/heads/main"})
    class RejectingAuthority:
        def verify_intent(self, *_: object) -> bool:
            raise ValueError("mismatch")

    cast(Any, journal)._authority = RejectingAuthority()
    with pytest.raises(CandidatePublicationJournalError, match="verification"):
        journal._verify("intent", wrong)  # pyright: ignore[reportPrivateUsage]
    cast(Any, journal)._authority = _TestAuthority()
    with pytest.raises(CandidatePublicationJournalError, match="binding"):
        journal._bind_marker(marker.model_copy(update={"intent_digest": "sha256:" + "a" * 64}), intent)
    journal._descriptor_mode = True  # pyright: ignore[reportPrivateUsage]
    journal._root_fd = None  # pyright: ignore[reportPrivateUsage]
    journal._index_fd = None  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(CandidatePublicationJournalError, match="descriptors"):
        journal._check_descriptors()  # pyright: ignore[reportPrivateUsage]
    def fake_fstat(_: int) -> os.stat_result:
        return os.stat_result((stat.S_IFREG, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    journal._root_fd = 10  # pyright: ignore[reportPrivateUsage]
    journal._index_fd = 11  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(journal_module.os, "fstat", fake_fstat)
    with pytest.raises(CandidatePublicationJournalError, match="directory"):
        journal._check_descriptors()  # pyright: ignore[reportPrivateUsage]


def test_publication_journal_adopts_only_the_valid_create_once_winner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal, intent, marker = _publication_journal(monkeypatch, tmp_path)
    publisher, _, _, _ = _publisher(monkeypatch)
    evidence = publisher._create(intent, marker)  # pyright: ignore[reportPrivateUsage]
    assert journal.read_response_evidence(intent.operation_id) is None
    assert journal.read_reconciliation("sha256:" + "f" * 64) is None
    with pytest.raises(CandidatePublicationJournalError, match="binding"):
        journal.record_response_evidence(evidence.model_copy(update={"intent_digest": "sha256:" + "a" * 64}))
    reconciliation = MainPersonalExactCasCandidatePublicationReconciliation.build(
        operation_id=intent.operation_id,
        repository_digest=intent.repository_digest,
        candidate_ref=intent.candidate_ref,
        candidate_commit=intent.candidate_commit,
        candidate_tree=intent.candidate_tree,
        candidate_parents=intent.candidate_parents,
        initial_ref_digest="sha256:" + "a" * 64,
        final_ref_digest="sha256:" + "a" * 64,
        response_evidence_digest=evidence.evidence_digest,
        observer_provenance_digest="sha256:" + "b" * 64,
        observed_at=datetime.now(UTC),
    )
    with pytest.raises(CandidatePublicationJournalError, match="repository"):
        journal.record_reconciliation(reconciliation.model_copy(update={"repository_digest": "sha256:" + "c" * 64}))
    reference = journal._record("dispatch-started", marker.operation_id, marker)  # pyright: ignore[reportPrivateUsage]
    def competing_record(*_: object, **__: object) -> None:
        raise CandidatePublicationRecordConflictError("race")

    reads = [0]
    def read_dispatch(_: str) -> tuple[MainPersonalExactCasCandidatePublicationDispatchStarted, ArtifactRef] | None:
        reads[0] += 1
        return None if reads[0] == 1 else (marker, reference)

    monkeypatch.setattr(journal, "read_dispatch_started", read_dispatch)
    monkeypatch.setattr(journal, "_record", competing_record)
    assert journal.claim_dispatch_started(marker) == (reference, False)


def test_authority_resolver_rejects_each_missing_or_wrong_typed_leaf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operation_id = "sha256:" + "1" * 64
    composition_journal = object.__new__(MainPersonalExactCasControllerCompositionJournal)
    graduation_journal = object.__new__(MainGraduationJournal)
    identity_journal = object.__new__(MainPersonalExactCasHostedIdentityJournal)
    composition = SimpleNamespace()
    def read_composition(_: str) -> Any:
        return composition

    def missing_preparation(_: str) -> None:
        return None

    def missing_identity() -> None:
        return None

    cast(Any, composition_journal).read = read_composition
    cast(Any, graduation_journal).read_preparation_authorization = missing_preparation
    cast(Any, identity_journal).read = missing_identity
    resolver = MainPersonalExactCasCandidatePublicationAuthorityResolver(
        composition_journal=composition_journal,
        graduation_journal=graduation_journal,
        hosted_identity_journal=identity_journal,
        configuration=GitHubCandidatePublisherConfiguration(
            app_id=77, installation_id=88, owner_id=99
        ),
    )
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        resolver.resolve(operation_id)
    def wrong_preparation(_: str) -> tuple[object, object]:
        return object(), object()

    cast(Any, graduation_journal).read_preparation_authorization = wrong_preparation
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        resolver.resolve(operation_id)
    preparation = MainPreparationAuthorization.model_construct()
    def malformed_preparation(_: str) -> tuple[MainPreparationAuthorization, object]:
        return preparation, object()

    cast(Any, graduation_journal).read_preparation_authorization = malformed_preparation
    def skip_record_ref(*_: object) -> None:
        pass

    monkeypatch.setattr(authority_module, "_require_record_ref", skip_record_ref)
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        resolver.resolve(operation_id)
    def wrong_identity() -> tuple[object, object]:
        return object(), object()

    cast(Any, identity_journal).read = wrong_identity
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        resolver.resolve(operation_id)


def test_authority_resolver_reads_only_digest_bound_canonical_diagnostic() -> None:
    from tests.unit.test_main_personal_exact_cas_hosted_configuration import (  # pyright: ignore[reportPrivateUsage]
        _subject,
    )

    diagnostic = _subject()[0].verify()  # pyright: ignore[reportPrivateUsage]
    raw = canonical_bytes(diagnostic)
    reference = ArtifactRef(
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        role="diagnostic",
        media_type="diagnostic",
        created_at=datetime.now(UTC),
    )
    resolver = cast(Any, object.__new__(MainPersonalExactCasCandidatePublicationAuthorityResolver))
    def read_raw(_: ArtifactRef) -> bytes:
        return raw

    resolver._identity = SimpleNamespace(artifact_store=SimpleNamespace(read_bytes=read_raw))
    assert resolver._read_diagnostic(reference) == diagnostic
    with pytest.raises(ValueError, match="digest"):
        resolver._read_diagnostic(reference.model_copy(update={"size_bytes": 1}))
    noncanonical = raw + b"\n"
    def read_noncanonical(_: ArtifactRef) -> bytes:
        return noncanonical

    resolver._identity = SimpleNamespace(
        artifact_store=SimpleNamespace(read_bytes=read_noncanonical)
    )
    noncanonical_ref = reference.model_copy(
        update={
            "digest": "sha256:" + hashlib.sha256(noncanonical).hexdigest(),
            "size_bytes": len(noncanonical),
        }
    )
    with pytest.raises(ValueError, match="canonical"):
        resolver._read_diagnostic(noncanonical_ref)


def test_authority_constructors_and_descriptor_capability_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="owner ID"):
        MainPersonalExactCasCandidatePublicationAuthorityResolver(
            composition_journal=object.__new__(MainPersonalExactCasControllerCompositionJournal),
            graduation_journal=object.__new__(MainGraduationJournal),
            hosted_identity_journal=object.__new__(MainPersonalExactCasHostedIdentityJournal),
            configuration=GitHubCandidatePublisherConfiguration(app_id=77, installation_id=88),
        )
    with pytest.raises(TypeError, match="resolver"):
        MainPersonalExactCasCandidatePublicationAuthorityJournal(tmp_path, resolver=object())  # type: ignore[arg-type]
    monkeypatch.setattr(authority_module.sys, "platform", "linux")
    monkeypatch.delattr(authority_module.os, "O_NOFOLLOW", raising=False)
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        authority_module._supports_descriptor_backend(object())  # pyright: ignore[reportPrivateUsage]
    closed = cast(Any, object.__new__(MainPersonalExactCasCandidatePublicationAuthorityJournal))
    closed._closed = False
    closed._root_fd = 10
    closed._index_fd = 11
    def close_error(_: int) -> None:
        raise OSError("already closed")

    monkeypatch.setattr(authority_module.os, "close", close_error)
    closed.close()
    closed.close()
def test_authority_journal_rejects_invalid_keys_and_missing_records(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _authority_root()
    resolver = object.__new__(MainPersonalExactCasCandidatePublicationAuthorityResolver)
    def resolve_root(*_: object) -> MainPersonalExactCasCandidatePublicationAuthorityRoot:
        return root

    monkeypatch.setattr(
        MainPersonalExactCasCandidatePublicationAuthorityResolver, "resolve", resolve_root
    )
    def qualified(path: Path) -> DurableBackendQualification:
        return DurableBackendQualification(
            root=path.resolve(), qualified=True, reason="test-qualified",
            filesystem_type="ext4", mount_id=1, device="8:1"
        )
    monkeypatch.setattr(authority_module, "require_durable_backend", qualified)
    monkeypatch.setattr(authority_module, "_fsync_directory", _noop_fsync)
    journal = MainPersonalExactCasCandidatePublicationAuthorityJournal(tmp_path, resolver=resolver)
    assert journal.read(root.operation_id) is None
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        journal._path("invalid")  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        journal._open_record("invalid", write=False)  # pyright: ignore[reportPrivateUsage]
    with journal as entered:
        assert entered is journal
    with pytest.raises(CandidatePublicationAuthorityResolutionError):
        journal.read(root.operation_id)


def test_authority_resolver_reassembles_exact_dependency_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operation_id = "sha256:" + "1" * 64
    def digest(digit: str) -> str:
        return "sha256:" + digit * 64
    now = datetime.now(UTC)
    artifact = ArtifactRef(
        digest=digest("a"), size_bytes=1, role="identity", media_type="identity", created_at=now
    )
    composition = SimpleNamespace(
        operation_id=operation_id,
        repository_digest=digest("b"),
        candidate_ref="refs/heads/avo/candidate/" + "1" * 64,
        base_commit="0" * 40,
        base_tree="2" * 40,
        candidate_commit="1" * 40,
        candidate_tree="3" * 40,
        candidate_parents=("0" * 40,),
        lease_identity="lease",
        lease_digest=digest("c"),
        lease_expires_at=now,
        source_plan_digest=digest("d"),
        source_composition_digest=digest("e"),
        source_package_digest=digest("f"),
        policy_digest=digest("0"),
        protection_ruleset_digest=digest("1"),
        source_composition_artifact=artifact,
        hosted_identity_root_artifact=artifact,
    )
    preparation = MainPreparationAuthorization.model_construct(
        operation_id=operation_id,
        authorization_digest=digest("2"),
        plan_digest=composition.source_plan_digest,
        intent_digest=digest("9"),
        composition_digest=composition.source_composition_digest,
        package_digest=composition.source_package_digest,
        policy_epoch=composition.policy_digest,
        base_commit=composition.base_commit,
        base_tree=composition.base_tree,
        candidate_commit=composition.candidate_commit,
        candidate_tree=composition.candidate_tree,
        lease_identity=composition.lease_identity,
        lease_digest=composition.lease_digest,
        authorized=True,
        authorized_at=now,
    )
    diagnostic = SimpleNamespace(
        owner_id=99,
        protection_ruleset_digest=composition.protection_ruleset_digest,
        writer_ruleset_digest=digest("3"),
        safety_ruleset_digest=digest("4"),
        rollback_ruleset_digest=digest("5"),
        candidate_creation_ruleset_digest=digest("6"),
        candidate_immutable_ruleset_digest=digest("7"),
    )
    identity_root = MainPersonalExactCasHostedIdentityEvidenceRoot.model_construct(
        writer_diagnostic_artifact=artifact, bundle_digest=digest("8")
    )
    bundle = SimpleNamespace(bundle_digest=digest("8"), assert_valid=lambda: None)
    composition_journal = object.__new__(MainPersonalExactCasControllerCompositionJournal)
    graduation_journal = object.__new__(MainGraduationJournal)
    identity_journal = object.__new__(MainPersonalExactCasHostedIdentityJournal)
    def read_composition(_: str) -> Any:
        return composition

    def read_preparation(_: str) -> tuple[MainPreparationAuthorization, ArtifactRef]:
        return preparation, artifact

    def read_identity() -> tuple[Any, MainPersonalExactCasHostedIdentityEvidenceRoot]:
        return bundle, identity_root

    cast(Any, composition_journal).read = read_composition
    cast(Any, graduation_journal).read_preparation_authorization = read_preparation
    cast(Any, identity_journal).read = read_identity
    config = GitHubCandidatePublisherConfiguration(app_id=77, installation_id=88, owner_id=99)
    resolver = MainPersonalExactCasCandidatePublicationAuthorityResolver(
        composition_journal=composition_journal,
        graduation_journal=graduation_journal,
        hosted_identity_journal=identity_journal,
        configuration=config,
    )
    def skip_record_ref(*_: object) -> None:
        pass

    def read_diagnostic(_: ArtifactRef) -> Any:
        return diagnostic

    def skip_bind(*_: object) -> None:
        pass

    def build_probe(**values: object) -> object:
        return values

    monkeypatch.setattr(authority_module, "_require_record_ref", skip_record_ref)
    monkeypatch.setattr(resolver, "_read_diagnostic", read_diagnostic)
    monkeypatch.setattr(resolver, "_bind", skip_bind)
    monkeypatch.setattr(
        MainPersonalExactCasCandidatePublicationAuthorityRoot,
        "build",
        staticmethod(build_probe),
    )
    result = cast(dict[str, object], resolver.resolve(operation_id))
    assert result["operation_id"] == operation_id
    assert result["publisher_app_id"] == 77


@pytest.mark.parametrize(
    ("status", "classification"),
    [
        (400, "unverifiable"),
        (401, "authentication_or_authorization_rejected"),
        (409, "conflict_or_rejected"),
        (429, "rate_limited"),
        (500, "ambiguous"),
    ],
)
def test_response_contract_classifies_all_non_created_statuses(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    classification: str,
) -> None:
    publisher, intent, marker, _ = _publisher(monkeypatch)
    evidence = publisher._create(intent, marker)  # pyright: ignore[reportPrivateUsage]
    payload = evidence.model_dump(exclude={"evidence_digest"})
    payload.update(response_status=status, response_classification=classification)
    payload.update(response_ref=None, response_sha=None)
    parsed = MainPersonalExactCasCandidatePublicationResponseEvidence.build(**payload)
    assert parsed.response_classification == classification


def test_response_contract_rejects_noncanonical_trace_and_mutation_echo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher, intent, marker, _ = _publisher(monkeypatch)
    evidence = publisher._create(intent, marker)  # pyright: ignore[reportPrivateUsage]
    base = evidence.model_dump(exclude={"evidence_digest"})
    bad_trace = dict(base, requests=())
    with pytest.raises(ValueError, match="trace"):
        MainPersonalExactCasCandidatePublicationResponseEvidence.build(**bad_trace)
    bad_echo = dict(
        base,
        response_status=400,
        response_classification="unverifiable",
        response_ref=intent.candidate_ref,
        response_sha=intent.candidate_commit,
    )
    with pytest.raises(ValueError, match="mutation evidence"):
        MainPersonalExactCasCandidatePublicationResponseEvidence.build(**bad_echo)


def test_authority_root_contract_rejects_each_dependency_shape() -> None:
    root = _authority_root()
    updates: tuple[dict[str, object], ...] = (
        {"composition_artifact": root.composition_artifact.model_copy(update={"role": "wrong"})},
        {"preparation_authorization_record_digest": "sha256:" + "a" * 64},
        {"hosted_identity_root_digest": "sha256:" + "a" * 64},
        {"candidate_ref": "refs/heads/main"},
        {"candidate_parents": ("1" * 40,)},
        {"candidate_policy_ruleset_digests": ("sha256:" + "b" * 64,) * 5},
        {"candidate_policy_digest": "sha256:" + "a" * 64},
    )
    for update in updates:
        with pytest.raises(ValueError):
            MainPersonalExactCasCandidatePublicationAuthorityRoot.model_validate_json(
                canonical_bytes(root.model_copy(update=update))
            )


def test_publication_contracts_reject_binding_digest_and_topology_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher, intent, marker, _ = _publisher(monkeypatch)
    for update in (
        {"candidate_ref": "refs/heads/main"},
        {"candidate_parents": ()},
        {"intent_digest": "sha256:" + "a" * 64},
    ):
        with pytest.raises(ValueError):
            MainPersonalExactCasCandidatePublicationIntent.model_validate_json(
                canonical_bytes(intent.model_copy(update=update))
            )
    for update in (
        {"candidate_ref": "refs/heads/main"},
        {"dispatch_marker_digest": "sha256:" + "a" * 64},
    ):
        with pytest.raises(ValueError):
            MainPersonalExactCasCandidatePublicationDispatchStarted.model_validate_json(
                canonical_bytes(marker.model_copy(update=update))
            )
    evidence = publisher._create(intent, marker)  # pyright: ignore[reportPrivateUsage]
    for update in (
        {"candidate_ref": "refs/heads/main"},
        {"request_digest": "sha256:" + "a" * 64},
        {"publisher_identity": "other"},
        {"response_status": 201, "requests": evidence.requests[:-1]},
        {"response_classification": "ambiguous"},
        {"response_ref": "refs/heads/main"},
    ):
        with pytest.raises(ValueError):
            MainPersonalExactCasCandidatePublicationResponseEvidence.model_validate_json(
                canonical_bytes(evidence.model_copy(update=update))
            )
    reconciliation = MainPersonalExactCasCandidatePublicationReconciliation.build(
        operation_id=intent.operation_id,
        repository_digest=intent.repository_digest,
        candidate_ref=intent.candidate_ref,
        candidate_commit=intent.candidate_commit,
        candidate_tree=intent.candidate_tree,
        candidate_parents=intent.candidate_parents,
        initial_ref_digest="sha256:" + "a" * 64,
        final_ref_digest="sha256:" + "a" * 64,
        response_evidence_digest=evidence.evidence_digest,
        observer_provenance_digest="sha256:" + "b" * 64,
        observed_at=datetime.now(UTC),
    )
    for update in (
        {"candidate_ref": "refs/heads/main"},
        {"final_ref_digest": "sha256:" + "c" * 64},
        {"candidate_parents": ()},
    ):
        with pytest.raises(ValueError):
            MainPersonalExactCasCandidatePublicationReconciliation.model_validate_json(
                canonical_bytes(reconciliation.model_copy(update=update))
            )
    root = _authority_root()
    with pytest.raises(ValueError, match="preparation"):
        MainPersonalExactCasCandidatePublicationAuthorityRoot.model_validate_json(
            canonical_bytes(
                root.model_copy(
                    update={"preparation_authorization_record_digest": "sha256:" + "a" * 64}
                )
            )
        )


def test_publication_journal_filesystem_helpers_reject_unsafe_descriptors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    journal_type = MainPersonalExactCasCandidatePublicationJournal
    assert journal_type._canonical(tmp_path / "new") == (tmp_path / "new").resolve()  # pyright: ignore[reportPrivateUsage]
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    def fake_symlink(value: Path) -> bool:
        return value == unsafe

    monkeypatch.setattr(journal_module.Path, "is_symlink", fake_symlink)
    with pytest.raises(CandidatePublicationJournalError, match="symlink"):
        journal_type._prepare(unsafe)  # pyright: ignore[reportPrivateUsage]
    monkeypatch.undo()
    not_directory = tmp_path / "not-directory"
    not_directory.mkdir()
    def fake_is_dir(value: Path) -> bool:
        return value != not_directory

    def fake_mkdir(self: Path, *, parents: bool = False, exist_ok: bool = False) -> None:
        del self, parents, exist_ok

    monkeypatch.setattr(journal_module.Path, "is_dir", fake_is_dir)
    monkeypatch.setattr(journal_module.Path, "mkdir", fake_mkdir)
    with pytest.raises(CandidatePublicationJournalError, match="directory"):
        journal_type._prepare(not_directory)  # pyright: ignore[reportPrivateUsage]
    monkeypatch.undo()
    journal = cast(Any, object.__new__(journal_type))
    journal._root_fd = 10
    journal._index_fd = 11
    journal._qualification = SimpleNamespace(mount_id=1)
    real_mount_id = journal_module._mount_id
    def fake_fstat(_: int) -> os.stat_result:
        return os.stat_result((stat.S_IFDIR, 1, 1, 1, 1, 1, 1, 1, 1, 1))

    monkeypatch.setattr(journal_module.os, "fstat", fake_fstat)
    def mount_one(_: int) -> int:
        return 1

    def mount_two(_: int) -> int:
        return 2

    monkeypatch.setattr(journal_module, "_mount_id", mount_one)
    journal._check_descriptors()  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(journal_module, "_mount_id", mount_two)
    with pytest.raises(CandidatePublicationJournalError, match="backend"):
        journal._check_descriptors()  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(journal_module, "_mount_id", real_mount_id)
    def fake_open(*_: object, **__: object) -> int:
        return 20

    def fake_close(_: int) -> None:
        pass

    monkeypatch.setattr(journal_module.os, "open", fake_open)
    monkeypatch.setattr(journal_module.os, "close", fake_close)
    def valid_fdinfo(*_: object) -> bytes:
        return b"mnt_id: 123\n"

    monkeypatch.setattr(journal_module, "_read_bounded", valid_fdinfo)
    monkeypatch.setattr(journal_module.sys, "platform", "linux")
    assert journal_module._mount_id(10) == 123  # pyright: ignore[reportPrivateUsage]
    def invalid_fdinfo(*_: object) -> bytes:
        return b"mnt_id: bad\n"

    monkeypatch.setattr(journal_module, "_read_bounded", invalid_fdinfo)
    with pytest.raises(ValueError, match="mount"):
        journal_module._mount_id(10)  # pyright: ignore[reportPrivateUsage]
    calls: list[Path] = []
    monkeypatch.setattr(journal_module, "_fsync_directory", calls.append)
    journal_module._fsync_ancestors(tmp_path / "one" / "two" / "leaf", tmp_path)  # pyright: ignore[reportPrivateUsage]
    assert calls


def test_publication_journal_file_helpers_bound_and_validate_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    file_path = tmp_path / "record"
    file_path.write_bytes(b"payload")
    descriptor = os.open(file_path, os.O_RDONLY)
    try:
        assert journal_module._read_no_follow(file_path) == b"payload"  # pyright: ignore[reportPrivateUsage]
        assert journal_module._read_bounded(descriptor, 10) == b"payload"  # pyright: ignore[reportPrivateUsage]
        os.lseek(descriptor, 0, os.SEEK_SET)
        with pytest.raises(ValueError, match="exceeds"):
            journal_module._read_bounded(descriptor, 2)  # pyright: ignore[reportPrivateUsage]
    finally:
        os.close(descriptor)
    output = tmp_path / "output"
    output_descriptor = os.open(output, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        journal_module._write_all(output_descriptor, b"written")  # pyright: ignore[reportPrivateUsage]
    finally:
        os.close(output_descriptor)
    assert output.read_bytes() == b"written"
    def fake_open(*_: object, **__: object) -> int:
        return 30

    def fake_close(_: int) -> None:
        pass

    def fake_fsync(_: int) -> None:
        pass

    monkeypatch.setattr(journal_module.os, "open", fake_open)
    monkeypatch.setattr(journal_module.os, "close", fake_close)
    monkeypatch.setattr(journal_module.os, "fsync", fake_fsync)
    journal_module._fsync_directory(tmp_path)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "values",
    [
        {"repository_id": 1},
        {"owner": "other"},
        {"repository": "other"},
        {"app_id": 0},
        {"installation_id": 0},
        {"owner_id": 0},
        {"timeout_seconds": 0},
        {"timeout_seconds": 61},
        {"max_response_bytes": 0},
    ],
)
def test_publisher_configuration_and_credentials_bounds_are_fail_closed(
    values: dict[str, object],
) -> None:
    kwargs: dict[str, Any] = {"app_id": 77, "installation_id": 88}
    kwargs.update(values)
    with pytest.raises(ValueError):
        GitHubCandidatePublisherConfiguration(**kwargs)
    with pytest.raises(ValueError):
        GitHubCandidatePublisherCredentials(cast(str, values.get("app_id", " "))).assert_valid()


def test_publisher_validates_optional_identity_fields_and_token_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher, _, _, _ = _publisher(monkeypatch)
    app: dict[str, JsonValue] = {
        "id": 77,
        "slug": "avo-c8-candidate-publisher-vandyand",
        "name": "avo-c8-candidate-publisher-vandyand",
        "permissions": {"contents": "write", "metadata": "read"},
        "events": [],
        "owner": {"login": "vandyand", "type": "User"},
        "public": False,
        "webhook_active": False,
    }
    publisher._verify_app(cast(JsonValue, app))  # pyright: ignore[reportPrivateUsage]
    for key, value in (("slug", "wrong"), ("events", ["push"]), ("public", True)):
        with pytest.raises(ValueError):
            publisher._verify_app(cast(JsonValue, app | {key: value}))  # pyright: ignore[reportPrivateUsage]
    installation = {
        "id": 88,
        "app_id": 77,
        "app_slug": "avo-c8-candidate-publisher-vandyand",
        "repository_selection": "selected",
        "account": {"login": "vandyand", "type": "User"},
        "target_type": "User",
    }
    publisher._verify_installation(cast(JsonValue, installation))  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError):
        publisher._verify_installation(cast(JsonValue, installation | {"target_type": "Organization"}))  # pyright: ignore[reportPrivateUsage]
    repository: JsonValue = {"id": 1354880741, "name": "avo-c8", "full_name": "vandyand/avo-c8", "owner": {"login": "vandyand", "type": "User"}}
    expires = (datetime.now(UTC) + timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert publisher._verify_mint(cast(JsonValue, {"token": "token", "permissions": {"contents": "write", "metadata": "read"}, "repository_selection": "selected", "repositories": [repository], "expires_at": expires})) == "token"  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError):
        publisher._verify_mint(cast(JsonValue, {"token": "token", "permissions": {}, "repository_selection": "selected", "repositories": [repository], "expires_at": expires}))  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError):
        publisher._verify_repository(cast(JsonValue, repository | {"name": "other"}))  # pyright: ignore[reportPrivateUsage]


def test_publisher_evidence_downgrades_malformed_created_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publisher, intent, marker, _ = _publisher(monkeypatch)
    valid = publisher._create(intent, marker)  # pyright: ignore[reportPrivateUsage]
    evidence = publisher._evidence(  # pyright: ignore[reportPrivateUsage]
        intent, marker, 201, {"ref": intent.candidate_ref, "object": {"type": "tree", "sha": "1" * 40}}, list(valid.requests), datetime.now(UTC)
    )
    assert evidence.response_status == 599
    assert evidence.response_classification == "ambiguous"


def test_publisher_private_bounds_and_reserved_controller_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from avo_correlate.adapters.hosted_git.main_personal_exact_cas_candidate_publisher import (
        GitHubCandidatePublisherError,
        MainPersonalExactCasCandidatePublicationController,
    )

    assert GitHubCandidatePublisherError().code == "candidate_publication_unresolved"
    assert repr(GitHubCandidatePublisherCredentials("secret")) == (
        "GitHubCandidatePublisherCredentials(app_jwt=<redacted>)"
    )
    with pytest.raises(TypeError):
        _CandidateRefTransport(object(), object())  # type: ignore[arg-type]
    publisher, intent, marker, _ = _publisher(monkeypatch)
    assert publisher.repository_id == 1354880741
    with pytest.raises(TypeError):
        publisher._check_inputs(cast(Any, object()), marker)  # pyright: ignore[reportPrivateUsage]
    valid_repo: JsonValue = {
        "id": 1354880741,
        "name": "avo-c8",
        "full_name": "vandyand/avo-c8",
        "owner": {"login": "vandyand"},
    }
    mint_base: JsonValue = {
        "token": "token",
        "permissions": {"contents": "write", "metadata": "read"},
        "repository_selection": "selected",
        "repositories": [valid_repo],
        "expires_at": (datetime.now(UTC) + timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with pytest.raises(ValueError):
        publisher._verify_mint(cast(JsonValue, mint_base | {"repositories": []}))  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError):
        publisher._verify_mint(cast(JsonValue, mint_base | {"expires_at": "bad"}))  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ValueError):
        publisher._verify_mint(cast(JsonValue, mint_base | {"expires_at": "2000-01-01T00:00:00Z"}))  # pyright: ignore[reportPrivateUsage]
    reserved = cast(Any, object.__new__(MainPersonalExactCasCandidatePublicationController))
    with pytest.raises(RuntimeError):
        reserved.execute(intent)
    with pytest.raises(RuntimeError):
        reserved.recover(intent.operation_id)
    with pytest.raises(TypeError):
        MainPersonalExactCasCandidatePublicationController(
            tmp_path,
            configuration=GitHubCandidatePublisherConfiguration(app_id=77, installation_id=88),
            credentials=GitHubCandidatePublisherCredentials("secret"),
            approved_composition=cast(Any, object()),
        )


@pytest.mark.parametrize("failure_stage", ["app", "installation", "mint", "repository"])
def test_publisher_returns_sanitized_evidence_for_each_preflight_rejection(
    monkeypatch: pytest.MonkeyPatch, failure_stage: str
) -> None:
    publisher, intent, marker, _ = _publisher(monkeypatch)
    repo: JsonValue = {
        "id": 1354880741,
        "name": "avo-c8",
        "full_name": "vandyand/avo-c8",
        "owner": {"login": "vandyand"},
    }
    app: JsonValue = {
        "id": 77,
        "slug": "avo-c8-candidate-publisher-vandyand",
        "name": "avo-c8-candidate-publisher-vandyand",
        "permissions": {"contents": "write", "metadata": "read"},
        "events": [],
        "owner": {"login": "vandyand"},
    }
    installation: JsonValue = {
        "id": 88,
        "app_id": 77,
        "app_slug": "avo-c8-candidate-publisher-vandyand",
        "repository_selection": "selected",
        "account": {"login": "vandyand"},
    }
    mint: JsonValue = {
        "token": "iat-secret",
        "permissions": {"contents": "write", "metadata": "read"},
        "repository_selection": "selected",
        "repositories": [repo],
        "expires_at": (datetime.now(UTC) + timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    responses = cast(list[tuple[int, JsonValue] | BaseException], {
        "app": [(403, {})],
        "installation": [(200, app), (403, {})],
        "mint": [(200, app), (200, installation), (403, {})],
        "repository": [(200, app), (200, installation), (201, mint), (403, {})],
    }[failure_stage])

    class SequenceTransport:
        def __call__(
            self, _method: str, _url: str, _body: JsonBody | None, _headers: Mapping[str, str]
        ) -> tuple[int, JsonValue]:
            response = responses.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response

    object.__setattr__(publisher, "_transport", SequenceTransport())
    evidence = publisher._create(intent, marker)  # pyright: ignore[reportPrivateUsage]
    assert evidence.response_status == 403
    assert evidence.response_ref is None and evidence.response_sha is None


@pytest.mark.parametrize("error", [GitHubRejected("rejected", status=422), GitHubTransportError("offline")])
def test_publisher_sanitizes_authoritative_and_transport_exceptions(
    monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    publisher, intent, marker, _ = _publisher(monkeypatch)

    def raising_transport(
        _method: str, _url: str, _body: JsonBody | None, _headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        raise error

    object.__setattr__(publisher, "_transport", raising_transport)
    evidence = publisher._create(intent, marker)  # pyright: ignore[reportPrivateUsage]
    expected_status = 422 if isinstance(error, GitHubRejected) else 599
    assert evidence.response_status == expected_status
