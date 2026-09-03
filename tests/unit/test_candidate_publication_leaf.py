# ruff: noqa: E501
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from avo_correlate.adapters.artifacts import MainPersonalExactCasCandidatePublicationJournal
from avo_correlate.adapters.artifacts.durable_backend_gate import DurableBackendQualification
from avo_correlate.adapters.hosted_git import (
    GitHubCandidatePublisherConfiguration,
    GitHubCandidatePublisherCredentials,
    MainPersonalExactCasCandidatePublicationController,
)
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_candidate_publisher import (
    _CandidateRefTransport,
)
from avo_correlate.contracts import (
    MainPersonalExactCasCandidatePublicationDispatchStarted,
    MainPersonalExactCasCandidatePublicationIntent,
    candidate_publication_request_digest,
)
from tests.unit.test_main_personal_exact_cas_controller_composition import _root


def _intent(configuration_digest: str = "sha256:" + "5" * 64):
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


def _publisher(monkeypatch: pytest.MonkeyPatch):
    config = GitHubCandidatePublisherConfiguration(app_id=77, installation_id=88)
    intent = _intent(config.configuration_digest)
    marker = MainPersonalExactCasCandidatePublicationDispatchStarted.build(
        operation_id=intent.operation_id,
        candidate_ref=intent.candidate_ref,
        intent_digest=intent.intent_digest,
        configuration_digest=config.configuration_digest,
        started_at=datetime.now(UTC),
    )
    calls: list[tuple[str, str, object, dict[str, str]]] = []

    class FakeTransport:
        def __init__(self, **_: object) -> None:
            pass

        def __call__(self, method: str, url: str, body: object, headers: dict[str, str]):
            path = url.removeprefix("https://api.github.com")
            calls.append((method, path, body, headers))
            repo = {"id": 1354880741, "name": "avo-c8", "full_name": "vandyand/avo-c8", "owner": {"login": "vandyand"}}
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
    return _CandidateRefTransport(config, GitHubCandidatePublisherCredentials("jwt-secret")), intent, marker, calls


def test_publisher_has_one_exact_post_and_redacts_credentials(monkeypatch: pytest.MonkeyPatch):
    publisher, intent, marker, calls = _publisher(monkeypatch)
    evidence = publisher._create(intent, marker)
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
        publisher._create(intent, wrong_marker)
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
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    def qualified(root):
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
        lambda _: None,
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
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    monkeypatch.setattr(
        "avo_correlate.adapters.artifacts.main_personal_exact_cas_candidate_publication_journal.require_durable_backend",
        lambda root: DurableBackendQualification(
            root=tmp_path,
            qualified=True,
            reason="test-qualified",
            filesystem_type="ext4",
            mount_id=1,
            device="8:1",
        ),
    )
    with pytest.raises(TypeError):
        MainPersonalExactCasCandidatePublicationJournal(tmp_path, authority_verifier=object())
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
    monkeypatch: pytest.MonkeyPatch, tmp_path
):
    config = GitHubCandidatePublisherConfiguration(app_id=77, installation_id=88)
    with pytest.raises(ValueError, match="authority root is not provisioned"):
        MainPersonalExactCasCandidatePublicationController(
            tmp_path,
            configuration=config,
            credentials=GitHubCandidatePublisherCredentials("jwt-secret"),
            approved_composition=_root(),
        )
