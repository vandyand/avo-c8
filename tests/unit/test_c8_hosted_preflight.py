from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from avo_correlate.application.c8_hosted_preflight import (
    C8HostedPreflightService,
    HostedC8PreflightReadOnly,
)
from avo_correlate.contracts.c8_hosted_preflight import (
    C8IsolatedIssuerRead,
    C8ProtectionRead,
    C8QueueConfigurationRead,
    C8RepositoryRead,
    C8RollbackNamespaceRead,
    C8ValidationIdentityRead,
    C8WorkflowRead,
    HostedC8PreflightReport,
)
from avo_correlate.contracts.main_graduation import MainValidationIdentity
from avo_correlate.contracts.main_graduation_ledger import (
    MainLedgerActivation,
    MainLedgerC8CapabilityEvidence,
)
from avo_correlate.domain.canonical import canonical_digest

DIGEST = "sha256:" + "a" * 64


class Observer:
    def observe_repository(self) -> C8RepositoryRead:
        return C8RepositoryRead(
            repository_digest=DIGEST,
            owner="avo-org",
            repo="avo",
            owner_type="Organization",
            main_commit="commit",
            main_tree="tree",
            main_parents=["parent"],
        )

    def observe_protection(self) -> C8ProtectionRead:
        return C8ProtectionRead(
            effective=True,
            ruleset_ids=[1],
            queue_required=True,
            bypass_allowed=False,
            direct_merge_allowed=False,
        )

    def observe_queue_configuration(self) -> C8QueueConfigurationRead:
        return C8QueueConfigurationRead(
            available=True,
            maximum_entries_to_merge=1,
            maximum_entries_to_build=1,
            merge_method="squash",
            merging_strategy="allgreen",
        )

    def observe_workflow(self) -> C8WorkflowRead:
        return C8WorkflowRead(
            path=".github/workflows/validation.yml",
            pull_request_event=True,
            merge_group_event=True,
            exact_sha_checkout=True,
        )

    def observe_validation_identity(self) -> C8ValidationIdentityRead:
        return C8ValidationIdentityRead(app_id=15368, identity="github-app-15368")

    def observe_rollback_namespace(self) -> C8RollbackNamespaceRead:
        return C8RollbackNamespaceRead(
            namespace="refs/heads/avo/main-rollback/*",
            exclusive=True,
            deletion_protected=True,
            bypass_allowed=False,
            exclusive_controller_write=True,
            controller_delete_authorized=True,
            other_delete_denied=True,
        )

    def observe_isolated_issuer(self) -> C8IsolatedIssuerRead:
        return C8IsolatedIssuerRead(
            available=True,
            identity="isolated-release",
            app_id=42,
            isolation_digest=DIGEST,
        )


def test_report_is_deterministic_and_sorted() -> None:
    first = C8HostedPreflightService(Observer()).run()
    second = C8HostedPreflightService(Observer()).run()

    assert first.result == "pass"
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.report_digest == canonical_digest(
        first.model_dump(exclude={"report_digest"}, mode="json")
    )
    assert list(first.observation_digests) == sorted(first.observation_digests)
    assert first.authority_consumable is False


@pytest.mark.parametrize("method", ["observe_repository", "observe_protection", "observe_workflow"])
def test_missing_or_error_read_is_unverifiable(method: str) -> None:
    observer = Observer()
    # A dynamic observer can omit a method even though the protocol describes it.
    if method == "observe_repository":
        observer.observe_repository = None  # type: ignore[method-assign]
    elif method == "observe_protection":
        observer.observe_protection = lambda: (_ for _ in ()).throw(RuntimeError("provider"))  # type: ignore[method-assign]
    else:
        observer.observe_workflow = lambda: {}  # type: ignore[method-assign]
    report = C8HostedPreflightService(observer).run()
    assert report.result == "unverifiable"
    assert any(method.removeprefix("observe_") in code for code in report.unverifiable_codes)


def test_incomplete_queue_and_issuer_fail_closed() -> None:
    observer = Observer()
    observer.observe_queue_configuration = lambda: C8QueueConfigurationRead(available=True)  # type: ignore[method-assign]
    observer.observe_isolated_issuer = lambda: C8IsolatedIssuerRead(available=False)  # type: ignore[method-assign]
    report = C8HostedPreflightService(observer).run()
    assert report.result == "blocked"
    assert "merge_queue_configuration_invalid" in report.blocker_codes
    assert "isolated_release_issuer_missing" in report.blocker_codes


def test_validation_identity_mismatch_and_issuer_incomplete_are_fail_closed() -> None:
    observer = Observer()
    observer.observe_validation_identity = lambda: C8ValidationIdentityRead(  # type: ignore[method-assign]
        app_id=None, identity=None
    )
    observer.observe_isolated_issuer = lambda: C8IsolatedIssuerRead(  # type: ignore[method-assign]
        available=True, identity="issuer", app_id=42, isolation_digest=None
    )
    report = C8HostedPreflightService(observer).run()
    assert report.result == "blocked"
    assert "validation_app15368_identity_unverified" in report.blocker_codes
    assert "isolated_issuer_read_unverifiable" in report.unverifiable_codes


def test_protocol_contains_observations_only() -> None:
    names = set(HostedC8PreflightReadOnly.__annotations__)
    names.update(HostedC8PreflightReadOnly.__dict__)
    assert not any(
        token in name.casefold()
        for name in names
        for token in ("write", "mutat", "create", "activate")
    )
    assert {name for name in names if name.startswith("observe_")} == {
        "observe_repository",
        "observe_protection",
        "observe_queue_configuration",
        "observe_workflow",
        "observe_validation_identity",
        "observe_rollback_namespace",
        "observe_isolated_issuer",
    }


def test_strict_models_reject_extras_and_forged_digest() -> None:
    with pytest.raises(ValidationError):
        C8WorkflowRead(
            path="workflow",
            pull_request_event=True,
            merge_group_event=True,
            exact_sha_checkout=True,
            secret="must not cross boundary",  # type: ignore[call-arg]
        )
    report = C8HostedPreflightService(Observer()).run()
    with pytest.raises(ValidationError):
        HostedC8PreflightReport.model_validate(
            {**report.model_dump(mode="json"), "report_digest": DIGEST}
        )


def test_report_is_not_activation_or_capability_evidence() -> None:
    payload: dict[str, Any] = C8HostedPreflightService(Observer()).run().model_dump(mode="json")
    with pytest.raises(ValidationError):
        MainLedgerActivation.model_validate(payload)
    with pytest.raises(ValidationError):
        MainLedgerC8CapabilityEvidence.model_validate(payload)
    with pytest.raises(ValidationError):
        MainValidationIdentity.model_validate(payload)
