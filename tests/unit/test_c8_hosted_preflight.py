from __future__ import annotations

import io
import warnings
from contextlib import redirect_stderr
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from avo_correlate.application.c8_hosted_preflight import (
    C8HostedPreflightService,
    HostedC8PreflightReadOnly,
)
from avo_correlate.contracts.c8_hosted_preflight import (
    C8IsolatedIssuerRead,
    C8ObservationBinding,
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
BINDING = C8ObservationBinding(
    repository_digest=DIGEST,
    configuration_epoch="epoch-1",
    source_observation_digest=DIGEST,
    observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
)


class Observer:
    def observe_repository(self) -> C8RepositoryRead:
        return C8RepositoryRead(
            binding=BINDING,
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
            binding=BINDING,
            ruleset_ids=[1],
            queue_required=True,
            bypass_allowed=False,
            direct_merge_allowed=False,
        )

    def observe_queue_configuration(self) -> C8QueueConfigurationRead:
        return C8QueueConfigurationRead(
            binding=BINDING,
            available=True,
            maximum_entries_to_merge=1,
            maximum_entries_to_build=1,
            merge_method="squash",
            merging_strategy="allgreen",
        )

    def observe_workflow(self) -> C8WorkflowRead:
        return C8WorkflowRead(
            binding=BINDING,
            path=".github/workflows/validation.yml",
            workflow_digest=DIGEST,
            policy_digest=DIGEST,
            validation_check_identity_digest=DIGEST,
            pull_request_event=True,
            merge_group_event=True,
            exact_sha_checkout=True,
            checkout_persist_credentials_false=True,
        )

    def observe_validation_identity(self) -> C8ValidationIdentityRead:
        return C8ValidationIdentityRead(binding=BINDING, app_id=15368, identity="github-app-15368")

    def observe_rollback_namespace(self) -> C8RollbackNamespaceRead:
        return C8RollbackNamespaceRead(
            binding=BINDING,
            namespace="refs/heads/avo/main-rollback/*",
            controller_exclusive_create_write=True,
            controller_delete_authorized=True,
            non_controller_create_denied=True,
            non_controller_delete_denied=True,
            bypass_allowed=False,
        )

    def observe_isolated_issuer(self) -> C8IsolatedIssuerRead:
        return C8IsolatedIssuerRead(
            binding=BINDING,
            available=True,
            identity="isolated-release",
            app_id=42,
            isolation_digest=DIGEST,
        )


def test_report_is_deterministic_and_sorted() -> None:
    first = C8HostedPreflightService(Observer()).run()
    second = C8HostedPreflightService(Observer()).run()

    assert first.result == "no_detected_configuration_blocker"
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.report_digest == canonical_digest(
        first.model_dump(exclude={"report_digest"}, mode="json")
    )
    assert list(first.observation_digests) == sorted(first.observation_digests)
    assert first.authority_consumable is False
    assert first.authoritative is False
    assert first.readiness_established is False


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
    observer.observe_queue_configuration = lambda: C8QueueConfigurationRead(
        binding=BINDING, available=True
    )  # type: ignore[method-assign]
    observer.observe_isolated_issuer = lambda: C8IsolatedIssuerRead(
        binding=BINDING, available=False
    )  # type: ignore[method-assign]
    report = C8HostedPreflightService(observer).run()
    assert report.result == "blocked"
    assert "merge_queue_configuration_invalid" in report.blocker_codes
    assert "isolated_release_issuer_missing" in report.blocker_codes


def test_validation_identity_mismatch_and_issuer_incomplete_are_fail_closed() -> None:
    observer = Observer()
    observer.observe_validation_identity = lambda: C8ValidationIdentityRead(  # type: ignore[method-assign]
        binding=BINDING, app_id=None, identity=None
    )
    observer.observe_isolated_issuer = lambda: C8IsolatedIssuerRead(  # type: ignore[method-assign]
        binding=BINDING, available=True, identity="issuer", app_id=42, isolation_digest=None
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
            checkout_persist_credentials_false=None,
            secret="must not cross boundary",  # type: ignore[call-arg]
        )
    with pytest.raises(ValidationError):
        C8RollbackNamespaceRead(
            binding=BINDING,
            namespace="refs/heads/avo/main-rollback/*",
            bypass_allowed=False,
            deletion_protected=True,  # type: ignore[call-arg]
        )
    report = C8HostedPreflightService(Observer()).run()
    with pytest.raises(ValidationError):
        HostedC8PreflightReport.model_validate(
            {**report.model_dump(mode="json"), "report_digest": DIGEST}
        )


def test_model_construct_string_boolean_is_revalidated() -> None:
    observer = Observer()
    observer.observe_protection = lambda: C8ProtectionRead.model_construct(  # type: ignore[method-assign]
        binding=BINDING,
        effective="true",
        ruleset_ids=[1],
        queue_required=True,
        bypass_allowed=False,
        direct_merge_allowed=False,
    )
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        report = C8HostedPreflightService(observer).run()
    assert report.result == "unverifiable"
    assert "protection_read_unverifiable" in report.unverifiable_codes
    assert emitted == []


def test_model_construct_numeric_strings_are_revalidated_without_warning() -> None:
    observer = Observer()
    observer.observe_queue_configuration = lambda: C8QueueConfigurationRead.model_construct(  # type: ignore[method-assign]
        binding=BINDING,
        available=True,
        maximum_entries_to_merge="1",
        maximum_entries_to_build=1,
        merge_method="squash",
        merging_strategy="allgreen",
    )
    with warnings.catch_warnings(record=True) as emitted:
        warnings.simplefilter("always")
        report = C8HostedPreflightService(observer).run()
    assert report.result == "unverifiable"
    assert "queue_configuration_read_unverifiable" in report.unverifiable_codes
    assert emitted == []


def test_model_construct_issuer_numeric_string_is_revalidated() -> None:
    observer = Observer()
    observer.observe_isolated_issuer = lambda: C8IsolatedIssuerRead.model_construct(  # type: ignore[method-assign]
        binding=BINDING,
        available=True,
        identity="issuer",
        app_id="42",
        isolation_digest=DIGEST,
    )
    report = C8HostedPreflightService(observer).run()
    assert report.result == "unverifiable"
    assert "isolated_issuer_read_unverifiable" in report.unverifiable_codes


def test_malformed_expected_binding_does_not_leak_canary() -> None:
    canary = "expected-binding-secret-canary"
    values = BINDING.model_dump()
    values["configuration_epoch"] = canary
    values["observed_at"] = "not-a-date"
    malformed = C8ObservationBinding.model_construct(**values)
    stderr = io.StringIO()
    with warnings.catch_warnings(record=True) as emitted, redirect_stderr(stderr):
        warnings.simplefilter("always")
        with pytest.raises(ValueError) as error:
            C8HostedPreflightService(Observer(), expected_binding=malformed)
    assert str(error.value) == "invalid expected observation binding"
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert emitted == []
    assert canary not in str(error.value)
    assert canary not in stderr.getvalue()


def test_mixed_or_stale_snapshot_is_unverifiable() -> None:
    observer = Observer()
    other_binding = BINDING.model_copy(update={"configuration_epoch": "epoch-2"})
    observer.observe_workflow = lambda: C8WorkflowRead(  # type: ignore[method-assign]
        binding=other_binding,
        path="workflow",
        workflow_digest=DIGEST,
        policy_digest=DIGEST,
        validation_check_identity_digest=DIGEST,
        pull_request_event=True,
        merge_group_event=True,
        exact_sha_checkout=True,
        checkout_persist_credentials_false=None,
    )
    report = C8HostedPreflightService(observer).run()
    assert report.result == "unverifiable"
    assert "observation_snapshot_mismatch" in report.unverifiable_codes

    stale_values = BINDING.model_dump()
    stale_values["observed_at"] = datetime(2025, 12, 31, tzinfo=UTC)
    stale = BINDING.model_construct(**stale_values)
    observer.observe_workflow = lambda: C8WorkflowRead(  # type: ignore[method-assign]
        binding=stale,
        path="workflow",
        workflow_digest=DIGEST,
        policy_digest=DIGEST,
        validation_check_identity_digest=DIGEST,
        pull_request_event=True,
        merge_group_event=True,
        exact_sha_checkout=True,
        checkout_persist_credentials_false=None,
    )
    report = C8HostedPreflightService(observer).run()
    assert "workflow_read_unverifiable" in report.unverifiable_codes


def test_report_is_not_activation_or_capability_evidence() -> None:
    payload: dict[str, Any] = C8HostedPreflightService(Observer()).run().model_dump(mode="json")
    with pytest.raises(ValidationError):
        MainLedgerActivation.model_validate(payload)
    with pytest.raises(ValidationError):
        MainLedgerC8CapabilityEvidence.model_validate(payload)
    with pytest.raises(ValidationError):
        MainValidationIdentity.model_validate(payload)


def test_report_rejects_removed_pass_result() -> None:
    with pytest.raises(ValidationError):
        HostedC8PreflightReport.model_validate(
            {
                "schema_version": 1,
                "result": "pass",
                "passed_codes": [],
                "blocker_codes": [],
                "unverifiable_codes": [],
                "observation_digests": {},
                "authority_consumable": False,
                "authoritative": False,
                "readiness_established": False,
                "report_digest": DIGEST,
            }
        )
