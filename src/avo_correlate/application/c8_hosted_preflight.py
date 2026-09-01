"""Pure, read-only hosted C8 preflight service."""

from __future__ import annotations

from typing import Final, Protocol, TypeVar

from avo_correlate.contracts.base import StrictModel
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
from avo_correlate.domain.canonical import canonical_digest

_ObservationT = TypeVar("_ObservationT", bound=StrictModel)


class HostedC8PreflightReadOnly(Protocol):
    """Future provider-authenticated observation boundary, with no writers.

    Current DTOs are diagnostic inputs only: this protocol authenticates
    nothing, creates no authority, and cannot establish hosted readiness.
    """

    def observe_repository(self) -> C8RepositoryRead: ...

    def observe_protection(self) -> C8ProtectionRead: ...

    def observe_queue_configuration(self) -> C8QueueConfigurationRead: ...

    def observe_workflow(self) -> C8WorkflowRead: ...

    def observe_validation_identity(self) -> C8ValidationIdentityRead: ...

    def observe_rollback_namespace(self) -> C8RollbackNamespaceRead: ...

    def observe_isolated_issuer(self) -> C8IsolatedIssuerRead: ...


class C8HostedPreflightService:
    """Classify diagnostic reads without creating authority or state.

    A future adapter may authenticate the reads.  This pure service does not,
    and its report therefore never establishes hosted readiness.
    """

    _ISOLATED_ISSUER_MISSING: Final[str] = "isolated_release_issuer_missing"

    def __init__(
        self,
        observer: HostedC8PreflightReadOnly,
        expected_binding: C8ObservationBinding | None = None,
    ) -> None:
        self._observer = observer
        invalid_binding = False
        checked_binding: C8ObservationBinding | None = None
        try:
            if expected_binding is not None:
                checked_binding = C8ObservationBinding.model_validate(
                    expected_binding.model_dump(mode="json", warnings="error")
                )
        except Exception:
            invalid_binding = True
        if invalid_binding:
            raise ValueError("invalid expected observation binding")
        self._expected_binding = checked_binding

    def run(self) -> HostedC8PreflightReport:
        passed: list[str] = []
        blockers: list[str] = []
        unverifiable: list[str] = []
        digests: dict[str, str] = {}

        repository = self._read(
            "repository",
            getattr(self._observer, "observe_repository", None),
            C8RepositoryRead,
            unverifiable,
        )
        if repository is not None:
            digests["repository"] = canonical_digest(repository)
            if repository.owner_type == "Organization":
                passed.append("organization_hosting")
            else:
                blockers.append("organization_hosting_required")
            if (
                repository.binding is not None
                and repository.binding.target_ref == "refs/heads/main"
            ):
                passed.append("protected_main_target")
            else:  # defensive; the typed contract already fixes this value.
                blockers.append("protected_main_target_mismatch")
            if repository.main_commit and repository.main_tree:
                passed.append("main_topology_read")
            else:
                unverifiable.append("main_topology_incomplete")

        protection = self._read(
            "protection",
            getattr(self._observer, "observe_protection", None),
            C8ProtectionRead,
            unverifiable,
        )
        if protection is not None:
            digests["protection"] = canonical_digest(protection)
            if not protection.effective or not protection.ruleset_ids:
                blockers.append("effective_protection_missing")
            else:
                passed.append("effective_protection_read")
            if protection.queue_required:
                passed.append("merge_queue_required_by_protection")
            else:
                blockers.append("merge_queue_protection_missing")
            if protection.bypass_allowed:
                blockers.append("protection_bypass_allowed")
            else:
                passed.append("protection_bypass_denied")
            if protection.direct_merge_allowed:
                blockers.append("direct_merge_allowed")
            else:
                passed.append("direct_merge_denied")

        queue = self._read(
            "queue_configuration",
            getattr(self._observer, "observe_queue_configuration", None),
            C8QueueConfigurationRead,
            unverifiable,
        )
        if queue is not None:
            digests["queue_configuration"] = canonical_digest(queue)
            if not queue.available:
                blockers.append("merge_queue_unavailable")
            elif (
                queue.maximum_entries_to_merge != 1
                or queue.maximum_entries_to_build is None
                or queue.maximum_entries_to_build < 1
                or queue.merge_method is None
                or queue.merge_method.casefold() != "squash"
                or queue.merging_strategy is None
                or queue.merging_strategy.casefold() not in {"allgreen", "all_green"}
            ):
                blockers.append("merge_queue_configuration_invalid")
            else:
                passed.append("merge_queue_configuration_read")

        workflow = self._read(
            "workflow",
            getattr(self._observer, "observe_workflow", None),
            C8WorkflowRead,
            unverifiable,
        )
        if workflow is not None:
            digests["workflow"] = canonical_digest(workflow)
            if (
                workflow.workflow_digest is None
                or workflow.policy_digest is None
                or workflow.validation_check_identity_digest is None
            ):
                unverifiable.append("workflow_binding_incomplete")
            if (
                workflow.pull_request_event is None
                or workflow.merge_group_event is None
                or workflow.exact_sha_checkout is None
            ):
                unverifiable.append("workflow_semantics_unverifiable")
            elif workflow.pull_request_event and workflow.merge_group_event:
                passed.append("workflow_events_required")
            else:
                blockers.append("workflow_events_incomplete")
            if workflow.exact_sha_checkout is True:
                passed.append("workflow_exact_sha_checkout")
            elif workflow.exact_sha_checkout is False:
                blockers.append("workflow_exact_sha_checkout_missing")

        validation = self._read(
            "validation_identity",
            getattr(self._observer, "observe_validation_identity", None),
            C8ValidationIdentityRead,
            unverifiable,
        )
        if validation is not None:
            digests["validation_identity"] = canonical_digest(validation)
            if validation.app_id != 15368 or validation.identity is None:
                blockers.append("validation_app15368_identity_unverified")
            else:
                passed.append("validation_app15368_identity_read")

        issuer = self._read(
            "isolated_issuer",
            getattr(self._observer, "observe_isolated_issuer", None),
            C8IsolatedIssuerRead,
            unverifiable,
        )
        if issuer is not None:
            digests["isolated_issuer"] = canonical_digest(issuer)
            if not issuer.available:
                blockers.append(self._ISOLATED_ISSUER_MISSING)
            elif (
                issuer.identity is None or issuer.app_id is None or issuer.isolation_digest is None
            ):
                unverifiable.append("isolated_release_issuer_incomplete")
            else:
                passed.append("isolated_release_issuer_available")

        namespace = self._read(
            "rollback_namespace",
            getattr(self._observer, "observe_rollback_namespace", None),
            C8RollbackNamespaceRead,
            unverifiable,
        )
        if namespace is not None:
            digests["rollback_namespace"] = canonical_digest(namespace)
            if namespace.namespace != "refs/heads/avo/main-rollback/*":
                blockers.append("rollback_namespace_mismatch")
            if namespace.bypass_allowed:
                blockers.append("rollback_namespace_bypass_allowed")
            if not namespace.controller_exclusive_create_write:
                blockers.append("rollback_namespace_controller_write_unverified")
            if not namespace.controller_delete_authorized:
                blockers.append("rollback_namespace_controller_delete_unverified")
            if not namespace.non_controller_create_denied:
                blockers.append("rollback_namespace_other_create_unverified")
            if not namespace.non_controller_delete_denied:
                blockers.append("rollback_namespace_other_delete_unverified")
            if (
                namespace.namespace == "refs/heads/avo/main-rollback/*"
                and not namespace.bypass_allowed
                and namespace.controller_exclusive_create_write
                and namespace.controller_delete_authorized
                and namespace.non_controller_create_denied
                and namespace.non_controller_delete_denied
            ):
                passed.append("rollback_namespace_controls_read")

        bindings = [
            value.binding
            for value in (repository, protection, queue, workflow, validation, issuer, namespace)
            if value is not None and value.binding is not None
        ]
        if bindings and any(binding != bindings[0] for binding in bindings[1:]):
            unverifiable.append("observation_snapshot_mismatch")

        return HostedC8PreflightReport.build(
            passed_codes=passed,
            blocker_codes=blockers,
            unverifiable_codes=unverifiable,
            observation_digests=digests,
        )

    def _read(
        self,
        name: str,
        method: object,
        expected_type: type[_ObservationT],
        unverifiable: list[str],
        /,
    ) -> _ObservationT | None:
        if not callable(method):
            unverifiable.append(f"{name}_observer_unavailable")
            return None
        try:
            value = method()
        except Exception:
            # Diagnostics intentionally do not expose provider errors or tokens.
            unverifiable.append(f"{name}_read_unverifiable")
            return None
        if not isinstance(value, expected_type):
            unverifiable.append(f"{name}_read_unverifiable")
            return None
        try:
            checked = expected_type.model_validate(value.model_dump(mode="json", warnings="error"))
        except Exception:
            unverifiable.append(f"{name}_read_unverifiable")
            return None
        binding = getattr(checked, "binding", None)
        if binding is None:
            unverifiable.append(f"{name}_snapshot_unbound")
            return None
        if self._expected_binding is not None and binding != self._expected_binding:
            unverifiable.append("observation_snapshot_mismatch")
            return None
        return checked


HostedC8Preflight = C8HostedPreflightService


__all__ = [
    "C8HostedPreflightService",
    "HostedC8Preflight",
    "HostedC8PreflightReadOnly",
]
