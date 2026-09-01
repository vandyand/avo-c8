"""Pure, read-only hosted C8 preflight service."""

from __future__ import annotations

from typing import Final, Protocol, TypeVar

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
from avo_correlate.domain.canonical import canonical_digest

_ObservationT = TypeVar("_ObservationT")


class HostedC8PreflightReadOnly(Protocol):
    """Authenticated observation boundary; deliberately has no write methods."""

    def observe_repository(self) -> C8RepositoryRead: ...

    def observe_protection(self) -> C8ProtectionRead: ...

    def observe_queue_configuration(self) -> C8QueueConfigurationRead: ...

    def observe_workflow(self) -> C8WorkflowRead: ...

    def observe_validation_identity(self) -> C8ValidationIdentityRead: ...

    def observe_rollback_namespace(self) -> C8RollbackNamespaceRead: ...

    def observe_isolated_issuer(self) -> C8IsolatedIssuerRead: ...


class C8HostedPreflightService:
    """Classify authenticated reads without creating authority or state."""

    _ISOLATED_ISSUER_MISSING: Final[str] = "isolated_release_issuer_missing"

    def __init__(self, observer: HostedC8PreflightReadOnly) -> None:
        self._observer = observer

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
            if repository.target_ref == "refs/heads/main":
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
            if workflow.pull_request_event and workflow.merge_group_event:
                passed.append("workflow_events_required")
            else:
                blockers.append("workflow_events_incomplete")
            if workflow.exact_sha_checkout:
                passed.append("workflow_exact_sha_checkout")
            else:
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
            if not namespace.exclusive:
                blockers.append("rollback_namespace_not_exclusive")
            if namespace.bypass_allowed:
                blockers.append("rollback_namespace_bypass_allowed")
            if not namespace.exclusive_controller_write:
                blockers.append("rollback_namespace_controller_write_unverified")
            if not namespace.controller_delete_authorized:
                blockers.append("rollback_namespace_controller_delete_unverified")
            if not namespace.other_delete_denied:
                blockers.append("rollback_namespace_other_delete_unverified")
            if (
                namespace.namespace == "refs/heads/avo/main-rollback/*"
                and namespace.exclusive
                and not namespace.bypass_allowed
                and namespace.exclusive_controller_write
                and namespace.controller_delete_authorized
                and namespace.other_delete_denied
            ):
                passed.append("rollback_namespace_controls_read")

        return HostedC8PreflightReport.build(
            passed_codes=passed,
            blocker_codes=blockers,
            unverifiable_codes=unverifiable,
            observation_digests=digests,
        )

    @staticmethod
    def _read(
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
        return value


HostedC8Preflight = C8HostedPreflightService


__all__ = [
    "C8HostedPreflightService",
    "HostedC8Preflight",
    "HostedC8PreflightReadOnly",
]
