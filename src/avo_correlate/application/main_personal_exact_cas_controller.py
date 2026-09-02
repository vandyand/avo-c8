"""Offline controller for one personal exact compare-and-swap attempt.

This module is deliberately an application leaf.  It owns the ordering and
recovery state machine, while dispatch, authoritative reads, lease fencing,
and time are injected as narrow ports.  There is no provider, HTTP, token, or
generic-ref capability in this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, cast

from avo_correlate.adapters.artifacts.main_personal_exact_cas_journal import (
    MainPersonalExactCasJournal,
)
from avo_correlate.contracts.base import Sha256Digest
from avo_correlate.contracts.main_personal_exact_cas import (
    MainPersonalExactCasAuthorization,
    MainPersonalExactCasCompletion,
    MainPersonalExactCasDispatchStarted,
    MainPersonalExactCasIntent,
    MainPersonalExactCasPostStateObservation,
    MainPersonalExactCasReceipt,
    MainPersonalExactCasReconciliation,
)
from avo_correlate.domain.canonical import canonical_digest


class MainPersonalExactCasDispatchPort(Protocol):
    """The sole injected capability allowed to attempt the exact CAS."""

    def apply(
        self, intent: MainPersonalExactCasIntent, marker: MainPersonalExactCasDispatchStarted
    ) -> MainPersonalExactCasReceipt: ...


class MainPersonalExactCasPostStateReader(Protocol):
    """Read-only authoritative post-state capability."""

    def observe(
        self, intent: MainPersonalExactCasIntent, receipt: MainPersonalExactCasReceipt
    ) -> MainPersonalExactCasPostStateObservation: ...


class MainPersonalExactCasLeasePort(Protocol):
    """Controller-owned durable lease/fence assertion."""

    def assert_current(
        self,
        *,
        operation_id: Sha256Digest,
        target_ref: str,
        lease_identity: str,
        lease_digest: Sha256Digest,
        lease_expires_at: datetime,
        now: datetime,
    ) -> None: ...


class MainPersonalExactCasTrustedClock(Protocol):
    def now(self) -> datetime: ...


class MainPersonalExactCasControllerError(RuntimeError):
    """Safe, non-secret controller failure."""


@dataclass(frozen=True)
class MainPersonalExactCasControllerResult:
    """Public state-machine result; it contains no provider error text."""

    operation_id: str
    state: str
    outcome: str | None = None
    dispatch_started: bool = False
    dispatch_count: int = 0
    completion_replayed: bool = False
    reason: str = ""


class MainPersonalExactCasController:
    """Run or recover one journaled personal exact-CAS operation.

    A completion is checked before any other state or clock access.  A durable
    marker without a receipt is unresolved and can never cause another call.
    """

    def __init__(
        self,
        journal: MainPersonalExactCasJournal,
        dispatch: MainPersonalExactCasDispatchPort,
        post_state: MainPersonalExactCasPostStateReader,
        lease: MainPersonalExactCasLeasePort,
        clock: MainPersonalExactCasTrustedClock,
    ) -> None:
        for value, methods, label in (
            (
                journal,
                (
                    "read_completion",
                    "read_dispatch_started",
                    "read_receipt",
                    "read_intent",
                    "read_post_state",
                    "read_reconciliation",
                    "record_authorization",
                    "record_intent",
                    "record_dispatch_started",
                    "claim_dispatch_started",
                    "record_receipt",
                    "record_post_state",
                    "record_reconciliation",
                    "record_completion",
                ),
                "journal",
            ),
            (dispatch, ("apply",), "dispatch port"),
            (post_state, ("observe",), "post-state reader"),
            (lease, ("assert_current",), "lease port"),
            (clock, ("now",), "trusted clock"),
        ):
            if any(not callable(getattr(value, name, None)) for name in methods):
                raise ValueError(f"{label} is required")
        self._journal = journal
        self._dispatch = dispatch
        self._post_state = post_state
        self._lease = lease
        self._clock = clock

    def execute(
        self, authorization: MainPersonalExactCasAuthorization
    ) -> MainPersonalExactCasControllerResult:
        """Execute once, or recover a previously started operation."""

        operation_id = authorization.operation_id
        # This is intentionally the first journal call: replay is read-only,
        # and must not consult the clock or any capability.
        try:
            completion = self._journal.read_completion(operation_id)
        except Exception:
            return self._unresolved(operation_id, "completion replay is unresolved")
        if completion is not None:
            return MainPersonalExactCasControllerResult(
                operation_id=operation_id,
                state="completed",
                outcome="applied",
                dispatch_started=True,
                completion_replayed=True,
                reason="completed_replay",
            )

        try:
            marker = self._journal.read_dispatch_started(operation_id)
            receipt = self._journal.read_receipt(operation_id)
        except Exception:
            return self._unresolved(operation_id, "durable recovery is unresolved")
        if marker is not None and receipt is None:
            return self._unresolved(operation_id, "dispatch marker has no receipt")
        if receipt is not None:
            return self._recover_receipt(receipt[0])

        # Authentication and source revalidation occur through the journal
        # before an intent is allowed to exist.
        try:
            self._journal.record_authorization(authorization)
            now = self._clock.now()
            self._assert_aware(now)
            self._assert_before_expiry(now, authorization.lease_expires_at)
            if now < authorization.authorized_at:
                raise ValueError("trusted clock precedes authorization")
            self._assert_lease(authorization, now=now)
            existing_intent = self._journal.read_intent(operation_id)
            if existing_intent is not None:
                intent = existing_intent[0]
                if intent.authorization_digest != authorization.authorization_digest:
                    raise ValueError("authorization differs from durable intent")
            else:
                intent = MainPersonalExactCasIntent.build(
                    **self._intent_values(authorization),
                    authorization_digest=authorization.authorization_digest,
                    recorded_at=now,
                )
                self._journal.record_intent(intent)
        except Exception as exc:
            return self._safe_failure(operation_id, "intent was not durably recorded", exc)

        # This is the last gate before the marker and sole dispatch.
        created = False
        try:
            last_moment = self._clock.now()
            self._assert_aware(last_moment)
            self._assert_before_expiry(last_moment, intent.lease_expires_at)
            if last_moment < intent.recorded_at:
                raise ValueError("trusted clock precedes durable intent")
            self._assert_lease(intent, now=last_moment)
            marker = MainPersonalExactCasDispatchStarted.build(
                **self._intent_values(intent),
                intent_digest=intent.intent_digest,
                started_at=last_moment,
            )
            _, created = self._journal.claim_dispatch_started(marker)
            if not created:
                return self._unresolved(
                    operation_id,
                    "dispatch marker is owned by another controller",
                    dispatch_started=True,
                )
            # Marker publication itself may pause.  Recheck immediately
            # before the irreversible call; expiry leaves marker/no receipt
            # for read-only recovery and never dispatches.
            post_marker = self._clock.now()
            self._assert_aware(post_marker)
            self._assert_before_expiry(post_marker, intent.lease_expires_at)
            if post_marker < last_moment:
                raise ValueError("trusted clock regressed after marker")
            self._assert_lease(intent, now=post_marker)
        except Exception as exc:
            if "created" in locals() and created:
                return self._unresolved(
                    operation_id,
                    "dispatch was fenced after marker publication",
                    dispatch_started=True,
                )
            return self._safe_failure(operation_id, "dispatch was fenced before start", exc)

        receipt = self._dispatch_once(intent, marker)
        if receipt is None:
            return self._unresolved(
                operation_id, "dispatch receipt is unresolved", dispatch_started=True, count=1
            )
        return self._finish_receipt(intent, marker, receipt, count=1)

    run = execute

    def _dispatch_once(
        self, intent: MainPersonalExactCasIntent, marker: MainPersonalExactCasDispatchStarted
    ) -> MainPersonalExactCasReceipt | None:
        try:
            candidate = self._dispatch.apply(intent, marker)
            if type(candidate) is not MainPersonalExactCasReceipt:
                raise ValueError("receipt is not concrete")
            # Reparse at the controller boundary, then require the returned
            # DTO to be exactly bound.  No controller code repairs provider
            # scope, marker, timestamps, or digest fields.
            checked = cast(
                MainPersonalExactCasReceipt,
                cast(Any, MainPersonalExactCasReceipt).model_validate(
                    cast(Any, candidate).model_dump(mode="json", warnings="error")
                ),
            )
            if checked != candidate or not self._receipt_exactly_bound(checked, intent, marker):
                raise ValueError("receipt binding differs")
            return checked
        except Exception:
            # A lost/invalid response leaves marker-without-receipt recovery
            # state.  It is never self-attested as an ambiguous receipt.
            return None

    def _finish_receipt(
        self,
        intent: MainPersonalExactCasIntent,
        marker: MainPersonalExactCasDispatchStarted,
        receipt: MainPersonalExactCasReceipt,
        *,
        count: int,
    ) -> MainPersonalExactCasControllerResult:
        try:
            self._journal.record_receipt(receipt)
        except Exception:
            return self._unresolved(
                intent.operation_id,
                "receipt was not durably authenticated",
                dispatch_started=True,
                count=count,
            )
        if receipt.outcome == "rejected":
            return MainPersonalExactCasControllerResult(
                intent.operation_id,
                "rejected",
                "rejected",
                bool(cast(Any, receipt).dispatch_started),
                count,
                reason="authoritative_rejection",
            )
        return self._observe_and_close(intent, marker, receipt, count=count)

    def _recover_receipt(
        self, receipt: MainPersonalExactCasReceipt
    ) -> MainPersonalExactCasControllerResult:
        if receipt.outcome == "rejected":
            return MainPersonalExactCasControllerResult(
                receipt.operation_id,
                "rejected",
                "rejected",
                bool(cast(Any, receipt).dispatch_started),
                0,
                reason="authoritative_rejection",
            )
        try:
            intent_result = self._journal.read_intent(receipt.operation_id)
            marker_result = self._journal.read_dispatch_started(receipt.operation_id)
            if intent_result is None or marker_result is None:
                return self._unresolved(
                    receipt.operation_id, "receipt chain is incomplete", dispatch_started=True
                )
            observation_result = self._journal.read_post_state(receipt.operation_id)
            reconciliation_result = self._journal.read_reconciliation(receipt.operation_id)
            if reconciliation_result is not None and observation_result is None:
                return self._unresolved(
                    receipt.operation_id,
                    "reconciliation chain is incomplete",
                    dispatch_started=True,
                )
            return self._observe_and_close(
                intent_result[0],
                marker_result[0],
                receipt,
                count=0,
                observation=None if observation_result is None else observation_result[0],
                reconciliation=(
                    None if reconciliation_result is None else reconciliation_result[0]
                ),
            )
        except Exception:
            return self._unresolved(
                receipt.operation_id, "receipt recovery is unresolved", dispatch_started=True
            )

    def _observe_and_close(
        self,
        intent: MainPersonalExactCasIntent,
        marker: MainPersonalExactCasDispatchStarted,
        receipt: MainPersonalExactCasReceipt,
        *,
        count: int,
        observation: MainPersonalExactCasPostStateObservation | None = None,
        reconciliation: MainPersonalExactCasReconciliation | None = None,
    ) -> MainPersonalExactCasControllerResult:
        try:
            if observation is None:
                observation = self._post_state.observe(intent, receipt)
                if type(observation) is not MainPersonalExactCasPostStateObservation:
                    raise ValueError("post-state is not concrete")
                observation = cast(
                    MainPersonalExactCasPostStateObservation,
                    cast(Any, MainPersonalExactCasPostStateObservation).model_validate(
                        cast(Any, observation).model_dump(mode="json", warnings="error")
                    ),
                )
                self._journal.record_post_state(observation)
            exact = self._exact_topology(observation)
            if receipt.outcome == "ambiguous":
                if reconciliation is None:
                    reconciliation = MainPersonalExactCasReconciliation.build(
                        activation_digest=receipt.activation_digest,
                        operation_id=receipt.operation_id,
                        ambiguous_receipt=receipt,
                        observation=observation,
                        outcome="applied" if exact else "ambiguous",
                        reconciled_at=observation.observed_at,
                    )
                    self._journal.record_reconciliation(reconciliation)
                if not exact:
                    return self._unresolved(
                        intent.operation_id,
                        "ambiguous receipt remains unresolved",
                        dispatch_started=True,
                        count=count,
                    )
                reconciliation_digest = canonical_digest(reconciliation)
            else:
                if not exact:
                    return self._unresolved(
                        intent.operation_id,
                        "applied receipt lacks exact post-state",
                        dispatch_started=True,
                        count=count,
                    )
                reconciliation_digest = None
            completion = MainPersonalExactCasCompletion.build(
                activation_digest=receipt.activation_digest,
                operation_id=receipt.operation_id,
                receipt_digest=receipt.receipt_digest,
                post_state_observation_digest=canonical_digest(observation),
                reconciliation_digest=reconciliation_digest,
                outcome="applied",
                completed_at=observation.observed_at,
            )
            self._journal.record_completion(completion)
            return MainPersonalExactCasControllerResult(
                intent.operation_id, "completed", "applied", True, count, reason="applied"
            )
        except Exception:
            return self._unresolved(
                intent.operation_id,
                "authoritative post-state is unresolved",
                dispatch_started=True,
                count=count,
            )

    @staticmethod
    def _intent_values(value: Any) -> dict[str, object]:
        fields = (
            "activation_digest", "operation_id", "repository_digest", "target_ref",
            "source_operation_id", "source_plan_digest", "source_package_digest",
            "source_composition_digest", "base_commit", "base_tree", "candidate_commit",
            "candidate_tree", "candidate_ref", "candidate_parents", "protection_ruleset_digest",
            "writer_app_id", "writer_installation_id", "writer_identity", "lease_identity",
            "lease_digest", "lease_expires_at", "claim_nonce", "claim_digest",
        )
        dumped = cast(dict[str, object], value.model_dump(mode="python"))
        return {name: dumped[name] for name in fields}

    @staticmethod
    def _exact_topology(observation: MainPersonalExactCasPostStateObservation) -> bool:
        return (
            observation.observed_ref == "refs/heads/main"
            and observation.observed_commit == observation.candidate_commit
            and observation.observed_tree == observation.candidate_tree
            and observation.observed_parents == (observation.base_commit,)
        )

    def _assert_lease(self, value: Any, *, now: datetime) -> None:
        self._lease.assert_current(
            operation_id=cast(Sha256Digest, value.operation_id),
            target_ref=cast(str, value.target_ref),
            lease_identity=cast(str, value.lease_identity),
            lease_digest=cast(Sha256Digest, value.lease_digest),
            lease_expires_at=cast(datetime, value.lease_expires_at),
            now=now,
        )

    @staticmethod
    def _assert_aware(value: datetime) -> None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("trusted clock returned naive time")

    @staticmethod
    def _assert_before_expiry(now: datetime, expiry: datetime) -> None:
        if now >= expiry:
            raise MainPersonalExactCasControllerError("lease expired")

    @staticmethod
    def _receipt_exactly_bound(
        receipt: MainPersonalExactCasReceipt,
        intent: MainPersonalExactCasIntent,
        marker: MainPersonalExactCasDispatchStarted,
    ) -> bool:
        return all(
            getattr(receipt, name) == getattr(intent, name)
            for name in (
                "activation_digest", "operation_id", "repository_digest", "target_ref",
                "source_operation_id", "source_plan_digest", "source_package_digest",
                "source_composition_digest", "base_commit", "base_tree", "candidate_commit",
                "candidate_tree", "candidate_ref", "candidate_parents", "protection_ruleset_digest",
                "writer_app_id", "writer_installation_id", "writer_identity", "lease_identity",
                "lease_digest", "lease_expires_at", "claim_nonce", "claim_digest",
            )
        ) and (
            receipt.authorization_digest == intent.authorization_digest
            and receipt.intent_digest == intent.intent_digest
            and receipt.dispatch_marker_digest == marker.dispatch_marker_digest
        )

    @staticmethod
    def _unresolved(
        operation_id: str,
        reason: str,
        *,
        dispatch_started: bool = False,
        count: int = 0,
    ) -> MainPersonalExactCasControllerResult:
        return MainPersonalExactCasControllerResult(
            operation_id=operation_id,
            state="reconciliation_required",
            outcome="ambiguous",
            dispatch_started=dispatch_started,
            dispatch_count=count,
            reason=reason,
        )

    @staticmethod
    def _safe_failure(
        operation_id: str, reason: str, _exc: Exception
    ) -> MainPersonalExactCasControllerResult:
        return MainPersonalExactCasControllerResult(
            operation_id=operation_id, state="rejected", outcome="rejected", reason=reason
        )


__all__ = [
    "MainPersonalExactCasController",
    "MainPersonalExactCasControllerError",
    "MainPersonalExactCasControllerResult",
    "MainPersonalExactCasDispatchPort",
    "MainPersonalExactCasLeasePort",
    "MainPersonalExactCasPostStateReader",
    "MainPersonalExactCasTrustedClock",
]
