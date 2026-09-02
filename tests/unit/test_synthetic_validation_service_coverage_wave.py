"""Additional state-machine coverage for synthetic validation service."""
# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportArgumentType=false, reportCallIssue=false, reportMissingImports=false, reportUnusedImport=false, reportUnusedVariable=false, reportUnnecessaryCast=false, reportAttributeAccessIssue=false, reportIndexIssue=false

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.synthetic_validation_journal import (
    SyntheticValidationJournal,
)
from avo_correlate.application.synthetic_validation_service import (
    SyntheticValidationCleanupRefusedError,
    SyntheticValidationConflictError,
    SyntheticValidationService,
)
from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationAttempt,
    SyntheticValidationCreateAuthorization,
    SyntheticValidationOutcome,
    SyntheticValidationPlan,
)
from tests.unit.test_synthetic_validation_contracts import observation, request
from tests.unit.test_synthetic_validation_service import (
    Provider,
    proof,
    service,
)


def test_prepare_accepts_observation_and_replays_exact_plan(tmp_path: Path) -> None:
    controller = service(tmp_path, Provider())
    plan = controller.prepare(
        observation(), trusted_check_contexts=["validate (windows-latest)"]
    )
    assert controller.prepare(
        observation(), trusted_check_contexts=["validate (windows-latest)"]
    ) == plan


def test_plan_replay_and_durable_read_bindings_fail_closed(tmp_path: Path) -> None:
    controller = service(tmp_path, Provider())
    plan = controller.prepare(request())

    class Journal:
        def __init__(self) -> None:
            self.plan = plan
            self.outcome: Any = None
            self.attempt: Any = None
            self.authorization: Any = None
            self.cleanup_value: Any = None

        def read_plan(self, _operation_id: str) -> Any:
            return self.plan

        def record_plan(self, _plan: SyntheticValidationPlan) -> Any:
            raise AssertionError("existing plan should not be recorded")

        def read_outcome(self, _operation_id: str) -> Any:
            return self.outcome

        def record_outcome(self, _outcome: SyntheticValidationOutcome) -> Any:
            return None

        def read_attempt(self, _operation_id: str) -> Any:
            return self.attempt

        def record_attempt(self, _attempt: SyntheticValidationAttempt) -> Any:
            return None

        def read_create_authorization(self, _operation_id: str) -> Any:
            return self.authorization

        def claim_create_authorization(self, _authorization: Any) -> bool:
            return False

        def read_cleanup(self, _operation_id: str) -> Any:
            return self.cleanup_value

        def record_cleanup(self, _outcome: SyntheticValidationOutcome) -> Any:
            return None

    journal = Journal()
    isolated = SyntheticValidationService(Provider(), journal)
    journal.plan = plan.model_copy(update={"expected_commit": "7" * 40})
    with pytest.raises(SyntheticValidationConflictError, match="conflicting replay"):
        isolated.prepare(request())
    bad_outcome = SyntheticValidationOutcome(
        operation_id=plan.operation_id,
        plan_digest="sha256:" + "f" * 64,
        validation_ref=plan.validation_ref,
        expected_commit=plan.expected_commit,
        expected_tree=plan.expected_tree,
        outcome="created",
        observed_commit=plan.expected_commit,
        observed_tree=plan.expected_tree,
    )
    journal.outcome = bad_outcome
    with pytest.raises(SyntheticValidationConflictError):
        isolated.trigger(plan)

    journal.plan = plan
    journal.outcome = None
    journal.attempt = SyntheticValidationAttempt(
        operation_id=plan.operation_id,
        plan_digest="sha256:" + "f" * 64,
        validation_ref=plan.validation_ref,
        expected_commit=plan.expected_commit,
        expected_tree=plan.expected_tree,
        kind="create_ambiguous",
    )
    with pytest.raises(SyntheticValidationConflictError, match="durable attempt"):
        isolated.trigger(plan)


def test_read_error_and_malformed_provider_observations_are_reconciliation_required(
    tmp_path: Path,
) -> None:
    class Broken(Provider):
        def read_validation_ref(self, repository_digest: str, ref: str) -> object | None:
            raise OSError("provider unavailable")

    result = service(tmp_path, Broken()).trigger(request())
    assert result.outcome == "reconciliation_required" and result.error == (
        "ref read requires reconciliation"
    )

    class Malformed(Provider):
        def read_validation_ref(self, repository_digest: str, ref: str) -> object | None:
            return {"commit": "5" * 40}

    result = service(tmp_path / "malformed", Malformed()).trigger(request())
    assert result.outcome == "reconciliation_required"


def test_claim_race_reconciles_exact_or_quarantines_wrong_ref(tmp_path: Path) -> None:
    class Loser(Provider):
        def __init__(self, ref: str) -> None:
            super().__init__()
            self.ref = ref

    # A failed claim must perform one read and never create.
    exact = Loser("5" * 40)
    controller = service(tmp_path, exact)
    plan = controller.prepare(request())
    journal = controller._journal  # pyright: ignore[reportPrivateUsage]
    authorization = SyntheticValidationCreateAuthorization(
        operation_id=plan.operation_id,
        plan_digest=plan.plan_digest,
        validation_ref=plan.validation_ref,
        expected_commit=plan.expected_commit,
        expected_tree=plan.expected_tree,
    )
    assert journal.claim_create_authorization(authorization)
    result = controller.trigger(plan)
    assert result.outcome == "already_present" and exact.create_calls == 0

    wrong = Loser("9" * 40)
    controller = service(tmp_path / "wrong", wrong)
    plan = controller.prepare(request())
    journal = controller._journal  # pyright: ignore[reportPrivateUsage]
    assert journal.claim_create_authorization(
        SyntheticValidationCreateAuthorization(
            operation_id=plan.operation_id,
            plan_digest=plan.plan_digest,
            validation_ref=plan.validation_ref,
            expected_commit=plan.expected_commit,
            expected_tree=plan.expected_tree,
        )
    )
    result = controller.trigger(plan)
    assert result.outcome == "invalid" and wrong.create_calls == 0


def test_create_success_followed_by_wrong_or_unreadable_state_is_quarantined(
    tmp_path: Path,
) -> None:
    class WrongAfterCreate(Provider):
        def read_validation_ref(self, repository_digest: str, ref: str) -> object | None:
            if self.create_calls:
                return {"commit": "9" * 40, "tree": "6" * 40}
            return super().read_validation_ref(repository_digest, ref)

    result = service(tmp_path, WrongAfterCreate()).trigger(request())
    assert result.outcome == "invalid"

    class UnreadableAfterCreate(Provider):
        def read_validation_ref(self, repository_digest: str, ref: str) -> object | None:
            if self.create_calls:
                raise OSError("read lost")
            return super().read_validation_ref(repository_digest, ref)

    result = service(tmp_path / "unreadable", UnreadableAfterCreate()).trigger(request())
    assert result.outcome == "reconciliation_required"


def test_cleanup_requires_durable_plan_verifier_and_handles_terminal_replays(
    tmp_path: Path,
) -> None:
    controller = service(tmp_path, Provider())
    plan = controller.prepare(request())
    bare = SyntheticValidationService(Provider(), SyntheticValidationJournal(tmp_path / "none"))
    bare_plan = bare.prepare(request())
    with pytest.raises(SyntheticValidationCleanupRefusedError, match="verification"):
        bare.cleanup(bare_plan, proof(bare_plan))
    with pytest.raises(SyntheticValidationConflictError, match="unknown"):
        controller.cleanup("sha256:" + "f" * 64, proof(plan))

    result = controller.trigger(plan)
    cleaned = controller.cleanup(plan.operation_id, proof(plan))
    assert cleaned.outcome == "cleaned"
    assert controller.cleanup(plan, proof(plan)) == cleaned
    assert result.outcome == "created"


def test_cleanup_read_error_wrong_ref_and_delete_reconciliation_paths(tmp_path: Path) -> None:
    class ReadError(Provider):
        def read_validation_ref(self, repository_digest: str, ref: str) -> object | None:
            raise OSError("read error")

    controller = service(tmp_path, ReadError())
    plan = controller.prepare(request())
    outcome = controller.cleanup(plan, proof(plan))
    assert outcome.outcome == "reconciliation_required"

    wrong = Provider(ref="9" * 40)
    controller = service(tmp_path / "wrong", wrong)
    plan = controller.prepare(request())
    assert controller.cleanup(plan, proof(plan)).outcome == "invalid"

    ambiguous = Provider(delete_error=True)
    controller = service(tmp_path / "ambiguous", ambiguous)
    controller.trigger(request())
    plan = controller.prepare(request())
    outcome = controller.cleanup(plan, proof(plan))
    assert outcome.outcome == "reconciliation_required"


def test_read_helpers_reject_durable_identity_collisions(tmp_path: Path) -> None:
    controller = service(tmp_path, Provider())
    plan = controller.prepare(request())
    loaded = controller.read_durable_plan(plan)
    assert loaded == plan
    with pytest.raises(SyntheticValidationConflictError):
        controller.read_durable_plan(plan.model_copy(update={"expected_tree": "7" * 40}))
    authorization = SyntheticValidationCreateAuthorization(
        operation_id=plan.operation_id,
        plan_digest=plan.plan_digest,
        validation_ref=plan.validation_ref,
        expected_commit=plan.expected_commit,
        expected_tree=plan.expected_tree,
    )
    assert controller.read_durable_authorization(authorization) is None
