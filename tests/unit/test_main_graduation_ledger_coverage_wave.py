"""Additional branch coverage for the authority-owned C6 ledger path.

This file intentionally adds only independent tests.  The fixtures imported
from the original durability tests are real Pydantic records and real
filesystem artifacts; no production code or existing test is weakened.
"""

# Compact cross-module fixture composition is intentional in this coverage
# wave; production-facing calls remain checked by the repository-wide suite.
# pyright: reportPrivateUsage=false, reportUnknownParameterType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false, reportOptionalSubscript=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from avo_correlate.application.main_graduation_ledger_service import (
    MainGraduationLedgerService,
)
from avo_correlate.contracts.main_graduation_ledger import (
    MainLedgerAccumulatorState,
    MainLedgerActivation,
    MainLedgerEvidencePackage,
    MainLedgerHostedRollbackProof,
    main_ledger_genesis_state,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_main_graduation_ledger_contracts import _activation
from tests.unit.test_main_graduation_ledger_journal import (
    _classification,
    _journal,
    _outcome,
    _submission,
    _with_digest,
)
from tests.unit.test_main_graduation_ledger_service import (
    Classifier,
    Clock,
    Resolver,
    _content,
)

# These imports are deliberately private fixture helpers from the same test
# package; pyright should still type-check the production-facing calls below.
# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportArgumentType=false

DIGEST = "sha256:" + "1" * 64
NOW = datetime(2026, 9, 1, tzinfo=UTC)


def test_service_accepts_legacy_constructor_aliases_and_replays_activation(tmp_path: Path) -> None:
    journal, activation, _store = _journal(tmp_path)
    service = MainGraduationLedgerService(
        journal,
        trusted_clock=Clock(),
        content_resolver=Resolver(),
        controller_classifier=Classifier(),
    )
    assert service.journal is journal
    assert service.activate(activation) == journal.read_activation()[1]
    assert service.read_status().activation == activation


@pytest.mark.parametrize(
    "mutator",
    [
        lambda values: values.update({"expires_at": NOW}),
        lambda values: values.update({"authorized_at": NOW + timedelta(days=1)}),
    ],
)
def test_authority_and_activation_cross_field_validation_closes_time_windows(
    mutator: Any,
) -> None:
    activation = _activation()
    values = activation.controller_authority.model_dump(mode="json")
    mutator(values)
    with pytest.raises(ValidationError):
        MainLedgerActivation.model_validate(
            {
                **activation.model_dump(mode="json"),
                "controller_authority": values,
            }
        )


def test_service_classification_binds_dict_authority_and_rejects_policy_drift(
    tmp_path: Path,
) -> None:
    journal, activation, store = _journal(tmp_path)
    service = MainGraduationLedgerService(journal, Clock(), Resolver(), Classifier())
    content = _content(store, 101)
    submission = service.submit(11, "scheduler", "coverage", content.digest, content)
    result = {
        "classification": "eligible",
        "paths": ["src/coverage.py"],
        "risk_class": "ordinary",
        "controller_authority": activation.controller_authority.model_dump(mode="json"),
    }
    classification = service.classify(
        submission.operation_id,
        resolver=Resolver(),
        classifier=type(
            "DictClassifier",
            (),
            {"classify": lambda _self, _content, _activation, _submission: result},
        )(),
    )
    assert classification.empty is False
    bad = dict(result)
    bad["policy_digest"] = DIGEST[:-1] + "2"
    with pytest.raises(Exception, match="activation-bound"):
        MainGraduationLedgerService._derive_classification(bad, activation, submission)


def test_state_derivation_covers_exclusion_success_failure_and_terminal_boundary() -> None:
    activation = _activation()
    prior = main_ledger_genesis_state(
        activation.activation_digest, activation.scheduler_sequence_watermark
    )
    excluded = MainGraduationLedgerService._next_state(prior, "excluded", None)
    assert excluded.last_scheduler_sequence == prior.last_scheduler_sequence + 1

    # Construct a valid failure outcome through the real fixture path.
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as raw:
        journal, _activation_again, store = _journal(Path(raw))
        submission = _submission(activation, store, 11)
        classification = _classification(activation, submission, store)
        outcome = _outcome(activation, submission, classification, store)
        failure = MainGraduationLedgerService._next_state(prior, "eligible", outcome)
        assert failure.failures == 1 and failure.streak == 0
        with pytest.raises(Exception, match="threshold"):
            MainGraduationLedgerService._boundary_state(
                _with_digest(
                    MainLedgerAccumulatorState,
                    {
                        **prior.model_dump(exclude={"state_digest"}),
                        "streak": 12,
                        "successes": 12,
                        "threshold_complete": True,
                    },
                    "state_digest",
                )
            )
        assert journal.root == Path(raw).resolve()


def test_journal_read_paths_and_create_once_conflicts_are_fail_closed(tmp_path: Path) -> None:
    journal, activation, store = _journal(tmp_path)
    assert journal.read_submission_by_sequence(11) is None
    submission = _submission(activation, store, 11)
    journal.record_submission(submission)
    classification = _classification(activation, submission, store)
    assert journal.record_classification(classification) == journal.record_classification(
        classification
    )
    outcome = _outcome(activation, submission, classification, store)
    journal.record_outcome(outcome)
    assert journal.read_classification(submission.operation_id) is not None
    assert journal.read_outcome(11) is not None
    # A different content artifact under the same scheduler identity is a
    # create-once conflict, never a last-writer-wins update.
    other = _content(store, 103)
    conflict = _submission(activation, store, 11, identity="submission-11")
    conflict_values = conflict.model_dump(mode="json")
    conflict_values["content_artifact"] = other.model_dump(mode="json")
    conflict_values["submission_digest"] = other.digest
    conflict_values["operation_id"] = canonical_digest(
        {
            "domain": "avo.main.ledger.submission.v2",
            "activation_digest": activation.activation_digest,
            "scheduler_sequence": 11,
            "source_identity": "scheduler",
            "submission_identity": "submission-11",
            "submission_digest": other.digest,
        }
    )
    conflict_values.pop("envelope_digest", None)
    conflict = _with_digest(type(submission), conflict_values, "envelope_digest")
    with pytest.raises(Exception, match="conflicting submission"):
        journal.record_submission(conflict)


def test_hosted_proof_digest_and_package_closure_reject_tamper() -> None:
    activation = _activation()
    proof = activation.hosted_rollback_proof.model_dump(mode="json")
    proof["deploy_performed"] = True
    with pytest.raises(ValidationError):
        MainLedgerHostedRollbackProof.model_validate(proof)
    package = MainLedgerEvidencePackage.model_construct(
        activation=activation,
        status="threshold_complete",
        submissions=[],
        classifications=[],
        outcomes=[],
        transitions=[],
        final_state=main_ledger_genesis_state(
            activation.activation_digest, activation.scheduler_sequence_watermark
        ),
        package_digest=DIGEST,
    )
    with pytest.raises(ValidationError):
        MainLedgerEvidencePackage.model_validate(package.model_dump(mode="json"))
