"""Fast offline checks for non-authoritative response classification."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from avo_correlate.adapters.artifacts import (
    main_personal_exact_cas_response_reconciliation as reconciliation_module,
)
from avo_correlate.adapters.artifacts.main_personal_exact_cas_journal import (
    MainPersonalExactCasJournal,
)
from avo_correlate.adapters.artifacts.main_personal_exact_cas_response_reconciliation import (
    MainPersonalExactCasResponseReconciliationClassificationJournal,
    MainPersonalExactCasResponseReconciliationError,
)
from avo_correlate.contracts.main_personal_exact_cas import (
    MainPersonalExactCasDispatchStarted,
    MainPersonalExactCasIntent,
)
from avo_correlate.contracts.main_personal_exact_cas_response_reconciliation import (
    MainPersonalExactCasResponseReconciliationClassification,
)
from avo_correlate.domain.canonical import canonical_bytes
from tests.unit.test_main_personal_exact_cas_response_evidence import (
    _chain,
    _journal,
    _observation,
    _qualified,
)


def _no_directory_fsync(_path: Path) -> None:
    return None


def _authority_journal(
    intent: MainPersonalExactCasIntent, marker: MainPersonalExactCasDispatchStarted
) -> MainPersonalExactCasJournal:
    journal = object.__new__(MainPersonalExactCasJournal)

    def read_intent(operation_id: str):
        del operation_id
        return intent, None

    def read_dispatch_started(operation_id: str):
        del operation_id
        return marker, None

    untyped = cast(Any, journal)
    untyped.read_intent = read_intent
    untyped.read_dispatch_started = read_dispatch_started
    return journal


def _classification_journal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    intent: MainPersonalExactCasIntent,
    marker: MainPersonalExactCasDispatchStarted,
    observation: Any,
) -> MainPersonalExactCasResponseReconciliationClassificationJournal:
    evidence = _journal(monkeypatch, tmp_path, intent, marker)
    evidence.record_response_evidence(intent, marker, observation)
    monkeypatch.setattr(reconciliation_module, "require_durable_backend", _qualified)
    monkeypatch.setattr(reconciliation_module, "_fsync_directory", _no_directory_fsync)
    return MainPersonalExactCasResponseReconciliationClassificationJournal(
        evidence.root,
        response_evidence_journal=evidence,
        authority_journal=_authority_journal(intent, marker),
    )


def test_classification_reopens_and_is_idempotent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    intent, marker = _chain()
    journal = _classification_journal(
        monkeypatch, tmp_path, intent, marker, _observation(intent, marker)
    )
    first = journal.classify(intent.operation_id)
    second = journal.classify(intent.operation_id)
    reopened = MainPersonalExactCasResponseReconciliationClassificationJournal(
        journal.root,
        response_evidence_journal=cast(Any, journal)._evidence,
        authority_journal=cast(Any, journal)._authority,
    )
    loaded = reopened.read_classification(intent.operation_id)
    assert first == second
    assert loaded is not None and loaded[0] == first
    assert first.classification == "candidate_observed"
    assert first.is_terminal is False and first.is_authoritative is False


def test_conclusive_rejection_is_only_a_classification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    intent, marker = _chain()
    observation = _observation(intent, marker)
    observation.status = 409
    observation.classification = "conflict_or_rejected"
    journal = _classification_journal(monkeypatch, tmp_path, intent, marker, observation)
    result = journal.classify(intent.operation_id)
    assert result.classification == "conclusive_rejection_observed"
    assert "receipt" not in result.model_dump(mode="json")


def test_ambiguous_5xx_requires_reconciliation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    intent, marker = _chain()
    observation = _observation(intent, marker)
    observation.status = 500
    observation.classification = "ambiguous"
    journal = _classification_journal(monkeypatch, tmp_path, intent, marker, observation)
    assert journal.classify(intent.operation_id).classification == "reconciliation_required"


def test_tampered_index_is_rejected_without_authority_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    intent, marker = _chain()
    journal = _classification_journal(
        monkeypatch, tmp_path, intent, marker, _observation(intent, marker)
    )
    journal.classify(intent.operation_id)
    index = next(
        journal.root.glob("main-personal-exact-cas-response-reconciliation-index/*/*.json")
    )
    index.write_bytes(b"{}")
    with pytest.raises(MainPersonalExactCasResponseReconciliationError) as raised:
        journal.read_classification(intent.operation_id)
    assert str(raised.value) == "malformed_index"
    assert raised.value.__cause__ is None and raised.value.__context__ is None


def test_reopen_rejects_rebound_classification_timestamp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    intent, marker = _chain()
    journal = _classification_journal(
        monkeypatch, tmp_path, intent, marker, _observation(intent, marker)
    )
    journal.classify(intent.operation_id)
    loaded = journal.read_classification(intent.operation_id)
    assert loaded is not None
    values = loaded[0].model_dump(exclude={"classification_digest"}, mode="python")
    values["classified_at"] = loaded[0].classified_at + timedelta(seconds=1)
    forged = MainPersonalExactCasResponseReconciliationClassification.build(**values)
    replacement = journal.artifact_store.put_bytes(
        canonical_bytes(forged),
        media_type=loaded[1].media_type,
        role=loaded[1].role,
        max_bytes=8 * 1024 * 1024,
    )
    index = next(
        journal.root.glob("main-personal-exact-cas-response-reconciliation-index/*/*.json")
    )
    index.write_bytes(canonical_bytes(replacement))
    with pytest.raises(MainPersonalExactCasResponseReconciliationError) as raised:
        journal.read_classification(intent.operation_id)
    assert str(raised.value) == "malformed_classification"


def test_constructor_rejects_caller_spoofed_authority_and_public_surface():
    with pytest.raises(ValueError):
        MainPersonalExactCasResponseReconciliationClassificationJournal(
            Path("."),
            response_evidence_journal=cast(Any, SimpleNamespace()),
            authority_journal=cast(Any, SimpleNamespace()),
        )
    names = set(dir(MainPersonalExactCasResponseReconciliationClassificationJournal))
    assert "apply" not in names and "verify_receipt" not in names
    source = Path(
        "src/avo_correlate/adapters/artifacts/main_personal_exact_cas_response_reconciliation.py"
    ).read_text(encoding="utf-8")
    assert "MainPersonalExactCasResponseEvidenceVerifier" not in source
    assert "MainPersonalExactCasReceipt" not in source
    assert "MainPersonalExactCasPostStateObservation" not in source
