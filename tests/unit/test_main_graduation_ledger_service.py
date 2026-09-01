"""Focused C6 service-boundary tests using the real on-disk journal."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.application.main_graduation_ledger_service import (
    MainGraduationLedgerService,
)
from avo_correlate.contracts.main_graduation_ledger import (
    CONTENT_ARTIFACT_MEDIA_TYPE,
    CONTENT_ARTIFACT_ROLE,
    TERMINAL_ARTIFACT_MEDIA_TYPE,
    TERMINAL_ARTIFACT_ROLE,
)
from avo_correlate.domain.canonical import canonical_bytes
from tests.unit.test_main_graduation_ledger_journal import _journal

NOW = datetime(2026, 9, 1, tzinfo=UTC)


class Clock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class CrashResolver:
    def __init__(self) -> None:
        self.calls = 0

    def resolve(self, _artifact: Any) -> object:
        self.calls += 1
        raise RuntimeError("resolver crash")


class Classifier:
    def classify(self, _content: object, _activation: Any, _submission: Any) -> dict[str, Any]:
        return {"classification": "eligible", "paths": ["src/feature.py"], "risk_class": "ordinary"}


class Resolver:
    def resolve(self, _artifact: Any) -> object:
        return b"content"


def _content(store: Any, value: int) -> Any:
    return store.put_bytes(
        canonical_bytes({"value": value}),
        media_type=CONTENT_ARTIFACT_MEDIA_TYPE,
        role=CONTENT_ARTIFACT_ROLE,
        max_bytes=1024 * 1024,
    )


def _terminal(store: Any) -> Any:
    return store.put_bytes(
        canonical_bytes({"terminal": True}),
        media_type=TERMINAL_ARTIFACT_MEDIA_TYPE,
        role=TERMINAL_ARTIFACT_ROLE,
        max_bytes=1024 * 1024,
    )


def test_submit_durable_before_resolver_and_retry_adopts_timestamp(tmp_path: Path) -> None:
    journal, _activation, store = _journal(tmp_path)
    resolver = CrashResolver()
    service = MainGraduationLedgerService(journal, Clock(), resolver, Classifier())
    content = _content(store, 1)
    first = service.submit(11, "scheduler", "one", content.digest, content)
    with pytest.raises(RuntimeError, match="resolver crash"):
        service.classify(11)
    assert resolver.calls == 1
    retry = service.submit(
        11,
        "scheduler",
        "one",
        content.digest,
        content,
        recorded_at=NOW + timedelta(days=1),
    )
    assert retry == first


def test_later_submission_is_durable_but_advance_stops_at_open_predecessor(tmp_path: Path) -> None:
    journal, _activation, store = _journal(tmp_path)
    service = MainGraduationLedgerService(
        journal, Clock(), resolver=Resolver(), classifier=Classifier()
    )
    first_content = _content(store, 1)
    second_content = _content(store, 2)
    service.submit(11, "scheduler", "one", first_content.digest, first_content)
    service.submit(12, "scheduler", "two", second_content.digest, second_content)
    assert service.advance() is None
    assert journal.read_submission_by_sequence(12) is not None


def test_exclusion_advances_without_counting(tmp_path: Path) -> None:
    journal, _activation, store = _journal(tmp_path)

    class ExcludingClassifier:
        def classify(self, _content: object, _activation: Any, _submission: Any) -> dict[str, Any]:
            evidence = store.put_bytes(
                canonical_bytes({"empty": True}),
                media_type="application/vnd.avo.ledger-exclusion-evidence+json",
                role="ledger-classification-exclusion-evidence",
                max_bytes=1024 * 1024,
            )
            return {
                "classification": "excluded",
                "paths": [],
                "risk_class": "ordinary",
                "exclusion_reason": "empty",
                "independent_exclusion_evidence_digest": evidence.digest,
                "independent_exclusion_evidence": evidence,
            }

    service = MainGraduationLedgerService(
        journal, Clock(), resolver=Resolver(), classifier=ExcludingClassifier()
    )
    content = _content(store, 3)
    service.submit(11, "scheduler", "three", content.digest, content)
    service.classify(11)
    transition = service.advance()
    assert transition is not None
    assert transition.resulting_state.last_scheduler_sequence == 11
    assert transition.resulting_state.successes == 0


def test_boundary_reset_closes_activation_and_replays_package_read_only(tmp_path: Path) -> None:
    journal, _activation, store = _journal(tmp_path)
    service = MainGraduationLedgerService(journal, Clock())
    evidence = store.put_bytes(
        canonical_bytes({"kind": "starvation"}),
        media_type="application/vnd.avo.ledger-boundary-violation+json",
        role="ledger-boundary-violation-evidence",
        max_bytes=1024 * 1024,
    )
    _, reset = service.record_boundary_violation("starvation", evidence)
    package = service.package()
    assert package.status == "boundary_reset"
    assert service.replay() == package
    with pytest.raises(Exception, match="terminal"):
        service.submit(11, "scheduler", "late", evidence.digest, evidence)
    assert reset.resulting_state.boundary_violations == 1
