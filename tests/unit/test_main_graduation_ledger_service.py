"""Focused C6 service-boundary tests using the real on-disk journal."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.main_graduation_ledger_journal import (
    MainGraduationLedgerJournal,
    MainGraduationLedgerJournalError,
)
from avo_correlate.application.main_graduation_ledger_service import (
    MainGraduationLedgerService,
)
from avo_correlate.contracts.main_graduation_ledger import (
    CONTENT_ARTIFACT_MEDIA_TYPE,
    CONTENT_ARTIFACT_ROLE,
    PACKAGE_ARTIFACT_MEDIA_TYPE,
    PACKAGE_ARTIFACT_ROLE,
    TERMINAL_ARTIFACT_MEDIA_TYPE,
    TERMINAL_ARTIFACT_ROLE,
)
from avo_correlate.domain.canonical import canonical_bytes
from tests.unit.test_main_graduation_ledger_journal import _journal, _Verifier

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


class CountingResolver:
    def __init__(self) -> None:
        self.calls = 0

    def resolve(self, _artifact: Any) -> object:
        self.calls += 1
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


def test_submitted_unclassified_envelope_is_bound_in_boundary_tail_and_replays(
    tmp_path: Path,
) -> None:
    journal, _activation, store = _journal(tmp_path)
    service = MainGraduationLedgerService(journal, Clock())
    content = _content(store, 7)
    submission = service.submit(11, "scheduler", "seven", content.digest, content)
    boundary_artifact = store.put_bytes(
        canonical_bytes({"kind": "withholding"}),
        media_type="application/vnd.avo.ledger-boundary-violation+json",
        role="ledger-boundary-violation-evidence",
        max_bytes=1024 * 1024,
    )
    evidence, _reset = service.record_boundary_violation("withholding", boundary_artifact)
    assert (
        evidence.submission_digest,
        evidence.operation_id,
        evidence.envelope_digest,
        evidence.content_artifact,
    ) == (
        submission.submission_digest,
        submission.operation_id,
        submission.envelope_digest,
        submission.content_artifact,
    )
    package = service.package()
    assert package.submissions == [submission]
    assert len(package.unresolved_tail) == 1
    tail = package.unresolved_tail[0]
    assert tail.envelope is None
    assert (
        tail.submission_digest,
        tail.operation_id,
        tail.envelope_digest,
        tail.content_artifact,
    ) == (
        submission.submission_digest,
        submission.operation_id,
        submission.envelope_digest,
        submission.content_artifact,
    )
    fresh_journal = MainGraduationLedgerJournal(
        tmp_path,
        _Verifier(),
        artifact_store=FilesystemArtifactStore(
            tmp_path / "artifacts", clock=lambda: NOW - timedelta(minutes=1)
        ),
    )
    fresh = MainGraduationLedgerService(fresh_journal, Clock(NOW + timedelta(days=1)))
    assert fresh.replay() == package


def test_missing_envelope_boundary_package_has_explicit_starvation_tail(tmp_path: Path) -> None:
    journal, _activation, store = _journal(tmp_path)
    service = MainGraduationLedgerService(journal, Clock())
    boundary_artifact = store.put_bytes(
        canonical_bytes({"kind": "starvation"}),
        media_type="application/vnd.avo.ledger-boundary-violation+json",
        role="ledger-boundary-violation-evidence",
        max_bytes=1024 * 1024,
    )
    evidence, _reset = service.record_boundary_violation("starvation", boundary_artifact)
    package = service.package()
    assert evidence.submission_digest is None
    assert len(package.unresolved_tail) == 1
    assert package.unresolved_tail[0].scheduler_sequence == evidence.expected_scheduler_sequence
    assert not package.unresolved_tail[0].has_envelope_identity


def test_fresh_callers_cannot_supply_mutation_timestamps(tmp_path: Path) -> None:
    journal, _activation, store = _journal(tmp_path)
    clock = Clock()
    service = MainGraduationLedgerService(journal, clock, Resolver(), Classifier())
    content = _content(store, 4)
    with pytest.raises(MainGraduationLedgerJournalError, match="timestamp is controller-owned"):
        service.submit(
            11,
            "scheduler",
            "four",
            content.digest,
            content,
            recorded_at=NOW - timedelta(minutes=1),
        )
    service.submit(11, "scheduler", "four", content.digest, content)
    service.classify(11)
    evidence = _terminal(store)
    with pytest.raises(MainGraduationLedgerJournalError, match="timestamp is controller-owned"):
        service.record_outcome(11, "failure", evidence, terminal_at=NOW - timedelta(minutes=1))
    boundary = store.put_bytes(
        canonical_bytes({"kind": "starvation-2"}),
        media_type="application/vnd.avo.ledger-boundary-violation+json",
        role="ledger-boundary-violation-evidence",
        max_bytes=1024 * 1024,
    )
    with pytest.raises(MainGraduationLedgerJournalError, match="timestamp is controller-owned"):
        service.record_boundary_violation("starvation", boundary, detected_at=NOW)


def test_crash_after_outcome_adopts_durable_record_after_expiry(tmp_path: Path) -> None:
    journal, _activation, store = _journal(tmp_path)
    clock = Clock()
    service = MainGraduationLedgerService(journal, clock, Resolver(), Classifier())
    content = _content(store, 5)
    service.submit(11, "scheduler", "five", content.digest, content)
    service.classify(11)
    evidence = _terminal(store)
    original = journal.record_outcome

    def crash_after_write(record: Any) -> Any:
        original(record)
        raise RuntimeError("crash after durable outcome")

    journal.record_outcome = crash_after_write  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="crash after durable outcome"):
        service.record_outcome(11, "failure", evidence, reason="upstream")
    journal.record_outcome = original  # type: ignore[method-assign]
    clock.value = NOW + timedelta(days=1)
    adopted = service.record_outcome(11, "failure", evidence, reason="upstream")
    assert adopted.terminal_at == NOW


def test_crash_after_boundary_evidence_derives_missing_reset_after_expiry(tmp_path: Path) -> None:
    journal, _activation, store = _journal(tmp_path)
    clock = Clock()
    resolver = CountingResolver()
    service = MainGraduationLedgerService(journal, clock, resolver, Classifier())
    evidence = store.put_bytes(
        canonical_bytes({"kind": "withholding"}),
        media_type="application/vnd.avo.ledger-boundary-violation+json",
        role="ledger-boundary-violation-evidence",
        max_bytes=1024 * 1024,
    )
    original = journal.record_boundary_reset

    def crash_before_reset(_record: Any) -> Any:
        raise RuntimeError("crash before boundary reset")

    journal.record_boundary_reset = crash_before_reset  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="crash before boundary reset"):
        service.record_boundary_violation("withholding", evidence)
    journal.record_boundary_reset = original  # type: ignore[method-assign]
    clock.value = NOW + timedelta(days=1)
    _, reset = service.record_boundary_violation("withholding", evidence)
    assert reset.resulting_state.boundary_violations == 1
    assert resolver.calls == 0


def test_mixed_case_paths_use_shared_policy_manifest_digest(tmp_path: Path) -> None:
    journal, _activation, store = _journal(tmp_path)

    class MixedCaseClassifier:
        def classify(self, _content: object, _activation: Any, _submission: Any) -> dict[str, Any]:
            return {
                "classification": "eligible",
                "paths": ["src/a.py", "src/Z.py"],
                "risk_class": "ordinary",
            }

    service = MainGraduationLedgerService(journal, Clock(), Resolver(), MixedCaseClassifier())
    content = _content(store, 6)
    service.submit(11, "scheduler", "six", content.digest, content)
    classification = service.classify(11)
    assert classification.path_manifest_digest


def test_threshold_completion_fences_new_submission_before_package(tmp_path: Path) -> None:
    journal, _activation, store = _journal(tmp_path)
    service = MainGraduationLedgerService(journal, Clock(), Resolver(), Classifier())
    package = store.put_bytes(
        canonical_bytes({"package": True}),
        media_type=PACKAGE_ARTIFACT_MEDIA_TYPE,
        role=PACKAGE_ARTIFACT_ROLE,
        max_bytes=1024 * 1024,
    )
    terminal = _terminal(store)
    for sequence in range(11, 23):
        content = _content(store, sequence)
        service.submit(sequence, "scheduler", str(sequence), content.digest, content)
        service.classify(sequence)
        service.record_outcome(sequence, "success", terminal, package_artifact=package)
        service.advance()
    assert service.read_status().state.threshold_complete
    content = _content(store, 23)
    with pytest.raises(MainGraduationLedgerJournalError, match="threshold"):
        service.submit(23, "scheduler", "twenty-three", content.digest, content)
