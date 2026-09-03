"""Fast offline checks for nonterminal personal CAS response evidence."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from avo_correlate.adapters.artifacts import (
    main_personal_exact_cas_response_evidence as evidence_module,
)
from avo_correlate.adapters.artifacts.durable_backend_gate import DurableBackendQualification
from avo_correlate.adapters.artifacts.main_personal_exact_cas_response_evidence import (
    MainPersonalExactCasResponseEvidenceConflictError,
    MainPersonalExactCasResponseEvidenceJournal,
    MainPersonalExactCasResponseEvidenceJournalError,
)
from avo_correlate.contracts.main_personal_exact_cas import (
    MainPersonalExactCasDispatchStarted,
    MainPersonalExactCasIntent,
    personal_cas_claim_digest,
    personal_cas_operation_id,
)
from avo_correlate.contracts.main_personal_exact_cas_response_evidence import (
    MainPersonalExactCasResponseEvidence,
)
from avo_correlate.domain.canonical import canonical_digest

NOW = datetime(2026, 1, 1, tzinfo=UTC)
HEX = "a" * 64
REPO = "sha256:" + HEX
OBJECTS = {
    "activation_digest": "sha256:" + "b" * 64,
    "source_operation_id": "sha256:" + "c" * 64,
    "source_plan_digest": "sha256:" + "d" * 64,
    "source_package_digest": "sha256:" + "e" * 64,
    "source_composition_digest": "sha256:" + "f" * 64,
    "base_commit": "1" * 40,
    "base_tree": "2" * 40,
    "candidate_commit": "3" * 40,
    "candidate_tree": "4" * 40,
    "candidate_ref": "refs/heads/avo/candidate/" + "5" * 64,
    "candidate_parents": ("1" * 40,),
    "protection_ruleset_digest": "sha256:" + "6" * 64,
    "lease_digest": "sha256:" + "7" * 64,
}


def _qualified(root: Path) -> DurableBackendQualification:
    return DurableBackendQualification(
        root=root.resolve(),
        qualified=True,
        reason="test-qualified",
        filesystem_type="testfs",
        mount_id=1,
        device="test-device",
    )


def _authority(intent: MainPersonalExactCasIntent, marker: MainPersonalExactCasDispatchStarted):
    class AuthorityReader:
        def read_intent(self, operation_id: str) -> MainPersonalExactCasIntent:
            del operation_id
            return intent

        def read_dispatch_started(self, operation_id: str) -> MainPersonalExactCasDispatchStarted:
            del operation_id
            return marker

    return AuthorityReader()


def _no_fsync(_path: Path) -> None:
    return None


def _chain() -> tuple[MainPersonalExactCasIntent, MainPersonalExactCasDispatchStarted]:
    expiry = NOW + timedelta(hours=1)
    lease_identity = "lease-fixture"
    lease_digest = "sha256:" + "7" * 64
    nonce = "nonce-fixture"
    operation_values: dict[str, Any] = {
        **{key: value for key, value in OBJECTS.items() if key != "source_package_digest"},
        "repository_digest": REPO,
        "target_ref": "refs/heads/main",
        "writer_app_id": 1,
        "writer_installation_id": 2,
        "writer_identity": "writer-fixture",
        "lease_identity": lease_identity,
        "lease_digest": lease_digest,
        "lease_expires_at": expiry,
        "claim_nonce": nonce,
    }
    operation_id = personal_cas_operation_id(**operation_values)
    common = {
        **operation_values,
        "operation_id": operation_id,
        "source_package_digest": OBJECTS["source_package_digest"],
    }
    common["claim_digest"] = personal_cas_claim_digest(
        operation_id=operation_id,
        lease_identity=lease_identity,
        lease_digest=lease_digest,
        lease_expires_at=expiry,
        claim_nonce=nonce,
    )
    # The digest is calculated by the contract's build method; only the intent
    # and marker are needed by this leaf, so use a valid authorization identity.
    from avo_correlate.contracts.main_personal_exact_cas import MainPersonalExactCasAuthorization

    authorization = MainPersonalExactCasAuthorization.build(
        **common, authorized_at=NOW + timedelta(minutes=1)
    )
    intent = MainPersonalExactCasIntent.build(
        **common,
        authorization_digest=authorization.authorization_digest,
        recorded_at=NOW + timedelta(minutes=2),
    )
    marker = MainPersonalExactCasDispatchStarted.build(
        **common,
        intent_digest=intent.intent_digest,
        started_at=NOW + timedelta(minutes=3),
    )
    return intent, marker


def _observation(
    intent: MainPersonalExactCasIntent, marker: MainPersonalExactCasDispatchStarted
) -> Any:
    payload = ('{"object":{"sha":"%s"},"ref":"refs/heads/main"}' % ("3" * 40)).encode()
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    return SimpleNamespace(
        operation_id=intent.operation_id,
        repository_digest=intent.repository_digest,
        target_ref=intent.target_ref,
        writer_app_id=intent.writer_app_id,
        writer_installation_id=intent.writer_installation_id,
        writer_identity=intent.writer_identity,
        intent_digest=intent.intent_digest,
        dispatch_marker_digest=marker.dispatch_marker_digest,
        status=200,
        classification="candidate_response",
        request_id="req-fixture",
        metadata={"x-github-request-id": "req-fixture"},
        observed_at=NOW + timedelta(minutes=4),
        payload_bytes=payload,
        payload_digest=digest,
    )


def _journal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, intent: Any, marker: Any):
    monkeypatch.setattr(evidence_module, "require_durable_backend", _qualified)
    monkeypatch.setattr(evidence_module, "_fsync_directory", _no_fsync)
    return MainPersonalExactCasResponseEvidenceJournal(
        tmp_path / "evidence", authority_reader=_authority(intent, marker)
    )


def test_record_reopen_and_read_revalidates_authority(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    intent, marker = _chain()
    journal = _journal(monkeypatch, tmp_path, intent, marker)
    observation = _observation(intent, marker)
    reference = journal.record_response_evidence(intent, marker, observation)
    assert journal.record_response_evidence(intent, marker, observation) == reference
    reopened = MainPersonalExactCasResponseEvidenceJournal(
        journal.root, authority_reader=_authority(intent, marker)
    )
    result = reopened.read_response_evidence(intent.operation_id)
    assert result is not None
    evidence, returned_reference = result
    assert returned_reference == reference
    assert evidence.is_terminal is False
    assert evidence.is_authoritative is False
    assert evidence.evidence_digest.startswith("sha256:")


def test_conflict_and_tamper_are_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    intent, marker = _chain()
    journal = _journal(monkeypatch, tmp_path, intent, marker)
    observation = _observation(intent, marker)
    journal.record_response_evidence(intent, marker, observation)
    with pytest.raises(MainPersonalExactCasResponseEvidenceConflictError):
        changed = _observation(intent, marker)
        changed.request_id = "req-other"
        changed.metadata = {"x-github-request-id": "req-other"}
        journal.record_response_evidence(intent, marker, changed)
    index = next(journal.root.glob("main-personal-exact-cas-response-evidence-index/*/*.json"))
    index.write_bytes(b"{}")
    with pytest.raises(MainPersonalExactCasResponseEvidenceJournalError) as raised:
        journal.read_response_evidence(intent.operation_id)
    assert str(raised.value) == "malformed_index"
    assert raised.value.__cause__ is None and raised.value.__context__ is None


def test_authority_mismatch_happens_before_first_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    intent, marker = _chain()
    journal = _journal(monkeypatch, tmp_path, intent, marker)
    forged = intent.model_copy(update={"writer_identity": "forged"})
    with pytest.raises(MainPersonalExactCasResponseEvidenceJournalError) as raised:
        journal.record_response_evidence(forged, marker, _observation(intent, marker))
    assert str(raised.value) == "authority_record_invalid"
    assert not list(journal.root.glob("artifacts/objects/sha256/*/*"))


def test_stale_payload_digest_is_rejected_before_first_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    intent, marker = _chain()
    journal = _journal(monkeypatch, tmp_path, intent, marker)
    observation = _observation(intent, marker)
    observation.payload_digest = "sha256:" + "0" * 64
    with pytest.raises(MainPersonalExactCasResponseEvidenceJournalError) as raised:
        journal.record_response_evidence(intent, marker, observation)
    assert str(raised.value) == "invalid_scope"
    assert not list(journal.root.glob("artifacts/objects/sha256/*/*"))


def test_inconsistent_response_classification_is_rejected_before_first_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    intent, marker = _chain()
    journal = _journal(monkeypatch, tmp_path, intent, marker)
    observation = _observation(intent, marker)
    observation.status = 409
    with pytest.raises(MainPersonalExactCasResponseEvidenceJournalError) as raised:
        journal.record_response_evidence(intent, marker, observation)
    assert str(raised.value) == "invalid_scope"
    assert not list(journal.root.glob("artifacts/objects/sha256/*/*"))


def test_contract_rejects_status_classification_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    intent, marker = _chain()
    journal = _journal(monkeypatch, tmp_path, intent, marker)
    journal.record_response_evidence(intent, marker, _observation(intent, marker))
    result = journal.read_response_evidence(intent.operation_id)
    assert result is not None
    values = result[0].model_dump(mode="json")
    values["response_classification"] = "ambiguous"
    values["evidence_digest"] = canonical_digest(
        {key: value for key, value in values.items() if key != "evidence_digest"}
    )
    with pytest.raises(ValueError, match="status classification"):
        MainPersonalExactCasResponseEvidence.model_validate(values)


def test_alternate_candidate_with_stale_digests_is_rejected_before_first_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    intent, marker = _chain()
    journal = _journal(monkeypatch, tmp_path, intent, marker)
    alternate_intent = intent.model_copy(update={"candidate_commit": "4" * 40})
    alternate_marker = marker.model_copy(update={"candidate_commit": "4" * 40})
    with pytest.raises(MainPersonalExactCasResponseEvidenceJournalError) as raised:
        journal.record_response_evidence(
            alternate_intent, alternate_marker, _observation(intent, marker)
        )
    assert str(raised.value) == "authority_record_invalid"
    assert not list(journal.root.glob("artifacts/objects/sha256/*/*"))


def test_missing_payload_fails_closed_on_reopen(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    intent, marker = _chain()
    journal = _journal(monkeypatch, tmp_path, intent, marker)
    journal.record_response_evidence(intent, marker, _observation(intent, marker))
    result = journal.read_response_evidence(intent.operation_id)
    assert result is not None
    payload_path = journal.artifact_store.path_for_digest(
        result[0].response_payload_artifact.digest
    )
    payload_path.unlink()
    with pytest.raises(MainPersonalExactCasResponseEvidenceJournalError):
        journal.read_response_evidence(intent.operation_id)


def test_secret_failures_are_value_free(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    intent, marker = _chain()
    journal = _journal(monkeypatch, tmp_path, intent, marker)

    class BadAuthority:
        def read_intent(self, operation_id: str) -> object:
            del operation_id
            raise RuntimeError("TOKEN-secret-should-not-leak")

        def read_dispatch_started(self, operation_id: str) -> object:
            del operation_id
            return marker

    bad = MainPersonalExactCasResponseEvidenceJournal(journal.root, authority_reader=BadAuthority())
    with pytest.raises(MainPersonalExactCasResponseEvidenceJournalError) as raised:
        bad.record_response_evidence(intent, marker, _observation(intent, marker))
    assert "TOKEN" not in repr(raised.value) and "secret" not in repr(raised.value)
    assert raised.value.__cause__ is None and raised.value.__context__ is None


def test_public_leaf_has_no_receipt_or_apply_surface():
    names = set(dir(MainPersonalExactCasResponseEvidenceJournal))
    assert "apply" not in names and "verify_receipt" not in names
    assert "Receipt" not in evidence_module.__dict__
