"""Adversarial tests for the offline exact-CAS forward-source reader."""
# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportArgumentType=false

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.trusted_main_graduation_source import (
    TrustedMainGraduationEvidenceReader,
    TrustedMainGraduationJournalConfiguration,
    TrustedMainGraduationSourceError,
    build_trusted_main_graduation_evidence_reader,
)
from avo_correlate.domain.canonical import canonical_bytes
from tests.unit.test_main_graduation_coordinator_preparation import (
    MAIN_OPERATION,
    _coordinator,
    _fixture,
)


class RollbackVerifier:
    """Configured fixture verifier; rollback reads are not used in C4."""

    def verify_rollback_result(self, *_args: object) -> None:
        return None

    def verify_rollback_cleanup_receipt(self, *_args: object) -> None:
        return None

    def verify_rollback_cleanup_intent(self, *_args: object) -> None:
        return None

    def verify_rollback_cleanup_observation(self, *_args: object) -> None:
        return None

    def verify_rollback_post_state(self, *_args: object) -> None:
        return None

    def verify_rollback_cleanup_terminal(self, *_args: object) -> None:
        return None


def _configured_reader(tmp_path: Path) -> tuple[Any, TrustedMainGraduationEvidenceReader, Any]:
    """Seed the existing genuine C4 fixture and build a fresh configured reader."""

    journal, provider = _fixture(tmp_path)
    _coordinator(journal, provider).prepare(MAIN_OPERATION)

    config = TrustedMainGraduationJournalConfiguration(
        source_root=journal.root,
        future_state_root=tmp_path.parent / "future-state-reader",
        repository_digest=journal._composition_repository_digest,
        release_issuer_binding=journal._release_issuer_binding,
        policy_epoch=journal._policy_epoch,
        composition_root=journal._composition_root,
        base_reader=journal._composition_base_reader,
        phase_a_authority_verifier=journal._phase_a_authority_verifier,
        rollback_authority_verifier=RollbackVerifier(),
    )
    return journal, build_trusted_main_graduation_evidence_reader(config), MAIN_OPERATION


def test_genuine_populated_c4_fixture_is_accepted(tmp_path: Path) -> None:
    journal, reader, intent = _configured_reader(tmp_path)
    result = reader.read(intent)
    assert result.accepted, result
    assert not hasattr(reader, "_journal")
    assert not hasattr(reader, "record_plan")
    assert journal.root == reader.source_root


def test_tampered_canonical_index_fails_closed(tmp_path: Path) -> None:
    journal, reader, intent = _configured_reader(tmp_path)
    index = journal.root / "main-graduation-index" / "plan" / f"{intent[7:]}.json"
    parsed = journal.read_plan(intent)
    assert parsed is not None
    bad_reference = parsed[1].model_copy(update={"digest": "sha256:" + "0" * 64})
    index.write_bytes(canonical_bytes(bad_reference))
    result = reader.read(intent)
    assert not result.accepted


def test_swapped_typed_artifact_reference_fails_closed(tmp_path: Path) -> None:
    journal, reader, operation_id = _configured_reader(tmp_path)
    plan_index = journal.root / "main-graduation-index" / "plan" / f"{operation_id[7:]}.json"
    intent = journal.read_intent(operation_id)
    assert intent is not None
    plan_index.write_bytes(canonical_bytes(intent[1]))
    assert not reader.read(operation_id).accepted


def test_wrong_release_issuer_binding_fails_at_composition(tmp_path: Path) -> None:
    journal, _reader, _intent = _configured_reader(tmp_path)
    bad_issuer = journal._release_issuer_binding.model_copy(  # pyright: ignore[reportPrivateUsage]
        update={"repository_digest": "sha256:" + "f" * 64}
    )
    config = TrustedMainGraduationJournalConfiguration(
        source_root=journal.root,
        future_state_root=tmp_path.parent / "future-issuer-reader",
        repository_digest=journal._release_issuer_binding.repository_digest,
        release_issuer_binding=bad_issuer,
        policy_epoch=journal._policy_epoch,
        composition_root=tmp_path / "checkout",
        base_reader=object(),
        phase_a_authority_verifier=journal._phase_a_authority_verifier,
        rollback_authority_verifier=RollbackVerifier(),
    )
    with pytest.raises(TrustedMainGraduationSourceError, match="authority pins"):
        TrustedMainGraduationEvidenceReader(config)


def test_missing_release_issuer_binding_fails_closed(tmp_path: Path) -> None:
    journal, _reader, _intent = _configured_reader(tmp_path)
    values = {
        "source_root": journal.root,
        "future_state_root": tmp_path.parent / "future-missing-issuer",
        "repository_digest": journal._composition_repository_digest,
        "release_issuer_binding": None,
        "policy_epoch": journal._policy_epoch,
        "composition_root": journal._composition_root,
        "base_reader": journal._composition_base_reader,
        "phase_a_authority_verifier": journal._phase_a_authority_verifier,
        "rollback_authority_verifier": RollbackVerifier(),
    }
    with pytest.raises(TrustedMainGraduationSourceError, match="concrete"):
        TrustedMainGraduationEvidenceReader(TrustedMainGraduationJournalConfiguration(**values))


@pytest.mark.parametrize(
    "field",
    ["phase_a_authority_verifier", "rollback_authority_verifier", "base_reader"],
)
def test_missing_pinned_authority_or_composition_capability_fails_closed(
    tmp_path: Path, field: str
) -> None:
    journal, _reader, _intent = _configured_reader(tmp_path)
    values = {
        "source_root": journal.root,
        "future_state_root": tmp_path.parent / "future-capability-reader",
        "repository_digest": journal._release_issuer_binding.repository_digest,
        "release_issuer_binding": journal._release_issuer_binding,
        "policy_epoch": journal._policy_epoch,
        "composition_root": tmp_path / "checkout",
        "base_reader": object(),
        "phase_a_authority_verifier": journal._phase_a_authority_verifier,
        "rollback_authority_verifier": RollbackVerifier(),
    }
    values[field] = None
    with pytest.raises(TrustedMainGraduationSourceError, match="not pinned"):
        TrustedMainGraduationEvidenceReader(TrustedMainGraduationJournalConfiguration(**values))


def test_cross_store_source_and_future_roots_fail_closed(tmp_path: Path) -> None:
    journal, _reader, _intent = _configured_reader(tmp_path)
    values = {
        "source_root": journal.root,
        "future_state_root": journal.root / "future-state",
        "repository_digest": journal._release_issuer_binding.repository_digest,
        "release_issuer_binding": journal._release_issuer_binding,
        "policy_epoch": journal._policy_epoch,
        "composition_root": tmp_path / "checkout",
        "base_reader": object(),
        "phase_a_authority_verifier": journal._phase_a_authority_verifier,
        "rollback_authority_verifier": RollbackVerifier(),
    }
    with pytest.raises(TrustedMainGraduationSourceError, match="distinct"):
        TrustedMainGraduationEvidenceReader(TrustedMainGraduationJournalConfiguration(**values))


def test_ledger_requires_an_explicit_activation_key(tmp_path: Path) -> None:
    journal, _reader, _intent = _configured_reader(tmp_path)
    values = {
        "source_root": journal.root,
        "future_state_root": tmp_path.parent / "future-ledger-reader",
        "repository_digest": journal._composition_repository_digest,
        "release_issuer_binding": journal._release_issuer_binding,
        "policy_epoch": journal._policy_epoch,
        "composition_root": journal._composition_root,
        "base_reader": journal._composition_base_reader,
        "phase_a_authority_verifier": journal._phase_a_authority_verifier,
        "rollback_authority_verifier": RollbackVerifier(),
        "require_ledger": True,
    }
    with pytest.raises(TrustedMainGraduationSourceError, match="activation digest"):
        TrustedMainGraduationEvidenceReader(TrustedMainGraduationJournalConfiguration(**values))


def test_invalid_ledger_activation_or_eligibility_fails_closed(tmp_path: Path) -> None:
    journal, _reader, operation_id = _configured_reader(tmp_path)
    config = TrustedMainGraduationJournalConfiguration(
        source_root=journal.root,
        future_state_root=tmp_path.parent / "future-invalid-ledger",
        repository_digest=journal._composition_repository_digest,
        release_issuer_binding=journal._release_issuer_binding,
        policy_epoch=journal._policy_epoch,
        composition_root=journal._composition_root,
        base_reader=journal._composition_base_reader,
        phase_a_authority_verifier=journal._phase_a_authority_verifier,
        rollback_authority_verifier=RollbackVerifier(),
        ledger_activation_digest="sha256:" + "d" * 64,
        require_ledger=True,
    )
    reader = TrustedMainGraduationEvidenceReader(config)
    assert not reader.read(operation_id).accepted


def test_queue_artifact_cannot_authorize_personal_cas(tmp_path: Path) -> None:
    journal, reader, operation_id = _configured_reader(tmp_path)
    queue_index = (
        journal.root / "main-graduation-index" / "queue-configuration" / f"{operation_id[7:]}.json"
    )
    if queue_index.is_file():
        intent = journal.read_intent(operation_id)
        assert intent is not None
        queue_index.write_bytes(canonical_bytes(intent[1]))
    assert reader.read(operation_id).accepted


def test_symlinked_source_root_fails_closed(tmp_path: Path) -> None:
    journal, _reader, _operation_id = _configured_reader(tmp_path)
    link = tmp_path.parent / "trusted-source-link"
    try:
        link.symlink_to(journal.root, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this Windows runner")
    values = {
        "source_root": link,
        "future_state_root": tmp_path.parent / "future-symlink",
        "repository_digest": journal._composition_repository_digest,
        "release_issuer_binding": journal._release_issuer_binding,
        "policy_epoch": journal._policy_epoch,
        "composition_root": journal._composition_root,
        "base_reader": journal._composition_base_reader,
        "phase_a_authority_verifier": journal._phase_a_authority_verifier,
        "rollback_authority_verifier": RollbackVerifier(),
    }
    with pytest.raises(TrustedMainGraduationSourceError, match="symlink"):
        TrustedMainGraduationEvidenceReader(TrustedMainGraduationJournalConfiguration(**values))
