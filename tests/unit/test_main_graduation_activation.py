from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import avo_correlate.application.main_graduation_activation as module
from avo_correlate.adapters.artifacts.main_graduation_ledger_journal import (
    MainGraduationLedgerJournal,
    MainGraduationLedgerJournalError,
)
from avo_correlate.application.main_graduation_activation import (
    LocalActivationCandidateArtifact,
    MainGraduationActivationPreparationError,
    prepare_local_main_graduation_activation_draft,
)
from avo_correlate.contracts.main_graduation_ledger import MainLedgerActivation
from avo_correlate.domain.canonical import canonical_bytes


def _candidate(role: str, digest_character: str) -> LocalActivationCandidateArtifact:
    return LocalActivationCandidateArtifact.model_validate(
        {
            "role": role,
            "artifact_digest": "sha256:" + digest_character * 64,
            "size_bytes": 17,
            "media_type": "application/vnd.avo.local-candidate+json",
        }
    )


def _candidates() -> tuple[LocalActivationCandidateArtifact, ...]:
    return (
        _candidate("controller-authority-candidate", "a"),
        _candidate("c8-capability-evidence-candidate", "b"),
        _candidate("hosted-rollback-proof-candidate", "c"),
    )


def _prepare(tmp_path: Path, **updates: Any) -> Any:
    values: dict[str, Any] = {
        "output_file": tmp_path / "local-activation-draft.json",
        "candidate_artifacts": _candidates(),
    }
    values.update(updates)
    return prepare_local_main_graduation_activation_draft(**values)


def test_local_draft_is_deterministic_create_once_and_explicitly_unconsumable(
    tmp_path: Path,
) -> None:
    draft = _prepare(tmp_path)
    assert draft.artifact_path.read_bytes() == canonical_bytes(draft.draft.model_dump(mode="json"))
    assert draft.draft.prepared_only is True
    assert draft.draft.activation_consumable is False
    assert draft.draft.rooted_verification is False
    assert [item.role for item in draft.draft.candidate_artifacts] == [
        "controller-authority-candidate",
        "c8-capability-evidence-candidate",
        "hosted-rollback-proof-candidate",
    ]

    replay = _prepare(tmp_path)
    assert replay.artifact_digest == draft.artifact_digest
    assert replay.semantic_digest == draft.semantic_digest


def test_local_draft_is_rejected_by_activation_contract_and_ledger(tmp_path: Path) -> None:
    draft = _prepare(tmp_path)
    payload = draft.draft.model_dump(mode="json")

    with pytest.raises(ValidationError):
        MainLedgerActivation.model_validate(payload)
    with pytest.raises(MainGraduationLedgerJournalError, match="malformed activation"):
        MainGraduationLedgerJournal(tmp_path / "ledger").record_activation(draft.draft)


def test_local_draft_rejects_bad_candidate_shape_order_and_conflicting_output(
    tmp_path: Path,
) -> None:
    malformed = LocalActivationCandidateArtifact.model_construct(
        role="controller-authority-candidate",
        artifact_digest="not-a-digest",
        size_bytes=17,
        media_type="application/vnd.avo.local-candidate+json",
    )
    with pytest.raises(MainGraduationActivationPreparationError, match="contract validation"):
        _prepare(tmp_path, candidate_artifacts=(malformed, *_candidates()[1:]))
    with pytest.raises(MainGraduationActivationPreparationError, match="contract validation"):
        _prepare(tmp_path, candidate_artifacts=tuple(reversed(_candidates())))

    _prepare(tmp_path)
    (tmp_path / "local-activation-draft.json").write_bytes(b"tampered")
    with pytest.raises(MainGraduationActivationPreparationError, match="conflicting"):
        _prepare(tmp_path)


def test_legacy_activation_builders_and_generic_verifier_aliases_are_absent() -> None:
    for name in (
        "prepare_main_graduation_activation",
        "prepare_main_ledger_activation",
        "prepare_hosted_activation",
        "prepare_activation",
        "PreparedMainGraduationActivation",
        "MainLedgerActivationArtifact",
    ):
        assert not hasattr(module, name)
