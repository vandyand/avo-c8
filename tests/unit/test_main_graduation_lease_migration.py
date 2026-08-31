"""Focused regression coverage for the unified C2/Phase-A lease boundary."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.contracts import (
    ArtifactRef,
    MainGraduationIntent,
    MainLeaseEvidence,
    MainLeaseEvidenceRecord,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

D = "sha256:" + "1" * 64
EPOCH = "sha256:" + "2" * 64
POLICY = "sha256:" + "3" * 64


class _Authority:
    def verify_lease_evidence(self, record: MainLeaseEvidenceRecord) -> None:
        return

    def verify_fence_resolution(self, resolution: Any, source_receipt: Any) -> None:
        return

    def verify_mutation_receipt(self, receipt: Any, intent: Any) -> None:
        return

    def verify_provider_post_state(
        self, observation: Any, provider_receipt: Any, reconciliation: Any
    ) -> None:
        return


def _lease() -> MainLeaseEvidenceRecord:
    now = datetime.now(UTC)
    values = {
        "repository_digest": D,
        "target_ref": "refs/heads/main",
        "operation_id": D,
        "owner": "c4-owner",
        "policy_epoch": POLICY,
        "lease_epoch_digest": EPOCH,
        "acquired_at": now,
        "expires_at": now + timedelta(minutes=5),
    }
    probe = cast(Any, MainLeaseEvidenceRecord.model_construct)(
        **values, lease_digest=D, evidence_digest=D
    )
    values["lease_digest"] = canonical_digest(
        probe.model_dump(exclude={"lease_digest", "evidence_digest"}, mode="json")
    )
    probe = cast(Any, MainLeaseEvidenceRecord.model_construct)(**values, evidence_digest=D)
    values["evidence_digest"] = canonical_digest(
        probe.model_dump(exclude={"evidence_digest"}, mode="json")
    )
    return MainLeaseEvidenceRecord.model_validate(values)


def _journal(root: Path) -> MainGraduationJournal:
    return MainGraduationJournal(root, phase_a_authority_verifier=_Authority())


def _intent(lease: MainLeaseEvidenceRecord, reference: ArtifactRef) -> MainGraduationIntent:
    values = {
        "repository_digest": D,
        "target_ref": "refs/heads/main",
        "operation_id": D,
        "plan_digest": D,
        "package_digest": D,
        "composition_digest": EPOCH,
        "base_commit": "a" * 40,
        "base_tree": "a" * 40,
        "candidate_commit": "b" * 40,
        "candidate_tree": "b" * 40,
        "candidate_ref": "refs/heads/avo/candidate/" + "1" * 64,
        "lease_identity": lease.owner,
        "lease_digest": lease.lease_digest,
        "lease_epoch_digest": lease.lease_epoch_digest,
        "lease_evidence_record": lease,
        "lease_evidence_artifact": reference,
        "policy_epoch": lease.policy_epoch,
        "recorded_at": lease.acquired_at,
    }
    probe = cast(Any, MainGraduationIntent.model_construct)(**values, intent_digest=D)
    values["intent_digest"] = canonical_digest(
        probe.model_dump(exclude={"intent_digest"}, mode="json")
    )
    return MainGraduationIntent.model_validate(values)


def test_v2_intent_uses_one_durable_lease_digest_and_epoch(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    lease = _lease()
    lease_ref = journal.record_lease_evidence_record(lease)
    intent = _intent(lease, lease_ref)

    journal.record_intent(intent)
    loaded = journal.read_intent(D)
    assert loaded is not None
    loaded_intent = cast(MainGraduationIntent, loaded[0])
    assert loaded_intent.lease_evidence_record == lease
    assert loaded_intent.lease_identity == lease.owner
    assert loaded_intent.lease_digest == lease.lease_digest
    assert loaded_intent.lease_epoch_digest == lease.lease_epoch_digest
    assert loaded_intent.policy_epoch == lease.policy_epoch


def test_legacy_c2_intent_is_rejected_with_phase_a_lease(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    lease = _lease()
    journal.record_lease_evidence_record(lease)
    now = lease.acquired_at
    legacy_probe = cast(Any, MainLeaseEvidence.model_construct)(
        operation_id=D,
        repository_digest=D,
        identity=lease.owner,
        acquired_at=now,
        expires_at=lease.expires_at,
        lease_digest=D,
    )
    legacy = MainLeaseEvidence(
        operation_id=D,
        repository_digest=D,
        identity=lease.owner,
        acquired_at=now,
        expires_at=lease.expires_at,
        lease_digest=canonical_digest(
            legacy_probe.model_dump(exclude={"lease_digest"}, mode="json")
        ),
    )
    reference = journal._store.put_bytes(  # pyright: ignore[reportPrivateUsage]
        canonical_bytes(legacy),
        media_type="application/vnd.avo.main-graduation-lease-evidence+json",
        role="main-graduation-lease-evidence",
        max_bytes=4096,
    )
    intent = cast(Any, MainGraduationIntent.model_construct)(
        operation_id=D,
        repository_digest=D,
        target_ref="refs/heads/main",
        lease_identity=legacy.identity,
        lease_digest=legacy.lease_digest,
        lease_evidence=legacy,
        lease_evidence_artifact=reference,
    )
    with pytest.raises(MainGraduationJournalError, match="legacy C2"):
        journal._verify_intent_lease(intent)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("field", ["lease_digest", "lease_epoch_digest"])
def test_stale_v2_lease_binding_fails_before_any_provider_boundary(
    tmp_path: Path, field: str
) -> None:
    journal = _journal(tmp_path)
    lease = _lease()
    lease_ref = journal.record_lease_evidence_record(lease)
    intent = _intent(lease, lease_ref)
    stale = intent.model_copy(update={field: "sha256:" + "f" * 64})

    with pytest.raises(MainGraduationJournalError, match="lease evidence binding"):
        journal._verify_intent_lease(stale)  # pyright: ignore[reportPrivateUsage]


def test_v2_intent_identity_survives_fresh_journal_reload(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    lease = _lease()
    lease_ref = journal.record_lease_evidence_record(lease)
    intent = _intent(lease, lease_ref)
    journal.record_intent(intent)

    reloaded = _journal(tmp_path).read_intent(D)
    assert reloaded is not None
    reloaded_intent = cast(MainGraduationIntent, reloaded[0])
    assert reloaded_intent.intent_digest == intent.intent_digest
    assert reloaded_intent.lease_evidence_record is not None
    assert reloaded_intent.lease_evidence_record.evidence_digest == lease.evidence_digest
