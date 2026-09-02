# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownLambdaType=false, reportUnknownParameterType=false, reportUnknownMemberType=false, reportArgumentType=false
"""Additional fail-closed branch coverage for offline rollback inventory."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import avo_correlate.application.main_graduation_hosted_rollback as module
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

D = "sha256:" + "a" * 64
NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)


def _draft() -> module.MainHostedRollbackEvidenceDraft:
    values: dict[str, Any] = {
        "operation_id": D,
        "repository_digest": D,
        "completion_package_artifact_digest": D,
        "rollback_authority_manifest_digest": D,
        "rollback_result_evidence_digest": D,
        "post_state_evidence_digest": D,
        "cleanup_terminal_evidence_digest": D,
        "observed_at": NOW,
    }
    probe = module.MainHostedRollbackEvidenceDraft.model_construct(**values, draft_digest=D)
    values["draft_digest"] = canonical_digest(
        probe.model_dump(exclude={"draft_digest"}, mode="json")
    )
    return module.MainHostedRollbackEvidenceDraft.model_validate(values)


def test_digest_and_deployment_claim_helpers_cover_nested_shapes() -> None:
    assert module._is_digest(D)
    assert not module._is_digest("bad")
    assert not module._is_digest(None)
    assert module._has_deployment_claim({"nested": [{"deploy_performed": True}]})
    assert not module._has_deployment_claim({"nested": [{"deploy_performed": False}]})
    assert not module._has_deployment_claim("scalar")


def test_strict_reload_and_pair_reject_untyped_invalid_and_bad_metadata() -> None:
    draft = _draft()
    with pytest.raises(module.HostedRollbackProofPreparationError, match="typed"):
        module._strict_reload({}, module.MainHostedRollbackEvidenceDraft, "draft")
    with pytest.raises(module.HostedRollbackProofPreparationError, match="pair"):
        module._pair(draft, module.MainHostedRollbackEvidenceDraft, "draft")
    payload = canonical_bytes(draft)
    ref = ArtifactRef(
        digest=canonical_digest(draft),
        size_bytes=len(payload),
        role="role",
        media_type="type",
        created_at=NOW,
    )
    assert module._pair((draft, ref), module.MainHostedRollbackEvidenceDraft, "draft")[0] == draft
    bad_ref = ref.model_copy(update={"size_bytes": 0})
    with pytest.raises(module.HostedRollbackProofPreparationError, match="content-addressed"):
        module._pair((draft, bad_ref), module.MainHostedRollbackEvidenceDraft, "draft")


def test_prepare_rejects_reader_contract_and_clock_failures(tmp_path: Path) -> None:
    with pytest.raises(module.HostedRollbackProofPreparationError, match="reader"):
        module.prepare_hosted_rollback_evidence(
            tmp_path / "draft.json",
            operation_id=D,
            completion_reader=None,  # type: ignore[arg-type]
        )
    with pytest.raises(module.HostedRollbackProofPreparationError, match="could not be read"):
        module.prepare_hosted_rollback_evidence(
            tmp_path / "draft.json",
            operation_id=D,
            completion_reader=lambda _op: (_ for _ in ()).throw(RuntimeError("read")),
        )
    with pytest.raises(module.HostedRollbackProofPreparationError, match="not durably"):
        module.prepare_hosted_rollback_evidence(
            tmp_path / "draft.json", operation_id=D, completion_reader=lambda _op: None
        )


def test_prepare_rejects_invalid_pair_and_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    draft = _draft()
    ref = ArtifactRef(
        digest=canonical_digest(draft),
        size_bytes=len(canonical_bytes(draft)),
        role="main-graduation-rollback-completion",
        media_type="application/vnd.avo.main-graduation-rollback-completion+json",
        created_at=NOW,
    )
    monkeypatch.setattr(module, "_pair", lambda *_args: (draft, ref))
    monkeypatch.setattr(module, "_validate_inputs", lambda *_args: None)
    with pytest.raises(module.HostedRollbackProofPreparationError, match="timezone"):
        module.prepare_hosted_rollback_evidence(
            tmp_path / "draft.json",
            operation_id=D,
            completion_reader=lambda _op: (draft, ref),
            clock=lambda: datetime.now(),
        )


def test_publish_rejects_size_symlink_and_conflict(tmp_path: Path) -> None:
    path = tmp_path / "draft.json"
    with pytest.raises(module.HostedRollbackProofPreparationError, match="size"):
        module._publish(path, b"x" * (module._MAX_DRAFT_BYTES + 1))
    target = tmp_path / "target"
    target.write_bytes(b"target")
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(module.HostedRollbackProofPreparationError, match="regular"):
        module._publish(path, b"x")
    path.unlink()
    path.write_bytes(b"old")
    with pytest.raises(module.HostedRollbackProofPreparationError, match="conflicting"):
        module._publish(path, b"new")


def test_validate_inputs_rejects_stale_operation_before_nested_reads() -> None:
    package = type("Package", (), {"operation_id": D})()
    ref = type("Ref", (), {})()
    with pytest.raises(module.HostedRollbackProofPreparationError, match="identity"):
        module._validate_inputs(package, ref, "bad", None)
