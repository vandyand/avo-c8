"""Second honest branch wave for the offline hosted-rollback inventory."""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportUnknownMemberType=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false, reportMissingImports=false, reportUntypedBaseClass=false, reportUntypedFunctionDecorator=false, reportUnusedImport=false, reportUnknownLambdaType=false

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict

import avo_correlate.application.main_graduation_hosted_rollback as module
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportUnknownMemberType=false, reportArgumentType=false

D = "sha256:" + "a" * 64
NOW = datetime(2026, 9, 1, 12, tzinfo=UTC)
BASE = "a" * 40
TREE = "b" * 40
RESULT = "c" * 40


class _Record:
    def __init__(self, **values: Any) -> None:
        self.__dict__.update(values)


class _Package(BaseModel):
    """A canonicalizable test envelope with real nested attribute access."""

    model_config = ConfigDict(arbitrary_types_allowed=True)
    operation_id: str
    repository_digest: str
    target_ref: str
    attempt_authority: Any
    rollback_authorization: Any
    rollback_result: Any
    post_state: Any
    cleanup_terminal: Any
    cleanup_intent: Any
    cleanup_receipt: Any
    queue_configuration: Any
    queue_observation: Any
    admission_observation: Any
    composition: Any
    source_completion: Any
    composition_id: str
    deploy_performed: bool = False

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        del args, kwargs
        return {
            "operation_id": self.operation_id,
            "kind": "rollback-package",
            "deploy_performed": self.deploy_performed,
        }


def _package(**changes: Any) -> _Package:
    source = {"source": "completion"}
    source_digest = canonical_digest(source)
    attempt = _Record(
        release_issuer_identity="release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        inverse_tree=BASE,
        current_main_commit=BASE,
        current_main_tree=TREE,
        manifest_digest=D,
        operation_id=D,
        completion_package_digest=source_digest,
    )
    authorization = _Record(
        release_issuer_identity="release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
    )
    result = _Record(
        outcome="applied",
        result_commit=RESULT,
        result_tree=BASE,
        result_parent_commit=BASE,
        result_parents=[BASE],
        current_main_commit=BASE,
        receipt_digest=D,
    )
    post = _Record(
        current_main_commit=BASE,
        result_commit=RESULT,
        result_tree=BASE,
        result_parents=[BASE],
        inverse_tree=BASE,
        result_receipt_digest=D,
        attempt_manifest_digest=D,
    )
    cleanup_intent = _Record(
        intent_digest=D,
        candidate_ref="refs/heads/rollback",
        candidate_commit=RESULT,
        pull_request_number=7,
    )
    cleanup_receipt = _Record(receipt_digest=D)
    terminal = _Record(
        terminal=True,
        outcome="absent",
        candidate_ref_absent=True,
        pull_request_state="closed",
        pull_request_merged=True,
        cleanup_intent_digest=D,
        cleanup_receipt_digest=D,
        candidate_ref=cleanup_intent.candidate_ref,
        candidate_commit=RESULT,
        pull_request_number=7,
    )
    config = _Record(
        expected_base_commit=BASE,
        expected_base_tree=TREE,
        queue_configuration_digest=D,
    )
    queue = _Record(queue_configuration_digest=D, pull_request_number=7)
    admission = _Record(pull_request_number=7)
    composition = _Record(composition_id=D)
    values: dict[str, Any] = dict(
        operation_id=D,
        repository_digest=D,
        target_ref="refs/heads/main",
        attempt_authority=attempt,
        rollback_authorization=authorization,
        rollback_result=result,
        post_state=post,
        cleanup_terminal=terminal,
        cleanup_intent=cleanup_intent,
        cleanup_receipt=cleanup_receipt,
        queue_configuration=config,
        queue_observation=queue,
        admission_observation=admission,
        composition=composition,
        source_completion=source,
        composition_id=D,
    )
    values.update(changes)
    return _Package.model_validate(values)


def _ref(package: _Package) -> ArtifactRef:
    payload = canonical_bytes(package)
    return ArtifactRef(
        digest=canonical_digest(package),
        size_bytes=len(payload),
        role="main-graduation-rollback-completion",
        media_type="application/vnd.avo.main-graduation-rollback-completion+json",
        created_at=NOW,
    )


def test_validate_inputs_accepts_complete_typed_inventory() -> None:
    package = _package()
    module._validate_inputs(package, _ref(package), D, None)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (
            "rollback_authorization",
            _Record(
                release_issuer_identity="other",
                release_issuer_app_id=9001,
                issuer_isolation_digest=D,
            ),
        ),
        (
            "rollback_result",
            _Record(
                outcome="reconciliation_required",
                result_commit=RESULT,
                result_tree=BASE,
                result_parent_commit=BASE,
                result_parents=[BASE],
                current_main_commit=BASE,
                receipt_digest=D,
            ),
        ),
        (
            "cleanup_terminal",
            _Record(
                terminal=False,
                outcome="absent",
                candidate_ref_absent=True,
                pull_request_state="closed",
                pull_request_merged=True,
                cleanup_intent_digest=D,
                cleanup_receipt_digest=D,
                candidate_ref="refs/heads/rollback",
                candidate_commit=RESULT,
                pull_request_number=7,
            ),
        ),
        (
            "queue_observation",
            _Record(queue_configuration_digest="sha256:" + "b" * 64, pull_request_number=7),
        ),
    ],
)
def test_validate_inputs_rejects_each_major_nested_failure(field: str, value: Any) -> None:
    package = _package(**{field: value})
    with pytest.raises(module.HostedRollbackProofPreparationError):
        module._validate_inputs(package, _ref(package), D, None)


def test_validate_inputs_rejects_deploy_claim_and_replay_identity() -> None:
    deployed = _package(deploy_performed=True)
    with pytest.raises(module.HostedRollbackProofPreparationError, match="deployment"):
        module._validate_inputs(deployed, _ref(deployed), D, None)
    stale = _package(composition_id="sha256:" + "b" * 64)
    with pytest.raises(module.HostedRollbackProofPreparationError, match="replay"):
        module._validate_inputs(stale, _ref(stale), D, None)


def test_validate_inputs_supports_two_reader_signatures_and_rejects_main_drift() -> None:
    package = _package()
    calls: list[str] = []

    def zero_arg() -> Any:
        calls.append("zero")
        return package.post_state

    # A non-typed result is rejected after the TypeError signature fallback.
    with pytest.raises(module.HostedRollbackProofPreparationError, match="typed"):
        module._validate_inputs(package, _ref(package), D, zero_arg)
    assert calls == ["zero"]

    def two_arg(*_args: Any) -> Any:
        return package.post_state

    with pytest.raises(module.HostedRollbackProofPreparationError, match="typed"):
        module._validate_inputs(package, _ref(package), D, two_arg)

    def fails(*_args: Any) -> Any:
        raise RuntimeError("offline")

    with pytest.raises(module.HostedRollbackProofPreparationError, match="re-read"):
        module._validate_inputs(package, _ref(package), D, fails)


def test_publish_success_and_parent_symlink_are_atomic(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "draft.json"
    payload = b"atomic"
    digest = module._publish(path, payload)
    assert digest == "sha256:" + __import__("hashlib").sha256(payload).hexdigest()
    assert path.read_bytes() == payload

    target = tmp_path / "real"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(module.HostedRollbackProofPreparationError, match="parent"):
        module._publish(link / "draft.json", payload)
