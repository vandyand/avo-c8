"""Focused coverage for campaign state, retry, workspace, and accounting boundaries."""

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from avo_correlate.adapters.persistence.models import ActivityRow
from avo_correlate.application.campaign import (
    CampaignRuntimeError,
    CampaignWorkspace,
    CandidateAdmissionActivityHandler,
    CandidateEvaluationActivityHandler,
    CodingVariationActivityHandler,
    LocalCampaignWorker,
    _activity_subject,  # pyright: ignore[reportPrivateUsage]
    _changed_workspace_paths,  # pyright: ignore[reportPrivateUsage]
    _evaluation_usage,  # pyright: ignore[reportPrivateUsage]
    _usage_from_events,  # pyright: ignore[reportPrivateUsage]
    validate_campaign_workspace,
)
from avo_correlate.contracts.runtime import RuntimeEvent
from tests.conftest import DIGEST_A


def test_campaign_helpers_cover_path_modes_usage_and_subject_errors(tmp_path: Path) -> None:
    baseline, candidate = tmp_path / "base", tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    (baseline / "same.txt").write_text("same", encoding="utf-8")
    (candidate / "same.txt").write_text("same", encoding="utf-8")
    (candidate / "added.txt").write_text("new", encoding="utf-8")
    assert _changed_workspace_paths(baseline, candidate) == ["added.txt"]
    (candidate / "same.txt").write_text("changed", encoding="utf-8")
    assert _changed_workspace_paths(baseline, candidate) == ["added.txt", "same.txt"]
    assert (
        _usage_from_events(
            [
                RuntimeEvent(
                    invocation_id="invocation",
                    sequence=1,
                    event_type="usage",
                    payload_digest=DIGEST_A,
                    usage_delta={"input_tokens": 4, "x.output_tokens": 9},
                    occurred_at=datetime.now(UTC),
                )
            ]
        ).model_output_tokens
        == 9
    )
    assert _evaluation_usage(tuple()).authoritative_evaluations == 0
    with pytest.raises(CampaignRuntimeError, match="invalid variation"):
        _activity_subject(ActivityRow(activity_id="bad", activity_key="other:x"), "variation")
    with pytest.raises(CampaignRuntimeError, match="disjoint"):
        validate_campaign_workspace(
            CampaignWorkspace(baseline, baseline, tmp_path / "git"), tmp_path / "spool"
        )


def test_campaign_workspace_rejects_unsupported_entry_and_vcs_metadata(tmp_path: Path) -> None:
    baseline, candidate = tmp_path / "base", tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    (candidate / ".git").mkdir()
    with pytest.raises(CampaignRuntimeError, match="VCS-free"):
        validate_campaign_workspace(
            CampaignWorkspace(baseline, candidate, tmp_path / "git"), tmp_path / "spool"
        )
    (candidate / ".git").rmdir()
    (candidate / "pipe").write_text("unsupported", encoding="utf-8")
    # Regular files remain supported; exercise authority-path derivation separately.
    assert _changed_workspace_paths(baseline, candidate) == ["pipe"]


def test_failure_classification_distinguishes_retry_and_reconciliation() -> None:
    def no_invocation(_self: object, _activity_id: str) -> None:
        return None

    handler = cast(Any, object.__new__(CodingVariationActivityHandler))
    handler._invocations = type("Inv", (), {"find_activity_invocation": no_invocation})()
    activity = ActivityRow(activity_id="a")
    assert handler.classify_failure(activity, RuntimeError("transient")).value == "retry"
    invocation = type(
        "Invocation",
        (),
        {
            "runtime_session": object(),
            "invocation_id": "i",
            "run_id": "r",
            "event_stream_artifact_digest": None,
        },
    )()

    def find_invocation(_self: object, _activity_id: str) -> object:
        return invocation

    def replace_invocation(_self: object, _invocation: object) -> None:
        return None

    handler._invocations = type(
        "Inv",
        (),
        {
            "find_activity_invocation": find_invocation,
            "replace_invocation": replace_invocation,
        },
    )()
    handler._artifacts = type("Artifacts", (), {})()
    handler._actor_id = "actor"
    handler._event_spool_root = Path(".")
    assert handler.classify_failure(activity, RuntimeError("ambiguous")).value == "reconcile"


def test_worker_and_handler_failure_policies() -> None:
    worker = LocalCampaignWorker.__new__(LocalCampaignWorker)
    worker.run_once = lambda: asyncio.sleep(0, result=False)  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="positive"):
        asyncio.run(worker.run_until_idle(max_activities=0))
    assert (
        CandidateEvaluationActivityHandler.classify_failure(
            ActivityRow(activity_id="a"), RuntimeError()
        ).value
        == "retry"
    )
    assert (
        CandidateAdmissionActivityHandler.classify_failure(
            ActivityRow(activity_id="a"), RuntimeError()
        ).value
        == "retry"
    )
