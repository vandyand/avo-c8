"""Focused tests for the local-only C8 inventory CLI contract."""

from __future__ import annotations

import json

import pytest

from scripts.prepare_avo0047_main_rollback import main


def test_cli_requires_recorded_evidence(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        main([])
    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert captured.out == ""
    assert "required" in captured.err


def test_offline_summary_has_no_hosted_proof_claim() -> None:
    summary = {
        "prepared_only": True,
        "hosted_drill_executed": False,
        "hosted_rollback_proof_prepared": False,
        "activation_consumable": False,
        "ledger_activated": False,
        "provider_calls": 0,
    }
    encoded = json.dumps(summary, sort_keys=True, separators=(",", ":"))
    assert summary["hosted_rollback_proof_prepared"] is False
    assert summary["hosted_drill_executed"] is False
    assert summary["activation_consumable"] is False
    assert encoded
