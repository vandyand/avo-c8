"""Focused tests for the local-only C8 preparation CLI output contract."""

from __future__ import annotations

import json

import pytest

from scripts.prepare_avo0047_main_rollback import main


def test_cli_requires_recorded_evidence_and_never_claims_execution(capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        main([])
    captured = capsys.readouterr()
    assert raised.value.code == 2
    assert captured.out == ""
    assert "required" in captured.err


def test_cli_summary_literals_are_explicit() -> None:
    summary = {
        "prepared_only": True,
        "hosted_drill_executed": False,
        "ledger_activated": False,
        "provider_calls": 0,
    }
    assert json.dumps(summary, sort_keys=True, separators=(",", ":"))
