"""Focused coverage for operator-facing CLI diagnostics and failure paths."""

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from avo_correlate.cli import app as cli
from avo_correlate.contracts.operations import CheckStatus, DoctorCheck, DoctorReport

runner = CliRunner()


def test_doctor_report_covers_host_and_tool_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_executable(_name: str) -> None:
        return None

    monkeypatch.setattr(cli.sys, "version_info", (3, 11))
    monkeypatch.setattr(cli.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(cli.platform, "release", lambda: "generic")
    monkeypatch.setattr(cli.platform, "system", lambda: "Plan9")
    monkeypatch.setattr(cli.shutil, "which", no_executable)
    report = cli.build_doctor_report(strict=True)
    assert report.overall == CheckStatus.FAIL
    assert {check.name for check in report.checks} == {
        "python",
        "host_topology",
        "uv",
        "git",
        "docker",
        "architecture",
    }
    assert all(check.next_action for check in report.checks if check.status == CheckStatus.FAIL)

    monkeypatch.setattr(cli.platform, "system", lambda: "Windows")
    windows = cli.build_doctor_report(strict=False)
    assert (
        next(check for check in windows.checks if check.name == "host_topology").status
        == CheckStatus.WARN
    )


def test_cli_render_emit_and_invalid_inputs_are_sanitized(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = DoctorReport(
        overall=CheckStatus.PASS,
        checks=[DoctorCheck(name="fixture", status=CheckStatus.PASS, detail="ok")],
    )
    cli._render(report, json_output=False)  # pyright: ignore[reportPrivateUsage]
    assert "AVO-Correlate platform status: pass" in capsys.readouterr().out
    cli._emit({"value": 1})  # pyright: ignore[reportPrivateUsage]
    assert json.loads(capsys.readouterr().out) == {"value": 1}

    invalid = tmp_path / "invalid.json"
    invalid.write_text("not-json", encoding="utf-8")
    with pytest.raises(cli.typer.Exit) as exc:
        cli._read_spec(invalid)  # pyright: ignore[reportPrivateUsage]
    assert exc.value.exit_code == 2
    bad_policy = runner.invoke(
        cli.app, ["policy", "test", "--bundle", str(invalid), "--cases", str(invalid)]
    )
    assert bad_policy.exit_code == 2
    assert "Invalid policy test input" in bad_policy.stderr


def test_c8_preflight_unknown_options_returns_unverifiable_without_secret_echo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    result = runner.invoke(
        cli.app,
        ["c8", "preflight", "--owner", "vandyand", "--repo", "avo-c8", "--token", "secret"],
    )
    assert result.exit_code == 2
    assert "secret" not in result.stdout
    payload = json.loads(result.stdout)
    assert payload["result"] == "unverifiable"


def test_test_layer_propagates_subprocess_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class Completed:
        returncode = 7

    def fake_run(*args: Any, **kwargs: Any) -> Completed:
        del args, kwargs
        return Completed()

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    with pytest.raises(cli.typer.Exit) as exc:
        cli._run_test_layer("tests/unit")  # pyright: ignore[reportPrivateUsage]
    assert exc.value.exit_code == 7
