import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from avo_correlate.cli.app import app
from avo_correlate.contracts.c8_hosted_preflight import HostedC8PreflightReport

runner = CliRunner()


def _report(result: Any) -> dict[str, object]:
    # CliRunner's result type is intentionally not part of the application
    # contract; keep assertions focused on the emitted JSON only.
    return json.loads(result.stdout)


def test_c8_preflight_requires_nonblank_environment_token(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    result = runner.invoke(
        app,
        ["c8", "preflight", "--owner", "avo", "--repo", "roadmap"],
    )

    assert result.exit_code == 2
    report = _report(result)
    assert report["result"] == "unverifiable"
    assert report["unverifiable_codes"] == ["c8_preflight_unverifiable"]
    assert not list(tmp_path.iterdir())


def test_c8_preflight_rejects_blank_token_without_constructing_adapter(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "   ")

    class UnexpectedAdapter:
        def __init__(self, **kwargs):
            raise AssertionError(f"adapter constructed: {kwargs}")

    monkeypatch.setattr(
        "avo_correlate.adapters.hosted_git.GitHubC8PreflightSnapshot",
        UnexpectedAdapter,
    )
    result = runner.invoke(
        app,
        ["c8", "preflight", "--owner", "avo", "--repo", "roadmap"],
    )

    assert result.exit_code == 2
    assert _report(result)["result"] == "unverifiable"
    assert "adapter constructed" not in result.stdout


def test_c8_preflight_uses_only_environment_token_and_redacts_adapter_errors(monkeypatch) -> None:
    token = "env-secret-canary"
    observed: list[str] = []
    monkeypatch.setenv("GITHUB_TOKEN", token)

    class FailingAdapter:
        def __init__(self, **kwargs):
            observed.append(kwargs["token"])
            raise RuntimeError(f"adapter secret {token}")

    monkeypatch.setattr(
        "avo_correlate.adapters.hosted_git.GitHubC8PreflightSnapshot",
        FailingAdapter,
    )
    result = runner.invoke(
        app,
        ["c8", "preflight", "--owner", "avo", "--repo", "roadmap"],
    )

    assert result.exit_code == 2
    assert observed == [token]
    assert token not in result.stdout
    assert _report(result)["result"] == "unverifiable"


def test_c8_preflight_unknown_token_option_is_rejected_without_echoing_secret(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    result = runner.invoke(
        app,
        [
            "c8",
            "preflight",
            "--owner",
            "avo",
            "--repo",
            "roadmap",
            "--token",
            "argv-secret-canary",
        ],
    )

    assert result.exit_code == 2
    assert "argv-secret-canary" not in result.stdout
    assert "argv-secret-canary" not in result.stderr
    assert _report(result)["result"] == "unverifiable"


def test_c8_preflight_has_no_persistence_or_transport_options() -> None:
    result = runner.invoke(app, ["c8", "preflight", "--help"])

    assert result.exit_code == 0
    assert "--token" not in result.stdout
    assert "--transport" not in result.stdout
    assert "--data-dir" not in result.stdout


def test_c8_preflight_emits_success_from_diagnostic_service(monkeypatch) -> None:
    token = "env-only-canary"
    observed: list[str] = []
    monkeypatch.setenv("GITHUB_TOKEN", token)

    class FakeAdapter:
        def __init__(self, **kwargs):
            observed.append(kwargs["token"])

    class FakeService:
        def __init__(self, observer):
            assert isinstance(observer, FakeAdapter)

        def run(self) -> HostedC8PreflightReport:
            return HostedC8PreflightReport.build(
                passed_codes=("diagnostic_only",),
                blocker_codes=(),
                unverifiable_codes=(),
                observation_digests={},
            )

    monkeypatch.setattr(
        "avo_correlate.adapters.hosted_git.GitHubC8PreflightSnapshot", FakeAdapter
    )
    monkeypatch.setattr(
        "avo_correlate.application.c8_hosted_preflight.C8HostedPreflightService", FakeService
    )
    result = runner.invoke(
        app,
        ["c8", "preflight", "--owner", "avo", "--repo", "roadmap"],
    )

    assert result.exit_code == 0
    assert observed == [token]
    assert _report(result)["result"] == "no_detected_configuration_blocker"
