"""Static security guardrails for required CI validation events."""

import re
from pathlib import Path

WORKFLOW = Path(__file__).parents[2] / ".github" / "workflows" / "ci.yml"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_required_validation_events_and_read_only_permissions() -> None:
    text = _workflow_text()
    assert re.search(
        r"^on:\n  pull_request:\n  merge_group:\n    types: \[checks_requested\]",
        text,
        re.MULTILINE,
    )
    assert re.search(r"^permissions:\n  contents: read\n", text, re.MULTILINE)
    assert "workflow_dispatch" not in text
    assert "avo-main-release" not in text
    assert "deploy" not in text.lower()
    assert "secrets" not in text.lower()
    assert "contents: write" not in text
    assert "actions: write" not in text


def test_validation_jobs_checkout_exact_event_sha() -> None:
    text = _workflow_text()
    assert text.count("ref: ${{ github.sha }}") == 2
    assert "github.event.pull_request.head.sha" not in text
    assert "actions/checkout@v4" not in text
    assert "astral-sh/setup-uv@v6" not in text
    assert "persist-credentials: false" in text
    assert "github.ref" not in text
    assert "github.head_ref" not in text
    assert "AVO_WSL_PROJECT_PATH" not in text
    assert "vars.AVO_WSL_PROJECT_PATH" not in text
    assert "wslpath -u \"$env:GITHUB_WORKSPACE\"" in text
    assert text.count("git rev-parse HEAD") >= 7
    assert text.count("$head -ne $env:GITHUB_SHA") >= 7
    assert text.count("git status --porcelain") >= 7
    assert text.count("-or $status") >= 7


def test_required_context_names_and_validation_surface_are_preserved() -> None:
    text = _workflow_text()
    assert re.search(r"^  validate:\n", text, re.MULTILINE)
    assert re.search(r"^  windows-wsl-parity:\n", text, re.MULTILINE)
    assert "        os: [ubuntu-latest, windows-latest]" in text
    for command in (
        "validate_roadmap.py",
        "uv run ruff check .",
        "uv run pyright",
        "uv run pytest --cov=avo_correlate",
        "export_schemas",
        "git diff --exit-code -- schemas",
    ):
        assert command in text
