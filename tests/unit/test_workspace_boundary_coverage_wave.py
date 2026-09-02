"""Focused coverage for bounded workspace mutation and scan policy branches."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import avo_correlate.adapters.tools.workspace as workspace_module
from avo_correlate.adapters.tools.workspace import ToolPolicyError, WorkspaceToolBroker
from avo_correlate.application.capabilities import CapabilityIssuer
from avo_correlate.contracts.tools import CapabilityClaims
from tests.conftest import DIGEST_A, experiment_spec


def _broker(
    tmp_path: Path, tools: list[str], *, limits: tuple[int, int] = (100, 500)
) -> tuple[WorkspaceToolBroker, str]:
    root = tmp_path / "workspace"
    (root / "src").mkdir(parents=True)
    (root / "src" / "module.py").write_text("needle = 1\n", encoding="utf-8")
    issuer = CapabilityIssuer(b"w" * 32)
    token = issuer.issue(
        CapabilityClaims(
            token_id="wave-token",
            session_id="wave-session",
            actor_id="wave",
            workspace_digest=DIGEST_A,
            tools=tools,
            policy_decision_id="policy",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    spec = experiment_spec().workspace.model_copy(
        update={
            "allowed_paths": ["src"],
            "forbidden_paths": [],
            "max_file_bytes": limits[0],
            "max_tree_bytes": limits[1],
        }
    )
    return WorkspaceToolBroker(
        root, spec, issuer=issuer, session_id="wave-session", workspace_digest=DIGEST_A
    ), token


def test_search_limits_and_read_size_are_enforced(tmp_path: Path) -> None:
    broker, token = _broker(tmp_path, ["read_file", "search_workspace"], limits=(5, 20))
    with pytest.raises(ToolPolicyError, match="read limit"):
        broker.read_file(token, "src/module.py")
    # A zero output limit is a valid caller boundary and must produce no records.
    assert broker.search_workspace(token, "needle", max_bytes=0) == []
    with pytest.raises(ToolPolicyError, match="cannot be empty"):
        broker.search_workspace(token, "")


def test_patch_validation_and_subprocess_failure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker, token = _broker(tmp_path, ["apply_patch"])
    for patch, message in [(b"not a diff", "no file headers"), (b"--- x\n+++ x\n", "a/ and b/")]:
        with pytest.raises(ToolPolicyError, match=message):
            broker.apply_patch(token, patch)

    def failed_apply(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        return type("R", (), {"returncode": 1, "stderr": b"failure"})()

    monkeypatch.setattr(workspace_module.subprocess, "run", failed_apply)
    with pytest.raises(ToolPolicyError, match="failure"):
        broker.apply_patch(
            token,
            b"--- a/src/module.py\n+++ b/src/module.py\n@@ -1 +1 @@\n-needle = 1\n+needle = 2\n",
        )


def test_replace_text_rejects_binary_and_rolls_back_scan_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker, token = _broker(tmp_path, ["replace_text"])
    target = tmp_path / "workspace" / "src" / "module.py"
    target.write_bytes(b"\xff\xfe")
    with pytest.raises(ToolPolicyError, match="UTF-8"):
        broker.replace_text(token, "src/module.py", "x", "y")
    target.write_text("needle = 1\n", encoding="utf-8")
    original = target.read_bytes()
    monkeypatch.setattr(
        broker, "_scan_after_mutation", lambda: (_ for _ in ()).throw(ToolPolicyError("scan"))
    )
    with pytest.raises(ToolPolicyError, match="scan"):
        broker.replace_text(token, "src/module.py", "needle", "changed")
    assert target.read_bytes() == original


def test_external_git_diff_failure_and_size_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broker, token = _broker(tmp_path, ["inspect_diff"])
    result = type("R", (), {"returncode": 1, "stdout": b"", "stderr": b""})()

    def failed_diff(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        return result

    monkeypatch.setattr(workspace_module.subprocess, "run", failed_diff)
    with pytest.raises(ToolPolicyError, match="git diff failed"):
        broker.inspect_diff(token)
