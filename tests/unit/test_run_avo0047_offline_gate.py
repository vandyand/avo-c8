# pyright: reportMissingImports=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUntypedFunctionDecorator=false

"""Focused tests for the redacted C7 reference script."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest

from scripts.run_avo0047_offline_gate import main, run


@pytest.fixture
def short_root() -> Any:
    root = Path(tempfile.mkdtemp(prefix="c7-script-", dir=Path.cwd().anchor))
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_script_default_fails_closed_stably_and_creates_no_result(short_root: Path) -> None:
    with pytest.raises(RuntimeError, match=r"^c7_authority_executor_unavailable$"):
        run(short_root)
    assert not (short_root / "main-graduation-offline-drill-v1").exists()


def test_script_cli_returns_stable_redacted_error(short_root: Path, capsys: Any) -> None:
    import sys

    original = sys.argv
    try:
        sys.argv = ["run_avo0047_offline_gate.py", "--root", str(short_root)]
        assert main() == 2
    finally:
        sys.argv = original
    output = capsys.readouterr().out.strip()
    assert output == "c7_authority_executor_unavailable"
    assert str(short_root) not in output


def test_script_refuses_nonempty_conflicting_root(short_root: Path) -> None:
    root = short_root / "conflict"
    root.mkdir()
    (root / "unrelated.json").write_text("{}", encoding="utf-8")

    with pytest.raises(RuntimeError, match="conflicting C7 root"):
        run(root)
