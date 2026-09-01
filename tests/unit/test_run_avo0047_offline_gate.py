# pyright: reportMissingImports=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUntypedFunctionDecorator=false

"""Focused tests for the redacted C7 reference script."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest

from scripts.run_avo0047_offline_gate import run


@pytest.fixture
def short_root() -> Any:
    root = Path(tempfile.mkdtemp(prefix="c7-script-", dir=Path.cwd().anchor))
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_script_output_is_stable_and_redacted(short_root: Path) -> None:
    first_root = short_root / "first"
    second_root = short_root / "second"
    first = run(first_root)
    second = run(second_root)

    assert first == second
    encoded = json.dumps(first, sort_keys=True, separators=(",", ":"))
    assert str(first_root) not in encoded
    assert str(second_root) not in encoded
    assert "created_at" not in encoded
    assert "provider" not in encoded
    assert first["status"] == "complete"
    assert first["case_count"] == 47
    assert first["vector_count"] == 47
    assert first["deploy_performed"] is False


def test_script_refuses_nonempty_conflicting_root(short_root: Path) -> None:
    root = short_root / "conflict"
    root.mkdir()
    (root / "unrelated.json").write_text("{}", encoding="utf-8")

    with pytest.raises(RuntimeError, match="conflicting C7 root"):
        run(root)


def test_script_same_root_replay_is_identical(short_root: Path) -> None:
    first = run(short_root)
    second = run(short_root)
    assert first == second
