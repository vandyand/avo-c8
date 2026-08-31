"""Typed public adapters for the validated C4 foundation fixture."""

from __future__ import annotations

from pathlib import Path

from avo_correlate.contracts.main_graduation import MainSourcePackageBinding
from tests.unit import test_main_graduation_c4_validated_fixture as fixture

MAIN_OPERATION = fixture.MAIN_OPERATION
REPOSITORY = fixture.REPOSITORY


def git(root: Path, *args: str) -> str:
    """Run a fixture-only Git command without exposing a private import."""
    return fixture._git(root, *args)  # pyright: ignore[reportPrivateUsage]


def source(root: Path) -> MainSourcePackageBinding:
    """Return the validated source package fixture."""
    return fixture._source(root)  # pyright: ignore[reportPrivateUsage]
