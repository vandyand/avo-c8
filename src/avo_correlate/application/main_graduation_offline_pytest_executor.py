# pyright: reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnnecessaryIsInstance=false
"""Hermetic pytest executor and strict JUnit normalizer for C7.

The executor owns one subprocess invocation.  It never constructs a drill
case/result and only emits an execution report bound to the supplied
authority.  Tests may inject ``runner`` and ``identity_checker``; production
uses the no-shell ``subprocess.run`` implementation.
"""

from __future__ import annotations

import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.application.main_graduation_offline_identity import (
    FROZEN_OFFLINE_EXECUTION_ARGV,
    C7WorkspaceIdentityVerifier,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation_offline_drill import (
    FROZEN_OFFLINE_EXECUTION_NODE_IDS,
    MainGraduationOfflineEvidenceKind,
    MainGraduationOfflineEvidenceRef,
    MainGraduationOfflineExecutionAuthority,
    MainGraduationOfflineExecutionReport,
    MainGraduationOfflineNodeObservation,
)
from avo_correlate.domain.canonical import canonical_digest


class OfflinePytestExecutionError(RuntimeError):
    """The hermetic command or its report violated the frozen authority."""


class ProcessRunner(Protocol):
    def __call__(self, argv: list[str], cwd: Path, report_path: Path) -> int: ...


def _default_runner(argv: list[str], cwd: Path, report_path: Path) -> int:
    del report_path
    completed = subprocess.run(
        argv,
        cwd=cwd,
        shell=False,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.returncode


class HermeticPytestExecutor:
    """Execute exactly one authority-pinned pytest command and normalize XML."""

    def __init__(
        self,
        workspace: Path,
        artifact_store: FilesystemArtifactStore,
        *,
        clock: Callable[[], datetime],
        runner: ProcessRunner | None = None,
        identity_checker: Callable[[MainGraduationOfflineExecutionAuthority], None] | None = None,
        max_report_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        self.workspace = workspace.resolve()
        self.artifact_store = artifact_store
        self.clock = clock
        self.runner = runner or _default_runner
        # Production always performs an independent local identity check.  A
        # checker may still be injected by focused unit tests, but omitting it
        # can never disable the boundary.
        self.identity_checker = identity_checker or C7WorkspaceIdentityVerifier(self.workspace)
        self.max_report_bytes = max_report_bytes
        self.calls = 0

    def validate_authority(self, authority: MainGraduationOfflineExecutionAuthority) -> None:
        """Check the immutable execution identity before every run/replay."""
        if not self.workspace.is_dir():
            raise OfflinePytestExecutionError("workspace is unavailable")
        if self.clock() > authority.expires_at:
            raise OfflinePytestExecutionError("execution authority expired")
        if not authority.argv or "pytest" not in authority.argv:
            raise OfflinePytestExecutionError("authority argv is not pytest")
        if tuple(authority.argv) != FROZEN_OFFLINE_EXECUTION_ARGV:
            raise OfflinePytestExecutionError("authority argv is not the frozen pytest command")
        forbidden = {";", "&&", "|", "`", "$(", "cmd.exe", "powershell"}
        if any(any(token in item.lower() for token in forbidden) for item in authority.argv):
            raise OfflinePytestExecutionError("authority argv contains unsafe token")
        if self.identity_checker is not None:
            try:
                self.identity_checker(authority)
            except OfflinePytestExecutionError:
                raise
            except Exception as exc:
                raise OfflinePytestExecutionError(
                    "workspace identity differs from authority"
                ) from exc

    def execute(
        self,
        authority: MainGraduationOfflineExecutionAuthority,
        authority_ref: ArtifactRef,
    ) -> MainGraduationOfflineExecutionReport:
        self.validate_authority(authority)
        argv = list(authority.argv)
        if not argv or any(not isinstance(item, str) or not item for item in argv):
            raise OfflinePytestExecutionError("authority argv is invalid")
        with tempfile.TemporaryDirectory(prefix="avo-c7-junit-") as temp:
            report_path = Path(temp) / "junit.xml"
            rendered = [item.replace("{junitxml}", f"--junitxml={report_path}") for item in argv]
            # The authority bounds the command shape; the frozen node list is
            # appended by this executor so callers cannot substitute a test.
            rendered.extend(node.node_id for node in authority.nodes)
            self.calls += 1
            exit_code = self.runner(rendered, self.workspace, report_path)
            if exit_code != 0:
                raise OfflinePytestExecutionError("pytest process did not exit zero")
            try:
                raw = report_path.read_bytes()
            except OSError as exc:
                raise OfflinePytestExecutionError("pytest did not produce a report") from exc
            if len(raw) > self.max_report_bytes:
                raise OfflinePytestExecutionError("pytest report exceeds bound")
        observations = self._parse_junit(raw, authority, authority_ref)
        now = self.clock()
        values: dict[str, Any] = {
            "operation_id": authority.operation_id,
            "authority_digest": authority.authority_digest,
            "repository_digest": authority.repository_digest,
            "source_commit": authority.source_commit,
            "source_tree": authority.source_tree,
            "source_tree_digest": authority.source_tree_digest,
            "protocol_digest": authority.protocol_digest,
            "configuration_digest": authority.configuration_digest,
            "policy_digest": authority.policy_digest,
            "activation_digest": authority.activation_digest,
            "lockfile_digest": authority.lockfile_digest,
            "interpreter_digest": authority.interpreter_digest,
            "pytest_digest": authority.pytest_digest,
            "plugin_set_digest": authority.plugin_set_digest,
            "toolchain_digest": authority.toolchain_digest,
            "argv": authority.argv,
            "collection_count": len(observations),
            "collected_node_ids": FROZEN_OFFLINE_EXECUTION_NODE_IDS,
            "observations": tuple(observations),
            "executed_at": now,
            "authority_expires_at": authority.expires_at,
        }
        values["report_digest"] = canonical_digest(
            {"domain": "avo-004.7-c7/offline-execution-report/v1", "value": values}
        )
        return MainGraduationOfflineExecutionReport.model_validate(values)

    def _parse_junit(
        self,
        raw: bytes,
        authority: MainGraduationOfflineExecutionAuthority,
        authority_ref: ArtifactRef,
    ) -> list[MainGraduationOfflineNodeObservation]:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise OfflinePytestExecutionError("malformed JUnit XML") from exc
        tests = list(root.iter("testcase"))
        if len(tests) != len(authority.nodes):
            raise OfflinePytestExecutionError("JUnit testcase count differs from authority")
        observations: list[MainGraduationOfflineNodeObservation] = []
        for testcase, node in zip(tests, authority.nodes, strict=True):
            identity = _node_identity(testcase)
            if identity != node.node_id:
                raise OfflinePytestExecutionError("JUnit node identity differs from authority")
            status = testcase.attrib.get("status", "passed").lower()
            if status not in {"", "passed", "success"} or list(testcase):
                raise OfflinePytestExecutionError("JUnit contains failure/skipped/error testcase")
            typed = MainGraduationOfflineEvidenceRef(
                kind=MainGraduationOfflineEvidenceKind.EXECUTION_AUTHORITY,
                artifact=authority_ref,
            )
            observations.append(
                MainGraduationOfflineNodeObservation(
                    node_id=node.node_id,
                    parameter_id=node.parameter_id,
                    case_id=node.case_id,
                    vector_id=node.vector_id,
                    outcome=node.expected_outcome,
                    reason_code="production-boundary-node-passed",
                    evidence_refs=(typed,),
                )
            )
        if tuple(item.node_id for item in observations) != FROZEN_OFFLINE_EXECUTION_NODE_IDS:
            raise OfflinePytestExecutionError("JUnit nodes are missing, extra, or reordered")
        return observations


def _node_identity(testcase: ET.Element) -> str:
    classname = testcase.attrib.get("classname", "")
    name = testcase.attrib.get("name", "")
    if not classname or not name:
        raise OfflinePytestExecutionError("JUnit testcase identity is incomplete")
    direct = f"{classname}::{name}"
    # pytest's junitxml writer commonly emits classname as a dotted module
    # name while the authority uses the repository-relative node id.
    if direct in FROZEN_OFFLINE_EXECUTION_NODE_IDS:
        return direct
    dotted = f"{classname.replace('.', '/')}::{name}"
    if dotted in FROZEN_OFFLINE_EXECUTION_NODE_IDS:
        return dotted
    raise OfflinePytestExecutionError("JUnit testcase identity differs from authority")


__all__ = ["HermeticPytestExecutor", "OfflinePytestExecutionError", "ProcessRunner"]
