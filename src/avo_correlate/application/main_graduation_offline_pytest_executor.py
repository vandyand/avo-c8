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
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, cast

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.application.main_graduation_offline_identity import (
    FROZEN_OFFLINE_EXECUTION_ARGV,
    C7WorkspaceIdentityError,
    C7WorkspaceIdentityVerifier,
    sanitized_child_environment,
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

_COMMAND_TIMEOUT_SECONDS = 300
_MAX_PROCESS_OUTPUT = 2 * 1024 * 1024


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
        encoding="utf-8",
        errors="replace",
        env=sanitized_child_environment(),
        timeout=_COMMAND_TIMEOUT_SECONDS,
    )
    if len(completed.stdout.encode("utf-8")) > _MAX_PROCESS_OUTPUT or len(
        completed.stderr.encode("utf-8")
    ) > _MAX_PROCESS_OUTPUT:
        raise OfflinePytestExecutionError("pytest process output exceeds bound")
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
        self._check_window(authority)
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
        before = self._measure_workspace(authority)
        argv = list(authority.argv)
        if not argv or any(not isinstance(item, str) or not item for item in argv):
            raise OfflinePytestExecutionError("authority argv is invalid")
        with tempfile.TemporaryDirectory(prefix="avo-c7-junit-") as temp:
            report_path = Path(temp) / "junit.xml"
            rendered = [item.replace("{junitxml}", f"--junitxml={report_path}") for item in argv]
            # Identity observation resolves and hashes uv once.  Use that
            # exact absolute path for execution; do not resolve a fresh bare
            # launcher after the toolchain has been authenticated.
            uv_path = getattr(self.identity_checker, "_last_uv_path", None)
            if not isinstance(uv_path, Path) or not uv_path.is_absolute() or not uv_path.is_file():
                raise OfflinePytestExecutionError(
                    "workspace identity did not provide a verified uv path"
                )
            if not rendered or rendered[0] != FROZEN_OFFLINE_EXECUTION_ARGV[0]:
                raise OfflinePytestExecutionError("authority command launcher is invalid")
            rendered[0] = str(uv_path)
            # The authority bounds the command shape; the frozen node list is
            # appended by this executor so callers cannot substitute a test.
            rendered.extend(_pytest_node_id(node.node_id) for node in authority.nodes)
            self.calls += 1
            self._check_expiry(authority)
            try:
                exit_code = self.runner(rendered, self.workspace, report_path)
            except (OSError, subprocess.TimeoutExpired, C7WorkspaceIdentityError) as exc:
                raise OfflinePytestExecutionError("pytest process failed or timed out") from exc
            self._check_expiry(authority)
            if exit_code != 0:
                raise OfflinePytestExecutionError("pytest process did not exit zero")
            try:
                raw = report_path.read_bytes()
            except OSError as exc:
                raise OfflinePytestExecutionError("pytest did not produce a report") from exc
            if len(raw) > self.max_report_bytes:
                raise OfflinePytestExecutionError("pytest report exceeds bound")
        after = self._measure_workspace(authority)
        if before != after:
            raise OfflinePytestExecutionError("workspace identity changed during pytest execution")
        observations = self._parse_junit(raw, authority, authority_ref)
        junit_ref = self.artifact_store.put_bytes(
            raw,
            media_type="application/vnd.avo.c7.junit+xml",
            role="c7-junit-xml",
            max_bytes=self.max_report_bytes,
        )
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
            "environment_identity_digest": before["environment_identity_digest"],
            "uv_digest": before["uv_digest"],
            "workspace_before_identity": before,
            "workspace_after_identity": after,
            "junit_xml_artifact": junit_ref,
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

    def _check_expiry(self, authority: MainGraduationOfflineExecutionAuthority) -> None:
        self._check_window(authority)

    def _check_window(self, authority: MainGraduationOfflineExecutionAuthority) -> None:
        now = self.clock()
        if now < authority.authorized_at or now >= authority.expires_at:
            raise OfflinePytestExecutionError("execution authority expired")

    def _measure_workspace(
        self, authority: MainGraduationOfflineExecutionAuthority
    ) -> dict[str, Any]:
        observer = getattr(self.identity_checker, "observe", None)
        if not callable(observer):
            raise OfflinePytestExecutionError(
                "identity checker must expose measured workspace observations"
            )
        try:
            observed = observer()
            self.identity_checker(authority)
        except OfflinePytestExecutionError:
            raise
        except Exception as exc:
            raise OfflinePytestExecutionError("workspace identity observation failed") from exc
        return asdict(cast(Any, observed))

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
            identity = _node_identity(testcase, node.node_id)
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
                    verification_status="pass",
                    reason_code="pinned-oracle-node-passed",
                    evidence_refs=(typed,),
                )
            )
        if tuple(item.node_id for item in observations) != FROZEN_OFFLINE_EXECUTION_NODE_IDS:
            raise OfflinePytestExecutionError("JUnit nodes are missing, extra, or reordered")
        return observations


def _node_identity(testcase: ET.Element, expected_node_id: str) -> str:
    classname = testcase.attrib.get("classname", "")
    name = testcase.attrib.get("name", "")
    if not classname or not name:
        raise OfflinePytestExecutionError("JUnit testcase identity is incomplete")
    path, separator, expected_name = expected_node_id.partition("::")
    if not separator or not path.endswith(".py") or not expected_name:
        raise OfflinePytestExecutionError("authority node identity is malformed")
    expected_classname = f"tests.unit.{path[:-3].replace('/', '.')}"
    if classname != expected_classname or name != expected_name:
        raise OfflinePytestExecutionError("JUnit testcase identity differs from authority")
    return expected_node_id


def _pytest_node_id(node_id: str) -> str:
    path, separator, name = node_id.partition("::")
    if (
        not separator
        or not path.endswith(".py")
        or "/" in path
        or "\\" in path
        or not name
    ):
        raise OfflinePytestExecutionError("frozen node identity is malformed")
    return f"tests/unit/{path}::{name}"


__all__ = ["HermeticPytestExecutor", "OfflinePytestExecutionError", "ProcessRunner"]
