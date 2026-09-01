"""Immutable, read-only Phase-1 GitHub C8 diagnostic snapshot.

This adapter is intentionally a very small trust boundary: it has exactly four
allowlisted GETs and provides no hosted writer or capability operation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Literal, NoReturn, cast
from urllib.parse import quote

from avo_correlate.contracts.c8_hosted_preflight import (
    C8ObservationBinding,
    C8RepositoryRead,
    C8WorkflowRead,
)
from avo_correlate.domain.canonical import canonical_digest

from .github import JsonBody, JsonValue, github_repository_digest
from .github_transport import GitHubJsonTransport

_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]+$")
_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_WORKFLOW = re.compile(r"^\.github/workflows/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$")


class C8SnapshotUnverifiable(RuntimeError):
    """A hosted observation could not be authenticated or parsed safely."""

    def __init__(self) -> None:
        super().__init__("C8 hosted snapshot is unverifiable")


class C8GitHubSnapshotAdapter:
    """Capture and replay one immutable repository/main/workflow observation."""

    def __init__(
        self,
        *,
        owner: str,
        repo: str,
        workflow_path: str,
        token: str,
        transport: Callable[[str, str, JsonBody | None, Mapping[str, str]], tuple[int, JsonValue]]
        | None = None,
        observed_at: datetime | None = None,
        freshness_cutoff: datetime | None = None,
        api_origin: str = "https://api.github.com",
    ) -> None:
        if not token:
            raise ValueError("GitHub token is required")
        self._validate_repo_part(owner, "owner")
        self._validate_repo_part(repo, "repo")
        if not _WORKFLOW.fullmatch(workflow_path):
            raise ValueError("workflow path is not allowlisted")
        if (
            ".." in workflow_path
            or "\\" in workflow_path
            or "?" in workflow_path
            or "#" in workflow_path
        ):
            raise ValueError("workflow path is not allowlisted")
        if workflow_path.endswith("/"):
            raise ValueError("workflow path is not allowlisted")
        now = observed_at or datetime.now(UTC)
        cutoff = freshness_cutoff or now
        if (
            now.tzinfo is None
            or now.utcoffset() is None
            or cutoff.tzinfo is None
            or cutoff.utcoffset() is None
        ):
            raise ValueError("observation timestamps must be timezone-aware")
        if now < cutoff:
            raise ValueError("observation is stale")
        if api_origin.rstrip("/") != "https://api.github.com":
            raise ValueError("GitHub API origin must be exact")
        self.owner, self.repo, self.workflow_path = owner, repo, workflow_path
        self._token = token  # retained only for request headers; never serialized
        self._observed_at, self._freshness_cutoff = now, cutoff
        self._transport = transport or GitHubJsonTransport(origin=api_origin)
        self._captured: tuple[C8RepositoryRead, C8WorkflowRead] | None = None
        self._binding: C8ObservationBinding | None = None

    @staticmethod
    def _validate_repo_part(value: str, label: str) -> None:
        if not value or not _SEGMENT.fullmatch(value) or value in {".", ".."}:
            raise ValueError(f"invalid GitHub {label}")

    def _get(self, path: str) -> JsonValue:
        url = "https://api.github.com" + path
        try:
            status, payload = self._transport(
                "GET",
                url,
                None,
                {
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "Authorization": "Bearer " + self._token,
                },
            )
            if status < 200 or status >= 300:
                raise C8SnapshotUnverifiable()
            return payload
        except C8SnapshotUnverifiable:
            raise
        except Exception:
            raise C8SnapshotUnverifiable() from None

    @staticmethod
    def _obj(value: JsonValue) -> dict[str, JsonValue]:
        if not isinstance(value, dict):
            raise C8SnapshotUnverifiable()
        return value

    @staticmethod
    def _string(obj: dict[str, JsonValue], key: str) -> str:
        value = obj.get(key)
        if not isinstance(value, str) or not value:
            raise C8SnapshotUnverifiable()
        return value

    def capture(self) -> tuple[C8RepositoryRead, C8WorkflowRead]:
        if self._captured is not None:
            return self._captured
        base = f"/repos/{quote(self.owner, safe='')}/{quote(self.repo, safe='')}"
        repository_raw = self._obj(self._get(base))
        full_name = self._string(repository_raw, "full_name")
        if full_name != f"{self.owner}/{self.repo}":
            raise C8SnapshotUnverifiable()
        owner_obj = self._obj(repository_raw.get("owner"))
        owner_type_raw = self._string(owner_obj, "type")
        if owner_type_raw not in {"Organization", "User", "Bot", "Unknown"}:
            raise C8SnapshotUnverifiable()
        owner_type = cast(Literal["Organization", "User", "Bot", "Unknown"], owner_type_raw)
        ref = self._obj(self._get(base + "/git/ref/heads/main"))
        if self._string(ref, "ref") != "refs/heads/main":
            raise C8SnapshotUnverifiable()
        ref_obj = self._obj(ref.get("object"))
        commit = self._string(ref_obj, "sha")
        if ref_obj.get("type") != "commit" or not _OBJECT.fullmatch(commit):
            raise C8SnapshotUnverifiable()
        commit_raw = self._obj(self._get(base + "/git/commits/" + commit))
        if self._string(commit_raw, "sha") != commit:
            raise C8SnapshotUnverifiable()
        tree = self._obj(commit_raw.get("tree"))
        tree_sha = self._string(tree, "sha")
        if not _OBJECT.fullmatch(tree_sha):
            raise C8SnapshotUnverifiable()
        parents_raw = commit_raw.get("parents")
        if not isinstance(parents_raw, list):
            raise C8SnapshotUnverifiable()
        parents: list[str] = []
        for parent in parents_raw:
            pobj = self._obj(parent)
            psha = self._string(pobj, "sha")
            if not _OBJECT.fullmatch(psha):
                raise C8SnapshotUnverifiable()
            parents.append(psha)
        workflow_raw = self._obj(
            self._get(base + "/contents/" + quote(self.workflow_path, safe="/") + "?ref=" + commit)
        )
        if (
            self._string(workflow_raw, "path") != self.workflow_path
            or workflow_raw.get("type") != "file"
        ):
            raise C8SnapshotUnverifiable()
        content = self._string(workflow_raw, "content").replace("\n", "")
        content_sha = self._string(workflow_raw, "sha")
        if not _OBJECT.fullmatch(content_sha):
            raise C8SnapshotUnverifiable()
        try:
            data = base64.b64decode(content, validate=True)
        except (ValueError, binascii.Error):
            raise C8SnapshotUnverifiable() from None
        workflow_digest = "sha256:" + hashlib.sha256(data).hexdigest()
        source = canonical_digest(
            {
                "repository": repository_raw,
                "ref": ref,
                "commit": commit_raw,
                "workflow": {
                    "path": self.workflow_path,
                    "sha": content_sha,
                    "content_digest": workflow_digest,
                },
                "observed_at": self._observed_at.isoformat(),
                "freshness_cutoff": self._freshness_cutoff.isoformat(),
            }
        )
        binding = C8ObservationBinding(
            repository_digest=github_repository_digest(self.owner, self.repo),
            configuration_epoch=source,
            source_observation_digest=source,
            observed_at=self._observed_at,
            freshness_cutoff=self._freshness_cutoff,
        )
        repo_read = C8RepositoryRead(
            binding=binding,
            owner=self.owner,
            repo=self.repo,
            owner_type=owner_type,
            main_commit=commit,
            main_tree=tree_sha,
            main_parents=parents,
        )
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise C8SnapshotUnverifiable() from None
        policy = canonical_digest(
            {
                "path": self.workflow_path,
                "content_sha": content_sha,
                "content_digest": workflow_digest,
            }
        )
        identity = canonical_digest({"workflow_digest": workflow_digest})
        checkout_blocks = re.findall(
            r"(?ms)^\s*-?\s*uses:\s*actions/checkout@[^\n]+(?P<body>.*?)(?=^\s*-?\s*uses:|\Z)",
            text,
        )
        exact_checkout = bool(checkout_blocks) and all(
            re.search(
                r"(?m)^\s*ref\s*:\s*(?:\$\{\{\s*github\.sha\s*\}\}|[0-9a-f]{40})\s*$",
                block,
            )
            is not None
            for block in checkout_blocks
        )
        workflow_read = C8WorkflowRead(
            binding=binding,
            path=self.workflow_path,
            workflow_digest=workflow_digest,
            policy_digest=policy,
            validation_check_identity_digest=identity,
            pull_request_event=bool(re.search(r"(?m)^\s*pull_request\s*:", text)),
            merge_group_event=bool(re.search(r"(?m)^\s*merge_group\s*:", text)),
            exact_sha_checkout=exact_checkout,
        )
        self._binding, self._captured = binding, (repo_read, workflow_read)
        return self._captured

    def observe_repository(self) -> C8RepositoryRead:
        return self.capture()[0]

    def observe_workflow(self) -> C8WorkflowRead:
        return self.capture()[1]

    # Explicit names make the one-shot boundary convenient without exposing a
    # second implementation or allowing a later network refresh.
    capture_snapshot = capture
    snapshot = capture

    def _unsupported(self) -> NoReturn:
        raise C8SnapshotUnverifiable()

    observe_protection = _unsupported
    observe_queue_configuration = _unsupported
    observe_validation_identity = _unsupported
    observe_rollback_namespace = _unsupported
    observe_isolated_issuer = _unsupported


GitHubC8SnapshotAdapter = C8GitHubSnapshotAdapter

__all__ = ["C8GitHubSnapshotAdapter", "C8SnapshotUnverifiable", "GitHubC8SnapshotAdapter"]
