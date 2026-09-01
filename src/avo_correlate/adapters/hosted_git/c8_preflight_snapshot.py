"""Atomic, read-only GitHub C8 Phase-2 preflight snapshot.

The Phase-1 snapshot remains deliberately small.  This module composes the
Phase-2 configuration reads in one transaction and exposes only frozen,
diagnostic observations.  It has no writer, authority, or issuer capability.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Any, Literal, NoReturn, cast
from urllib.parse import quote

from avo_correlate.contracts.c8_hosted_preflight import (
    C8ObservationBinding,
    C8ProtectionRead,
    C8QueueConfigurationRead,
    C8RepositoryRead,
    C8WorkflowRead,
)
from avo_correlate.domain.canonical import canonical_digest

from .c8_phase2 import (
    C8Phase2Error,
    EffectiveMainRules,
    MergeQueueConfiguration,
    RequiredChecksConfiguration,
    parse_effective_main_rules,
    parse_merge_queue_configuration,
    parse_required_checks,
)
from .c8_workflow_semantics import (
    C8WorkflowSemanticsUnverifiable,
    parse_c8_workflow_semantics,
)
from .github import JsonBody, JsonObject, JsonValue, github_repository_digest
from .github_transport import GitHubJsonTransport

_SEGMENT = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?$")
_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_WORKFLOW = re.compile(r"^\.github/workflows/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+$")

_MERGE_QUEUE_QUERY = """
query AvoC8MergeQueue($owner: String!, $name: String!, $branch: String!) {
  repository(owner: $owner, name: $name) {
    mergeQueue(branch: $branch) {
      configuration {
        maximumEntriesToBuild
        maximumEntriesToMerge
        mergeMethod
        mergingStrategy
      }
      entries(first: 100) {
        totalCount
        nodes { id }
        pageInfo { hasNextPage }
      }
    }
  }
}
"""


@dataclass(frozen=True)
class _ConfigurationPass:
    raw: dict[str, JsonValue]
    rules: EffectiveMainRules
    queue: MergeQueueConfiguration
    checks: RequiredChecksConfiguration


class C8PreflightSnapshotUnverifiable(RuntimeError):
    """A hosted C8 observation was not authoritative or could not be parsed."""

    def __init__(self) -> None:
        # Never include transport/provider text: it may contain credentials.
        super().__init__("C8 hosted snapshot is unverifiable")


class GitHubC8PreflightSnapshot:
    """Single-flight immutable observer for the complete Phase-2 read set."""

    def __init__(
        self,
        *,
        owner: str,
        repo: str,
        workflow_path: str,
        token: str,
        transport: Callable[
            [str, str, JsonBody | None, Mapping[str, str]], tuple[int, JsonValue]
        ] | None = None,
        clock: Callable[[], datetime] | None = None,
        freshness_window: timedelta = timedelta(minutes=5),
        api_origin: str = "https://api.github.com",
    ) -> None:
        if not token or not token.strip():
            raise ValueError("GitHub token is required")
        if _SEGMENT.fullmatch(owner) is None or _SEGMENT.fullmatch(repo) is None:
            raise ValueError("invalid GitHub repository")
        if _WORKFLOW.fullmatch(workflow_path) is None or ".." in workflow_path:
            raise ValueError("workflow path is not allowlisted")
        if freshness_window <= timedelta(0):
            raise ValueError("freshness window must be positive")
        if api_origin.rstrip("/") != "https://api.github.com":
            raise ValueError("GitHub API origin must be exact")
        self.owner, self.repo, self.workflow_path = owner, repo, workflow_path
        self._token = token
        self._transport = transport or GitHubJsonTransport(origin=api_origin)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._freshness_window = freshness_window
        self._captured = False
        self._failed = False
        self._capture_lock = Lock()
        self._observations: tuple[
            C8RepositoryRead,
            C8ProtectionRead,
            C8QueueConfigurationRead,
            C8WorkflowRead,
        ] | None = None

    @staticmethod
    def _obj(value: JsonValue) -> JsonObject:
        if not isinstance(value, dict):
            raise C8PreflightSnapshotUnverifiable()
        return value

    @staticmethod
    def _str(value: JsonObject, key: str) -> str:
        item = value.get(key)
        if not isinstance(item, str) or not item or "\x00" in item:
            raise C8PreflightSnapshotUnverifiable()
        return item

    @staticmethod
    def _git(value: str) -> str:
        if _OBJECT.fullmatch(value) is None:
            raise C8PreflightSnapshotUnverifiable()
        return value

    def _get(self, path: str) -> JsonValue:
        # Every path is assembled internally from validated components.
        response: tuple[int, JsonValue] | None = None
        try:
            response = self._transport(
                "GET",
                "https://api.github.com" + path,
                None,
                {
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "Authorization": "Bearer " + self._token,
                },
            )
        except Exception:
            response = None
        if response is None:
            raise C8PreflightSnapshotUnverifiable()
        status, payload = response
        if type(status) is not int or status < 200 or status >= 300:
            raise C8PreflightSnapshotUnverifiable()
        return copy.deepcopy(payload)

    def _graphql(self) -> JsonValue:
        response: tuple[int, JsonValue] | None = None
        try:
            response = self._transport(
                "POST",
                "https://api.github.com/graphql",
                {
                    "query": _MERGE_QUEUE_QUERY,
                    "variables": {"owner": self.owner, "name": self.repo, "branch": "main"},
                },
                {
                    "Accept": "application/vnd.github+json",
                    "Content-Type": "application/json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "Authorization": "Bearer " + self._token,
                },
            )
        except Exception:
            response = None
        if response is None:
            raise C8PreflightSnapshotUnverifiable()
        status, payload = response
        if type(status) is not int or status < 200 or status >= 300:
            raise C8PreflightSnapshotUnverifiable()
        return copy.deepcopy(payload)

    def capture(self) -> GitHubC8PreflightSnapshot:
        """Read all configuration once, then return this cached observer."""
        if self._captured:
            return self
        if self._failed:
            raise C8PreflightSnapshotUnverifiable()
        with self._capture_lock:
            if self._captured:
                return self
            if self._failed:
                raise C8PreflightSnapshotUnverifiable()
            failure: C8PreflightSnapshotUnverifiable | None = None
            try:
                self._capture_locked()
            except Exception as exc:
                self._failed = True
                if isinstance(exc, C8PreflightSnapshotUnverifiable):
                    failure = exc
                else:
                    failure = C8PreflightSnapshotUnverifiable()
            if failure is not None:
                failure.__context__ = None
                failure.__cause__ = None
                raise failure
            return self

    def _configuration_pass(self, base: str) -> _ConfigurationPass:
        """Read and parse the mutable configuration set once."""
        raw: dict[str, JsonValue] = {}
        effective = self._get(base + "/rules/branches/main?per_page=100&page=1")
        raw["effective_rules"] = effective
        if not isinstance(effective, list) or len(effective) >= 100:
            # Without Link headers, exactly a full page is ambiguous.
            raise C8PreflightSnapshotUnverifiable()
        repo_rules: list[JsonObject] = []
        org_rules: list[JsonObject] = []
        for item in effective:
            entry = self._obj(item)
            source_type = entry.get("ruleset_source_type")
            source = entry.get("ruleset_source")
            ident = entry.get("ruleset_id")
            if source_type not in ("Repository", "Organization") or not isinstance(source, str):
                raise C8PreflightSnapshotUnverifiable()
            if type(ident) is not int or ident <= 0:
                raise C8PreflightSnapshotUnverifiable()
            if source_type == "Repository" and source.casefold() != (
                f"{self.owner}/{self.repo}".casefold()
            ):
                raise C8PreflightSnapshotUnverifiable()
            if source_type == "Organization" and source.casefold() != self.owner.casefold():
                raise C8PreflightSnapshotUnverifiable()
            path = (
                base + f"/rulesets/{ident}"
                if source_type == "Repository"
                else f"/orgs/{quote(self.owner, safe='')}/rulesets/{ident}"
            )
            detail = self._obj(self._get(path))
            raw[f"ruleset:{source_type}:{ident}"] = detail
            (repo_rules if source_type == "Repository" else org_rules).append(detail)
        protection = self._obj(self._get(base + "/branches/main/protection"))
        raw["protection"] = protection
        queue_response = self._graphql()
        raw["graphql"] = queue_response
        parsed: (
            tuple[EffectiveMainRules, RequiredChecksConfiguration, MergeQueueConfiguration]
            | None
        ) = None
        try:
            parsed = (
                parse_effective_main_rules(effective, repo_rules, org_rules),
                parse_required_checks(protection),
                parse_merge_queue_configuration(queue_response),
            )
        except C8Phase2Error:
            parsed = None
        if parsed is None:
            raise C8PreflightSnapshotUnverifiable()
        rules, checks, queue = parsed
        self._cross_bind_queue(effective, queue)
        return _ConfigurationPass(raw, rules, queue, checks)

    @staticmethod
    def _cross_bind_queue(effective: JsonValue, queue: MergeQueueConfiguration) -> None:
        """Bind the sole REST merge_queue rule to the GraphQL configuration."""
        if not isinstance(effective, list):
            raise C8PreflightSnapshotUnverifiable()
        merge_entries = [
            item for item in effective
            if isinstance(item, dict) and item.get("type") == "merge_queue"
        ]
        if len(merge_entries) != 1:
            raise C8PreflightSnapshotUnverifiable()
        parameters = merge_entries[0].get("parameters")
        if not isinstance(parameters, dict):
            raise C8PreflightSnapshotUnverifiable()
        maximum_merge = parameters.get("max_entries_to_merge")
        maximum_build = parameters.get("max_entries_to_build")
        method = parameters.get("merge_method")
        strategy = parameters.get("grouping_strategy")
        if (
            type(maximum_merge) is not int
            or type(maximum_build) is not int
            or type(method) is not str
            or type(strategy) is not str
            or maximum_merge != queue.maximum_entries_to_merge
            or maximum_build != queue.maximum_entries_to_build
            or method != queue.merge_method
            or strategy != queue.merging_strategy
        ):
            raise C8PreflightSnapshotUnverifiable()
    def _capture_locked(self) -> None:
        started = self._clock()
        if (
            type(started) is not datetime
            or started.tzinfo is None
            or started.utcoffset() is None
        ):
            raise C8PreflightSnapshotUnverifiable()
        base = f"/repos/{quote(self.owner, safe='')}/{quote(self.repo, safe='')}"
        raw: dict[str, JsonValue] = {}
        repository = self._obj(self._get(base))
        raw["repository"] = repository
        if self._str(repository, "full_name") != f"{self.owner}/{self.repo}":
            raise C8PreflightSnapshotUnverifiable()
        owner = self._obj(repository.get("owner"))
        owner_type_raw = self._str(owner, "type")
        if owner_type_raw not in {"Organization", "User", "Bot", "Unknown"}:
            raise C8PreflightSnapshotUnverifiable()
        owner_type = cast(Literal["Organization", "User", "Bot", "Unknown"], owner_type_raw)

        ref = self._obj(self._get(base + "/git/ref/heads/main"))
        raw["initial_ref"] = ref
        if self._str(ref, "ref") != "refs/heads/main":
            raise C8PreflightSnapshotUnverifiable()
        ref_object = self._obj(ref.get("object"))
        commit = self._git(self._str(ref_object, "sha"))
        if ref_object.get("type") != "commit":
            raise C8PreflightSnapshotUnverifiable()
        commit_raw = self._obj(self._get(base + "/git/commits/" + commit))
        raw["commit"] = commit_raw
        if self._str(commit_raw, "sha") != commit:
            raise C8PreflightSnapshotUnverifiable()
        tree = self._obj(commit_raw.get("tree"))
        tree_sha = self._git(self._str(tree, "sha"))
        parents_raw = commit_raw.get("parents")
        if not isinstance(parents_raw, list) or len(parents_raw) > 100:
            raise C8PreflightSnapshotUnverifiable()
        parents: list[str] = []
        for parent in parents_raw:
            parents.append(self._git(self._str(self._obj(parent), "sha")))

        workflow = self._obj(
            self._get(base + "/contents/" + quote(self.workflow_path, safe="/") + "?ref=" + commit)
        )
        raw["workflow"] = workflow
        if self._str(workflow, "path") != self.workflow_path or workflow.get("type") != "file":
            raise C8PreflightSnapshotUnverifiable()
        if workflow.get("encoding") != "base64":
            raise C8PreflightSnapshotUnverifiable()
        encoded = self._str(workflow, "content").replace("\n", "")
        blob_sha = self._git(self._str(workflow, "sha"))
        decode_failure = False
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            decode_failure = True
            content = b""
        if decode_failure:
            raise C8PreflightSnapshotUnverifiable()
        size = workflow.get("size")
        if type(size) is not int or size != len(content):
            raise C8PreflightSnapshotUnverifiable()
        blob_header = f"blob {len(content)}\0".encode() + content
        expected_blob = (
            hashlib.sha1(blob_header).hexdigest()
            if len(blob_sha) == 40
            else hashlib.sha256(blob_header).hexdigest()
        )
        if blob_sha != expected_blob:
            raise C8PreflightSnapshotUnverifiable()
        decode_failure = False
        try:
            content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            decode_failure = True
        if decode_failure:
            raise C8PreflightSnapshotUnverifiable()
        try:
            workflow_semantics = parse_c8_workflow_semantics(content)
        except C8WorkflowSemanticsUnverifiable:
            workflow_semantics = None

        first_config = self._configuration_pass(base)
        second_config = self._configuration_pass(base)
        if canonical_digest(first_config.raw) != canonical_digest(second_config.raw):
            raise C8PreflightSnapshotUnverifiable()
        if (
            first_config.rules != second_config.rules
            or first_config.queue != second_config.queue
            or first_config.checks != second_config.checks
        ):
            raise C8PreflightSnapshotUnverifiable()
        raw["configuration_pass_1"] = first_config.raw
        raw["configuration_pass_2"] = second_config.raw
        rules = first_config.rules
        queue = first_config.queue

        final_ref = self._obj(self._get(base + "/git/ref/heads/main"))
        raw["final_ref"] = final_ref
        final_obj = self._obj(final_ref.get("object"))
        if (
            self._str(final_ref, "ref") != "refs/heads/main"
            or final_obj.get("type") != "commit"
            or self._str(final_obj, "sha") != commit
        ):
            raise C8PreflightSnapshotUnverifiable()
        finished = self._clock()
        if (
            type(finished) is not datetime
            or finished.tzinfo is None
            or finished.utcoffset() is None
        ):
            raise C8PreflightSnapshotUnverifiable()
        if finished < started or finished - started > self._freshness_window:
            raise C8PreflightSnapshotUnverifiable()
        freshness_cutoff = finished - self._freshness_window
        source = canonical_digest(
            {
                "responses": raw,
                "workflow_bytes": base64.b64encode(content).decode("ascii"),
                "workflow_digest": "sha256:" + hashlib.sha256(content).hexdigest(),
                "observed_at": finished.isoformat(),
                "freshness_cutoff": freshness_cutoff.isoformat(),
            }
        )
        binding = C8ObservationBinding(
            repository_digest=github_repository_digest(self.owner, self.repo),
            configuration_epoch=source,
            source_observation_digest=source,
            observed_at=finished,
            freshness_cutoff=freshness_cutoff,
        )
        workflow_digest = "sha256:" + hashlib.sha256(content).hexdigest()
        repo_read = C8RepositoryRead(
            binding=binding,
            owner=self.owner,
            repo=self.repo,
            owner_type=owner_type,
            main_commit=commit,
            main_tree=tree_sha,
            main_parents=parents,
        )
        protection_read = C8ProtectionRead(
            binding=binding,
            effective=True,
            ruleset_ids=sorted(set(rules.repository_ruleset_ids + rules.organization_ruleset_ids)),
            queue_required=True,
            bypass_allowed=False,
            direct_merge_allowed=False,
        )
        queue_read = C8QueueConfigurationRead(
            binding=binding,
            available=True,
            maximum_entries_to_merge=queue.maximum_entries_to_merge,
            maximum_entries_to_build=queue.maximum_entries_to_build,
            merge_method=queue.merge_method,
            merging_strategy=queue.merging_strategy,
        )
        workflow_read = C8WorkflowRead(
            binding=binding,
            path=self.workflow_path,
            workflow_digest=workflow_digest,
            policy_digest=canonical_digest({"path": self.workflow_path, "blob_sha": blob_sha}),
            validation_check_identity_digest=None,
            pull_request_event=(
                None if workflow_semantics is None else workflow_semantics.pull_request_event
            ),
            merge_group_event=(
                None if workflow_semantics is None else workflow_semantics.merge_group_event
            ),
            exact_sha_checkout=(
                None if workflow_semantics is None else workflow_semantics.exact_sha_checkout
            ),
            checkout_persist_credentials_false=(
                None
                if workflow_semantics is None
                else workflow_semantics.checkout_persist_credentials_false
            ),
        )
        self._observations = (
            repo_read,
            protection_read,
            queue_read,
            workflow_read,
        )
        self._captured = True

    def _observation(self, index: int) -> Any:
        if not self._captured or self._observations is None:
            self.capture()
        assert self._observations is not None
        return self._observations[index]

    def observe_repository(self) -> C8RepositoryRead:
        return cast(C8RepositoryRead, self._observation(0))

    def observe_protection(self) -> C8ProtectionRead:
        return cast(C8ProtectionRead, self._observation(1))

    def observe_queue_configuration(self) -> C8QueueConfigurationRead:
        return cast(C8QueueConfigurationRead, self._observation(2))

    def observe_workflow(self) -> C8WorkflowRead:
        return cast(C8WorkflowRead, self._observation(3))

    def observe_validation_identity(self) -> NoReturn:
        self._unsupported()

    def _unsupported(self) -> NoReturn:
        raise C8PreflightSnapshotUnverifiable()

    observe_rollback_namespace = _unsupported
    observe_isolated_issuer = _unsupported


C8GitHubPreflightSnapshot = GitHubC8PreflightSnapshot
C8PreflightSnapshotAdapter = GitHubC8PreflightSnapshot
GitHubC8PreflightAdapter = GitHubC8PreflightSnapshot
C8HostedPreflightSnapshot = GitHubC8PreflightSnapshot

__all__ = [
    "C8GitHubPreflightSnapshot",
    "C8HostedPreflightSnapshot",
    "C8PreflightSnapshotAdapter",
    "C8PreflightSnapshotUnverifiable",
    "GitHubC8PreflightAdapter",
    "GitHubC8PreflightSnapshot",
]
