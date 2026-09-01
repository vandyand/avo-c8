"""Strict, bounded semantic checks for the C8 validation workflow."""
# pyright: reportUnknownVariableType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnnecessaryIsInstance=false, reportIncompatibleVariableOverride=false

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, ClassVar

import yaml
from yaml import AliasToken, AnchorToken, MappingNode, Node, ScalarNode, SequenceNode, TagToken

from avo_correlate.domain.canonical import canonical_digest

_SHA = re.compile(r"^[0-9a-f]{40}$")
_EXACT_SHA_REF = "${{ github.sha }}"
_MAX_BYTES = 1_048_576
_MAX_TOKENS = 10_000
_MAX_NODES = 5_000
_MAX_DEPTH = 32
_MAX_COLLECTION = 500
_MAX_SCALAR = 16_384


class C8WorkflowSemanticsUnverifiable(RuntimeError):
    """Malformed or unsupported workflow input (with a code-only message)."""

    def __init__(self, code: str = "WORKFLOW_UNVERIFIABLE") -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class C8WorkflowSemantics:
    pull_request_event: bool
    merge_group_event: bool
    exact_sha_checkout: bool
    checkout_persist_credentials_false: bool
    digest: str


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader with YAML 1.2-style booleans and duplicate-key rejection."""

    yaml_implicit_resolvers: ClassVar[dict[Any, Any]] = {
        key: [item for item in values if item[0] != "tag:yaml.org,2002:bool"]
        for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    yaml_implicit_resolvers.setdefault("t", []).append(
        ("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$"))
    )
    yaml_implicit_resolvers.setdefault("f", []).append(
        ("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$"))
    )

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, MappingNode):
            raise C8WorkflowSemanticsUnverifiable("WORKFLOW_MAPPING_EXPECTED")
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise C8WorkflowSemanticsUnverifiable("WORKFLOW_KEY_UNSUPPORTED")
            if key in result:
                raise C8WorkflowSemanticsUnverifiable("WORKFLOW_DUPLICATE_KEY")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _reject_unsupported_nodes(node: Node, *, depth: int = 0, count: list[int]) -> None:
    if depth > _MAX_DEPTH:
        raise C8WorkflowSemanticsUnverifiable("WORKFLOW_DEPTH_LIMIT")
    count[0] += 1
    if count[0] > _MAX_NODES:
        raise C8WorkflowSemanticsUnverifiable("WORKFLOW_NODE_LIMIT")
    if isinstance(node, ScalarNode):
        if len(node.value) > _MAX_SCALAR:
            raise C8WorkflowSemanticsUnverifiable("WORKFLOW_SCALAR_LIMIT")
        if node.value == "<<":
            raise C8WorkflowSemanticsUnverifiable("WORKFLOW_MERGE_KEY")
        if node.tag not in {
            "tag:yaml.org,2002:null",
            "tag:yaml.org,2002:bool",
            "tag:yaml.org,2002:int",
            "tag:yaml.org,2002:float",
            "tag:yaml.org,2002:str",
        }:
            raise C8WorkflowSemanticsUnverifiable("WORKFLOW_TAG_UNSUPPORTED")
    elif isinstance(node, MappingNode):
        if len(node.value) > _MAX_COLLECTION:
            raise C8WorkflowSemanticsUnverifiable("WORKFLOW_MAPPING_LIMIT")
        for key, value in node.value:
            _reject_unsupported_nodes(key, depth=depth + 1, count=count)
            _reject_unsupported_nodes(value, depth=depth + 1, count=count)
    elif isinstance(node, SequenceNode):
        if len(node.value) > _MAX_COLLECTION:
            raise C8WorkflowSemanticsUnverifiable("WORKFLOW_SEQUENCE_LIMIT")
        for item in node.value:
            _reject_unsupported_nodes(item, depth=depth + 1, count=count)
    else:
        raise C8WorkflowSemanticsUnverifiable("WORKFLOW_NODE_UNSUPPORTED")


def _mapping(value: Any, code: str) -> dict[Any, Any]:
    if not isinstance(value, dict):
        raise C8WorkflowSemanticsUnverifiable(code)
    return value


def _steps_for_job(job: Any) -> list[Any]:
    mapping = _mapping(job, "WORKFLOW_JOB_INVALID")
    if "uses" in mapping:
        raise C8WorkflowSemanticsUnverifiable("WORKFLOW_REUSABLE_JOB_UNVERIFIABLE")
    steps = mapping.get("steps")
    if not isinstance(steps, list):
        raise C8WorkflowSemanticsUnverifiable("WORKFLOW_STEPS_MISSING")
    return steps


def parse_c8_workflow_semantics(content: bytes) -> C8WorkflowSemantics:
    """Parse bounded YAML and return conservative static workflow facts."""
    if not isinstance(content, bytes) or len(content) > _MAX_BYTES:
        raise C8WorkflowSemanticsUnverifiable("WORKFLOW_BYTES_LIMIT")
    failure = C8WorkflowSemanticsUnverifiable("WORKFLOW_MALFORMED")
    try:
        content.decode("utf-8", errors="strict")
        tokens = list(yaml.scan(content, Loader=_StrictLoader))
        if len(tokens) > _MAX_TOKENS:
            raise C8WorkflowSemanticsUnverifiable("WORKFLOW_TOKEN_LIMIT")
        if any(isinstance(token, (AliasToken, AnchorToken, TagToken)) for token in tokens):
            raise C8WorkflowSemanticsUnverifiable("WORKFLOW_ALIAS_OR_TAG")
        documents = list(yaml.compose_all(content, Loader=_StrictLoader))
        if len(documents) != 1 or documents[0] is None:
            raise C8WorkflowSemanticsUnverifiable("WORKFLOW_DOCUMENT_COUNT")
        root_node = documents[0]
        _reject_unsupported_nodes(root_node, count=[0])
        root = _mapping(yaml.load(content, Loader=_StrictLoader), "WORKFLOW_ROOT_INVALID")
        triggers = _mapping(root.get("on"), "WORKFLOW_ON_INVALID")
        pull_request_value = triggers.get("pull_request")
        if pull_request_value is not None and not isinstance(pull_request_value, dict):
            raise C8WorkflowSemanticsUnverifiable("WORKFLOW_PULL_REQUEST_INVALID")
        pull_request = "pull_request" in triggers
        merge_group_value = triggers.get("merge_group")
        merge_group = False
        if isinstance(merge_group_value, dict):
            types = merge_group_value.get("types")
            if isinstance(types, list):
                if len(types) > 20 or any(not isinstance(item, str) for item in types):
                    raise C8WorkflowSemanticsUnverifiable("WORKFLOW_MERGE_GROUP_INVALID")
                merge_group = "checks_requested" in types
            elif types is not None:
                raise C8WorkflowSemanticsUnverifiable("WORKFLOW_MERGE_GROUP_INVALID")
        elif merge_group_value is not None:
            raise C8WorkflowSemanticsUnverifiable("WORKFLOW_MERGE_GROUP_INVALID")
        jobs = _mapping(root.get("jobs"), "WORKFLOW_JOBS_INVALID")
        if not jobs:
            raise C8WorkflowSemanticsUnverifiable("WORKFLOW_JOBS_EMPTY")
        checkout_count = 0
        exact = True
        persist = True
        for job in jobs.values():
            for step in _steps_for_job(job):
                step_mapping = _mapping(step, "WORKFLOW_STEP_INVALID")
                if "uses" not in step_mapping:
                    continue
                uses = step_mapping["uses"]
                if not isinstance(uses, str) or "${{" in uses:
                    raise C8WorkflowSemanticsUnverifiable("WORKFLOW_DYNAMIC_USES")
                if uses.casefold().startswith("actions/checkout@"):
                    checkout_count += 1
                    action_sha = uses.split("@", 1)[1]
                    if _SHA.fullmatch(action_sha) is None:
                        exact = False
                    with_mapping = step_mapping.get("with")
                    if not isinstance(with_mapping, dict):
                        exact = False
                        persist = False
                        continue
                    if with_mapping.get("ref") != _EXACT_SHA_REF:
                        exact = False
                    if with_mapping.get("persist-credentials") is not False:
                        persist = False
        if checkout_count == 0:
            exact = False
            persist = False
        facts = {
            "pull_request_event": pull_request,
            "merge_group_event": merge_group,
            "exact_sha_checkout": exact,
            "checkout_persist_credentials_false": persist,
        }
        return C8WorkflowSemantics(**facts, digest=canonical_digest(facts))
    except C8WorkflowSemanticsUnverifiable as exc:
        failure = exc
    except Exception:
        failure = C8WorkflowSemanticsUnverifiable("WORKFLOW_MALFORMED")
    # Raise outside the exception handler so hostile parser text cannot
    # survive in ``__context__`` or ``__cause__``.
    failure.__context__ = None
    failure.__cause__ = None
    raise failure


__all__ = [
    "C8WorkflowSemantics",
    "C8WorkflowSemanticsUnverifiable",
    "parse_c8_workflow_semantics",
]
