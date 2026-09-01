# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownMemberType=false
"""Pure, fail-closed parsers for the authenticated C8 Phase-2 observations.

This module deliberately has no GitHub client, transport, or authority model.
Callers authenticate and complete responses first, then pass the resulting
``JsonValue`` objects to these functions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from avo_correlate.domain.canonical import canonical_digest

# Structural alias kept local so importing this pure module does not import
# the transport/adapter dependency graph.
JsonValue = Any


class C8Phase2Error(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class C8Phase2Blocked(C8Phase2Error):
    """Authenticated, complete evidence proves a required configuration is absent/invalid."""


class C8Phase2Unverifiable(C8Phase2Error):
    """The response is malformed, incomplete, or does not establish permission."""


@dataclass(frozen=True)
class EffectiveMainRules:
    entries: tuple[tuple[str, int, str], ...]
    repository_ruleset_ids: tuple[int, ...]
    organization_ruleset_ids: tuple[int, ...]
    digest: str


@dataclass(frozen=True)
class MergeQueueConfiguration:
    maximum_entries_to_merge: int
    maximum_entries_to_build: int
    merge_method: str
    merging_strategy: str
    total_count: int
    digest: str


@dataclass(frozen=True)
class RequiredChecksConfiguration:
    contexts: tuple[tuple[str, int], ...]
    validation_contexts: tuple[str, ...]
    release_context: str
    digest: str


def _obj(value: JsonValue, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise C8Phase2Unverifiable(code)
    return value


def _list(value: Any, code: str) -> list[Any]:
    if not isinstance(value, list):
        raise C8Phase2Unverifiable(code)
    return list(value)


def _int(value: Any, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise C8Phase2Unverifiable(code)
    return value


def _field(obj: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in obj:
            return obj[name]
    return None


def _ruleset_list(value: JsonValue, code: str) -> list[dict[str, Any]]:
    values = _list(value, code)
    if len(values) > 100:
        raise C8Phase2Blocked("RULES_TOO_MANY_ENTRIES")
    return [_obj(v, code) for v in values]


def _conditions(detail: dict[str, Any]) -> None:
    conditions = _obj(detail.get("conditions"), "RULES_CONDITIONS_MISSING")
    refs = _obj(conditions.get("ref_name"), "RULES_CONDITIONS_MISSING")
    includes = _list(refs.get("include"), "RULES_CONDITIONS_INVALID")
    excludes = _list(refs.get("exclude"), "RULES_CONDITIONS_INVALID")
    if len(includes) > 100 or len(excludes) > 100:
        raise C8Phase2Unverifiable("RULES_CONDITIONS_TOO_MANY")
    if any(not isinstance(v, str) or not v for v in includes + excludes):
        raise C8Phase2Unverifiable("RULES_CONDITIONS_INVALID")
    accepted = {"refs/heads/main", "~DEFAULT_BRANCH", "~ALL"}
    if not any(v in accepted for v in includes):
        raise C8Phase2Unverifiable("RULES_UNSUPPORTED_BRANCH_PATTERN")
    if any(v in accepted for v in excludes):
        raise C8Phase2Blocked("RULES_EXCLUDES_MAIN")
    if excludes:
        raise C8Phase2Unverifiable("RULES_UNSUPPORTED_EXCLUSION")
    if len(set(includes)) != len(includes) or len(set(excludes)) != len(excludes):
        raise C8Phase2Blocked("RULES_CONDITIONS_DUPLICATE")


def parse_effective_main_rules(
    effective_rules: JsonValue,
    repository_rulesets: JsonValue,
    organization_rulesets: JsonValue,
) -> EffectiveMainRules:
    """Parse exact repository/organization rulesets resolved for ``main``.

    The authenticated adapter should resolve inheritance and branch matching;
    this parser still checks every supplied entry's active-main/no-bypass facts.
    """
    try:
        effective = [
            _obj(v, "RULES_EFFECTIVE_INCOMPLETE")
            for v in _list(effective_rules, "RULES_EFFECTIVE_INCOMPLETE")
        ]
        repo = _ruleset_list(repository_rulesets, "RULES_REPOSITORY_INCOMPLETE")
        org = _ruleset_list(organization_rulesets, "RULES_ORGANIZATION_INCOMPLETE")
        if len(effective) > 100:
            raise C8Phase2Blocked("RULES_TOO_MANY_ENTRIES")
        effective_identity_keys = [
            (
                item.get("ruleset_source_type"),
                item.get("ruleset_source"),
                item.get("ruleset_id"),
                item.get("type"),
                canonical_digest(item.get("parameters")),
            )
            for item in effective
        ]
        if len(set(effective_identity_keys)) != len(effective_identity_keys):
            raise C8Phase2Blocked("RULES_DUPLICATE_ENTRY")
        entries: list[tuple[str, int, str]] = []
        ids: dict[str, list[int]] = {"Repository": [], "Organization": []}
        resolved: dict[tuple[str, str, int], dict[str, Any]] = {}
        resolved_rules: dict[tuple[str, str, int], list[tuple[Any, Any]]] = {}
        for source, values in (("Repository", repo), ("Organization", org)):
            for item in values:
                ident = item.get("id")
                source_name = item.get("source")
                source_type = item.get("source_type")
                if (
                    isinstance(ident, int)
                    and not isinstance(ident, bool)
                    and isinstance(source_name, str)
                    and source_type == source
                ):
                    key = (source, source_name, ident)
                    if key in resolved:
                        raise C8Phase2Blocked("RULES_DUPLICATE_IDENTITY")
                    _conditions(item)
                    raw_rules = _list(item.get("rules"), "RULES_RESOLUTION_INCOMPLETE")
                    if len(raw_rules) > 100:
                        raise C8Phase2Blocked("RULES_TOO_MANY_ENTRIES")
                    parsed_rules: list[tuple[Any, Any]] = []
                    for rule in raw_rules:
                        robj = _obj(rule, "RULES_RESOLUTION_INCOMPLETE")
                        rtype = robj.get("type")
                        if not isinstance(rtype, str) or not rtype or "parameters" not in robj:
                            raise C8Phase2Unverifiable("RULES_RESOLUTION_INCOMPLETE")
                        parsed_rules.append((rtype, robj.get("parameters")))
                    resolved[key] = item
                    resolved_rules[key] = parsed_rules
                else:
                    raise C8Phase2Unverifiable("RULES_RESOLUTION_INCOMPLETE")
        for item in effective:
            source = item.get("ruleset_source_type")
            source_name = item.get("ruleset_source")
            ident = item.get("ruleset_id")
            typ = item.get("type")
            if (
                source not in ("Repository", "Organization")
                or not isinstance(source_name, str)
                or not source_name
            ):
                raise C8Phase2Blocked("RULES_SOURCE_MISMATCH")
            if isinstance(ident, bool) or not isinstance(ident, int) or ident <= 0:
                raise C8Phase2Blocked("RULES_INVALID_ENTRY")
            if not isinstance(typ, str) or not typ:
                raise C8Phase2Blocked("RULES_INVALID_ENTRY")
            full = resolved.get((source, source_name, ident))
            if full is None:
                raise C8Phase2Unverifiable("RULES_RESOLUTION_INCOMPLETE")
            parameters = item.get("parameters")
            if parameters is None:
                raise C8Phase2Unverifiable("RULES_ENTRY_INCOMPLETE")
            key = (source, source_name, ident)
            effective_by_identity = [
                (entry.get("type"), entry.get("parameters"))
                for entry in effective
                if (
                    entry.get("ruleset_source_type"),
                    entry.get("ruleset_source"),
                    entry.get("ruleset_id"),
                )
                == key
            ]
            if sorted(resolved_rules[key], key=repr) != sorted(effective_by_identity, key=repr):
                raise C8Phase2Blocked("RULES_RULE_SET_MISMATCH")
            enforcement = _field(full, "enforcement", "status")
            if enforcement is None:
                raise C8Phase2Unverifiable("RULES_ENTRY_INCOMPLETE")
            if enforcement != "active":
                raise C8Phase2Blocked("RULES_INACTIVE")
            bypass = _field(full, "bypass_actors", "bypassActors", "bypass")
            if bypass is None:
                raise C8Phase2Unverifiable("RULES_ENTRY_INCOMPLETE")
            if bypass not in ([], False):
                raise C8Phase2Blocked("RULES_BYPASS")
            branch = _field(full, "target", "branch", "ref")
            if branch is None:
                raise C8Phase2Unverifiable("RULES_ENTRY_INCOMPLETE")
            if branch != "branch":
                raise C8Phase2Blocked("RULES_WRONG_BRANCH")
            entries.append((source, ident, typ))
            ids[source].append(ident)
        expected_identities = {
            (item.get("ruleset_source_type"), item.get("ruleset_source"), item.get("ruleset_id"))
            for item in effective
        }
        actual_identities = set(resolved)
        if actual_identities != expected_identities:
            raise C8Phase2Unverifiable("RULES_RESOLUTION_SET_MISMATCH")
        if len(set(entries)) != len(entries):
            raise C8Phase2Blocked("RULES_DUPLICATE_ENTRY")
        queue = [entry for entry in entries if entry[2] == "merge_queue"]
        if len(queue) != 1:
            raise C8Phase2Blocked("RULES_QUEUE_CARDINALITY")
        entries.sort()
        repo_ids = tuple(sorted(ids["Repository"]))
        org_ids = tuple(sorted(ids["Organization"]))
        digest = canonical_digest(
            {"entries": entries, "repository": repo_ids, "organization": org_ids}
        )
        return EffectiveMainRules(tuple(entries), repo_ids, org_ids, digest)
    except C8Phase2Error:
        raise
    except Exception:
        raise C8Phase2Unverifiable("RULES_MALFORMED") from None


def parse_merge_queue_configuration(response: JsonValue) -> MergeQueueConfiguration:
    """Parse the fixed GraphQL mergeQueue response/configuration shape."""
    try:
        root = _obj(response, "QUEUE_MALFORMED")
        errors = root.get("errors")
        if errors not in (None, []):
            raise C8Phase2Unverifiable("QUEUE_GRAPHQL_ERRORS")
        data = _obj(root.get("data"), "QUEUE_DATA_MISSING")
        repository = _obj(_field(data, "repository"), "QUEUE_REPOSITORY_MISSING")
        queue = _field(repository, "mergeQueue", "merge_queue")
        if queue is None:
            raise C8Phase2Blocked("QUEUE_ABSENT")
        q = _obj(queue, "QUEUE_MALFORMED")
        config = _obj(_field(q, "configuration"), "QUEUE_CONFIG_INCOMPLETE")
        maximum_merge = _field(config, "maximumEntriesToMerge", "maximum_entries_to_merge")
        maximum_build = _field(config, "maximumEntriesToBuild", "maximum_entries_to_build")
        method = _field(config, "mergeMethod", "merge_method")
        strategy = _field(config, "mergingStrategy", "merging_strategy")
        if (
            _int(maximum_merge, "QUEUE_CONFIG_INCOMPLETE") != 1
            or _int(maximum_build, "QUEUE_CONFIG_INCOMPLETE") < 1
        ):
            raise C8Phase2Blocked("QUEUE_CONFIG_INVALID")
        if method != "SQUASH" or strategy != "ALLGREEN":
            raise C8Phase2Blocked("QUEUE_CONFIG_INVALID")
        entries = _obj(_field(q, "entries", "queueEntries"), "QUEUE_ENTRIES_MISSING")
        total = _int(_field(entries, "totalCount", "total_count"), "QUEUE_COUNT_INVALID")
        nodes = _list(entries.get("nodes"), "QUEUE_NODES_INVALID")
        page = _obj(entries.get("pageInfo"), "QUEUE_PAGE_INVALID")
        if total != len(nodes) or page.get("hasNextPage") is not False:
            raise C8Phase2Unverifiable("QUEUE_PAGINATION_INCOMPLETE")
        if total > 0:
            raise C8Phase2Blocked("QUEUE_NOT_EMPTY_OR_PAGED")
        facts = MergeQueueConfiguration(1, maximum_build, "SQUASH", "ALLGREEN", total, "")
        digest = canonical_digest(
            {
                "maximum_entries_to_merge": 1,
                "maximum_entries_to_build": maximum_build,
                "merge_method": "SQUASH",
                "merging_strategy": "ALLGREEN",
                "total_count": total,
            }
        )
        return MergeQueueConfiguration(
            facts.maximum_entries_to_merge,
            facts.maximum_entries_to_build,
            facts.merge_method,
            facts.merging_strategy,
            facts.total_count,
            digest,
        )
    except C8Phase2Error:
        raise
    except Exception:
        raise C8Phase2Unverifiable("QUEUE_MALFORMED") from None


def parse_required_checks(configuration: JsonValue) -> RequiredChecksConfiguration:
    """Parse required context/App pairs; this is configuration, never issuer proof."""
    try:
        obj = _obj(configuration, "CHECKS_MALFORMED")
        required = _field(obj, "required_status_checks", "requiredStatusChecks")
        required_obj = _obj(required, "CHECKS_MISSING")
        if required_obj.get("strict") is not True:
            raise C8Phase2Blocked("CHECKS_NOT_STRICT")
        raw = required_obj.get("checks")
        configured_contexts = required_obj.get("contexts")
        context_list = _list(configured_contexts, "CHECKS_CONTEXTS_MISSING")
        if not context_list or any(not isinstance(c, str) or not c for c in context_list):
            raise C8Phase2Unverifiable("CHECKS_CONTEXTS_INVALID")
        if len(set(context_list)) != len(context_list):
            raise C8Phase2Blocked("CHECKS_CONTEXTS_DUPLICATE")
        values = _list(raw, "CHECKS_MISSING")
        pairs: list[tuple[str, int]] = []
        for value in values:
            item = _obj(value, "CHECKS_ENTRY_INVALID")
            context = _field(item, "context", "name")
            app = _field(item, "app_id", "appId")
            if (
                not isinstance(context, str)
                or not context
                or app is None
                or isinstance(app, bool)
                or not isinstance(app, int)
            ):
                raise C8Phase2Unverifiable("CHECKS_ENTRY_INCOMPLETE")
            pairs.append((context, app))
        if len({context for context, _app in pairs}) != len(pairs):
            raise C8Phase2Blocked("CHECKS_DUPLICATE")
        releases = [context for context, _app in pairs if context == "avo-main-release"]
        if len(releases) != 1 or dict(pairs)["avo-main-release"] == 15368:
            raise C8Phase2Blocked("CHECKS_RELEASE_INVALID")
        validation = tuple(sorted(context for context, app in pairs if app == 15368))
        expected_validation = {"validate (ubuntu-latest)", "validate (windows-latest)"}
        if set(validation) != expected_validation:
            raise C8Phase2Blocked("CHECKS_VALIDATION_APP_MISSING")
        if {context for context, _app in pairs} != expected_validation | {"avo-main-release"}:
            raise C8Phase2Blocked("CHECKS_CONTEXT_SET_INVALID")
        if set(context_list) != {context for context, _app in pairs}:
            raise C8Phase2Blocked("CHECKS_CONTEXT_SET_INVALID")
        digest = canonical_digest(
            {
                "contexts": sorted(pairs),
                "validation_contexts": validation,
                "release_context": "avo-main-release",
            }
        )
        return RequiredChecksConfiguration(
            tuple(sorted(pairs)), validation, "avo-main-release", digest
        )
    except C8Phase2Error:
        raise
    except Exception:
        raise C8Phase2Unverifiable("CHECKS_MALFORMED") from None


# Descriptive aliases keep the adapter seam stable while its transport naming
# evolves.
parse_rules = parse_effective_main_rules
parse_merge_queue = parse_merge_queue_configuration
parse_branch_protection_checks = parse_required_checks


__all__ = [
    "C8Phase2Blocked",
    "C8Phase2Unverifiable",
    "EffectiveMainRules",
    "MergeQueueConfiguration",
    "RequiredChecksConfiguration",
    "parse_branch_protection_checks",
    "parse_effective_main_rules",
    "parse_merge_queue",
    "parse_merge_queue_configuration",
    "parse_required_checks",
    "parse_rules",
]
