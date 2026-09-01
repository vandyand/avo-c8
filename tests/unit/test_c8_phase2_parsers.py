# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownParameterType=false, reportUnknownLambdaType=false, reportMissingParameterType=false, reportIndexIssue=false
from __future__ import annotations

from typing import Any

import pytest

from avo_correlate.adapters.hosted_git.c8_phase2 import (
    C8Phase2Blocked,
    C8Phase2Unverifiable,
    parse_effective_main_rules,
    parse_merge_queue_configuration,
    parse_required_checks,
)


def rules(*items: dict[str, object]) -> list[dict[str, object]]:
    return list(items)


def rule(kind: str = "merge_queue", ident: int = 1) -> dict[str, object]:
    return {
        "source_type": "Repository",
        "source": "repo",
        "id": ident,
        "rules": [{"type": kind, "parameters": {}}],
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
    }


def effective(*items: tuple[str, int, str]) -> list[dict[str, object]]:
    return [
        {
            "ruleset_source_type": source.title(),
            "ruleset_source": "repo" if source == "repository" else "org",
            "ruleset_id": ident,
            "type": kind,
            "parameters": {},
        }
        for source, ident, kind in items
    ]


def test_rules_are_sanitized_and_digest_deterministic() -> None:
    first = parse_effective_main_rules(
        effective(("repository", 1, "merge_queue"), ("organization", 2, "pull_request")),
        rules(rule()),
        [{**rule("pull_request", 2), "source_type": "Organization", "source": "org"}],
    )
    second = parse_effective_main_rules(
        effective(("repository", 1, "merge_queue"), ("organization", 2, "pull_request")),
        rules(rule()),
        [{**rule("pull_request", 2), "source_type": "Organization", "source": "org"}],
    )
    assert first == second
    assert first.entries == (("Organization", 2, "pull_request"), ("Repository", 1, "merge_queue"))
    assert "secret" not in repr(first)


@pytest.mark.parametrize(
    "mutation, code",
    [
        (lambda x: x.update(enforcement="inactive"), "RULES_INACTIVE"),
        (lambda x: x.update(bypass_actors=[1]), "RULES_BYPASS"),
    ],
)
def test_rules_reject_invalid_configuration(mutation, code: str) -> None:
    item = rule()
    mutation(item)
    with pytest.raises(C8Phase2Blocked, match=code):
        parse_effective_main_rules(
            effective(("repository", 1, "merge_queue")), rules(item), rules()
        )


def test_queue_requires_empty_unpaged_entries() -> None:
    payload = {
        "data": {
            "repository": {
                "mergeQueue": {
                    "configuration": {
                        "maximumEntriesToMerge": 1,
                        "maximumEntriesToBuild": 1,
                        "mergeMethod": "SQUASH",
                        "mergingStrategy": "ALLGREEN",
                    },
                    "entries": {"totalCount": 0, "nodes": [], "pageInfo": {"hasNextPage": False}},
                }
            }
        }
    }
    assert parse_merge_queue_configuration(payload).digest.startswith("sha256:")


def test_queue_errors_are_unverifiable_and_absence_blocked() -> None:
    with pytest.raises(C8Phase2Unverifiable, match="QUEUE_GRAPHQL_ERRORS"):
        parse_merge_queue_configuration({"errors": [{"message": "secret"}]})
    with pytest.raises(C8Phase2Blocked, match="QUEUE_ABSENT"):
        parse_merge_queue_configuration({"data": {"repository": {"mergeQueue": None}}})


def test_checks_require_two_validation_contexts_and_distinct_release_app() -> None:
    value = {
        "required_status_checks": {
            "strict": True,
            "contexts": [
                "validate (ubuntu-latest)",
                "validate (windows-latest)",
                "avo-main-release",
            ],
            "checks": [
                {"context": "validate (ubuntu-latest)", "app_id": 15368},
                {"context": "validate (windows-latest)", "app_id": 15368},
                {"context": "avo-main-release", "app_id": 42},
            ],
        }
    }
    result = parse_required_checks(value)
    assert result.release_context == "avo-main-release"
    with pytest.raises(C8Phase2Blocked, match="CHECKS_RELEASE_INVALID"):
        parse_required_checks(
            {
                "required_status_checks": {
                    "strict": True,
                    "contexts": value["required_status_checks"]["contexts"],
                    "checks": [
                        *value["required_status_checks"]["checks"][:-1],
                        {"context": "avo-main-release", "app_id": 15368},
                    ],
                }
            }
        )


@pytest.mark.parametrize(
    ("effective_item", "code"),
    [
        (("other", 1, "merge_queue"), "RULES_SOURCE_MISMATCH"),
        (("repository", 9, "merge_queue"), "RULES_RESOLUTION_INCOMPLETE"),
    ],
)
def test_rules_cross_bind_source_and_id(effective_item: tuple[str, int, str], code: str) -> None:
    with pytest.raises((C8Phase2Blocked, C8Phase2Unverifiable), match=code):
        parse_effective_main_rules(effective(effective_item), rules(rule()), rules())


def test_rules_duplicate_oversized_and_queue_cardinality() -> None:
    duplicate = effective(("repository", 1, "merge_queue"), ("repository", 1, "merge_queue"))
    with pytest.raises(C8Phase2Blocked, match="RULES_DUPLICATE_ENTRY"):
        parse_effective_main_rules(duplicate, rules(rule()), rules())
    oversized = effective(*[("repository", i, "merge_queue") for i in range(101)])
    with pytest.raises(C8Phase2Blocked, match="RULES_TOO_MANY_ENTRIES"):
        parse_effective_main_rules(oversized, rules(), rules())


@pytest.mark.parametrize(
    "bad",
    [
        {"totalCount": 1, "nodes": [], "pageInfo": {"hasNextPage": False}},
        {"totalCount": 0, "nodes": [{}], "pageInfo": {"hasNextPage": False}},
        {"totalCount": 0, "nodes": [], "pageInfo": {"hasNextPage": True}},
    ],
)
def test_queue_count_nodes_and_page_are_consistent(bad: dict[str, Any]) -> None:
    payload = {
        "data": {
            "repository": {
                "mergeQueue": {
                    "configuration": {
                        "maximumEntriesToMerge": 1,
                        "maximumEntriesToBuild": 1,
                        "mergeMethod": "SQUASH",
                        "mergingStrategy": "ALLGREEN",
                    },
                    "entries": bad,
                }
            }
        }
    }
    with pytest.raises(C8Phase2Unverifiable, match="QUEUE_PAGINATION_INCOMPLETE"):
        parse_merge_queue_configuration(payload)


@pytest.mark.parametrize(
    "entry",
    [
        {"context": None, "app_id": 15368},
        {"context": "x", "app_id": True},
        {"context": "x", "app_id": "15368"},
    ],
)
def test_checks_reject_incomplete_or_wrong_types(entry: dict[str, Any]) -> None:
    with pytest.raises(C8Phase2Unverifiable):
        parse_required_checks({"required_status_checks": {"strict": True, "checks": [entry]}})


def test_rules_conditions_fail_closed_for_main_exclusion_and_wildcard() -> None:
    base = rule()
    base["conditions"] = {
        "ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": ["refs/heads/main"]}
    }
    with pytest.raises(C8Phase2Blocked, match="RULES_EXCLUDES_MAIN"):
        parse_effective_main_rules(
            effective(("repository", 1, "merge_queue")), rules(base), rules()
        )
    base["conditions"] = {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": ["refs/heads/*"]}}
    with pytest.raises(C8Phase2Unverifiable, match="RULES_UNSUPPORTED_EXCLUSION"):
        parse_effective_main_rules(
            effective(("repository", 1, "merge_queue")), rules(base), rules()
        )


def test_rules_missing_conditions_and_malformed_extra_detail_fail_closed() -> None:
    base = rule()
    del base["conditions"]
    with pytest.raises(C8Phase2Unverifiable, match="RULES_CONDITIONS_MISSING"):
        parse_effective_main_rules(
            effective(("repository", 1, "merge_queue")), rules(base), rules()
        )
    with pytest.raises(C8Phase2Unverifiable, match="RULES_RESOLUTION_INCOMPLETE"):
        parse_effective_main_rules(
            effective(("repository", 1, "merge_queue")), rules(rule()), rules({"id": "bad"})
        )


def test_rules_resolved_rule_set_detects_extra_missing_and_parameter_drift() -> None:
    effective_value = effective(("repository", 1, "merge_queue"))
    extra = rule()
    extra["rules"] = [
        {"type": "merge_queue", "parameters": {}},
        {"type": "pull_request", "parameters": {}},
    ]
    with pytest.raises(C8Phase2Blocked, match="RULES_RULE_SET_MISMATCH"):
        parse_effective_main_rules(effective_value, rules(extra), rules())
    drift = rule()
    drift["rules"] = [{"type": "merge_queue", "parameters": {"strict": True}}]
    with pytest.raises(C8Phase2Blocked, match="RULES_RULE_SET_MISMATCH"):
        parse_effective_main_rules(effective_value, rules(drift), rules())


def test_rules_duplicate_resolved_identity_is_rejected() -> None:
    detail = rule()
    with pytest.raises(C8Phase2Blocked, match="RULES_DUPLICATE_IDENTITY"):
        parse_effective_main_rules(
            effective(("repository", 1, "merge_queue")), rules(detail, dict(detail)), rules()
        )
