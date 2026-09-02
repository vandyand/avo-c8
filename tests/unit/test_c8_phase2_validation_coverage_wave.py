# pyright: reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUntypedFunctionDecorator=false, reportArgumentType=false
"""Adversarial coverage for the authenticated C8 validation-principal parser.

These tests model already-authenticated REST pages.  They deliberately keep
the parser pure and assert that malformed, stale, incomplete, and terminally
wrong observations never become a successful validation identity.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

import avo_correlate.adapters.hosted_git.c8_phase2 as module
from tests.unit.test_c8_phase2_parsers import effective, rule, rules

SHA = "a" * 40
CONTEXTS = ["validate (ubuntu-latest)", "validate (windows-latest)"]
OBSERVED = datetime(2026, 1, 1, 12, tzinfo=UTC)
CUTOFF = OBSERVED - timedelta(hours=1)


def _run(
    context: str,
    run_id: int,
    *,
    app_id: int = 15368,
    app_slug: str = "github-actions",
    app_name: str = "GitHub Actions",
    head_sha: str = SHA,
    status: str = "completed",
    conclusion: str | None = "success",
    completed_at: str = "2026-01-01T11:30:00+00:00",
) -> dict[str, Any]:
    return {
        "id": run_id,
        "name": context,
        "head_sha": head_sha,
        "status": status,
        "conclusion": conclusion,
        "completed_at": completed_at,
        "app": {"id": app_id, "slug": app_slug, "name": app_name},
    }


def _pages(*runs: dict[str, Any], total_count: int | None = None) -> list[dict[str, Any]]:
    return [
        {"total_count": len(runs) if total_count is None else total_count, "check_runs": list(runs)}
    ]


def _parse(pages: Any, *, contexts: Any = CONTEXTS, observed: Any = OBSERVED, cutoff: Any = CUTOFF):
    return module.parse_validation_principal_check_runs(pages, SHA, contexts, observed, cutoff)


def test_validation_parser_accepts_complete_pages_and_sanitizes_identity() -> None:
    evidence = _parse(_pages(*(_run(context, index) for index, context in enumerate(CONTEXTS, 1))))

    assert evidence.contexts == tuple(CONTEXTS)
    assert [item.context for item in evidence.identities] == sorted(CONTEXTS)
    assert all(item.app_id == 15368 for item in evidence.identities)
    assert evidence.identity_digest.startswith("sha256:")
    assert evidence.outcome == "verified"
    assert evidence.identities[0].canonical()["context"] == evidence.identities[0].context
    assert "url" not in repr(evidence)


@pytest.mark.parametrize(
    ("pages", "code"),
    [
        (None, "VALIDATION_PAGINATION_INCOMPLETE"),
        ([], "VALIDATION_PAGINATION_INCOMPLETE"),
        ([{}] * 11, "VALIDATION_PAGINATION_OVERSIZED"),
        (["not-a-page"], "VALIDATION_PAGE_MALFORMED"),
        ([{"total_count": -1, "check_runs": []}], "VALIDATION_TOTAL_COUNT_INVALID"),
        ([{"total_count": 1001, "check_runs": []}], "VALIDATION_TOTAL_COUNT_INVALID"),
        ([{"total_count": "2", "check_runs": []}], "VALIDATION_TOTAL_COUNT_INVALID"),
        ([{"total_count": 2, "check_runs": []}], "VALIDATION_PAGE_CARDINALITY"),
        ([{"total_count": 0, "check_runs": [{}]}], "VALIDATION_PAGE_CARDINALITY"),
    ],
)
def test_validation_parser_rejects_pagination_and_page_shape(pages: Any, code: str) -> None:
    with pytest.raises(module.C8Phase2Unverifiable, match=code):
        _parse(pages)


def test_validation_parser_rejects_changed_total_count_across_pages() -> None:
    first_page = [_run(CONTEXTS[0], index) for index in range(1, 101)]
    with pytest.raises(module.C8Phase2Unverifiable, match="VALIDATION_TOTAL_COUNT_CHANGED"):
        _parse(
            [
                {"total_count": 101, "check_runs": first_page},
                {"total_count": 102, "check_runs": [_run(CONTEXTS[1], 101)]},
            ]
        )


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (lambda page: page.update(total_count=1), "VALIDATION_PAGE_CARDINALITY"),
        (
            lambda page: page["check_runs"].append(_run(CONTEXTS[0], 3)),
            "VALIDATION_PAGE_CARDINALITY",
        ),
        (lambda page: page["check_runs"].__setitem__(0, "bad"), "VALIDATION_RUN_MALFORMED"),
        (lambda page: page["check_runs"][0].update(id=0), "VALIDATION_RUN_ID_INVALID"),
        (lambda page: page["check_runs"][1].update(id=1), "VALIDATION_DUPLICATE_RUN_ID"),
        (lambda page: page["check_runs"][0].update(name=""), "VALIDATION_RUN_INCOMPLETE"),
        (lambda page: page["check_runs"][0].update(head_sha="b" * 40), "VALIDATION_WRONG_SHA"),
        (lambda page: page["check_runs"][0].update(status=None), "VALIDATION_RUN_INCOMPLETE"),
        (lambda page: page["check_runs"][0].update(conclusion=3), "VALIDATION_RUN_INCOMPLETE"),
        (lambda page: page["check_runs"][0].update(completed_at=None), "VALIDATION_RUN_INCOMPLETE"),
        (
            lambda page: page["check_runs"][0].update(completed_at="not-a-time"),
            "VALIDATION_TIMESTAMP_INVALID",
        ),
        (
            lambda page: page["check_runs"][0].update(completed_at="2026-01-01T10:00:00+00:00"),
            "VALIDATION_TIMESTAMP_STALE",
        ),
        (
            lambda page: page["check_runs"][0].update(completed_at="2026-01-01T13:00:00+00:00"),
            "VALIDATION_TIMESTAMP_FUTURE",
        ),
        (lambda page: page["check_runs"][0].update(app=None), "VALIDATION_APP_METADATA_UNKNOWN"),
        (
            lambda page: page["check_runs"][0]["app"].update(id=True),
            "VALIDATION_APP_METADATA_UNKNOWN",
        ),
        (
            lambda page: page["check_runs"][0]["app"].update(slug=3),
            "VALIDATION_APP_METADATA_UNKNOWN",
        ),
    ],
)
def test_validation_parser_rejects_tampered_run_fields(mutator: Any, code: str) -> None:
    pages = _pages(*(_run(context, index) for index, context in enumerate(CONTEXTS, 1)))
    mutator(pages[0])
    with pytest.raises(module.C8Phase2Unverifiable, match=code):
        _parse(pages)


def test_validation_parser_requires_all_expected_contexts_and_no_extra_page() -> None:
    first = _run(CONTEXTS[0], 1)
    second = _run(CONTEXTS[1], 2)
    with pytest.raises(module.C8Phase2Unverifiable, match="VALIDATION_CONTEXT_ABSENT"):
        _parse(_pages(first), contexts=CONTEXTS)

    complete = _pages(first, second)
    with pytest.raises(module.C8Phase2Unverifiable, match="VALIDATION_PAGINATION_EXTRA"):
        _parse([*complete, {"total_count": 2, "check_runs": []}])


@pytest.mark.parametrize(
    ("contexts", "code"),
    [
        ("not-a-list", "VALIDATION_CONTEXTS_INVALID"),
        ([], "VALIDATION_CONTEXTS_INVALID"),
        ([""], "VALIDATION_CONTEXTS_INVALID"),
        ([CONTEXTS[0], CONTEXTS[0]], "VALIDATION_CONTEXTS_INVALID"),
        ([CONTEXTS[0], 3], "VALIDATION_CONTEXTS_INVALID"),
    ],
)
def test_validation_parser_rejects_invalid_context_configuration(contexts: Any, code: str) -> None:
    with pytest.raises(module.C8Phase2Unverifiable, match=code):
        _parse(
            _pages(*(_run(context, index) for index, context in enumerate(CONTEXTS, 1))),
            contexts=contexts,
        )


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"pinned": "not-a-sha"}, "VALIDATION_SHA_INVALID"),
        ({"observed": datetime(2026, 1, 1, 12)}, "VALIDATION_TIMESTAMP_INVALID"),
        ({"cutoff": OBSERVED + timedelta(seconds=1)}, "VALIDATION_TIMESTAMP_INVALID"),
    ],
)
def test_validation_parser_rejects_invalid_snapshot_window(
    kwargs: dict[str, Any], code: str
) -> None:
    pages = _pages(*(_run(context, index) for index, context in enumerate(CONTEXTS, 1)))
    if "pinned" in kwargs:
        with pytest.raises(module.C8Phase2Unverifiable, match=code):
            module.parse_validation_principal_check_runs(
                pages, kwargs["pinned"], CONTEXTS, OBSERVED, CUTOFF
            )
    else:
        with pytest.raises(module.C8Phase2Unverifiable, match=code):
            _parse(
                pages,
                observed=kwargs.get("observed", OBSERVED),
                cutoff=kwargs.get("cutoff", CUTOFF),
            )


def test_validation_parser_blocks_terminal_wrong_app_and_nonsuccess() -> None:
    wrong_app = _pages(_run(CONTEXTS[0], 1, app_id=42), _run(CONTEXTS[1], 2))
    with pytest.raises(
        module.C8ValidationPrincipalBlocked, match="VALIDATION_TERMINAL_NONSUCCESS"
    ) as caught:
        _parse(wrong_app)
    assert len(caught.value.records) == 2
    assert all(record.app_id in {42, 15368} for record in caught.value.records)
    assert caught.value.records[0].canonical()["run_id"] == caught.value.records[0].run_id

    failed = _pages(_run(CONTEXTS[0], 1, conclusion="failure"), _run(CONTEXTS[1], 2))
    with pytest.raises(module.C8ValidationPrincipalBlocked, match="VALIDATION_TERMINAL_NONSUCCESS"):
        _parse(failed)


def test_validation_parser_rejects_duplicate_expected_context_and_unknown_identity() -> None:
    duplicate = _pages(
        _run(CONTEXTS[0], 1),
        _run(CONTEXTS[0], 2),
        _run(CONTEXTS[1], 3),
        total_count=3,
    )
    with pytest.raises(
        module.C8ValidationPrincipalBlocked, match="VALIDATION_DUPLICATE_CONTEXT"
    ) as caught:
        _parse(duplicate)
    assert len(caught.value.records) == 3

    unknown_app = _pages(_run(CONTEXTS[0], 1, app_slug="other"), _run(CONTEXTS[1], 2))
    with pytest.raises(module.C8Phase2Unverifiable, match="VALIDATION_APP_METADATA_UNKNOWN"):
        _parse(unknown_app)


def test_validation_parser_ignores_unrelated_in_progress_run_but_checks_pagination() -> None:
    unrelated = _run("unrelated", 9, status="queued", conclusion=None, completed_at="")
    evidence = _parse(
        _pages(*(_run(context, index) for index, context in enumerate(CONTEXTS, 1)), unrelated)
    )
    assert len(evidence.identities) == 2


def test_freshness_revalidation_accepts_identity_and_rejects_stale_or_future() -> None:
    evidence = _parse(_pages(*(_run(context, index) for index, context in enumerate(CONTEXTS, 1))))
    assert module.revalidate_validation_principal_freshness(evidence, OBSERVED, CUTOFF) == evidence

    stale = replace(
        evidence,
        identities=tuple(
            replace(identity, completed_at="2026-01-01T10:00:00+00:00")
            for identity in evidence.identities
        ),
    )
    with pytest.raises(module.C8Phase2Unverifiable, match="VALIDATION_TIMESTAMP_STALE"):
        module.revalidate_validation_principal_freshness(stale, OBSERVED, CUTOFF)

    future = replace(
        evidence,
        identities=tuple(
            replace(identity, completed_at="2026-01-01T13:00:00+00:00")
            for identity in evidence.identities
        ),
    )
    with pytest.raises(module.C8Phase2Unverifiable, match="VALIDATION_TIMESTAMP_FUTURE"):
        module.revalidate_validation_principal_freshness(future, OBSERVED, CUTOFF)

    with pytest.raises(module.C8Phase2Unverifiable, match="VALIDATION_TIMESTAMP_INVALID"):
        module.revalidate_validation_principal_freshness(evidence, datetime(2026, 1, 1), CUTOFF)


def _queue_response(
    *, config: dict[str, Any] | None = None, entries: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "data": {
            "repository": {
                "mergeQueue": {
                    "configuration": config
                    if config is not None
                    else {
                        "maximumEntriesToMerge": 1,
                        "maximumEntriesToBuild": 2,
                        "mergeMethod": "SQUASH",
                        "mergingStrategy": "ALLGREEN",
                    },
                    "entries": entries
                    if entries is not None
                    else {"totalCount": 0, "nodes": [], "pageInfo": {"hasNextPage": False}},
                }
            }
        }
    }


@pytest.mark.parametrize(
    ("response", "exception", "code"),
    [
        (None, module.C8Phase2Unverifiable, "QUEUE_MALFORMED"),
        ({"data": None}, module.C8Phase2Unverifiable, "QUEUE_DATA_MISSING"),
        ({"data": {"repository": None}}, module.C8Phase2Unverifiable, "QUEUE_REPOSITORY_MISSING"),
        (_queue_response(config={}), module.C8Phase2Unverifiable, "QUEUE_CONFIG_INCOMPLETE"),
        (
            _queue_response(
                config={
                    "maximumEntriesToMerge": 2,
                    "maximumEntriesToBuild": 1,
                    "mergeMethod": "SQUASH",
                    "mergingStrategy": "ALLGREEN",
                }
            ),
            module.C8Phase2Blocked,
            "QUEUE_CONFIG_INVALID",
        ),
        (
            _queue_response(
                config={
                    "maximumEntriesToMerge": 1,
                    "maximumEntriesToBuild": 1,
                    "mergeMethod": "MERGE",
                    "mergingStrategy": "ALLGREEN",
                }
            ),
            module.C8Phase2Blocked,
            "QUEUE_CONFIG_INVALID",
        ),
        (
            _queue_response(
                entries={"totalCount": "0", "nodes": [], "pageInfo": {"hasNextPage": False}}
            ),
            module.C8Phase2Unverifiable,
            "QUEUE_COUNT_INVALID",
        ),
        (
            _queue_response(
                entries={"totalCount": 0, "nodes": {}, "pageInfo": {"hasNextPage": False}}
            ),
            module.C8Phase2Unverifiable,
            "QUEUE_NODES_INVALID",
        ),
        (
            _queue_response(entries={"totalCount": 0, "nodes": [], "pageInfo": None}),
            module.C8Phase2Unverifiable,
            "QUEUE_PAGE_INVALID",
        ),
        (
            _queue_response(
                entries={"totalCount": 1, "nodes": [{}], "pageInfo": {"hasNextPage": False}}
            ),
            module.C8Phase2Blocked,
            "QUEUE_NOT_EMPTY_OR_PAGED",
        ),
        (
            _queue_response(
                entries={"totalCount": 0, "nodes": [], "pageInfo": {"hasNextPage": True}}
            ),
            module.C8Phase2Unverifiable,
            "QUEUE_PAGINATION_INCOMPLETE",
        ),
    ],
)
def test_queue_parser_rejects_malformed_or_unsafe_configuration(
    response: Any, exception: type[Exception], code: str
) -> None:
    with pytest.raises(exception, match=code):
        module.parse_merge_queue_configuration(response)


def _required_checks(
    *,
    strict: Any = True,
    contexts: list[Any] | None = None,
    checks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "required_status_checks": {
            "strict": strict,
            "contexts": contexts
            if contexts is not None
            else ["validate (ubuntu-latest)", "validate (windows-latest)", "avo-main-release"],
            "checks": checks
            if checks is not None
            else [
                {"context": "validate (ubuntu-latest)", "app_id": 15368},
                {"context": "validate (windows-latest)", "app_id": 15368},
                {"context": "avo-main-release", "app_id": 42},
            ],
        }
    }


@pytest.mark.parametrize(
    ("configuration", "code"),
    [
        (_required_checks(strict=False), "CHECKS_NOT_STRICT"),
        (_required_checks(contexts=[]), "CHECKS_CONTEXTS_INVALID"),
        (_required_checks(contexts=["validate (ubuntu-latest)"] * 2), "CHECKS_CONTEXTS_DUPLICATE"),
        (
            _required_checks(checks=[{"context": "validate (ubuntu-latest)"}]),
            "CHECKS_ENTRY_INCOMPLETE",
        ),
        (
            _required_checks(checks=[{"context": "validate (ubuntu-latest)", "app_id": 15368}] * 2),
            "CHECKS_DUPLICATE",
        ),
        (
            _required_checks(
                checks=[
                    {"context": "validate (ubuntu-latest)", "app_id": 15368},
                    {"context": "validate (windows-latest)", "app_id": 15368},
                    {"context": "avo-main-release", "app_id": 15368},
                ]
            ),
            "CHECKS_RELEASE_INVALID",
        ),
        (
            _required_checks(
                checks=[
                    {"context": "validate (ubuntu-latest)", "app_id": 42},
                    {"context": "validate (windows-latest)", "app_id": 15368},
                    {"context": "avo-main-release", "app_id": 42},
                ]
            ),
            "CHECKS_VALIDATION_APP_MISSING",
        ),
        (
            _required_checks(
                contexts=["validate (ubuntu-latest)", "validate (windows-latest)", "unexpected"]
            ),
            "CHECKS_CONTEXT_SET_INVALID",
        ),
    ],
)
def test_required_checks_parser_rejects_invalid_policy_shapes(
    configuration: dict[str, Any], code: str
) -> None:
    with pytest.raises((module.C8Phase2Blocked, module.C8Phase2Unverifiable), match=code):
        module.parse_required_checks(configuration)


def test_required_checks_parser_rejects_unexpected_check_context() -> None:
    configuration = _required_checks(
        contexts=["validate (ubuntu-latest)", "validate (windows-latest)", "unexpected"],
        checks=[
            {"context": "validate (ubuntu-latest)", "app_id": 15368},
            {"context": "validate (windows-latest)", "app_id": 15368},
            {"context": "avo-main-release", "app_id": 42},
            {"context": "unexpected", "app_id": 42},
        ],
    )
    with pytest.raises(module.C8Phase2Blocked, match="CHECKS_CONTEXT_SET_INVALID"):
        module.parse_required_checks(configuration)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (
            lambda item: item["conditions"]["ref_name"].update(include=["refs/heads/dev"]),
            "RULES_UNSUPPORTED_BRANCH_PATTERN",
        ),
        (
            lambda item: item["conditions"]["ref_name"].update(
                include=["~DEFAULT_BRANCH", "~DEFAULT_BRANCH"]
            ),
            "RULES_CONDITIONS_DUPLICATE",
        ),
        (
            lambda item: item["conditions"]["ref_name"].update(include=[3]),
            "RULES_CONDITIONS_INVALID",
        ),
        (
            lambda item: item["conditions"]["ref_name"].update(exclude=["~ALL"]),
            "RULES_EXCLUDES_MAIN",
        ),
        (
            lambda item: item["conditions"]["ref_name"].update(exclude=["refs/heads/release"]),
            "RULES_UNSUPPORTED_EXCLUSION",
        ),
        (
            lambda item: item["conditions"]["ref_name"].update(include=["~DEFAULT_BRANCH"] * 101),
            "RULES_CONDITIONS_TOO_MANY",
        ),
    ],
)
def test_rules_parser_rejects_hostile_branch_conditions(mutation: Any, code: str) -> None:
    item = rule()
    mutation(item)
    with pytest.raises((module.C8Phase2Blocked, module.C8Phase2Unverifiable), match=code):
        module.parse_effective_main_rules(
            effective(("repository", 1, "merge_queue")), rules(item), rules()
        )


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda item: item.update(enforcement=None), "RULES_ENTRY_INCOMPLETE"),
        (
            lambda item: item.update(enforcement="active", bypass_actors=None),
            "RULES_ENTRY_INCOMPLETE",
        ),
        (lambda item: item.update(enforcement="active", bypass_actors=["bot"]), "RULES_BYPASS"),
        (lambda item: item.update(enforcement="active", target="tag"), "RULES_WRONG_BRANCH"),
        (lambda item: item.pop("target"), "RULES_ENTRY_INCOMPLETE"),
        (lambda item: item.update(enforcement="active", rules=[]), "RULES_RULE_SET_MISMATCH"),
    ],
)
def test_rules_parser_rejects_unsafe_resolved_rule_facts(mutation: Any, code: str) -> None:
    item = rule()
    mutation(item)
    with pytest.raises((module.C8Phase2Blocked, module.C8Phase2Unverifiable), match=code):
        module.parse_effective_main_rules(
            effective(("repository", 1, "merge_queue")), rules(item), rules()
        )


def test_rules_parser_rejects_invalid_effective_entries_and_rule_payloads() -> None:
    with pytest.raises(module.C8Phase2Unverifiable, match="RULES_EFFECTIVE_INCOMPLETE"):
        module.parse_effective_main_rules([None], rules(), rules())
    with pytest.raises(module.C8Phase2Blocked, match="RULES_INVALID_ENTRY"):
        module.parse_effective_main_rules(
            [
                {
                    "ruleset_source_type": "Repository",
                    "ruleset_source": "repo",
                    "ruleset_id": 0,
                    "type": "merge_queue",
                    "parameters": {},
                }
            ],
            rules(rule()),
            rules(),
        )
    malformed_rule = rule()
    malformed_rule["rules"] = [{}]
    with pytest.raises(module.C8Phase2Unverifiable, match="RULES_RESOLUTION_INCOMPLETE"):
        module.parse_effective_main_rules(
            effective(("repository", 1, "merge_queue")), rules(malformed_rule), rules()
        )

    with pytest.raises(module.C8Phase2Unverifiable, match="RULES_REPOSITORY_INCOMPLETE"):
        module.parse_effective_main_rules(
            effective(("repository", 1, "merge_queue")), [None], rules()
        )

    too_many_rules = rule()
    too_many_rules["rules"] = [{"type": "merge_queue", "parameters": {}}] * 101
    with pytest.raises(module.C8Phase2Blocked, match="RULES_TOO_MANY_ENTRIES"):
        module.parse_effective_main_rules(
            effective(("repository", 1, "merge_queue")), rules(too_many_rules), rules()
        )

    too_many_repository_rules = [rule() for _ in range(101)]
    with pytest.raises(module.C8Phase2Blocked, match="RULES_TOO_MANY_ENTRIES"):
        module.parse_effective_main_rules(
            effective(("repository", 1, "merge_queue")), too_many_repository_rules, rules()
        )

    missing_parameters = rule()
    effective_item = effective(("repository", 1, "merge_queue"))[0]
    effective_item["parameters"] = None
    with pytest.raises(module.C8Phase2Unverifiable, match="RULES_ENTRY_INCOMPLETE"):
        module.parse_effective_main_rules([effective_item], rules(missing_parameters), rules())

    only_pull_request = rule("pull_request")
    with pytest.raises(module.C8Phase2Blocked, match="RULES_QUEUE_CARDINALITY"):
        module.parse_effective_main_rules(
            effective(("repository", 1, "pull_request")), rules(only_pull_request), rules()
        )

    invalid_type = effective(("repository", 1, "merge_queue"))[0]
    invalid_type["type"] = None
    with pytest.raises(module.C8Phase2Blocked, match="RULES_INVALID_ENTRY"):
        module.parse_effective_main_rules([invalid_type], rules(rule()), rules())

    extra_resolved = [rule(), {**rule("pull_request", 2), "id": 2}]
    with pytest.raises(module.C8Phase2Unverifiable, match="RULES_RESOLUTION_SET_MISMATCH"):
        module.parse_effective_main_rules(
            effective(("repository", 1, "merge_queue")), extra_resolved, rules()
        )


def test_validation_parser_rejects_naive_completion_timestamp() -> None:
    pages = _pages(
        _run(CONTEXTS[0], 1, completed_at="2026-01-01T11:30:00"),
        _run(CONTEXTS[1], 2),
    )
    with pytest.raises(module.C8Phase2Unverifiable, match="VALIDATION_TIMESTAMP_INVALID"):
        _parse(pages)


def test_freshness_revalidation_rejects_malformed_evidence() -> None:
    with pytest.raises(module.C8Phase2Unverifiable, match="VALIDATION_MALFORMED"):
        module.revalidate_validation_principal_freshness(None, OBSERVED, CUTOFF)

    evidence = _parse(_pages(*(_run(context, index) for index, context in enumerate(CONTEXTS, 1))))
    malformed = replace(
        evidence,
        identities=tuple(
            replace(identity, completed_at="not-a-time") for identity in evidence.identities
        ),
    )
    with pytest.raises(module.C8Phase2Unverifiable, match="VALIDATION_TIMESTAMP_INVALID"):
        module.revalidate_validation_principal_freshness(malformed, OBSERVED, CUTOFF)

    naive = replace(
        evidence,
        identities=tuple(
            replace(identity, completed_at="2026-01-01T11:30:00")
            for identity in evidence.identities
        ),
    )
    with pytest.raises(module.C8Phase2Unverifiable, match="VALIDATION_TIMESTAMP_INVALID"):
        module.revalidate_validation_principal_freshness(naive, OBSERVED, CUTOFF)
