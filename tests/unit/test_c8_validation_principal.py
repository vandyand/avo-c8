from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from avo_correlate.adapters.hosted_git import (
    C8Phase2Unverifiable,
    C8ValidationPrincipalBlocked,
    parse_validation_principal_check_runs,
)

SHA = "a" * 40
OBSERVED = datetime(2026, 1, 1, 0, 5, tzinfo=UTC)
CUTOFF = OBSERVED - timedelta(minutes=5)
CONTEXTS = ["validate (ubuntu-latest)", "validate (windows-latest)"]


def run(run_id: int, context: str, **changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "id": run_id,
        "name": context,
        "head_sha": SHA,
        "status": "completed",
        "conclusion": "success",
        "completed_at": "2026-01-01T00:00:00+00:00",
        "app": {"id": 15368, "slug": "github-actions", "name": "GitHub Actions"},
    }
    value.update(changes)
    return value


def pages(*runs: dict[str, Any], total_count: int | None = None) -> list[dict[str, Any]]:
    return [
        {
            "total_count": len(runs) if total_count is None else total_count,
            "check_runs": list(runs),
        }
    ]


def parse(payloads: list[dict[str, Any]]) -> Any:
    return parse_validation_principal_check_runs(
        payloads, SHA, CONTEXTS, OBSERVED, CUTOFF
    )


def test_verified_evidence_is_sanitized_and_digest_binds_run_ids() -> None:
    payload = pages(
        run(101, CONTEXTS[0], html_url="https://secret.invalid", output={"text": "secret"}),
        run(102, CONTEXTS[1]),
    )
    before = deepcopy(payload)
    result = parse(payload)
    assert payload == before
    assert result.outcome == "verified"
    assert result.contexts == tuple(sorted(CONTEXTS))
    assert [item.run_id for item in result.identities] == [101, 102]
    assert result.identity_digest.startswith("sha256:")
    assert "secret" not in repr(result)
    assert parse(deepcopy(payload)).identity_digest == result.identity_digest
    changed = deepcopy(payload)
    changed[0]["check_runs"][0]["id"] = 999
    assert parse(changed).identity_digest != result.identity_digest


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"total_count": 1001}, "VALIDATION_TOTAL_COUNT_INVALID"),
        ({"total_count": 2, "check_runs": [run(1, CONTEXTS[0])]}, "VALIDATION_PAGE_CARDINALITY"),
        (
            {"total_count": 2, "check_runs": [run(1, CONTEXTS[0]), run(1, CONTEXTS[1])]},
            "VALIDATION_DUPLICATE_RUN_ID",
        ),
    ],
)
def test_pagination_and_run_identity_are_bounded(change: dict[str, Any], code: str) -> None:
    payload = pages(run(1, CONTEXTS[0]), run(2, CONTEXTS[1]))
    payload[0].update(change)
    with pytest.raises(C8Phase2Unverifiable, match=code):
        parse(payload)


def test_pagination_requires_exact_pages_and_rejects_extra_pages() -> None:
    first = [run(i, f"other-{i}") for i in range(1, 101)]
    second = [run(101, CONTEXTS[0]), run(102, CONTEXTS[1])]
    assert parse(
        [
            {"total_count": 102, "check_runs": first},
            {"total_count": 102, "check_runs": second},
        ]
    ).outcome == "verified"
    with pytest.raises(C8Phase2Unverifiable, match="VALIDATION_PAGINATION_INCOMPLETE"):
        parse([{"total_count": 102, "check_runs": first}])
    with pytest.raises(C8Phase2Unverifiable, match="VALIDATION_PAGINATION_EXTRA"):
        parse(
            [
                {"total_count": 2, "check_runs": [run(1, CONTEXTS[0]), run(2, CONTEXTS[1])]},
                {"total_count": 2, "check_runs": []},
            ]
        )
    with pytest.raises(C8Phase2Unverifiable, match="VALIDATION_PAGINATION_OVERSIZED"):
        parse([{"total_count": 0, "check_runs": []}] * 11)


def test_unrelated_in_progress_run_needs_only_page_identity_fields() -> None:
    unrelated = {"id": 103, "name": "build (unrelated)", "head_sha": SHA}
    result = parse(pages(run(1, CONTEXTS[0]), run(2, CONTEXTS[1]), unrelated))
    assert result.outcome == "verified"
    assert [item.run_id for item in result.identities] == [1, 2]


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ({"head_sha": "b" * 40}, C8Phase2Unverifiable),
        ({"app": {"id": 15368, "slug": "unknown", "name": "GitHub Actions"}}, C8Phase2Unverifiable),
        ({"completed_at": "2025-12-31T23:59:59+00:00"}, C8Phase2Unverifiable),
        ({"completed_at": "2026-01-01T00:06:00+00:00"}, C8Phase2Unverifiable),
    ],
)
def test_unverifiable_identity_facts_fail_closed(
    change: dict[str, Any], error: type[Exception]
) -> None:
    value = pages(run(1, CONTEXTS[0]), run(2, CONTEXTS[1]))
    value[0]["check_runs"][0].update(change)
    with pytest.raises(error):
        parse(value)


@pytest.mark.parametrize(
    "change",
    [
        {"app": {"id": 42, "slug": "other", "name": "Other"}},
        {"status": "completed", "conclusion": "failure"},
        {"status": "completed", "conclusion": "cancelled"},
    ],
)
def test_conclusive_blockers_are_typed(change: dict[str, Any]) -> None:
    value = pages(run(1, CONTEXTS[0]), run(2, CONTEXTS[1]))
    value[0]["check_runs"][0].update(change)
    with pytest.raises(C8ValidationPrincipalBlocked) as caught:
        parse(value)
    assert caught.value.records[0].run_id == 1
    assert caught.value.records[0].context == CONTEXTS[0]
    assert "secret" not in repr(caught.value)


def test_duplicate_expected_context_is_blocked_but_absent_is_unverifiable() -> None:
    with pytest.raises(
        C8ValidationPrincipalBlocked, match="VALIDATION_DUPLICATE_CONTEXT"
    ) as caught:
        parse(pages(run(1, CONTEXTS[0]), run(2, CONTEXTS[0]), run(3, CONTEXTS[1])))
    assert [item.run_id for item in caught.value.records] == [1, 2, 3]
    with pytest.raises(C8Phase2Unverifiable, match="VALIDATION_CONTEXT_ABSENT"):
        parse(pages(run(1, CONTEXTS[0])))


def test_malformed_secret_errors_have_no_exception_context() -> None:
    class Hostile(dict[str, Any]):
        def get(self, key: str, default: Any = None) -> Any:
            raise RuntimeError("token-secret-canary")

    with pytest.raises(C8Phase2Unverifiable) as caught:
        parse([Hostile()])
    assert str(caught.value) == "VALIDATION_MALFORMED"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "token-secret-canary" not in repr(caught.value)
