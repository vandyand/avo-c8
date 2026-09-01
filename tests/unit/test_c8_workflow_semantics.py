from __future__ import annotations

from pathlib import Path

import pytest

from avo_correlate.adapters.hosted_git import (
    C8WorkflowSemanticsUnverifiable,
    parse_c8_workflow_semantics,
)

WORKFLOW = Path(".github/workflows/ci.yml").read_bytes()
CHECKOUT = "11d5960a326750d5838078e36cf38b85af677262"


def workflow(*, trigger: str = "pull_request", checkout: str = CHECKOUT) -> bytes:
    return (
        f"""name: ci
on:
  {trigger}:
  merge_group:
    types: [checks_requested]
jobs:
  validate:
    steps:
      - uses: actions/checkout@{checkout}
        with:
          ref: ${{{{ github.sha }}}}
          persist-credentials: false
"""
    ).encode()


def test_real_ci_workflow_is_supported_and_on_is_not_yaml11_boolean() -> None:
    facts = parse_c8_workflow_semantics(WORKFLOW)
    assert facts.pull_request_event
    assert facts.merge_group_event
    assert facts.exact_sha_checkout
    assert facts.checkout_persist_credentials_false
    assert facts.digest.startswith("sha256:")


@pytest.mark.parametrize(
    "content",
    [
        workflow(trigger="push"),
        workflow(checkout="a" * 39),
        workflow(checkout="A" * 40),
        workflow(checkout="v4"),
        workflow().replace(b"ref: ${{ github.sha }}", b"ref: main"),
        workflow().replace(b"persist-credentials: false", b"persist-credentials: true"),
        workflow().replace(b"persist-credentials: false", b"# omitted"),
    ],
)
def test_supported_yaml_reports_static_negative_facts(content: bytes) -> None:
    facts = parse_c8_workflow_semantics(content)
    if b"  pull_request:" not in content:
        assert not facts.pull_request_event
    if b"  merge_group:" not in content:
        assert not facts.merge_group_event
    if b"types: [checks_requested]" not in content:
        assert not facts.merge_group_event
    if b"actions/checkout@" in content and b"11d5960" not in content:
        assert not facts.exact_sha_checkout
    if b"ref: ${{ github.sha }}" not in content:
        assert not facts.exact_sha_checkout
    if b"persist-credentials: false" not in content:
        assert not facts.checkout_persist_credentials_false


def test_missing_merge_group_and_checks_requested_are_false() -> None:
    missing_merge_group = b"on: {pull_request: {}}\njobs: {build: {steps: []}}\n"
    missing_check = (
        b"on: {pull_request: {}, merge_group: {types: [other]}}\n"
        b"jobs: {build: {steps: []}}\n"
    )
    assert parse_c8_workflow_semantics(missing_merge_group).merge_group_event is False
    assert parse_c8_workflow_semantics(missing_check).merge_group_event is False


@pytest.mark.parametrize(
    "content",
    [
        workflow().replace(b"on:\n", b"on:\n  pull_request:\n  pull_request:\n"),
        workflow().replace(b"persist-credentials: false", b"persist-credentials: !!str false"),
        workflow().replace(b"on:\n", b"on: &root\n"),
        workflow().replace(b"jobs:\n", b"jobs: *root\n"),
        workflow().replace(b"with:\n", b"with:\n          1: bad\n"),
        workflow().replace(b"with:\n", b"with:\n          <<: {ref: bad}\n"),
        workflow().replace(
            b"merge_group:\n",
            b"merge_group:\n    types: [other]\n    types: [checks_requested]\n",
        ),
        workflow().replace(b"on:\n", b"---\non:\n").rstrip() + b"\n---\nname: second\n",
        b"\xff\xfe",
    ],
)
def test_malformed_or_ambiguous_workflow_is_code_only_unverifiable(content: bytes) -> None:
    with pytest.raises(C8WorkflowSemanticsUnverifiable) as error:
        parse_c8_workflow_semantics(content)
    assert "secret" not in str(error.value)
    assert "actions" not in str(error.value)


def test_reusable_or_dynamic_jobs_are_unverifiable() -> None:
    reusable = (
        b"on: {pull_request: {}}\njobs: "
        b"{build: {uses: org/reusable/.github/workflows/x.yml}}\n"
    )
    dynamic = workflow().replace(b"actions/checkout@", b"${{ matrix.action }}@")
    for content in (reusable, dynamic):
        with pytest.raises(C8WorkflowSemanticsUnverifiable):
            parse_c8_workflow_semantics(content)


def test_parser_does_not_mutate_global_yaml_resolvers() -> None:
    import yaml

    before = repr(yaml.SafeLoader.yaml_implicit_resolvers)
    parse_c8_workflow_semantics(WORKFLOW)
    assert repr(yaml.SafeLoader.yaml_implicit_resolvers) == before


def test_malformed_yaml_does_not_retain_parser_exception_context() -> None:
    with pytest.raises(C8WorkflowSemanticsUnverifiable) as error:
        parse_c8_workflow_semantics(b"on: [parser-secret-canary")
    assert str(error.value) == "WORKFLOW_MALFORMED"
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "parser-secret-canary" not in str(error.value)


@pytest.mark.parametrize(
    "content",
    [
        b"on: {pull_request: {}}\njobs: {build: {steps: [{run: echo}]}}\n",
        workflow().replace(
            b"merge_group:\n    types: [checks_requested]", b"merge_group:\n    types: [other]"
        ),
        workflow().replace(b"jobs:\n", b"jobs:\n  empty: {steps: []}\n"),
        workflow().replace(b"      - uses:", b"      - run: echo ok\n      - uses:"),
    ],
)
def test_negative_facts_are_deterministic_for_supported_shapes(content: bytes) -> None:
    facts = parse_c8_workflow_semantics(content)
    assert facts.digest.startswith("sha256:")


@pytest.mark.parametrize(
    "content",
    [
        b"on: {pull_request: {}}\njobs: {build: {steps: []}}\n",
        b"on: {pull_request: {}}\njobs: {build: {steps: [{run: echo}]}}\n",
        b"on: {pull_request: {}}\njobs: {build: {steps: [{uses: actions/checkout@v4}]}}\n",
    ],
)
def test_no_checkout_or_empty_steps_reports_false_checkout_facts(content: bytes) -> None:
    facts = parse_c8_workflow_semantics(content)
    assert facts.exact_sha_checkout is False
    assert facts.checkout_persist_credentials_false is False


@pytest.mark.parametrize(
    "content",
    [
        b"x" * 1_048_577,
        b"on: {pull_request: {}}\njobs: {build: {steps: [{run: " + b"x" * 16_385 + b"}]}}\n",
        b"on: {pull_request: {}}\njobs: {build: {steps: [" + b"{run: x}," * 501 + b"]}}\n",
        (b"a: {" * 34) + b"x: y" + (b"}" * 34),
        b"on: {pull_request: {}}\njobs: {build: {steps: [" + b"{run: x}," * 2_501 + b"]}}\n",
    ],
    ids=["bytes", "scalar", "collection", "depth", "nodes"],
)
def test_bounded_yaml_resources_are_unverifiable(content: bytes) -> None:
    with pytest.raises(C8WorkflowSemanticsUnverifiable):
        parse_c8_workflow_semantics(content)
