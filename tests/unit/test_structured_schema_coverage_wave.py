"""Additional adversarial coverage for strict structured-schema compilation."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel

import avo_correlate.domain.structured_schema as module
from avo_correlate.domain.structured_schema import (
    StructuredSchemaError,
    compile_strict_output_schema,
)


def _model(monkeypatch: pytest.MonkeyPatch, schema: object) -> type[BaseModel]:
    class Model(BaseModel):
        value: str

    def render() -> object:
        return schema

    monkeypatch.setattr(Model, "model_json_schema", render)
    return Model


@pytest.mark.parametrize(
    "schema",
    [
        [],
        {"type": "string"},
        {"type": "not-json"},
    ],
)
def test_rejects_non_object_or_invalid_roots(
    monkeypatch: pytest.MonkeyPatch, schema: object
) -> None:
    with pytest.raises(StructuredSchemaError):
        compile_strict_output_schema(_model(monkeypatch, schema))


def test_source_and_wire_digest_failures_are_domain_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(StructuredSchemaError, match="invalid source schema"):
        compile_strict_output_schema(_model(monkeypatch, {"type": "object", "bad": {1}}))

    calls = 0

    def fail_wire(value: object) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ValueError("wire failure")
        return "sha256:" + "a" * 64

    monkeypatch.setattr(module, "canonical_digest", fail_wire)
    with pytest.raises(StructuredSchemaError, match="invalid compiled schema"):
        compile_strict_output_schema(_model(monkeypatch, {"type": "object"}))


def test_cycle_guard_and_nested_nodes_are_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    schema: dict[str, Any] = {"type": "object", "properties": {}}
    schema["properties"]["self"] = schema

    def constant_digest(_value: object) -> str:
        return "sha256:" + "a" * 64

    monkeypatch.setattr(module, "canonical_digest", constant_digest)
    compiled = compile_strict_output_schema(_model(monkeypatch, schema))
    assert compiled.wire_schema["additionalProperties"] is False


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "object", "type_override": "bad"},
        {"type": "object", "properties": []},
        {"type": "string", "properties": {"value": {"type": "string"}}},
        {"type": "object", "properties": {1: {"type": "string"}}},
        {"type": "object", "required": "value"},
        {"type": "object", "required": [1]},
        {"type": "object", "required": ["value"]},
        {"type": "object", "required": ["value", "value"], "properties": {"value": {}}},
        {"type": "object", "required": ["other"], "properties": {"value": {}}},
        {"type": "string", "additionalProperties": False},
        {"type": "object", "$defs": []},
        {"type": "object", "$defs": {1: {}}},
        {"type": "object", "anyOf": {}},
        {"type": "object", "anyOf": []},
        {"type": "object", "patternProperties": {}},
    ],
)
def test_rejects_malformed_schema_shapes(
    monkeypatch: pytest.MonkeyPatch, schema: dict[Any, Any]
) -> None:
    if "type_override" in schema:
        schema = {"type": "invalid"}
    with pytest.raises(StructuredSchemaError):
        compile_strict_output_schema(_model(monkeypatch, schema))


def test_valid_empty_required_items_definitions_and_compositions_compile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema: dict[str, Any] = {
        "type": "object",
        "required": [],
        "properties": {
            "values": {
                "type": "array",
                "items": {"type": "string"},
                "anyOf": [{"type": "array", "items": {"type": "string"}}],
            }
        },
        "$defs": {"Named": {"type": "object", "properties": {}}},
    }
    compiled = compile_strict_output_schema(_model(monkeypatch, schema))
    assert compiled.wire_schema["required"] == ["values"]
    assert compiled.wire_schema["$defs"]["Named"]["additionalProperties"] is False


@pytest.mark.parametrize(
    "child",
    [
        {"type": "invalid"},
        {"type": "string", "properties": {}},
        {"type": "string", "additionalProperties": False},
    ],
)
def test_nested_type_and_object_keyword_conflicts_are_rejected(
    monkeypatch: pytest.MonkeyPatch, child: dict[str, object]
) -> None:
    schema = {"type": "object", "properties": {"value": child}}
    with pytest.raises(StructuredSchemaError):
        compile_strict_output_schema(_model(monkeypatch, schema))


def test_object_without_properties_normalizes_empty_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compiled = compile_strict_output_schema(
        _model(monkeypatch, {"type": "object", "required": []})
    )
    assert compiled.wire_schema["required"] == []


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "object", "properties": {1: {}}},
        {"type": "object", "$defs": {1: {}}},
    ],
)
def test_compiler_rejects_non_string_mapping_names_defensively(
    schema: dict[object, object],
) -> None:
    with pytest.raises(StructuredSchemaError):
        module._compile_node(  # pyright: ignore[reportPrivateUsage]
            schema,
            root=schema,  # pyright: ignore[reportArgumentType]
            path="$",
            seen=set(),
        )


@pytest.mark.parametrize(
    "ref",
    [
        1,
        "#/$defs",
        "#/$defs/Missing",
        "#/$defs/Leaf",
        "#/$defs/Leaf/child",
    ],
)
def test_local_reference_validation_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch, ref: object
) -> None:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {"value": {"$ref": ref}},
        "$defs": {"Leaf": 1},
    }
    with pytest.raises(StructuredSchemaError):
        compile_strict_output_schema(_model(monkeypatch, schema))
