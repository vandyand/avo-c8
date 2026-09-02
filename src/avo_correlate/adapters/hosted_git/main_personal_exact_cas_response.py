"""Pure response parsing for the future personal exact-CAS controller.

This module deliberately stops at response classification.  It has no network,
credential, provider, URL, writer, or journal capability.  In particular, a
successful HTTP status remains a candidate response until a separately
authenticated post-state observation proves the mutation.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, TypeGuard

type MainPersonalExactCasJsonPrimitive = str | int | float | bool | None
type MainPersonalExactCasJsonValue = (
    MainPersonalExactCasJsonPrimitive
    | list[MainPersonalExactCasJsonValue]
    | dict[str, MainPersonalExactCasJsonValue]
)
type MainPersonalExactCasResponseClassification = Literal[
    "candidate_response",
    "conflict_or_rejected",
    "configuration_or_validation_rejected",
    "authentication_or_authorization_rejected",
    "rate_limited",
    "ambiguous",
    "unverifiable",
]

_ALLOWED_HEADERS = frozenset(
    {
        "retry-after",
        "x-github-request-id",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "x-ratelimit-resource",
    }
)
_DISALLOWED_SECRET_HEADERS = frozenset(
    {"authorization", "cookie", "proxy-authorization", "set-cookie"}
)
_DEFAULT_MAX_BODY_BYTES = 1024 * 1024
_DEFAULT_MAX_BODY_DEPTH = 32
_DEFAULT_MAX_HEADERS = 64
_DEFAULT_MAX_HEADER_KEY_LENGTH = 128
_DEFAULT_MAX_HEADER_VALUE_LENGTH = 2048
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_UNSIGNED_INTEGER_PATTERN = re.compile(r"^[0-9]{1,20}$")
_RESOURCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class MainPersonalExactCasResponseError(ValueError):
    """The response value set is malformed or exceeds the offline bounds."""

    def __init__(self) -> None:
        super().__init__("invalid exact-CAS response")

    def __repr__(self) -> str:
        """Keep even the generic diagnostic text out of repr consumers."""

        return "MainPersonalExactCasResponseError()"


@dataclass(frozen=True, slots=True, repr=False)
class MainPersonalExactCasResponse:
    """A bounded, sanitized response that is never terminal mutation proof."""

    status: int
    body: MainPersonalExactCasJsonValue
    classification: MainPersonalExactCasResponseClassification
    metadata: Mapping[str, str]
    is_terminal: Literal[False] = False

    @property
    def headers(self) -> Mapping[str, str]:
        """Return the allowlisted response metadata under its HTTP-facing name."""

        return self.metadata

    @property
    def http_status(self) -> int:
        """Compatibility name for callers that model HTTP responses explicitly."""

        return self.status

    @property
    def payload(self) -> MainPersonalExactCasJsonValue:
        """Compatibility name for callers that model the body as a payload."""

        return self.body

    @property
    def sanitized_metadata(self) -> Mapping[str, str]:
        """Return the same immutable allowlisted metadata explicitly by purpose."""

        return self.metadata

    def __repr__(self) -> str:
        """Keep untrusted body and metadata values out of diagnostic reprs."""

        return (
            "MainPersonalExactCasResponse("
            f"status={self.status!r}, classification={self.classification!r}, "
            f"is_terminal={self.is_terminal!r})"
        )


def parse_main_personal_exact_cas_response(
    status: object,
    body: object,
    headers: object,
    *,
    max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES,
    max_body_depth: int = _DEFAULT_MAX_BODY_DEPTH,
    max_headers: int = _DEFAULT_MAX_HEADERS,
    max_header_key_length: int = _DEFAULT_MAX_HEADER_KEY_LENGTH,
    max_header_value_length: int = _DEFAULT_MAX_HEADER_VALUE_LENGTH,
) -> MainPersonalExactCasResponse:
    """Parse and classify one already-delivered response value set.

    Headers outside the small allowlist are dropped, including credential and
    cookie headers.  All malformed or over-bound input is rejected with the
    same value-free exception.  No status is interpreted as proof that main
    was changed.
    """

    _validate_bounds(
        max_body_bytes,
        max_body_depth,
        max_headers,
        max_header_key_length,
        max_header_value_length,
    )
    checked_status = _validate_status(status)
    checked_body = _validate_body(body, max_body_depth, max_body_bytes)
    checked_headers = _sanitize_headers(
        headers,
        max_headers=max_headers,
        max_key_length=max_header_key_length,
        max_value_length=max_header_value_length,
    )
    serialization_failed = False
    encoded_body = b""
    try:
        encoded_body = json.dumps(
            checked_body,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, OverflowError):
        serialization_failed = True
    if serialization_failed:
        raise MainPersonalExactCasResponseError()
    if len(encoded_body) > max_body_bytes:
        raise MainPersonalExactCasResponseError()
    return MainPersonalExactCasResponse(
        status=checked_status,
        body=checked_body,
        classification=_classify(checked_status),
        metadata=MappingProxyType(checked_headers),
    )


def _validate_bounds(*bounds: object) -> None:
    if any(type(value) is not int or value <= 0 for value in bounds):
        raise MainPersonalExactCasResponseError()


def _validate_status(value: object) -> int:
    if type(value) is not int or not 100 <= value <= 599:
        raise MainPersonalExactCasResponseError()
    return value


def _validate_body(value: object, depth: int, max_bytes: int) -> MainPersonalExactCasJsonValue:
    if depth < 0:
        raise MainPersonalExactCasResponseError()
    if value is None or _is_plain_bool(value):
        return value
    if _is_plain_str(value):
        encoded_length = _utf8_length(value)
        if encoded_length is None or encoded_length > max_bytes:
            raise MainPersonalExactCasResponseError()
        return value
    if _is_plain_int(value):
        if value.bit_length() > max_bytes * 8:
            raise MainPersonalExactCasResponseError()
        return value
    if _is_plain_float(value):
        if not math.isfinite(value):
            raise MainPersonalExactCasResponseError()
        return value
    if _is_plain_list(value):
        items = value
        if len(items) > max_bytes:
            raise MainPersonalExactCasResponseError()
        return [_validate_body(item, depth - 1, max_bytes) for item in items]
    if _is_plain_dict(value):
        mapping = value
        if len(mapping) > max_bytes:
            raise MainPersonalExactCasResponseError()
        checked: dict[str, MainPersonalExactCasJsonValue] = {}
        for key, item in mapping.items():
            if not _is_plain_str(key):
                raise MainPersonalExactCasResponseError()
            key_length = _utf8_length(key)
            if key_length is None or key_length > max_bytes or key in checked:
                raise MainPersonalExactCasResponseError()
            checked[key] = _validate_body(item, depth - 1, max_bytes)
        return checked
    raise MainPersonalExactCasResponseError()


def _sanitize_headers(
    headers: object,
    *,
    max_headers: int,
    max_key_length: int,
    max_value_length: int,
) -> dict[str, str]:
    if not _is_mapping(headers):
        raise MainPersonalExactCasResponseError()
    items_failed = False
    iterator: Iterator[object] = iter(())
    try:
        iterator = iter(headers.items())
    except Exception:
        items_failed = True
    if items_failed:
        raise MainPersonalExactCasResponseError()
    checked: dict[str, str] = {}
    iteration_failed = False
    exhausted = False
    for _ in range(max_headers + 1):
        try:
            element = next(iterator)
        except StopIteration:
            exhausted = True
            break
        except Exception:
            iteration_failed = True
            break
        if not _is_plain_pair(element):
            raise MainPersonalExactCasResponseError()
        key, value = element
        if not _is_plain_str(key) or not _is_plain_str(value):
            raise MainPersonalExactCasResponseError()
        if (
            not key
            or len(key) > max_key_length
            or len(value) > max_value_length
            or any(ord(char) < 0x20 or ord(char) > 0x7E for char in key)
            or any(ord(char) < 0x20 or ord(char) > 0x7E for char in value)
        ):
            raise MainPersonalExactCasResponseError()
        normalized = key.lower()
        if normalized in _DISALLOWED_SECRET_HEADERS or normalized not in _ALLOWED_HEADERS:
            continue
        sanitized_value = value.strip()
        if not sanitized_value or not _valid_retained_value(normalized, sanitized_value):
            continue
        if normalized in checked:
            raise MainPersonalExactCasResponseError()
        checked[normalized] = sanitized_value
    if iteration_failed or not exhausted:
        raise MainPersonalExactCasResponseError()
    return checked


def _utf8_length(value: str) -> int | None:
    try:
        return len(value.encode("utf-8"))
    except UnicodeError:
        return None


def _valid_retained_value(name: str, value: str) -> bool:
    if name == "x-github-request-id":
        return _REQUEST_ID_PATTERN.fullmatch(value) is not None
    if name == "x-ratelimit-resource":
        return _RESOURCE_PATTERN.fullmatch(value) is not None
    return _UNSIGNED_INTEGER_PATTERN.fullmatch(value) is not None


def _is_mapping(value: object) -> TypeGuard[Mapping[object, object]]:
    return isinstance(value, Mapping)


def _is_plain_bool(value: object) -> TypeGuard[bool]:
    return type(value) is bool


def _is_plain_str(value: object) -> TypeGuard[str]:
    return type(value) is str


def _is_plain_int(value: object) -> TypeGuard[int]:
    return type(value) is int


def _is_plain_float(value: object) -> TypeGuard[float]:
    return type(value) is float


def _is_plain_list(value: object) -> TypeGuard[list[object]]:
    return type(value) is list


def _is_plain_dict(value: object) -> TypeGuard[dict[object, object]]:
    return type(value) is dict


def _is_plain_pair(value: object) -> TypeGuard[tuple[object, object]]:
    if not _is_tuple(value) or type(value) is not tuple:
        return False
    return len(value) == 2


def _is_tuple(value: object) -> TypeGuard[tuple[object, ...]]:
    return isinstance(value, tuple)


def _classify(status: int) -> MainPersonalExactCasResponseClassification:
    if status == 200:
        return "candidate_response"
    if status == 409:
        return "conflict_or_rejected"
    if status == 422:
        return "configuration_or_validation_rejected"
    if status in {401, 403}:
        return "authentication_or_authorization_rejected"
    if status == 429:
        return "rate_limited"
    if 500 <= status <= 599:
        return "ambiguous"
    return "unverifiable"


__all__ = [
    "MainPersonalExactCasJsonPrimitive",
    "MainPersonalExactCasJsonValue",
    "MainPersonalExactCasResponse",
    "MainPersonalExactCasResponseClassification",
    "MainPersonalExactCasResponseError",
    "parse_main_personal_exact_cas_response",
]
