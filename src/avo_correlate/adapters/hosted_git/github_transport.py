"""Bounded, origin-pinned JSON transport for authenticated GitHub calls."""
# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnnecessaryIsInstance=false, reportArgumentType=false

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .github import GitHubRejected, GitHubTransportError, JsonBody, JsonValue


class GitHubJsonTransport:
    """Callable REST transport with no credential or response ambiguity leaks."""

    def __init__(
        self,
        *,
        origin: str = "https://api.github.com",
        timeout_seconds: float = 30.0,
        max_request_bytes: int = 1024 * 1024,
        max_response_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        self._origin = self._validate_origin(origin)
        if timeout_seconds <= 0 or timeout_seconds > 60:
            raise ValueError("timeout must be between 0 and 60 seconds")
        if max_request_bytes <= 0 or max_response_bytes <= 0:
            raise ValueError("request and response bounds must be positive")
        self._timeout = timeout_seconds
        self._max_request = max_request_bytes
        self._max_response = max_response_bytes

    @staticmethod
    def _validate_origin(origin: str) -> tuple[str, str, int | None]:
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("GitHub transport origin must be an exact HTTPS origin")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("GitHub transport origin has an invalid port") from exc
        return parsed.scheme, parsed.hostname, port

    def _validate_url(self, url: str) -> None:
        parsed = urlsplit(url)
        expected_scheme, expected_host, expected_port = self._origin
        try:
            actual_port = parsed.port
        except ValueError as exc:
            raise ValueError("GitHub request URL has an invalid port") from exc
        if (
            parsed.scheme != expected_scheme
            or parsed.hostname != expected_host
            or actual_port != expected_port
            or parsed.username is not None
            or parsed.password is not None
            or not parsed.path.startswith("/")
            or parsed.query or parsed.fragment
        ):
            raise ValueError("GitHub request URL is outside the configured origin")

    @staticmethod
    def _reject_duplicate(pairs: list[tuple[Any, Any]]) -> None:
        del pairs
        raise ValueError("duplicate JSON key")

    @staticmethod
    def _reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant: {value}")

    @staticmethod
    def _json_value(value: object) -> JsonValue:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, list):
            items = cast(list[Any], value)
            return [GitHubJsonTransport._json_value(item) for item in items]
        if isinstance(value, dict):
            raw = cast(dict[Any, Any], value)
            return {
                str(key): GitHubJsonTransport._json_value(item)
                for key, item in raw.items()
            }
        raise ValueError("unsupported JSON value")

    def __call__(
        self, method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        self._validate_url(url)
        if not isinstance(method, str) or not method or any(ord(char) < 33 for char in method):
            raise ValueError("invalid HTTP method")
        try:
            request_data = (
                json.dumps(body, separators=(",", ":"), allow_nan=False).encode("utf-8")
                if body is not None
                else None
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("request body is not strict JSON") from exc
        if request_data is not None and len(request_data) > self._max_request:
            raise ValueError("GitHub request body exceeded configured bound")
        safe_headers = dict(headers)
        request = Request(url, data=request_data, method=method, headers=safe_headers)
        try:
            with urlopen(request, timeout=self._timeout) as response:
                raw = response.read(self._max_response + 1)
                if len(raw) > self._max_response:
                    raise GitHubTransportError("GitHub response exceeded configured bound")
                parsed: object = json.loads(
                    raw or b"{}",
                    object_pairs_hook=self._reject_duplicate,
                    parse_constant=self._reject_constant,
                )
                return int(response.status), self._json_value(parsed)
        except HTTPError as exc:
            if 400 <= exc.code < 500:
                raise GitHubRejected(
                    f"GitHub request rejected ({exc.code})", status=exc.code
                ) from None
            raise GitHubTransportError("GitHub transport failure") from None
        except GitHubRejected:
            raise
        except GitHubTransportError:
            raise
        except (ValueError, TypeError) as exc:
            raise GitHubTransportError("GitHub response was not strict JSON") from exc
        except Exception as exc:
            raise GitHubTransportError("GitHub transport failure") from exc


__all__ = ["GitHubJsonTransport"]
