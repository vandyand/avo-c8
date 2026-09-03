"""Untrusted, fixed-operation transport observation for personal main CAS.

This leaf deliberately stops at a frozen sanitized provider observation. It does
not create a receipt, persist evidence, verify authority, or wire a controller.
The caller cannot provide a URL, ref, method, force flag, or request body.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from email.message import Message
from types import MappingProxyType
from typing import Any, Literal, Protocol, cast
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from avo_correlate.adapters.hosted_git.github import github_repository_digest
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_response import (
    MainPersonalExactCasJsonValue,
    MainPersonalExactCasResponse,
    MainPersonalExactCasResponseClassification,
    MainPersonalExactCasResponseError,
    parse_main_personal_exact_cas_response,
)
from avo_correlate.contracts.main_personal_exact_cas import (
    MainPersonalExactCasDispatchStarted,
    MainPersonalExactCasIntent,
)

_API_ORIGIN = "https://api.github.com"
_API_VERSION = "2022-11-28"
_TARGET_REF = "refs/heads/main"
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_OWNER_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}[A-Za-z0-9])?\Z")
_REPO_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?\Z")

type MainPersonalExactCasImmutableJsonValue = (
    str
    | int
    | float
    | bool
    | tuple[MainPersonalExactCasImmutableJsonValue, ...]
    | Mapping[str, MainPersonalExactCasImmutableJsonValue]
    | None
)


class MainPersonalExactCasTransportError(RuntimeError):
    """Value-free, code-only transport failure with no provider detail."""

    def __init__(self, code: str) -> None:
        if code not in {
            "transport_ambiguous",
            "malformed_response",
            "response_too_large",
            "redirect_rejected",
        }:
            code = "transport_ambiguous"
        self.code = code
        super().__init__(code)

    def __repr__(self) -> str:
        return f"MainPersonalExactCasTransportError({self.code!r})"


def _freeze_json(
    value: MainPersonalExactCasJsonValue,
) -> MainPersonalExactCasImmutableJsonValue:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


@dataclass(frozen=True, slots=True, repr=False)
class MainPersonalExactCasTransportObservation:
    """Sanitized, non-authoritative result from one fixed provider exchange."""

    operation_id: str
    repository_digest: str
    target_ref: str
    writer_app_id: int
    writer_installation_id: int
    writer_identity: str
    intent_digest: str
    dispatch_marker_digest: str
    status: int
    body: MainPersonalExactCasImmutableJsonValue
    classification: MainPersonalExactCasResponseClassification
    metadata: Mapping[str, str]
    observed_at: datetime
    payload_bytes: bytes
    payload_digest: str
    is_terminal: Literal[False] = False
    is_authoritative: Literal[False] = False

    @property
    def http_status(self) -> int:
        return self.status

    @property
    def request_id(self) -> str | None:
        return self.metadata.get("x-github-request-id")

    @property
    def sanitized_metadata(self) -> Mapping[str, str]:
        return self.metadata

    def __repr__(self) -> str:
        return (
            "MainPersonalExactCasTransportObservation("
            f"status={self.status!r}, classification={self.classification!r})"
        )


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        raise MainPersonalExactCasTransportError("redirect_rejected")


_NO_REDIRECT_OPENER = build_opener(_NoRedirectHandler())


class _OpenResponse(Protocol):
    status: int
    headers: Mapping[str, str] | Message

    def read(self, limit: int = -1) -> bytes: ...

    def getcode(self) -> int | None: ...

    def __enter__(self) -> _OpenResponse: ...

    def __exit__(self, *args: object) -> object: ...


class _Opener(Protocol):
    def open(self, request: Request, *, timeout: float) -> _OpenResponse: ...


class _MessageHeaders(Mapping[str, str]):
    """Expose urllib's HTTPMessage through the bounded Mapping parser."""

    def __init__(self, headers: Message) -> None:
        self._headers = headers

    def __iter__(self):
        return (key for key, _value in self._headers.raw_items())

    def __len__(self) -> int:
        return len(self._headers)

    def __getitem__(self, key: str) -> str:
        value = self._headers[key]
        if type(value) is not str:
            raise KeyError(key)
        return value


class MainPersonalExactCasGitHubTransport:
    """Constructor-pinned, no-redirect HTTPS transport observation leaf.

    The token is used only to form this request's Authorization header and is
    never returned or included in exceptions. The observation is intentionally
    not a receipt and cannot be consumed as durable authority without a separate
    controller-rooted verifier and restart-safe journal.
    """

    def __init__(
        self,
        *,
        owner: str,
        repo: str,
        repository_digest: str,
        token: str,
        writer_app_id: int,
        writer_installation_id: int,
        writer_identity: str,
        opener: _Opener | None = None,
        timeout_seconds: float = 30.0,
        trusted_clock: Callable[[], datetime],
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
    ) -> None:
        self._validate_part(owner, "owner")
        self._validate_part(repo, "repo")
        expected_repository_digest = github_repository_digest(owner, repo)
        if repository_digest != expected_repository_digest:
            raise ValueError("repository digest does not match pinned GitHub repository")
        if type(token) is not str or not token.strip():
            raise ValueError("authenticated writer token is required")
        if type(writer_app_id) is not int or writer_app_id <= 0:
            raise ValueError("writer app ID must be positive")
        if type(writer_installation_id) is not int or writer_installation_id <= 0:
            raise ValueError("writer installation ID must be positive")
        if type(writer_identity) is not str or not writer_identity.strip():
            raise ValueError("writer identity is required")
        if (
            type(timeout_seconds) not in {int, float}
            or not math.isfinite(float(timeout_seconds))
            or timeout_seconds <= 0
            or timeout_seconds > 60
        ):
            raise ValueError("timeout must be between 0 and 60 seconds")
        if (
            type(max_response_bytes) is not int
            or max_response_bytes <= 0
            or max_response_bytes > _MAX_RESPONSE_BYTES
        ):
            raise ValueError("response bound must be positive")
        if opener is not None and not callable(getattr(opener, "open", None)):
            raise ValueError("opener must provide open")
        if not callable(trusted_clock):
            raise ValueError("trusted clock must be callable")
        self._owner = owner
        self._repo = repo
        self._repository_digest = repository_digest
        self._token = token
        self._writer_app_id = writer_app_id
        self._writer_installation_id = writer_installation_id
        self._writer_identity = writer_identity.strip()
        self._opener = _NO_REDIRECT_OPENER if opener is None else opener
        self._timeout = float(timeout_seconds)
        self._trusted_clock = trusted_clock
        self._max_response_bytes = max_response_bytes

    def exchange(
        self,
        intent: MainPersonalExactCasIntent,
        marker: MainPersonalExactCasDispatchStarted,
    ) -> MainPersonalExactCasTransportObservation:
        """Perform the one fixed PATCH and return only sanitized observation data."""

        if type(intent) is not MainPersonalExactCasIntent:
            raise TypeError("personal exact-CAS intent is required")
        if type(marker) is not MainPersonalExactCasDispatchStarted:
            raise TypeError("personal exact-CAS dispatch marker is required")
        validation_failed = False
        checked_intent: MainPersonalExactCasIntent | None = None
        checked_marker: MainPersonalExactCasDispatchStarted | None = None
        try:
            checked_intent = MainPersonalExactCasIntent.model_validate(
                intent.model_dump(mode="json", warnings="error")
            )
            checked_marker = MainPersonalExactCasDispatchStarted.model_validate(
                marker.model_dump(mode="json", warnings="error")
            )
        except Exception:
            validation_failed = True
        if validation_failed or checked_intent is None or checked_marker is None:
            raise MainPersonalExactCasTransportError("transport_ambiguous")
        intent = checked_intent
        marker = checked_marker
        if not self._binds(intent, marker):
            raise MainPersonalExactCasTransportError("transport_ambiguous")
        request = Request(
            f"{_API_ORIGIN}/repos/{self._owner}/{self._repo}/git/refs/heads/main",
            data=json.dumps(
                {"sha": intent.candidate_commit, "force": False},
                ensure_ascii=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("ascii"),
            method="PATCH",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self._token,
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": _API_VERSION,
            },
        )
        failure: str | None = None
        response = None
        parsed = None
        try:
            response = self._open(request)
            parsed = self._parse(response)
        except MainPersonalExactCasResponseError:
            failure = "malformed_response"
        except MainPersonalExactCasTransportError as exc:
            failure = exc.code
        except Exception:
            failure = "transport_ambiguous"
        if failure is not None:
            raise MainPersonalExactCasTransportError(failure)
        assert parsed is not None
        payload_bytes = _canonical_payload_bytes(parsed.body)
        return MainPersonalExactCasTransportObservation(
            operation_id=intent.operation_id,
            repository_digest=intent.repository_digest,
            target_ref=intent.target_ref,
            writer_app_id=intent.writer_app_id,
            writer_installation_id=intent.writer_installation_id,
            writer_identity=intent.writer_identity,
            intent_digest=intent.intent_digest,
            dispatch_marker_digest=marker.dispatch_marker_digest,
            status=parsed.status,
            body=_freeze_json(parsed.body),
            classification=parsed.classification,
            metadata=MappingProxyType(dict(parsed.metadata)),
            observed_at=self._now(),
            payload_bytes=payload_bytes,
            payload_digest=_payload_digest(payload_bytes),
        )

    @staticmethod
    def _validate_part(value: object, label: str) -> None:
        if (
            type(value) is not str
            or not value
            or (
                _OWNER_PATTERN.fullmatch(value) is None
                if label == "owner"
                else _REPO_PATTERN.fullmatch(value) is None
            )
        ):
            raise ValueError(f"invalid GitHub {label} binding")

    def _open(self, request: Request) -> _OpenResponse:
        try:
            return cast(_OpenResponse, self._opener.open(request, timeout=self._timeout))
        except HTTPError as exc:
            return cast(_OpenResponse, exc)

    @staticmethod
    def _json_pairs(pairs: list[tuple[object, object]]) -> dict[str, object]:
        parsed: dict[str, object] = {}
        for key, value in pairs:
            if type(key) is not str or key in parsed:
                raise MainPersonalExactCasTransportError("malformed_response")
            parsed[key] = value
        return parsed

    @staticmethod
    def _reject_constant(_value: str) -> None:
        raise MainPersonalExactCasTransportError("malformed_response")

    def _parse(self, response: _OpenResponse) -> MainPersonalExactCasResponse:
        failure: str | None = None
        parsed: MainPersonalExactCasResponse | None = None
        try:
            with response as opened:
                status: object = getattr(opened, "status", None)
                if type(status) is not int:
                    status = opened.getcode()
                raw: object = opened.read(self._max_response_bytes + 1)
                if type(raw) is not bytes:
                    failure = "malformed_response"
                elif len(raw) > self._max_response_bytes:
                    failure = "response_too_large"
                else:
                    body: object = json.loads(
                        raw or b"{}",
                        object_pairs_hook=self._json_pairs,
                        parse_constant=self._reject_constant,
                    )
                    parsed = parse_main_personal_exact_cas_response(
                        status,
                        body,
                        _headers_for_parser(getattr(opened, "headers", {})),
                    )
        except MainPersonalExactCasTransportError as exc:
            failure = exc.code
        except MainPersonalExactCasResponseError:
            failure = "malformed_response"
        except Exception:
            failure = "malformed_response"
        if failure is not None:
            raise MainPersonalExactCasTransportError(failure)
        assert parsed is not None
        return parsed

    def _now(self) -> datetime:
        failure = False
        value: object = None
        try:
            value = self._trusted_clock()
            if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
                failure = True
        except Exception:
            failure = True
        if failure:
            raise MainPersonalExactCasTransportError("transport_ambiguous")
        return cast(datetime, value)

    def _binds(
        self,
        intent: MainPersonalExactCasIntent,
        marker: MainPersonalExactCasDispatchStarted,
    ) -> bool:
        if (
            intent.repository_digest != self._repository_digest
            or intent.target_ref != _TARGET_REF
            or intent.writer_app_id != self._writer_app_id
            or intent.writer_installation_id != self._writer_installation_id
            or intent.writer_identity != self._writer_identity
        ):
            return False
        fields = (
            "activation_digest",
            "operation_id",
            "repository_digest",
            "target_ref",
            "source_operation_id",
            "source_plan_digest",
            "source_package_digest",
            "source_composition_digest",
            "base_commit",
            "base_tree",
            "candidate_commit",
            "candidate_tree",
            "candidate_ref",
            "candidate_parents",
            "protection_ruleset_digest",
            "writer_app_id",
            "writer_installation_id",
            "writer_identity",
            "lease_identity",
            "lease_digest",
            "lease_expires_at",
            "claim_nonce",
            "claim_digest",
        )
        return all(getattr(intent, field) == getattr(marker, field) for field in fields) and (
            marker.intent_digest == intent.intent_digest
        )


def _headers_for_parser(value: object) -> object:
    if isinstance(value, Message):
        return _MessageHeaders(value)  # pyright: ignore[reportUnknownArgumentType]
    return value


def _canonical_payload_bytes(value: MainPersonalExactCasJsonValue) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _payload_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


__all__ = [
    "MainPersonalExactCasGitHubTransport",
    "MainPersonalExactCasTransportError",
    "MainPersonalExactCasTransportObservation",
]
