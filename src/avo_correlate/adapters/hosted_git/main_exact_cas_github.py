"""One capability-specific GitHub writer for the personal exact-CAS boundary."""
# pyright: reportArgumentType=false, reportUnnecessaryIsInstance=false

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Protocol
from urllib.parse import quote

from avo_correlate.adapters.hosted_git.github import (
    GitHubRejected,
    GitHubTransportError,
    JsonBody,
    github_repository_digest,
)
from avo_correlate.contracts.main_graduation_exact_cas import (
    JsonValue,
    MainExactCasIntent,
    MainExactCasReceipt,
    MainExactCasReconciliation,
    MainExactCasTopologyObservation,
    MainExactCasTransportResponse,
)
from avo_correlate.domain.canonical import canonical_digest

_API_ORIGIN = "https://api.github.com"
_API_VERSION = "2022-11-28"
_TARGET_REF = "refs/heads/main"


class MainExactCasError(RuntimeError):
    """Base exact-CAS capability error."""


class ExactCasTransport(Protocol):
    def __call__(
        self, method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> MainExactCasTransportResponse: ...


class MainExactCasDispatchVerifier(Protocol):
    """Controller-owned durable authority/fence check immediately before PATCH."""

    def __call__(self, intent: MainExactCasIntent) -> bool: ...


class MainExactCasReconciliationVerifier(Protocol):
    """Exclusive-writer proof for classifying an ambiguous response as applied."""

    def __call__(
        self, receipt: MainExactCasReceipt, observation: MainExactCasTopologyObservation
    ) -> bool: ...


def _response_digest(value: object) -> str:
    try:
        return canonical_digest(value)
    except Exception:
        return canonical_digest({"response_class": type(value).__name__})


def _response_sha(payload: JsonValue) -> tuple[str, str] | None:
    if not isinstance(payload, dict):
        return None
    ref = payload.get("ref")
    obj = payload.get("object")
    sha = obj.get("sha") if isinstance(obj, dict) else None
    if not isinstance(ref, str) or not isinstance(sha, str):
        return None
    return ref, sha


def _error_code_for_status(status: int) -> str:
    if status == 409:
        return "cas_conflict"
    if status == 422:
        return "configuration_failed"
    if status in {401, 403}:
        return "auth_failed"
    if status == 429:
        return "rate_limited"
    return "configuration_failed"


class GitHubPersonalExactCasWriter:
    """Single hard-coded main-ref CAS writer; its DTO is evidence, not authority."""

    def __init__(
        self,
        owner: str,
        repo: str,
        repository_digest: str,
        *,
        transport: ExactCasTransport,
        dispatch_verifier: MainExactCasDispatchVerifier,
        reconciliation_verifier: MainExactCasReconciliationVerifier,
        trusted_clock: Callable[[], datetime],
        writer_app_id: int,
        writer_installation_id: int,
        writer_identity: str,
        token: str,
    ) -> None:
        if not owner or not repo or any(char in owner + repo for char in "/\\"):
            raise ValueError("invalid GitHub repository binding")
        if repository_digest != github_repository_digest(owner, repo):
            raise ValueError("repository digest does not match GitHub repository")
        if isinstance(writer_app_id, bool) or writer_app_id <= 0:
            raise ValueError("writer app ID must be positive")
        if isinstance(writer_installation_id, bool) or writer_installation_id <= 0:
            raise ValueError("writer installation ID must be positive")
        if not writer_identity or not writer_identity.strip():
            raise ValueError("writer identity is required")
        if not token or not token.strip():
            raise ValueError("authenticated writer token is required")
        if not callable(transport) or not callable(dispatch_verifier):
            raise ValueError("transport and dispatch verifier are required")
        if not callable(reconciliation_verifier) or not callable(trusted_clock):
            raise ValueError("reconciliation verifier and trusted clock are required")
        self.owner = owner
        self.repo = repo
        self.repository_digest = repository_digest
        self._transport = transport
        self._dispatch_verifier = dispatch_verifier
        self._reconciliation_verifier = reconciliation_verifier
        self._trusted_clock = trusted_clock
        self._writer_app_id = writer_app_id
        self._writer_installation_id = writer_installation_id
        self._writer_identity = writer_identity.strip()
        self._token = token

    def apply(self, intent: MainExactCasIntent) -> MainExactCasReceipt:
        """Perform one PATCH after trusted-clock and controller verification."""
        if not isinstance(intent, MainExactCasIntent):
            raise TypeError("exact-CAS writer accepts only MainExactCasIntent")
        now = self._clock_or_error()
        if intent.lease_expires_at <= now:
            return self._receipt(intent, now, "rejected", False, None, "lease_expired")
        if (
            intent.repository_digest != self.repository_digest
            or intent.target_ref != _TARGET_REF
            or intent.writer_app_id != self._writer_app_id
            or intent.writer_installation_id != self._writer_installation_id
            or intent.writer_identity != self._writer_identity
        ):
            return self._receipt(intent, now, "rejected", False, None, "verifier_rejected")
        try:
            verified = self._dispatch_verifier(intent)
        except Exception:
            verified = False
        if verified is not True:
            return self._receipt(
                intent, self._clock_or_error(), "rejected", False, None, "verifier_rejected"
            )
        last_moment = self._clock_or_error()
        if intent.lease_expires_at <= last_moment:
            return self._receipt(
                intent, last_moment, "rejected", False, None, "lease_expired"
            )
        body: JsonBody = {"sha": intent.candidate_commit, "force": False}
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
            "Authorization": "Bearer " + self._token,
        }
        url = (
            f"{_API_ORIGIN}/repos/{quote(self.owner, safe='')}/{quote(self.repo, safe='')}"
            "/git/refs/heads/main"
        )
        try:
            response = self._transport("PATCH", url, body, headers)
        except GitHubRejected:
            return self._receipt(
                intent,
                self._clock_or_error(),
                "ambiguous",
                True,
                None,
                "malformed_response",
            )
        except (GitHubTransportError, TimeoutError, OSError):
            return self._receipt(
                intent, self._clock_or_error(), "ambiguous", True, None, "transport_ambiguous"
            )
        except Exception:
            return self._receipt(
                intent, self._clock_or_error(), "ambiguous", True, None, "transport_ambiguous"
            )
        observed_at = self._clock_or_error()
        if not isinstance(response, MainExactCasTransportResponse):
            return self._receipt(
                intent,
                observed_at,
                "ambiguous",
                True,
                None,
                "malformed_response",
            )
        try:
            response = MainExactCasTransportResponse.model_validate(
                response.model_dump(mode="python")
            )
        except Exception:
            return self._receipt(
                intent,
                observed_at,
                "ambiguous",
                True,
                None,
                "malformed_response",
            )
        status = response.http_status
        payload = response.payload
        request_id = response.request_id
        response_digest = _response_digest(payload)
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            return self._receipt(
                intent,
                observed_at,
                "ambiguous",
                True,
                None,
                "malformed_response",
                response_digest=response_digest,
            )
        if status == 200:
            parsed = _response_sha(payload)
            if parsed is None:
                return self._receipt(
                    intent,
                    observed_at,
                    "ambiguous",
                    True,
                    status,
                    "malformed_response",
                    request_id=request_id,
                    response_digest=response_digest,
                )
            response_ref, response_sha = parsed
            if response_ref != _TARGET_REF or response_sha != intent.candidate_commit:
                return self._receipt(
                    intent,
                    observed_at,
                    "ambiguous",
                    True,
                    status,
                    "stale_response",
                    request_id=request_id,
                    response_digest=response_digest,
                )
            return self._receipt(
                intent, observed_at, "applied", True, status, None,
                response_ref=response_ref,
                response_sha=response_sha,
                request_id=request_id,
                response_digest=response_digest,
            )
        if 400 <= status < 500:
            return self._receipt(
                intent,
                observed_at,
                "rejected",
                True,
                status,
                _error_code_for_status(status),
                request_id=request_id,
                response_digest=response_digest,
            )
        return self._receipt(
            intent, observed_at, "ambiguous", True, status,
            "server_ambiguous", request_id=request_id, response_digest=response_digest,
        )

    def reconcile(
        self, receipt: MainExactCasReceipt, observation: MainExactCasTopologyObservation
    ) -> MainExactCasReconciliation:
        if receipt.outcome != "ambiguous":
            raise ValueError("only ambiguous exact-CAS receipts can be reconciled")
        try:
            verified = self._reconciliation_verifier(receipt, observation)
        except Exception:
            verified = False
        outcome = "applied" if verified is True else "ambiguous"
        values = {
            "operation_id": receipt.operation_id,
            "ambiguous_receipt": receipt,
            "observation": observation,
            "outcome": outcome,
            "reconciled_at": self._clock_or_error(),
            "reconciliation_digest": "sha256:" + "0" * 64,
        }
        probe = MainExactCasReconciliation.model_construct(**values)
        values["reconciliation_digest"] = canonical_digest(
            probe.model_dump(exclude={"reconciliation_digest"}, mode="json")
        )
        return MainExactCasReconciliation.model_validate(values)

    def _clock_or_error(self) -> datetime:
        value = self._trusted_clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("trusted clock must return an aware datetime")
        return value

    @staticmethod
    def _receipt(
        intent: MainExactCasIntent,
        observed_at: datetime,
        outcome: str,
        dispatch_started: bool,
        http_status: int | None,
        error_code: str | None,
        *,
        request_id: str | None = None,
        response_ref: str | None = None,
        response_sha: str | None = None,
        response_digest: str | None = None,
    ) -> MainExactCasReceipt:
        values = {
            key: value
            for key, value in intent.model_dump(mode="python").items()
            if key in MainExactCasReceipt.model_fields
        }
        values.update(
            {
                "authorization_digest": intent.authorization_digest,
                "intent_digest": intent.intent_digest,
                "response_digest": response_digest or _response_digest({"code": error_code}),
                "http_status": http_status,
                "request_id": request_id,
                "observed_at": observed_at,
                "outcome": outcome,
                "dispatch_started": dispatch_started,
                "response_ref": response_ref,
                "response_sha": response_sha,
                "error_code": error_code,
            }
        )
        probe = MainExactCasReceipt.model_construct(
            **values, receipt_digest="sha256:" + "0" * 64
        )
        values["receipt_digest"] = canonical_digest(
            probe.model_dump(exclude={"receipt_digest"}, mode="json")
        )
        return MainExactCasReceipt.model_validate(values)


__all__ = [
    "ExactCasTransport",
    "GitHubPersonalExactCasWriter",
    "MainExactCasDispatchVerifier",
    "MainExactCasError",
    "MainExactCasReconciliationVerifier",
]
