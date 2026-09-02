from __future__ import annotations

# pyright: reportArgumentType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from pydantic import ValidationError

from avo_correlate.adapters.hosted_git.github import github_repository_digest
from avo_correlate.adapters.hosted_git.main_exact_cas_github import GitHubPersonalExactCasWriter
from avo_correlate.contracts.main_graduation_exact_cas import (
    MainExactCasAuthorization,
    MainExactCasIntent,
    MainExactCasPostStateObservation,
    MainExactCasReceipt,
    MainExactCasTopologyObservation,
    MainExactCasTransportResponse,
    exact_cas_claim_digest,
    exact_cas_operation_id,
    exact_cas_raw_request_digest,
)
from avo_correlate.domain.canonical import canonical_digest

D = "sha256:" + "a" * 64
NOW = datetime(2030, 1, 1, tzinfo=UTC)
BASE = "1" * 40
TREE = "2" * 40
CANDIDATE = "3" * 40
CANDIDATE_TREE = "4" * 40
CANDIDATE_REF = "refs/heads/avo/candidate/" + "5" * 64


def intent(**updates: Any) -> MainExactCasIntent:
    values: dict[str, Any] = {
        "repository_digest": github_repository_digest("avo-org", "avo"),
        "target_ref": "refs/heads/main",
        "base_commit": BASE,
        "base_tree": TREE,
        "candidate_commit": CANDIDATE,
        "candidate_tree": CANDIDATE_TREE,
        "candidate_ref": CANDIDATE_REF,
        "candidate_parents": (BASE,),
        "candidate_ref_immutable": True,
        "candidate_reachable": True,
        "protection_ruleset_digest": D,
        "writer_app_id": 42,
        "writer_installation_id": 43,
        "writer_identity": "personal-cas-installation",
        "lease_identity": "break-glass-owner",
        "lease_digest": D,
        "lease_expires_at": datetime(2030, 1, 2, tzinfo=UTC),
        "claim_nonce": "one-use-nonce",
        "one_use": True,
        "claim_digest": D,
        "raw_request_digest": D,
        "operation_id": "sha256:" + "0" * 64,
        "authorization_digest": D,
        "recorded_at": NOW,
        "intent_digest": "sha256:" + "0" * 64,
    }
    values.update(updates)
    values["operation_id"] = exact_cas_operation_id(
        **{
            key: values[key]
            for key in (
                "repository_digest",
                "target_ref",
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
                "raw_request_digest",
            )
        }
    )
    values["claim_digest"] = exact_cas_claim_digest(
        operation_id=values["operation_id"],
        lease_identity=values["lease_identity"],
        lease_digest=values["lease_digest"],
        lease_expires_at=values["lease_expires_at"],
        claim_nonce=values["claim_nonce"],
    )
    values["raw_request_digest"] = exact_cas_raw_request_digest(
        repository_digest=values["repository_digest"],
        target_ref=values["target_ref"],
        candidate_commit=values["candidate_commit"],
    )
    values["operation_id"] = exact_cas_operation_id(
        **{
            key: values[key]
            for key in (
                "repository_digest", "target_ref", "base_commit", "base_tree",
                "candidate_commit", "candidate_tree", "candidate_ref", "candidate_parents",
                "protection_ruleset_digest", "writer_app_id", "writer_installation_id",
                "writer_identity", "lease_identity", "lease_digest", "lease_expires_at",
                "claim_nonce", "raw_request_digest",
            )
        }
    )
    values["claim_digest"] = exact_cas_claim_digest(
        operation_id=values["operation_id"],
        lease_identity=values["lease_identity"],
        lease_digest=values["lease_digest"],
        lease_expires_at=values["lease_expires_at"],
        claim_nonce=values["claim_nonce"],
    )
    probe = MainExactCasIntent.model_construct(**values)
    values["intent_digest"] = canonical_digest(
        probe.model_dump(exclude={"intent_digest"}, mode="json")
    )
    return MainExactCasIntent.model_validate(values)


class Transport:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[tuple[str, str, object, object]] = []

    def __call__(
        self, method: str, url: str, body: object, headers: object
    ) -> MainExactCasTransportResponse:
        self.calls.append((method, url, body, headers))
        result: object = self.result
        if isinstance(result, BaseException):
            raise result
        if isinstance(result, tuple):
            status, payload = cast(tuple[Any, Any], result)
            return MainExactCasTransportResponse(
                http_status=status, payload=payload, request_id="req-test-123"
            )  # type: ignore[arg-type]
        return result  # type: ignore[return-value]


def writer(
    transport: Transport,
    *,
    dispatch_verifier: Any = None,
    trusted_clock: Any = None,
) -> GitHubPersonalExactCasWriter:
    return GitHubPersonalExactCasWriter(
        "avo-org",
        "avo",
        github_repository_digest("avo-org", "avo"),
        transport=transport,
        dispatch_verifier=dispatch_verifier or (lambda _intent: True),
        reconciliation_verifier=lambda _receipt, _observation: True,
        trusted_clock=trusted_clock or (lambda: NOW),
        writer_app_id=42,
        writer_installation_id=43,
        writer_identity="personal-cas-installation",
        token="secret",
    )


def test_success_is_one_exact_patch_and_strict_response() -> None:
    transport = Transport((200, {"ref": "refs/heads/main", "object": {"sha": CANDIDATE}}))
    receipt = writer(transport).apply(intent())
    assert receipt.outcome == "applied"
    assert receipt.request_id == "req-test-123"
    assert len(transport.calls) == 1
    method, url, body, headers = transport.calls[0]
    assert method == "PATCH"
    assert url.endswith("/repos/avo-org/avo/git/refs/heads/main")
    assert body == {"sha": CANDIDATE, "force": False}
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"  # type: ignore[index]


@pytest.mark.parametrize(
    ("status", "error_code"), [(409, "cas_conflict"), (422, "configuration_failed")]
)
def test_provider_rejection_is_classified_without_retry(status: int, error_code: str) -> None:
    transport = Transport((status, {"message": "conflict"}))
    receipt = writer(transport).apply(intent())
    assert receipt.outcome == "rejected"
    assert receipt.error_code == error_code
    assert receipt.request_id == "req-test-123"
    assert len(transport.calls) == 1


@pytest.mark.parametrize("result", [TimeoutError("timeout"), RuntimeError("transport")])
def test_transport_failure_is_ambiguous_without_retry(result: BaseException) -> None:
    transport = Transport(result)
    receipt = writer(transport).apply(intent())
    assert receipt.outcome == "ambiguous"
    assert "secret" not in repr(receipt.model_dump())
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "request_id", ["", "\nsecret", "bad request", "x" * 129]
)
def test_transport_response_requires_sanitized_request_id(request_id: str) -> None:
    with pytest.raises(ValidationError):
        MainExactCasTransportResponse(
            http_status=200,
            payload={"ref": "refs/heads/main"},
            request_id=request_id,
        )


def test_transport_response_requires_request_id_for_delivered_response() -> None:
    with pytest.raises(ValidationError):
        MainExactCasTransportResponse.model_validate(
            {"http_status": 200, "payload": {"ref": "refs/heads/main"}}
        )


def test_receipt_binds_and_sanitizes_delivered_request_id() -> None:
    receipt = writer(
        Transport((200, {"ref": "refs/heads/main", "object": {"sha": CANDIDATE}}))
    ).apply(intent())
    assert receipt.request_id == "req-test-123"
    for request_id in (None, "\nsecret"):
        with pytest.raises(ValidationError):
            MainExactCasReceipt.model_validate(
                {**receipt.model_dump(), "request_id": request_id}
            )


def test_invalid_bypassed_transport_request_id_is_ambiguous_without_leakage() -> None:
    response = MainExactCasTransportResponse.model_construct(
        http_status=200,
        payload={"secret": "do-not-persist"},
        request_id="\nsecret",
    )
    receipt = writer(Transport(response)).apply(intent())
    assert receipt.outcome == "ambiguous"
    assert receipt.error_code == "malformed_response"
    assert receipt.http_status is None
    assert "do-not-persist" not in repr(receipt.model_dump())
    assert "secret" not in repr(receipt.model_dump())


@pytest.mark.parametrize(
    "result", [(500, {}), (200, {}), (200, {"ref": "refs/heads/main", "object": {"sha": BASE}})]
)
def test_server_or_stale_response_is_ambiguous(result: object) -> None:
    receipt = writer(Transport(result)).apply(intent())
    assert receipt.outcome == "ambiguous"


@pytest.mark.parametrize(
    "field,value",
    [
        ("candidate_parents", (BASE, BASE)),
        ("candidate_ref_immutable", False),
        ("candidate_reachable", False),
        ("deploy_performed", True),
    ],
)
def test_binding_rejects_unsafe_topology_and_deploy(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        intent(**{field: value})


def test_writer_has_no_generic_force_surface() -> None:
    public = {name for name in dir(GitHubPersonalExactCasWriter) if not name.startswith("_")}
    assert "update_ref" not in public
    assert "force" not in public


def test_expired_durable_intent_replay_parses_but_dispatch_is_fenced() -> None:
    current = intent()
    assert current.lease_expires_at > NOW
    transport = Transport((200, {"ref": "refs/heads/main", "object": {"sha": CANDIDATE}}))
    receipt = writer(
        transport, trusted_clock=lambda: datetime(2030, 1, 3, tzinfo=UTC)
    ).apply(current)
    assert receipt.outcome == "rejected"
    assert receipt.error_code == "lease_expired"
    assert not transport.calls


@pytest.mark.parametrize(
    "verifier",
    [
        lambda _intent: False,
        lambda _intent: None,
        lambda _intent: (_ for _ in ()).throw(RuntimeError("secret")),
    ],
)
def test_dispatch_verifier_must_return_true_and_never_leaks_exception(verifier: Any) -> None:
    transport = Transport((200, {"ref": "refs/heads/main", "object": {"sha": CANDIDATE}}))
    receipt = writer(transport, dispatch_verifier=verifier).apply(intent())
    assert receipt.outcome == "rejected"
    assert receipt.error_code == "verifier_rejected"
    assert "secret" not in repr(receipt.model_dump())
    assert not transport.calls


def test_writer_requires_token_and_rejects_authorization_dto() -> None:
    with pytest.raises(ValueError):
        GitHubPersonalExactCasWriter(
            "avo-org", "avo", github_repository_digest("avo-org", "avo"),
            transport=Transport((200, {})), dispatch_verifier=lambda _intent: True,
            reconciliation_verifier=lambda _receipt, _observation: True,
            trusted_clock=lambda: NOW, writer_app_id=42, writer_installation_id=43,
            writer_identity="personal-cas-installation", token="",
        )

    with pytest.raises(TypeError):
        GitHubPersonalExactCasWriter(
            "avo-org", "avo", github_repository_digest("avo-org", "avo"),
            transport=Transport((200, {})), dispatch_verifier=lambda _intent: True,
            reconciliation_verifier=lambda _receipt, _observation: True,
            trusted_clock=lambda: NOW, writer_app_id=42, writer_installation_id=43,
            writer_identity="personal-cas-installation", token="secret",
        ).apply(MainExactCasAuthorization.model_construct())


def test_post_state_requires_exact_candidate_topology_for_applied() -> None:
    current = intent()
    values: dict[str, Any] = {
        **{
            key: value
            for key, value in current.model_dump(mode="python").items()
            if key in MainExactCasPostStateObservation.model_fields
        },
        "authorization_digest": current.authorization_digest,
        "intent_digest": current.intent_digest,
        "receipt_digest": D,
        "receipt_outcome": "applied",
        "observed_ref": "refs/heads/main",
        "observed_commit": CANDIDATE,
        "observed_tree": CANDIDATE_TREE,
        "observed_parents": (BASE,),
        "observed_at": NOW,
        "observation_digest": "sha256:" + "0" * 64,
    }
    probe = MainExactCasPostStateObservation.model_construct(**values)
    values["observation_digest"] = canonical_digest(
        probe.model_dump(exclude={"observation_digest"}, mode="json")
    )
    observation = MainExactCasPostStateObservation.model_validate(values)
    assert observation.observed_commit == CANDIDATE
    with pytest.raises(ValidationError):
        MainExactCasPostStateObservation.model_validate(
            {**values, "observed_tree": TREE}
        )


@pytest.mark.parametrize("status", [401, 403, 429])
def test_terminal_auth_and_rate_limit_statuses_are_classified(status: int) -> None:
    receipt = writer(Transport((status, {}))).apply(intent())
    assert receipt.outcome == "rejected"
    assert receipt.http_status == status
    assert receipt.error_code in {"auth_failed", "rate_limited"}


def test_ambiguous_receipt_can_only_be_applied_by_verified_exact_topology() -> None:
    current = intent()
    receipt = writer(Transport((500, {}))).apply(current)
    assert receipt.outcome == "ambiguous"
    observation_values: dict[str, Any] = {
        "operation_id": receipt.operation_id,
        "repository_digest": receipt.repository_digest,
        "target_ref": receipt.target_ref,
        "observed_ref": receipt.target_ref,
        "base_commit": receipt.base_commit,
        "base_tree": receipt.base_tree,
        "candidate_commit": receipt.candidate_commit,
        "candidate_tree": receipt.candidate_tree,
        "observed_commit": receipt.candidate_commit,
        "observed_tree": receipt.candidate_tree,
        "observed_parents": (receipt.base_commit,),
        "observed_at": NOW,
        "observation_digest": "sha256:" + "0" * 64,
    }
    probe = MainExactCasTopologyObservation.model_construct(**observation_values)
    observation_values["observation_digest"] = canonical_digest(
        probe.model_dump(exclude={"observation_digest"}, mode="json")
    )
    observation = MainExactCasTopologyObservation.model_validate(observation_values)
    reconciliation = writer(Transport((500, {}))).reconcile(receipt, observation)
    assert reconciliation.outcome == "applied"
    assert reconciliation.ambiguous_receipt.receipt_digest == receipt.receipt_digest


def test_authorization_is_not_an_intent_even_when_structurally_similar() -> None:
    assert not isinstance(intent(), MainExactCasAuthorization)
