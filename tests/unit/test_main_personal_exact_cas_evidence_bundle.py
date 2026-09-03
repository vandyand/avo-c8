"""Offline checks for the non-authoritative exact-CAS evidence bundle."""

# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportMissingImports=false, reportUntypedFunctionDecorator=false

from __future__ import annotations

import inspect
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import pytest

from avo_correlate.adapters.artifacts import (
    main_personal_exact_cas_evidence_bundle as bundle_module,
)
from avo_correlate.adapters.artifacts.main_personal_exact_cas_evidence_bundle import (
    MainPersonalExactCasEvidenceBundle,
    MainPersonalExactCasEvidenceBundleAdapter,
    MainPersonalExactCasEvidenceBundleError,
)
from avo_correlate.adapters.artifacts.main_personal_exact_cas_journal import (
    MainPersonalExactCasJournal,
)
from avo_correlate.adapters.artifacts.main_personal_exact_cas_post_state import (
    MainPersonalExactCasReadOnlyPostStateJournal,
)
from avo_correlate.adapters.artifacts.main_personal_exact_cas_response_evidence import (
    MainPersonalExactCasResponseEvidenceJournal,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_personal_exact_cas import (
    MainPersonalExactCasDispatchStarted,
    MainPersonalExactCasIntent,
)
from avo_correlate.contracts.main_personal_exact_cas_post_state import (
    MainPersonalExactCasReadOnlyPostState,
)
from avo_correlate.contracts.main_personal_exact_cas_response_evidence import (
    MainPersonalExactCasResponseEvidence,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_main_personal_exact_cas_response_evidence import _chain, _observation


def _artifact(
    *, digest: str, role: str, media_type: str, created_at: datetime, size: int
) -> ArtifactRef:
    return ArtifactRef(
        digest=digest,
        size_bytes=size,
        media_type=media_type,
        role=role,
        created_at=created_at,
    )


def _authority_ref(model: object, *, role: str) -> ArtifactRef:
    timestamp = getattr(model, "recorded_at", None)
    if timestamp is None:
        timestamp = model.started_at
    return _artifact(
        digest=canonical_digest(model),
        role=role,
        media_type=f"application/vnd.avo.{role}+json",
        created_at=timestamp,
        size=len(canonical_bytes(model)),
    )


class _AuthorityReader:
    def __init__(
        self, intent: MainPersonalExactCasIntent, marker: MainPersonalExactCasDispatchStarted
    ):
        self.intent = intent
        self.marker = marker

    def read_intent(self, operation_id: str) -> tuple[MainPersonalExactCasIntent, ArtifactRef]:
        del operation_id
        return self.intent, _authority_ref(
            self.intent, role="main-personal-exact-cas-intent"
        )

    def read_dispatch_started(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasDispatchStarted, ArtifactRef]:
        del operation_id
        return self.marker, _authority_ref(
            self.marker, role="main-personal-exact-cas-dispatch-started"
        )


class _ResponseReader:
    def __init__(self, value: tuple[MainPersonalExactCasResponseEvidence, ArtifactRef] | None):
        self.value = value
        self.read_calls = 0
        self.record_calls = 0

    def read_response_evidence(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasResponseEvidence, ArtifactRef] | None:
        self.read_calls += 1
        if self.value is not None and self.value[0].operation_id != operation_id:
            return None
        return self.value


class _PostStateReader:
    def __init__(self, value: tuple[MainPersonalExactCasReadOnlyPostState, ArtifactRef] | None):
        self.value = value
        self.read_calls = 0
        self.capture_calls = 0

    def read(
        self, operation_id: str
    ) -> tuple[MainPersonalExactCasReadOnlyPostState, ArtifactRef] | None:
        self.read_calls += 1
        if self.value is not None and self.value[0].operation_id != operation_id:
            return None
        return self.value


def _as_exact_journal(cls: type[Any], reader: object) -> Any:
    """Install only read methods on an exact journal instance for offline tests."""

    result = object.__new__(cls)
    for name in ("read_intent", "read_dispatch_started", "read_response_evidence", "read"):
        method = getattr(reader, name, None)
        if method is not None:
            setattr(result, name, method)
    return result


def _durable_records(
    intent: MainPersonalExactCasIntent, marker: MainPersonalExactCasDispatchStarted
) -> tuple[
    tuple[MainPersonalExactCasResponseEvidence, ArtifactRef],
    tuple[MainPersonalExactCasReadOnlyPostState, ArtifactRef],
]:
    source = _observation(intent, marker)
    payload = cast(bytes, source.payload_bytes)
    payload_ref = _artifact(
        digest=cast(str, source.payload_digest),
        role="main-personal-exact-cas-response",
        media_type="application/vnd.avo.main-personal-exact-cas-response+json",
        created_at=source.observed_at,
        size=len(payload),
    )
    evidence = MainPersonalExactCasResponseEvidence.build(
        operation_id=intent.operation_id,
        repository_digest=intent.repository_digest,
        target_ref=intent.target_ref,
        writer_app_id=intent.writer_app_id,
        writer_installation_id=intent.writer_installation_id,
        writer_identity=intent.writer_identity,
        intent_digest=intent.intent_digest,
        dispatch_marker_digest=marker.dispatch_marker_digest,
        candidate_commit=intent.candidate_commit,
        request_digest=canonical_digest(
            {
                "repository_digest": intent.repository_digest,
                "target_ref": intent.target_ref,
                "method": "PATCH",
                "candidate_sha": intent.candidate_commit,
                "force": False,
            }
        ),
        response_status=source.status,
        response_classification=source.classification,
        response_request_id=source.request_id,
        response_metadata=dict(source.metadata),
        response_metadata_digest=canonical_digest(dict(source.metadata)),
        response_payload_artifact=payload_ref,
        observed_at=source.observed_at,
    )
    evidence_ref = _artifact(
        digest=canonical_digest(evidence),
        role="main-personal-exact-cas-response-evidence",
        media_type="application/vnd.avo.main-personal-exact-cas-response-evidence+json",
        # The filesystem journal's object publication time may differ from
        # the provider observation time; the digest/role/media/size bind it.
        created_at=evidence.observed_at + timedelta(milliseconds=1),
        size=len(canonical_bytes(evidence)),
    )
    started_at = marker.started_at + timedelta(seconds=1)
    finished_at = marker.started_at + timedelta(seconds=2)
    post_state = MainPersonalExactCasReadOnlyPostState.build(
        operation_id=intent.operation_id,
        intent_digest=intent.intent_digest,
        repository_digest=intent.repository_digest,
        owner="fixture",
        repository="repo",
        target_ref=intent.target_ref,
        observed_ref=intent.target_ref,
        base_commit=intent.base_commit,
        candidate_commit=intent.candidate_commit,
        observed_commit=intent.candidate_commit,
        observed_tree=intent.candidate_tree,
        observed_parents=(intent.base_commit,),
        response_ref_digest=canonical_digest({"ref": "main"}),
        response_commit_digest=canonical_digest({"commit": intent.candidate_commit}),
        response_fence_digest=canonical_digest({"fence": "main"}),
        started_at=started_at,
        finished_at=finished_at,
    )
    post_ref = _artifact(
        digest=canonical_digest(post_state),
        role="main-personal-exact-cas-post-state",
        media_type="application/vnd.avo.main-personal-exact-cas-post-state+json",
        created_at=post_state.finished_at,
        size=len(canonical_bytes(post_state)),
    )
    return (evidence, evidence_ref), (post_state, post_ref)


def _adapter() -> tuple[
    Any, _AuthorityReader, _ResponseReader, _PostStateReader, MainPersonalExactCasIntent
]:
    intent, marker = _chain()
    response_value, post_value = _durable_records(intent, marker)
    authority = _AuthorityReader(intent, marker)
    response_reader = _ResponseReader(response_value)
    post_reader = _PostStateReader(post_value)
    adapter = MainPersonalExactCasEvidenceBundleAdapter(
        authority_journal=_as_exact_journal(MainPersonalExactCasJournal, authority),
        response_evidence_journal=_as_exact_journal(
            MainPersonalExactCasResponseEvidenceJournal, response_reader
        ),
        post_state_journal=_as_exact_journal(
            MainPersonalExactCasReadOnlyPostStateJournal, post_reader
        ),
    )
    return adapter, authority, response_reader, post_reader, intent


def test_compose_binds_complete_durable_records_and_is_non_authoritative() -> None:
    adapter, _authority, response, post_state, intent = _adapter()

    result = adapter.compose(intent.operation_id)

    assert result.operation_id == intent.operation_id
    assert result.response_evidence.intent_digest == intent.intent_digest
    assert result.response_evidence.dispatch_marker_digest
    assert result.response_evidence_artifact.digest == canonical_digest(result.response_evidence)
    assert result.post_state.intent_digest == intent.intent_digest
    assert result.post_state_artifact.digest == canonical_digest(result.post_state)
    assert result.is_authoritative is False
    assert result.is_terminal is False
    assert result.readiness_authorized is False
    assert result.deploy_performed is False
    assert response.record_calls == 0
    assert post_state.capture_calls == 0


def test_replay_reads_durable_records_with_zero_network_or_publication() -> None:
    adapter, _authority, response, post_state, intent = _adapter()

    first = adapter.compose(intent.operation_id)
    second = adapter.compose(intent.operation_id)

    assert second == first
    assert response.record_calls == 0
    assert post_state.capture_calls == 0
    assert response.read_calls == 2
    assert post_state.read_calls == 2


def test_public_surface_has_no_provider_exchange_capture_or_writer_path() -> None:
    adapter, _authority, _response, _post_state, _intent = _adapter()
    public = {name for name in dir(adapter) if not name.startswith("_")}
    assert public == {"compose"}
    source = inspect.getsource(bundle_module)
    for forbidden in (
        "MainPersonalExactCasGitHubTransport",
        "MainPersonalExactCasController",
        ".exchange(",
        ".capture(",
        ".apply(",
    ):
        assert forbidden not in source


def test_missing_response_record_fails_closed() -> None:
    adapter, _authority, response, post_state, intent = _adapter()
    response.value = None

    with pytest.raises(MainPersonalExactCasEvidenceBundleError):
        adapter.compose(intent.operation_id)

    assert response.record_calls == 0
    assert post_state.capture_calls == 0


def test_missing_post_state_record_fails_closed() -> None:
    adapter, _authority, response, post_state, intent = _adapter()
    post_state.value = None

    with pytest.raises(MainPersonalExactCasEvidenceBundleError):
        adapter.compose(intent.operation_id)

    assert response.record_calls == 0
    assert post_state.capture_calls == 0


def test_malformed_authority_chain_fails_closed_before_leaf_reads() -> None:
    adapter, authority, response, post_state, intent = _adapter()
    authority.marker = cast(Any, SimpleNamespace(intent_digest="malformed"))

    with pytest.raises(MainPersonalExactCasEvidenceBundleError):
        adapter.compose(intent.operation_id)

    assert response.read_calls == 0
    assert post_state.read_calls == 0


def test_requested_operation_mismatch_fails_closed_before_leaf_reads() -> None:
    adapter, _authority, response, post_state, _intent = _adapter()

    with pytest.raises(MainPersonalExactCasEvidenceBundleError):
        adapter.compose("sha256:" + "f" * 64)

    assert response.read_calls == 0
    assert post_state.read_calls == 0


def test_authority_chain_change_after_first_compose_fails_closed() -> None:
    adapter, authority, response, post_state, intent = _adapter()
    adapter.compose(intent.operation_id)
    authority.marker = authority.marker.model_copy(update={"claim_nonce": "changed"})

    with pytest.raises(MainPersonalExactCasEvidenceBundleError):
        adapter.compose(intent.operation_id)

    assert response.read_calls == 1
    assert post_state.read_calls == 1


def test_model_copy_tampered_evidence_fails_closed() -> None:
    adapter, _authority, response, _post_state, intent = _adapter()
    assert response.value is not None
    evidence, reference = response.value
    response.value = (evidence.model_copy(update={"response_status": 409}), reference)

    with pytest.raises(MainPersonalExactCasEvidenceBundleError):
        adapter.compose(intent.operation_id)


def test_public_bundle_build_rejects_model_copy_tamper_with_stale_digest() -> None:
    adapter, _authority, _response, _post_state, intent = _adapter()
    valid = adapter.compose(intent.operation_id)
    tampered = valid.response_evidence.model_copy(update={"response_status": 409})

    with pytest.raises(ValueError):
        MainPersonalExactCasEvidenceBundle.build(
            operation_id=valid.operation_id,
            response_evidence=tampered,
            response_evidence_artifact=valid.response_evidence_artifact,
            post_state=valid.post_state,
            post_state_artifact=valid.post_state_artifact,
        )


def test_wrong_role_reference_fails_closed() -> None:
    adapter, _authority, response, _post_state, intent = _adapter()
    assert response.value is not None
    evidence, reference = response.value
    response.value = (evidence, reference.model_copy(update={"role": "wrong-role"}))

    with pytest.raises(MainPersonalExactCasEvidenceBundleError):
        adapter.compose(intent.operation_id)


class _ForgedAuthorityJournal(MainPersonalExactCasJournal):
    pass


class _ForgedResponseJournal(MainPersonalExactCasResponseEvidenceJournal):
    pass


class _ForgedPostStateJournal(MainPersonalExactCasReadOnlyPostStateJournal):
    pass


@pytest.mark.parametrize(
    "journal_type",
    [
        _ForgedAuthorityJournal,
        _ForgedResponseJournal,
        _ForgedPostStateJournal,
    ],
)
def test_forged_journal_subclasses_are_rejected(journal_type: type[Any]) -> None:
    adapter, _authority, _response, _post_state, _intent = _adapter()
    exact_authority = adapter._authority
    exact_response = adapter._response
    exact_post_state = adapter._post_state
    forged = object.__new__(journal_type)

    with pytest.raises(ValueError):
        MainPersonalExactCasEvidenceBundleAdapter(
            authority_journal=(
                forged if journal_type is _ForgedAuthorityJournal else exact_authority
            ),
            response_evidence_journal=(
                forged if journal_type is _ForgedResponseJournal else exact_response
            ),
            post_state_journal=(
                forged if journal_type is _ForgedPostStateJournal else exact_post_state
            ),
        )
