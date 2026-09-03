# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportAttributeAccessIssue=false, reportUnnecessaryIsInstance=false

"""Durable, non-authoritative evidence bundle for personal main exact-CAS.

This adapter composes the existing response-evidence and read-only post-state
journals. It is deliberately not an authority verifier: a provider response
or a post-state DTO can only become evidence in the two journals, never a
receipt, completion, or permission to mutate ``main``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, TypeVar, cast

from avo_correlate.adapters.artifacts.main_personal_exact_cas_journal import (
    MainPersonalExactCasJournal,
    MainPersonalExactCasJournalError,
)
from avo_correlate.adapters.artifacts.main_personal_exact_cas_post_state import (
    MainPersonalExactCasPostStateJournalError,
    MainPersonalExactCasReadOnlyPostStateJournal,
)
from avo_correlate.adapters.artifacts.main_personal_exact_cas_response_evidence import (
    MainPersonalExactCasResponseEvidenceJournal,
    MainPersonalExactCasResponseEvidenceJournalError,
)
from avo_correlate.contracts.base import ArtifactRef, Sha256Digest, StrictModel
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

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class MainPersonalExactCasEvidenceBundleError(RuntimeError):
    """Value-free failure to compose or revalidate the evidence bundle."""

    def __init__(self, code: str = "evidence_bundle_unresolved") -> None:
        self.code = (
            code
            if code in {"evidence_bundle_unresolved", "authority_chain_changed"}
            else "evidence_bundle_unresolved"
        )
        super().__init__(self.code)

    def __repr__(self) -> str:
        return f"MainPersonalExactCasEvidenceBundleError({self.code!r})"


_T = TypeVar("_T", bound=StrictModel)


def _canonical_exact(value: object, expected: type[StrictModel]) -> StrictModel:
    """Reparse an exact contract and reject model-copy or noncanonical values."""

    if type(value) is not expected:
        raise ValueError("evidence bundle contract type differs")
    checked = expected.model_validate_json(canonical_bytes(value))
    if type(checked) is not expected or canonical_bytes(checked) != canonical_bytes(value):
        raise ValueError("evidence bundle contract is not canonical")
    return checked


@dataclass(frozen=True, slots=True)
class MainPersonalExactCasEvidenceBundle:
    """Durable evidence references; this record has no authority semantics."""

    operation_id: Sha256Digest
    response_evidence: MainPersonalExactCasResponseEvidence
    response_evidence_artifact: ArtifactRef
    post_state: MainPersonalExactCasReadOnlyPostState
    post_state_artifact: ArtifactRef
    is_authoritative: Literal[False] = False
    is_terminal: Literal[False] = False
    readiness_authorized: Literal[False] = False
    deploy_performed: Literal[False] = False
    bundle_digest: Sha256Digest = ""

    def __post_init__(self) -> None:
        response_evidence = _canonical_exact(
            self.response_evidence, MainPersonalExactCasResponseEvidence
        )
        response_ref = _canonical_exact(self.response_evidence_artifact, ArtifactRef)
        post_state = _canonical_exact(self.post_state, MainPersonalExactCasReadOnlyPostState)
        post_ref = _canonical_exact(self.post_state_artifact, ArtifactRef)
        if not _DIGEST.fullmatch(self.operation_id):
            raise ValueError("evidence bundle operation is malformed")
        if (
            response_evidence.operation_id != self.operation_id
            or post_state.operation_id != self.operation_id
            or self.is_authoritative is not False
            or self.is_terminal is not False
            or self.readiness_authorized is not False
            or self.deploy_performed is not False
            or response_evidence.is_authoritative is not False
            or response_evidence.is_terminal is not False
            or post_state.is_authoritative is not False
            or post_state.is_terminal is not False
            or type(response_evidence.response_payload_artifact) is not ArtifactRef
            or response_ref.digest != canonical_digest(response_evidence)
            or response_ref.role != "main-personal-exact-cas-response-evidence"
            or response_ref.media_type
            != "application/vnd.avo.main-personal-exact-cas-response-evidence+json"
            or response_ref.size_bytes != len(canonical_bytes(response_evidence))
            or post_ref.digest != canonical_digest(post_state)
            or post_ref.role != "main-personal-exact-cas-post-state"
            or post_ref.media_type != "application/vnd.avo.main-personal-exact-cas-post-state+json"
            or post_ref.size_bytes != len(canonical_bytes(post_state))
            or post_ref.created_at != post_state.finished_at
            or response_evidence.response_payload_artifact.role
            != "main-personal-exact-cas-response"
            or response_evidence.response_payload_artifact.media_type
            != "application/vnd.avo.main-personal-exact-cas-response+json"
            or response_evidence.response_payload_artifact.created_at
            != response_evidence.observed_at
        ):
            raise ValueError("evidence bundle scope differs")
        expected = canonical_digest(self._digest_values())
        if self.bundle_digest != expected:
            raise ValueError("evidence bundle digest mismatch")

    def _digest_values(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "response_evidence_digest": self.response_evidence.evidence_digest,
            "response_evidence_artifact": self.response_evidence_artifact,
            "post_state_digest": self.post_state.observation_digest,
            "post_state_artifact": self.post_state_artifact,
            "is_authoritative": False,
            "is_terminal": False,
            "readiness_authorized": False,
            "deploy_performed": False,
        }

    @classmethod
    def build(
        cls,
        *,
        operation_id: Sha256Digest,
        response_evidence: MainPersonalExactCasResponseEvidence,
        response_evidence_artifact: ArtifactRef,
        post_state: MainPersonalExactCasReadOnlyPostState,
        post_state_artifact: ArtifactRef,
    ) -> MainPersonalExactCasEvidenceBundle:
        digest = canonical_digest(
            {
                "operation_id": operation_id,
                "response_evidence_digest": response_evidence.evidence_digest,
                "response_evidence_artifact": response_evidence_artifact,
                "post_state_digest": post_state.observation_digest,
                "post_state_artifact": post_state_artifact,
                "is_authoritative": False,
                "is_terminal": False,
                "readiness_authorized": False,
                "deploy_performed": False,
            }
        )
        return cls(
            operation_id=operation_id,
            response_evidence=response_evidence,
            response_evidence_artifact=response_evidence_artifact,
            post_state=post_state,
            post_state_artifact=post_state_artifact,
            bundle_digest=digest,
        )


class MainPersonalExactCasEvidenceBundleAdapter:
    """Compose two durable observations while preserving nonterminal status."""

    def __init__(
        self,
        *,
        authority_journal: MainPersonalExactCasJournal,
        response_evidence_journal: MainPersonalExactCasResponseEvidenceJournal,
        post_state_journal: MainPersonalExactCasReadOnlyPostStateJournal,
    ) -> None:
        if type(authority_journal) is not MainPersonalExactCasJournal:
            raise ValueError("exact-CAS authority journal is required")
        if type(response_evidence_journal) is not MainPersonalExactCasResponseEvidenceJournal:
            raise ValueError("exact-CAS response evidence journal is required")
        if type(post_state_journal) is not MainPersonalExactCasReadOnlyPostStateJournal:
            raise ValueError("exact-CAS post-state journal is required")
        self._authority = authority_journal
        self._response = response_evidence_journal
        self._post_state = post_state_journal

    def compose(self, operation_id: Sha256Digest) -> MainPersonalExactCasEvidenceBundle:
        """Compose a bundle from existing records without invoking a provider."""

        if type(operation_id) is not str or _DIGEST.fullmatch(operation_id) is None:
            raise MainPersonalExactCasEvidenceBundleError()
        try:
            intent, marker = self._authority_chain(operation_id)
            response = self._response.read_response_evidence(operation_id)
            post_state = self._post_state.read(operation_id)
            if response is None or post_state is None:
                raise MainPersonalExactCasEvidenceBundleError()
            self._assert_chain(operation_id, intent, marker)
            return self._bundle(operation_id, intent, marker, response, post_state)
        except MainPersonalExactCasEvidenceBundleError:
            raise
        except (
            MainPersonalExactCasJournalError,
            MainPersonalExactCasResponseEvidenceJournalError,
            MainPersonalExactCasPostStateJournalError,
            ValueError,
            TypeError,
            KeyError,
        ) as exc:
            del exc
            raise MainPersonalExactCasEvidenceBundleError() from None
        except Exception:
            raise MainPersonalExactCasEvidenceBundleError() from None

    def _authority_chain(
        self, operation_id: Sha256Digest
    ) -> tuple[MainPersonalExactCasIntent, MainPersonalExactCasDispatchStarted]:
        intent = self._read_authority("read_intent", operation_id, MainPersonalExactCasIntent)
        marker = self._read_authority(
            "read_dispatch_started", operation_id, MainPersonalExactCasDispatchStarted
        )
        if (
            intent.operation_id != operation_id
            or marker.operation_id != operation_id
            or marker.intent_digest != intent.intent_digest
        ):
            raise MainPersonalExactCasEvidenceBundleError("authority_chain_changed")
        return intent, marker

    def _assert_chain(
        self,
        operation_id: Sha256Digest,
        intent: MainPersonalExactCasIntent,
        marker: MainPersonalExactCasDispatchStarted,
    ) -> None:
        current_intent, current_marker = self._authority_chain(operation_id)
        if canonical_bytes(current_intent) != canonical_bytes(intent) or canonical_bytes(
            current_marker
        ) != canonical_bytes(marker):
            raise MainPersonalExactCasEvidenceBundleError("authority_chain_changed")

    def _read_authority(
        self, method: str, operation_id: Sha256Digest, expected: type[_T]
    ) -> _T:
        result = getattr(self._authority, method)(operation_id)
        if not isinstance(result, tuple) or len(result) != 2:
            raise ValueError("authority record shape differs")
        candidate = result[0]
        reference = result[1]
        kind = method.removeprefix("read_").replace("_", "-")
        if type(candidate) is not expected:
            raise ValueError("authority record type differs")
        if type(reference) is not ArtifactRef:
            raise ValueError("authority reference type differs")
        checked = expected.model_validate_json(canonical_bytes(candidate))
        checked_reference = ArtifactRef.model_validate_json(canonical_bytes(reference))
        if (
            type(checked) is not expected
            or canonical_bytes(checked) != canonical_bytes(candidate)
            or canonical_bytes(checked_reference) != canonical_bytes(reference)
            or reference.digest != canonical_digest(candidate)
            or reference.role != f"main-personal-exact-cas-{kind}"
            or reference.media_type
            != f"application/vnd.avo.main-personal-exact-cas-{kind}+json"
            or reference.size_bytes != len(canonical_bytes(candidate))
        ):
            raise ValueError("authority record canonicality differs")
        return cast(_T, checked)

    def _bundle(
        self,
        operation_id: Sha256Digest,
        intent: MainPersonalExactCasIntent,
        marker: MainPersonalExactCasDispatchStarted,
        response: tuple[MainPersonalExactCasResponseEvidence, ArtifactRef],
        post_state: tuple[MainPersonalExactCasReadOnlyPostState, ArtifactRef],
    ) -> MainPersonalExactCasEvidenceBundle:
        response_evidence_raw, response_ref_raw = response
        observation_raw, post_ref_raw = post_state
        response_evidence = self._checked_model(
            response_evidence_raw, MainPersonalExactCasResponseEvidence
        )
        response_ref = self._checked_model(response_ref_raw, ArtifactRef)
        observation = self._checked_model(observation_raw, MainPersonalExactCasReadOnlyPostState)
        post_ref = self._checked_model(post_ref_raw, ArtifactRef)
        if (
            response_evidence.operation_id != operation_id
            or response_evidence.intent_digest != intent.intent_digest
            or response_evidence.dispatch_marker_digest != marker.dispatch_marker_digest
            or response_evidence.repository_digest != intent.repository_digest
            or response_evidence.target_ref != intent.target_ref
            or response_evidence.writer_app_id != intent.writer_app_id
            or response_evidence.writer_installation_id != intent.writer_installation_id
            or response_evidence.writer_identity != intent.writer_identity
            or response_evidence.candidate_commit != intent.candidate_commit
            or observation.operation_id != operation_id
            or observation.intent_digest != intent.intent_digest
            or observation.repository_digest != intent.repository_digest
            or observation.target_ref != intent.target_ref
            or observation.observed_ref != intent.target_ref
            or observation.base_commit != intent.base_commit
            or observation.candidate_commit != intent.candidate_commit
            or response_evidence.observed_at < marker.started_at
            or observation.started_at < marker.started_at
            or observation.is_authoritative is not False
            or observation.is_terminal is not False
            or response_evidence.is_authoritative is not False
            or response_evidence.is_terminal is not False
            or response_ref.digest != canonical_digest(response_evidence)
            or post_ref.digest != canonical_digest(observation)
            or response_ref.role != "main-personal-exact-cas-response-evidence"
            or response_ref.media_type
            != "application/vnd.avo.main-personal-exact-cas-response-evidence+json"
            or response_ref.size_bytes != len(canonical_bytes(response_evidence))
            or post_ref.role != "main-personal-exact-cas-post-state"
            or post_ref.media_type != "application/vnd.avo.main-personal-exact-cas-post-state+json"
            or post_ref.size_bytes != len(canonical_bytes(observation))
            or post_ref.created_at != observation.finished_at
            or response_evidence.response_payload_artifact.role
            != "main-personal-exact-cas-response"
            or response_evidence.response_payload_artifact.media_type
            != "application/vnd.avo.main-personal-exact-cas-response+json"
            or response_evidence.response_payload_artifact.created_at
            != response_evidence.observed_at
        ):
            raise MainPersonalExactCasEvidenceBundleError("authority_chain_changed")
        return MainPersonalExactCasEvidenceBundle.build(
            operation_id=operation_id,
            response_evidence=response_evidence,
            response_evidence_artifact=response_ref,
            post_state=observation,
            post_state_artifact=post_ref,
        )

    @staticmethod
    def _checked_model(value: object, expected: type[_T]) -> _T:
        if type(value) is not expected:
            raise MainPersonalExactCasEvidenceBundleError("authority_chain_changed")
        checked = expected.model_validate_json(canonical_bytes(value))
        if type(checked) is not expected or canonical_bytes(checked) != canonical_bytes(value):
            raise MainPersonalExactCasEvidenceBundleError("authority_chain_changed")
        return cast(_T, checked)


__all__ = [
    "MainPersonalExactCasEvidenceBundle",
    "MainPersonalExactCasEvidenceBundleAdapter",
    "MainPersonalExactCasEvidenceBundleError",
]
