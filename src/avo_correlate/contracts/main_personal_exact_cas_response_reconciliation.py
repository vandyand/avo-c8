"""Non-authoritative classification of a durable personal CAS response.

This contract deliberately contains neither post-state nor receipt fields.
It records only that a response was observed, was conclusively rejected, or
still requires reconciliation.  It cannot assert that ``main`` changed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, cast

from pydantic import Field, StrictInt, field_validator, model_validator

from avo_correlate.contracts.base import NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.contracts.main_personal_exact_cas import MainRef
from avo_correlate.domain.canonical import canonical_digest

MainPersonalExactCasResponseReconciliationClassificationKind = Literal[
    "candidate_observed", "conclusive_rejection_observed", "reconciliation_required"
]
_RESPONSE_CLASSES = frozenset(
    {
        "candidate_response",
        "conflict_or_rejected",
        "configuration_or_validation_rejected",
        "authentication_or_authorization_rejected",
        "rate_limited",
        "ambiguous",
        "unverifiable",
    }
)
_CLASSIFICATION_BY_RESPONSE = {
    "candidate_response": "candidate_observed",
    "conflict_or_rejected": "conclusive_rejection_observed",
    "configuration_or_validation_rejected": "conclusive_rejection_observed",
    "authentication_or_authorization_rejected": "conclusive_rejection_observed",
}


def _aware(value: datetime) -> datetime:
    if type(value) is not datetime:
        raise ValueError("classification timestamp must be timezone-aware")
    failed = False
    try:
        tzinfo = value.tzinfo
        offset = value.utcoffset()
    except Exception:
        failed = True
        tzinfo = None
        offset = None
    if failed or tzinfo is None or offset is None:
        raise ValueError("classification timestamp must be timezone-aware")
    return value


class MainPersonalExactCasResponseReconciliationClassification(StrictModel):
    """Durable response classification; never terminal or authoritative."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"
    writer_app_id: StrictInt = Field(gt=0)
    writer_installation_id: StrictInt = Field(gt=0)
    writer_identity: NonEmptyString
    intent_digest: Sha256Digest
    dispatch_marker_digest: Sha256Digest
    response_evidence_digest: Sha256Digest
    response_status: StrictInt = Field(ge=100, le=599)
    response_classification: str
    classification: MainPersonalExactCasResponseReconciliationClassificationKind
    classified_at: datetime
    is_terminal: Literal[False] = False
    is_authoritative: Literal[False] = False
    classification_digest: Sha256Digest

    _aware_classified_at = field_validator("classified_at")(_aware)

    @model_validator(mode="after")
    def validate_classification(
        self,
    ) -> MainPersonalExactCasResponseReconciliationClassification:
        if self.target_ref != "refs/heads/main":
            raise ValueError("classification target is not exact main")
        if self.response_classification not in _RESPONSE_CLASSES:
            raise ValueError("response classification is not approved")
        if (
            _CLASSIFICATION_BY_RESPONSE.get(self.response_classification, "reconciliation_required")
            != self.classification
        ):
            raise ValueError("response classification mapping differs")
        if self.classification_digest != canonical_digest(
            self.model_dump(exclude={"classification_digest"}, mode="json")
        ):
            raise ValueError("response classification digest mismatch")
        return self

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasResponseReconciliationClassification:
        zero = "sha256:" + "0" * 64
        probe = cast(
            MainPersonalExactCasResponseReconciliationClassification,
            cast(Any, cls).model_construct(**dict(values, classification_digest=zero)),
        )
        digest = canonical_digest(probe.model_dump(exclude={"classification_digest"}, mode="json"))
        return cast(
            MainPersonalExactCasResponseReconciliationClassification,
            cls.model_validate(dict(values, classification_digest=digest)),
        )


__all__ = [
    "MainPersonalExactCasResponseReconciliationClassification",
    "MainPersonalExactCasResponseReconciliationClassificationKind",
]
