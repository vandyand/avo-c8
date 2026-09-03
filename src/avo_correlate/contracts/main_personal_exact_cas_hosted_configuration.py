"""Non-authoritative diagnostic for the personal exact-CAS hosted boundary."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Literal, cast

from pydantic import Field, StrictInt, field_validator, model_validator

from avo_correlate.contracts.base import NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.contracts.main_personal_exact_cas import GitObject, MainRef
from avo_correlate.domain.canonical import canonical_digest

_ZERO = "sha256:" + "0" * 64
_OWNER = "vandyand"
_REPOSITORY = "avo-c8"
_REPOSITORY_ID = 1_354_880_741
_APP_SLUG = "avo-c8-main-writer-vandyand"


def _aware(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("hosted configuration timestamp must be timezone-aware")
    return value


class MainPersonalExactCasHostedConfigurationDiagnostic(StrictModel):
    """Exact matched configuration facts that grant no authority by themselves."""

    schema_version: Literal[1] = 1
    repository_digest: Sha256Digest
    owner: Literal["vandyand"] = _OWNER
    repository: Literal["avo-c8"] = _REPOSITORY
    repository_id: Literal[1_354_880_741] = _REPOSITORY_ID
    owner_id: StrictInt = Field(gt=0)
    owner_type: Literal["User"] = "User"
    visibility: Literal["public"] = "public"
    target_ref: MainRef = "refs/heads/main"
    main_commit: GitObject
    writer_ruleset_id: StrictInt = Field(gt=0)
    writer_ruleset_name: NonEmptyString
    safety_ruleset_id: StrictInt = Field(gt=0)
    safety_ruleset_name: NonEmptyString
    rollback_ruleset_id: StrictInt = Field(gt=0)
    rollback_ruleset_name: NonEmptyString
    writer_app_id: StrictInt = Field(gt=0)
    writer_app_slug: Literal["avo-c8-main-writer-vandyand"] = _APP_SLUG
    writer_app_name: Literal["avo-c8-main-writer-vandyand"] = _APP_SLUG
    writer_app_homepage: Literal["https://github.com/vandyand/avo-c8"] = (
        "https://github.com/vandyand/avo-c8"
    )
    writer_installation_id: StrictInt = Field(gt=0)
    repository_selection: Literal["selected"] = "selected"
    selected_repository_ids: tuple[StrictInt, ...]
    contents_permission: Literal["write"] = "write"
    metadata_permission: Literal["read"] = "read"
    subscribed_events: tuple[str, ...] = ()
    writer_ruleset_digest: Sha256Digest
    safety_ruleset_digest: Sha256Digest
    rollback_ruleset_digest: Sha256Digest
    branch_protection_digest: Sha256Digest
    app_configuration_digest: Sha256Digest
    installation_configuration_digest: Sha256Digest
    selected_repositories_digest: Sha256Digest
    protection_ruleset_digest: Sha256Digest
    configuration_digest: Sha256Digest
    initial_ref_digest: Sha256Digest
    first_pass_digest: Sha256Digest
    second_pass_digest: Sha256Digest
    final_ref_digest: Sha256Digest
    source_digest: Sha256Digest
    started_at: datetime
    finished_at: datetime
    verification_status: Literal["matched"] = "matched"
    is_authoritative: Literal[False] = False
    is_terminal: Literal[False] = False
    readiness_authorized: Literal[False] = False
    deploy_performed: Literal[False] = False
    observation_digest: Sha256Digest

    _aware_started_at = field_validator("started_at")(_aware)
    _aware_finished_at = field_validator("finished_at")(_aware)

    @model_validator(mode="after")
    def validate_diagnostic(self) -> MainPersonalExactCasHostedConfigurationDiagnostic:
        if self.started_at > self.finished_at or self.finished_at - self.started_at > timedelta(
            minutes=5
        ):
            raise ValueError("hosted configuration observation window is invalid")
        if len(
            {
                self.writer_ruleset_id,
                self.safety_ruleset_id,
                self.rollback_ruleset_id,
            }
        ) != 3:
            raise ValueError("hosted configuration ruleset identities overlap")
        if self.selected_repository_ids != (self.repository_id,):
            raise ValueError("hosted configuration selected repository is not exact")
        if self.subscribed_events:
            raise ValueError("hosted configuration App subscribes to events")
        if self.first_pass_digest != self.second_pass_digest:
            raise ValueError("hosted configuration changed between passes")
        expected_protection = canonical_digest(
            {
                "writer_ruleset": self.writer_ruleset_digest,
                "safety_ruleset": self.safety_ruleset_digest,
                "rollback_ruleset": self.rollback_ruleset_digest,
            }
        )
        if self.protection_ruleset_digest != expected_protection:
            raise ValueError("hosted configuration protection digest mismatch")
        expected_configuration = canonical_digest(
            {
                "repository_digest": self.repository_digest,
                "repository_id": self.repository_id,
                "owner_id": self.owner_id,
                "target_ref": self.target_ref,
                "writer_ruleset_id": self.writer_ruleset_id,
                "writer_ruleset_name": self.writer_ruleset_name,
                "safety_ruleset_id": self.safety_ruleset_id,
                "safety_ruleset_name": self.safety_ruleset_name,
                "rollback_ruleset_id": self.rollback_ruleset_id,
                "rollback_ruleset_name": self.rollback_ruleset_name,
                "writer_app_id": self.writer_app_id,
                "writer_installation_id": self.writer_installation_id,
                "writer_app_homepage": self.writer_app_homepage,
                "protection_ruleset_digest": self.protection_ruleset_digest,
                "branch_protection_digest": self.branch_protection_digest,
                "app_configuration_digest": self.app_configuration_digest,
                "installation_configuration_digest": self.installation_configuration_digest,
                "selected_repositories_digest": self.selected_repositories_digest,
            }
        )
        if self.configuration_digest != expected_configuration:
            raise ValueError("hosted configuration digest mismatch")
        expected_source = canonical_digest(
            {
                "initial_ref": self.initial_ref_digest,
                "configuration_pass_1": self.first_pass_digest,
                "configuration_pass_2": self.second_pass_digest,
                "final_ref": self.final_ref_digest,
            }
        )
        if self.source_digest != expected_source:
            raise ValueError("hosted configuration source digest mismatch")
        if self.observation_digest != canonical_digest(
            self.model_dump(exclude={"observation_digest"}, mode="json")
        ):
            raise ValueError("hosted configuration observation digest mismatch")
        return self

    @classmethod
    def build(cls, **values: object) -> MainPersonalExactCasHostedConfigurationDiagnostic:
        values = dict(values)
        values["protection_ruleset_digest"] = canonical_digest(
            {
                "writer_ruleset": values["writer_ruleset_digest"],
                "safety_ruleset": values["safety_ruleset_digest"],
                "rollback_ruleset": values["rollback_ruleset_digest"],
            }
        )
        values["configuration_digest"] = canonical_digest(
            {
                "repository_digest": values["repository_digest"],
                "repository_id": values["repository_id"],
                "owner_id": values["owner_id"],
                "target_ref": values.get("target_ref", "refs/heads/main"),
                "writer_ruleset_id": values["writer_ruleset_id"],
                "writer_ruleset_name": values["writer_ruleset_name"],
                "safety_ruleset_id": values["safety_ruleset_id"],
                "safety_ruleset_name": values["safety_ruleset_name"],
                "rollback_ruleset_id": values["rollback_ruleset_id"],
                "rollback_ruleset_name": values["rollback_ruleset_name"],
                "writer_app_id": values["writer_app_id"],
                "writer_installation_id": values["writer_installation_id"],
                "writer_app_homepage": values.get(
                    "writer_app_homepage", "https://github.com/vandyand/avo-c8"
                ),
                "protection_ruleset_digest": values["protection_ruleset_digest"],
                "branch_protection_digest": values["branch_protection_digest"],
                "app_configuration_digest": values["app_configuration_digest"],
                "installation_configuration_digest": values[
                    "installation_configuration_digest"
                ],
                "selected_repositories_digest": values["selected_repositories_digest"],
            }
        )
        values["source_digest"] = canonical_digest(
            {
                "initial_ref": values["initial_ref_digest"],
                "configuration_pass_1": values["first_pass_digest"],
                "configuration_pass_2": values["second_pass_digest"],
                "final_ref": values["final_ref_digest"],
            }
        )
        values["observation_digest"] = _ZERO
        probe = cast(Any, cls).model_construct(**values)
        digest = canonical_digest(probe.model_dump(exclude={"observation_digest"}, mode="json"))
        return cast(
            MainPersonalExactCasHostedConfigurationDiagnostic,
            cls.model_validate({**values, "observation_digest": digest}),
        )


__all__ = ["MainPersonalExactCasHostedConfigurationDiagnostic"]
