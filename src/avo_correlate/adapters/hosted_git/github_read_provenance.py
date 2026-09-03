"""Immutable, secret-free provenance for authenticated GitHub reads.

The records in this module describe the identity and shape of a read.  They
never contain bearer credentials or hashes of credential-bearing responses.
The digest is therefore stable when GitHub rotates a short-lived token while
remaining sensitive to any authenticated identity, scope, endpoint, or
observed ref/configuration change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, TypeVar

from avo_correlate.domain.canonical import canonical_digest

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_ROLES = {"app_jwt", "owner_admin_token", "installation_token"}
_EXPIRY_POLICY = "now<expires_at<=now+65m"


@dataclass(frozen=True, slots=True)
class GitHubReadRequest:
    """One successful sanitized request in an authenticated read trace."""

    method: Literal["GET", "POST"]
    path: str
    credential_role: str

    def __post_init__(self) -> None:
        if self.method not in {"GET", "POST"}:
            raise ValueError("GitHub provenance method is invalid")
        if type(self.path) is not str or not self.path.startswith("/") or "\x00" in self.path:
            raise ValueError("GitHub provenance path is invalid")
        if self.credential_role not in _ROLES:
            raise ValueError("GitHub provenance credential role is invalid")


@dataclass(frozen=True, slots=True)
class GitHubReadProvenance:
    """Strict canonical identity for one completed authenticated read."""

    reader_identity: str
    api_origin: Literal["https://api.github.com"]
    api_version: Literal["2022-11-28"]
    owner: str
    owner_id: int
    repository: str
    repository_id: int
    repository_digest: str
    target_ref: Literal["refs/heads/main"]
    app_slug: str
    app_id: int
    installation_id: int
    requested_repository_id: int
    requested_permissions: tuple[str, ...]
    observed_permissions: tuple[str, ...]
    repository_selection: Literal["selected"]
    token_expiry_policy: Literal["now<expires_at<=now+65m"]
    requests: tuple[GitHubReadRequest, ...]
    endpoint_observation_digests: tuple[tuple[str, str], ...]
    initial_ref_digest: str
    commit_digest: str
    final_ref_digest: str
    configuration_pass_digests: tuple[str, ...] = ()
    configuration_digest: str | None = None
    writer_app_id: int | None = None
    writer_installation_id: int | None = None
    provenance_digest: str = field(init=False)

    def __post_init__(self) -> None:
        self.assert_valid(include_digest=False)
        object.__setattr__(self, "provenance_digest", canonical_digest(self._payload()))

    def _payload(self) -> dict[str, object]:
        return {
            "api_origin": self.api_origin,
            "api_version": self.api_version,
            "app_id": self.app_id,
            "app_slug": self.app_slug,
            "commit_digest": self.commit_digest,
            "configuration_digest": self.configuration_digest,
            "configuration_pass_digests": self.configuration_pass_digests,
            "endpoint_observation_digests": self.endpoint_observation_digests,
            "final_ref_digest": self.final_ref_digest,
            "initial_ref_digest": self.initial_ref_digest,
            "installation_id": self.installation_id,
            "observed_permissions": self.observed_permissions,
            "owner": self.owner,
            "owner_id": self.owner_id,
            "reader_identity": self.reader_identity,
            "repository": self.repository,
            "repository_digest": self.repository_digest,
            "repository_id": self.repository_id,
            "repository_selection": self.repository_selection,
            "requested_permissions": self.requested_permissions,
            "requested_repository_id": self.requested_repository_id,
            "requests": tuple(
                {
                    "credential_role": item.credential_role,
                    "method": item.method,
                    "path": item.path,
                }
                for item in self.requests
            ),
            "target_ref": self.target_ref,
            "token_expiry_policy": self.token_expiry_policy,
            "writer_app_id": self.writer_app_id,
            "writer_installation_id": self.writer_installation_id,
        }

    def assert_valid(self, *, include_digest: bool = True) -> None:
        """Recompute semantic state so reflective tampering fails closed."""

        if type(self.reader_identity) is not str or not _IDENTITY.fullmatch(self.reader_identity):
            raise ValueError("GitHub provenance reader identity is invalid")
        if self.api_origin != "https://api.github.com" or self.api_version != "2022-11-28":
            raise ValueError("GitHub provenance API binding is invalid")
        if (
            type(self.owner) is not str
            or _IDENTITY.fullmatch(self.owner) is None
            or type(self.repository) is not str
            or _IDENTITY.fullmatch(self.repository) is None
            or type(self.owner_id) is not int
            or self.owner_id <= 0
            or type(self.repository_id) is not int
            or self.repository_id <= 0
            or type(self.requested_repository_id) is not int
            or self.requested_repository_id <= 0
            or self.requested_repository_id != self.repository_id
        ):
            raise ValueError("GitHub provenance repository binding is invalid")
        for digest in (
            self.repository_digest,
            self.initial_ref_digest,
            self.commit_digest,
            self.final_ref_digest,
            *(digest for _, digest in self.endpoint_observation_digests),
            *self.configuration_pass_digests,
        ):
            if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
                raise ValueError("GitHub provenance digest is invalid")
        if self.configuration_digest is not None and _DIGEST.fullmatch(
            self.configuration_digest
        ) is None:
            raise ValueError("GitHub provenance configuration digest is invalid")
        if type(self.app_slug) is not str or _IDENTITY.fullmatch(self.app_slug) is None:
            raise ValueError("GitHub provenance App slug is invalid")
        if type(self.app_id) is not int or self.app_id <= 0:
            raise ValueError("GitHub provenance App ID is invalid")
        if type(self.installation_id) is not int or self.installation_id <= 0:
            raise ValueError("GitHub provenance installation ID is invalid")
        if (self.writer_app_id is None) != (self.writer_installation_id is None):
            raise ValueError("GitHub provenance writer identity is incomplete")
        if self.writer_app_id is not None and (
            type(self.writer_app_id) is not int
            or self.writer_app_id <= 0
            or type(self.writer_installation_id) is not int
            or self.writer_installation_id <= 0
            or self.app_id == self.writer_app_id
            or self.installation_id == self.writer_installation_id
        ):
            raise ValueError("GitHub provenance observer and writer must be distinct")
        if self.requested_permissions != ("contents:read",):
            raise ValueError("GitHub provenance requested permissions are not exact")
        if self.observed_permissions != ("contents:read", "metadata:read"):
            raise ValueError("GitHub provenance observed permissions are not exact")
        if self.repository_selection != "selected" or self.token_expiry_policy != _EXPIRY_POLICY:
            raise ValueError("GitHub provenance token semantics are not exact")
        if type(self.requests) is not tuple or not self.requests or any(
            type(item) is not GitHubReadRequest for item in self.requests
        ):
            raise ValueError("GitHub provenance request trace is empty")
        if type(self.endpoint_observation_digests) is not tuple or any(
            type(item) is not tuple or len(item) != 2 or type(item[0]) is not str
            for item in self.endpoint_observation_digests
        ):
            raise ValueError("GitHub provenance endpoint observations are malformed")
        if type(self.configuration_pass_digests) is not tuple:
            raise ValueError("GitHub provenance configuration passes are malformed")
        if tuple(sorted(label for label, _ in self.endpoint_observation_digests)) != tuple(
            label for label, _ in self.endpoint_observation_digests
        ):
            raise ValueError("GitHub provenance endpoint labels are not canonical")
        if len({label for label, _ in self.endpoint_observation_digests}) != len(
            self.endpoint_observation_digests
        ):
            raise ValueError("GitHub provenance endpoint labels are duplicated")
        labels = {label for label, _ in self.endpoint_observation_digests}
        if not {"app", "installation", "repository"}.issubset(labels):
            raise ValueError("GitHub provenance endpoint identities are incomplete")
        if include_digest and self.provenance_digest != canonical_digest(self._payload()):
            raise ValueError("GitHub provenance digest does not match semantic state")


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class GitHubReadWithProvenance[T]:
    """Existing read result paired with its immutable sanitized provenance."""

    result: T
    provenance: GitHubReadProvenance

    def __post_init__(self) -> None:
        if type(self.provenance) is not GitHubReadProvenance:
            raise TypeError("GitHub read provenance is required")
        self.provenance.assert_valid()


__all__ = ["GitHubReadProvenance", "GitHubReadRequest", "GitHubReadWithProvenance"]
