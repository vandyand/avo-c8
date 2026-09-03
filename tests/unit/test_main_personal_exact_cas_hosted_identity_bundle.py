"""Adversarial tests for the offline hosted identity evidence bundle."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from avo_correlate.adapters.hosted_git.github import github_repository_digest
from avo_correlate.adapters.hosted_git.github_main_base_reader import (
    GitHubMainBaseReaderConfiguration,
)
from avo_correlate.adapters.hosted_git.github_read_provenance import (
    GitHubReadProvenance,
    GitHubReadRequest,
    GitHubReadWithProvenance,
)
from avo_correlate.adapters.hosted_git.main_personal_exact_cas_hosted_identity_bundle import (
    MainPersonalExactCasHostedIdentityEvidenceBundle,
)
from avo_correlate.contracts.main_personal_exact_cas_hosted_configuration import (
    MainPersonalExactCasHostedConfigurationDiagnostic,
)
from avo_correlate.domain.canonical import canonical_digest

if TYPE_CHECKING:
    from avo_correlate.adapters.git.main_composition import MainBaseSnapshot

OWNER = "vandyand"
REPOSITORY = "avo-c8"
REPOSITORY_ID = 1_354_880_741
OWNER_ID = 100_001
WRITER_APP_ID = 4_817_867
WRITER_INSTALLATION_ID = 158_775_763
OBSERVER_APP_ID = 91_001
OBSERVER_INSTALLATION_ID = 92_002
COMMIT = "a" * 40
TREE = "b" * 40
NOW = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)
D = "sha256:" + "1" * 64


def _writer(**changes: object) -> MainPersonalExactCasHostedConfigurationDiagnostic:
    values: dict[str, object] = {
        "repository_digest": github_repository_digest(OWNER, REPOSITORY),
        "owner": OWNER,
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID,
        "owner_id": OWNER_ID,
        "target_ref": "refs/heads/main",
        "main_commit": COMMIT,
        "writer_ruleset_id": 101,
        "writer_ruleset_name": "C8 main writer",
        "safety_ruleset_id": 202,
        "safety_ruleset_name": "C8 main safety",
        "writer_app_id": WRITER_APP_ID,
        "writer_installation_id": WRITER_INSTALLATION_ID,
        "selected_repository_ids": (REPOSITORY_ID,),
        "writer_ruleset_digest": D,
        "safety_ruleset_digest": "sha256:" + "2" * 64,
        "branch_protection_digest": "sha256:" + "3" * 64,
        "app_configuration_digest": "sha256:" + "4" * 64,
        "installation_configuration_digest": "sha256:" + "5" * 64,
        "selected_repositories_digest": "sha256:" + "6" * 64,
        "initial_ref_digest": "sha256:" + "7" * 64,
        "first_pass_digest": "sha256:" + "8" * 64,
        "second_pass_digest": "sha256:" + "8" * 64,
        "final_ref_digest": "sha256:" + "9" * 64,
        "started_at": NOW,
        "finished_at": NOW,
    }
    values.update(changes)
    return MainPersonalExactCasHostedConfigurationDiagnostic.build(**values)


def _observer() -> GitHubReadWithProvenance[MainBaseSnapshot]:
    from avo_correlate.adapters.git.main_composition import MainBaseSnapshot

    repository_digest = github_repository_digest(OWNER, REPOSITORY)
    configuration = GitHubMainBaseReaderConfiguration(
        owner=OWNER,
        owner_id=OWNER_ID,
        repo=REPOSITORY,
        repository_id=REPOSITORY_ID,
        repository_digest=repository_digest,
        observer_identity="avo-c8-main-observer-vandyand",
        observer_app_name="AVO C8 Main Observer",
        observer_app_id=OBSERVER_APP_ID,
        observer_installation_id=OBSERVER_INSTALLATION_ID,
        writer_app_id=WRITER_APP_ID,
        writer_installation_id=WRITER_INSTALLATION_ID,
    )
    snapshot = MainBaseSnapshot(repository_digest, COMMIT, TREE)
    ref_digest = canonical_digest(
        {"ref": "refs/heads/main", "object": {"type": "commit", "sha": COMMIT}}
    )
    provenance = GitHubReadProvenance(
        reader_identity="github_main_base_reader",
        api_origin="https://api.github.com",
        api_version="2022-11-28",
        owner=OWNER,
        owner_id=OWNER_ID,
        repository=REPOSITORY,
        repository_id=REPOSITORY_ID,
        repository_digest=repository_digest,
        target_ref="refs/heads/main",
        app_slug="avo-c8-main-observer-vandyand",
        app_id=OBSERVER_APP_ID,
        installation_id=OBSERVER_INSTALLATION_ID,
        requested_repository_id=REPOSITORY_ID,
        requested_permissions=("contents:read",),
        observed_permissions=("contents:read", "metadata:read"),
        repository_selection="selected",
        token_expiry_policy="now<expires_at<=now+65m",
        requests=(GitHubReadRequest("GET", "/app", "app_jwt"),),
        endpoint_observation_digests=(
            ("app", "sha256:" + "a" * 64),
            ("installation", "sha256:" + "b" * 64),
            ("repository", "sha256:" + "c" * 64),
        ),
        initial_ref_digest=ref_digest,
        commit_digest=canonical_digest({"commit": COMMIT, "tree": TREE}),
        final_ref_digest=ref_digest,
        configuration_digest=configuration.configuration_digest,
        writer_app_id=WRITER_APP_ID,
        writer_installation_id=WRITER_INSTALLATION_ID,
    )
    return GitHubReadWithProvenance(snapshot, provenance)


def _bundle() -> MainPersonalExactCasHostedIdentityEvidenceBundle:
    return MainPersonalExactCasHostedIdentityEvidenceBundle.build(_writer(), _observer())


def test_bundle_is_deterministic_scalar_and_non_authoritative() -> None:
    first = _bundle()
    second = _bundle()
    assert first == second
    assert first.bundle_digest == second.bundle_digest
    assert first.is_authoritative is False
    assert first.is_terminal is False
    assert first.readiness_authorized is False
    assert first.deploy_performed is False
    assert first.mutation_performed is False
    assert first.receipt_issued is False
    assert first.completion_claimed is False
    assert "token" not in repr(first).lower()


@pytest.mark.parametrize(
    "changes",
    [
        {"repository_digest": "sha256:" + "f" * 64},
        {"owner": "other"},
        {"owner_id": OWNER_ID + 1},
        {"repository": "other"},
        {"repository_id": REPOSITORY_ID + 1},
        {"target_ref": "refs/heads/dev"},
        {"main_commit": "c" * 40},
    ],
)
def test_writer_observer_identity_mismatches_fail_closed(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(_writer(**changes), _observer())


@pytest.mark.parametrize("field", ["writer_app_id", "writer_installation_id"])
def test_observer_writer_identity_mismatch_fails_closed(field: str) -> None:
    observer = _observer()
    provenance = replace(observer.provenance, **{field: 123456})
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(
            _writer(), GitHubReadWithProvenance(observer.result, provenance)
        )


@pytest.mark.parametrize("field", ["requested_permissions", "observed_permissions"])
def test_observer_scope_mismatch_fails_closed(field: str) -> None:
    observer = _observer()
    object.__setattr__(observer.provenance, field, ("contents:write",))
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(_writer(), observer)


def test_reflective_nested_tampering_is_revalidated() -> None:
    writer = _writer()
    object.__setattr__(writer, "writer_app_id", WRITER_APP_ID + 1)
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(writer, _observer())

    observer = _observer()
    object.__setattr__(observer.result, "commit", "c" * 40)
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(_writer(), observer)

    object.__setattr__(observer.provenance, "app_id", OBSERVER_APP_ID + 1)
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(_writer(), observer)


def test_bundle_reflective_tamper_and_frozen_surface_fail_closed() -> None:
    bundle = _bundle()
    with pytest.raises(FrozenInstanceError):
        bundle.main_commit = "c" * 40  # type: ignore[misc]
    object.__setattr__(bundle, "main_commit", "c" * 40)
    with pytest.raises(ValueError, match="digest"):
        bundle.assert_valid()


def test_secret_canary_is_not_accepted_or_retained() -> None:
    writer = _writer()
    object.__setattr__(writer, "secret_canary", "admin-token-secret-canary")
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(writer, _observer())
    assert "admin-token-secret-canary" not in repr(_bundle())


def test_builder_has_no_io_or_mutating_surface() -> None:
    import inspect

    module = inspect.getmodule(MainPersonalExactCasHostedIdentityEvidenceBundle)
    assert module is not None
    source = inspect.getsource(module)
    for forbidden in ("GitHubJsonTransport", "requests.", "httpx", "open(", "Path(", "write("):
        assert forbidden not in source
    public = {name for name in dir(_bundle()) if not name.startswith("_")}
    assert "dispatch" not in public and "mutate" not in public and "receipt" not in public
