"""Adversarial tests for the offline hosted identity evidence bundle."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

import pytest

from avo_correlate.adapters.hosted_git.github import JsonValue, github_repository_digest
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
    validate_hosted_configuration_provenance,
)
from avo_correlate.contracts.main_personal_exact_cas_hosted_configuration import (
    MainPersonalExactCasHostedConfigurationDiagnostic,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit import (
    test_main_personal_exact_cas_hosted_configuration as hosted_configuration_fixtures,
)

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


def _writer(
    **changes: object,
) -> GitHubReadWithProvenance[MainPersonalExactCasHostedConfigurationDiagnostic]:
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
        "rollback_ruleset_id": 303,
        "rollback_ruleset_name": "C8 rollback namespace",
        "candidate_creation_ruleset_id": 404,
        "candidate_creation_ruleset_name": "C8 candidate creation",
        "candidate_immutable_ruleset_id": 505,
        "candidate_immutable_ruleset_name": "C8 candidate immutable",
        "writer_app_id": WRITER_APP_ID,
        "writer_installation_id": WRITER_INSTALLATION_ID,
        "candidate_publisher_app_id": 100,
        "candidate_publisher_app_slug": "avo-c8-candidate-publisher-vandyand",
        "candidate_publisher_app_name": "avo-c8-candidate-publisher-vandyand",
        "candidate_publisher_app_homepage": "https://github.com/vandyand/avo-c8",
        "candidate_publisher_installation_id": 111,
        "selected_repository_ids": (REPOSITORY_ID,),
        "writer_ruleset_digest": D,
        "safety_ruleset_digest": "sha256:" + "2" * 64,
        "rollback_ruleset_digest": "sha256:" + "a" * 64,
        "candidate_creation_ruleset_digest": "sha256:" + "b" * 64,
        "candidate_immutable_ruleset_digest": "sha256:" + "c" * 64,
        "candidate_publisher_identity_digest": canonical_digest(
            {
                "app_id": 100,
                "slug": "avo-c8-candidate-publisher-vandyand",
                "name": "avo-c8-candidate-publisher-vandyand",
                "homepage": "https://github.com/vandyand/avo-c8",
            }
        ),
        "candidate_publisher_installation_digest": canonical_digest(
            {"app_id": 100, "installation_id": 111}
        ),
        "candidate_publisher_app_configuration_digest": "sha256:" + "f" * 64,
        "candidate_publisher_installation_configuration_digest": "sha256:" + "0" * 64,
        "candidate_publisher_selected_repositories_digest": "sha256:" + "4" * 64,
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
    diagnostic = MainPersonalExactCasHostedConfigurationDiagnostic.build(**values)
    base = "/repos/vandyand/avo-c8"
    pass_trace = (
        GitHubReadRequest("GET", base, "owner_admin_token"),
        GitHubReadRequest("GET", "/app", "app_jwt"),
        GitHubReadRequest("GET", "/app/installations?per_page=100&page=1", "app_jwt"),
        GitHubReadRequest(
            "POST", f"/app/installations/{WRITER_INSTALLATION_ID}/access_tokens", "app_jwt"
        ),
        GitHubReadRequest(
            "GET", "/installation/repositories?per_page=100&page=1", "installation_token"
        ),
        GitHubReadRequest("GET", "/app", "app_jwt"),
        GitHubReadRequest("GET", "/app/installations/111", "app_jwt"),
        GitHubReadRequest("POST", "/app/installations/111/access_tokens", "app_jwt"),
        GitHubReadRequest(
            "GET", "/installation/repositories?per_page=100&page=1", "installation_token"
        ),
        GitHubReadRequest("GET", base + "/rulesets?per_page=100&page=1", "owner_admin_token"),
        GitHubReadRequest("GET", base + "/rulesets/101", "owner_admin_token"),
        GitHubReadRequest("GET", base + "/rulesets/202", "owner_admin_token"),
        GitHubReadRequest("GET", base + "/rulesets/303", "owner_admin_token"),
        GitHubReadRequest("GET", base + "/rulesets/404", "owner_admin_token"),
        GitHubReadRequest("GET", base + "/rulesets/505", "owner_admin_token"),
        GitHubReadRequest("GET", base + "/branches/main/protection", "owner_admin_token"),
    )
    ref = GitHubReadRequest("GET", base + "/git/ref/heads/main", "owner_admin_token")
    provenance = GitHubReadProvenance(
        reader_identity="main_personal_exact_cas_hosted_configuration_verifier",
        api_origin="https://api.github.com",
        api_version="2022-11-28",
        owner=OWNER,
        owner_id=OWNER_ID,
        repository=REPOSITORY,
        repository_id=REPOSITORY_ID,
        repository_digest=diagnostic.repository_digest,
        target_ref="refs/heads/main",
        app_slug="avo-c8-main-writer-vandyand",
        app_id=WRITER_APP_ID,
        installation_id=WRITER_INSTALLATION_ID,
        requested_repository_id=REPOSITORY_ID,
        requested_permissions=("contents:read",),
        observed_permissions=("contents:read", "metadata:read"),
        repository_selection="selected",
        token_expiry_policy="now<expires_at<=now+65m",
        requests=(ref, *pass_trace, *pass_trace, ref),
        endpoint_observation_digests=(
            ("app", diagnostic.app_configuration_digest),
            ("candidate_publisher_app", diagnostic.candidate_publisher_app_configuration_digest),
            ("candidate_publisher_identity", diagnostic.candidate_publisher_identity_digest),
            (
                "candidate_publisher_installation",
                diagnostic.candidate_publisher_installation_digest,
            ),
            (
                "candidate_publisher_installation_observation",
                diagnostic.candidate_publisher_installation_configuration_digest,
            ),
            (
                "candidate_publisher_selected_repositories",
                diagnostic.candidate_publisher_selected_repositories_digest,
            ),
            ("installation", diagnostic.installation_configuration_digest),
            ("repository", diagnostic.repository_digest),
            ("selected_repositories", diagnostic.selected_repositories_digest),
        ),
        initial_ref_digest=diagnostic.initial_ref_digest,
        commit_digest=canonical_digest({"commit": diagnostic.main_commit}),
        final_ref_digest=diagnostic.final_ref_digest,
        configuration_pass_digests=(diagnostic.first_pass_digest, diagnostic.second_pass_digest),
        configuration_digest=diagnostic.configuration_digest,
    )
    return GitHubReadWithProvenance(diagnostic, provenance)


def _observer(
    *,
    owner_id: int = OWNER_ID,
    writer_app_id: int = WRITER_APP_ID,
    writer_installation_id: int = WRITER_INSTALLATION_ID,
) -> tuple[
    GitHubReadWithProvenance[MainBaseSnapshot], GitHubMainBaseReaderConfiguration
]:
    from avo_correlate.adapters.git.main_composition import MainBaseSnapshot

    repository_digest = github_repository_digest(OWNER, REPOSITORY)
    configuration = GitHubMainBaseReaderConfiguration(
        owner=OWNER,
        owner_id=owner_id,
        repo=REPOSITORY,
        repository_id=REPOSITORY_ID,
        repository_digest=repository_digest,
        observer_identity="avo-c8-main-observer-vandyand",
        observer_app_name="AVO C8 Main Observer",
        observer_app_id=OBSERVER_APP_ID,
        observer_installation_id=OBSERVER_INSTALLATION_ID,
        writer_app_id=writer_app_id,
        writer_installation_id=writer_installation_id,
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
        owner_id=owner_id,
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
        requests=(
            GitHubReadRequest("GET", "/app", "app_jwt"),
            GitHubReadRequest(
                "GET", f"/app/installations/{OBSERVER_INSTALLATION_ID}", "app_jwt"
            ),
            GitHubReadRequest(
                "POST",
                f"/app/installations/{OBSERVER_INSTALLATION_ID}/access_tokens",
                "app_jwt",
            ),
            GitHubReadRequest("GET", f"/repositories/{REPOSITORY_ID}", "installation_token"),
            GitHubReadRequest(
                "GET", "/repos/vandyand/avo-c8/git/ref/heads/main", "installation_token"
            ),
            GitHubReadRequest(
                "GET", f"/repos/vandyand/avo-c8/git/commits/{COMMIT}", "installation_token"
            ),
            GitHubReadRequest(
                "GET", "/repos/vandyand/avo-c8/git/ref/heads/main", "installation_token"
            ),
        ),
        endpoint_observation_digests=(
            ("app", "sha256:" + "a" * 64),
            ("installation", "sha256:" + "b" * 64),
            ("repository", "sha256:" + "c" * 64),
        ),
        initial_ref_digest=ref_digest,
        commit_digest=canonical_digest({"commit": COMMIT, "tree": TREE, "parents": ()}),
        final_ref_digest=ref_digest,
        configuration_digest=configuration.configuration_digest,
        writer_app_id=writer_app_id,
        writer_installation_id=writer_installation_id,
    )
    return GitHubReadWithProvenance(snapshot, provenance), configuration


def _bundle() -> MainPersonalExactCasHostedIdentityEvidenceBundle:
    observer, configuration = _observer()
    return MainPersonalExactCasHostedIdentityEvidenceBundle.build(
        _writer(), observer, configuration
    )


def _verified_writer_with_summary_order(
    order: tuple[int, int, int, int, int],
) -> GitHubReadWithProvenance[MainPersonalExactCasHostedConfigurationDiagnostic]:
    responses: Any = hosted_configuration_fixtures._responses()
    for summary_index in (10, 26):
        status, raw_summaries_value = responses[summary_index]
        raw_summaries: Any = raw_summaries_value
        if type(status) is not int or type(raw_summaries) is not list:
            raise AssertionError("summary fixture is malformed")
        summaries: dict[int, dict[str, JsonValue]] = {}
        for raw_item in cast(list[JsonValue], raw_summaries):
            if type(raw_item) is not dict:
                continue
            item = raw_item
            ident = item.get("id")
            if type(ident) is int:
                summaries[ident] = item
        responses[summary_index] = (status, [copy.deepcopy(summaries[ident]) for ident in order])
        detail_index = summary_index + 1
        details: dict[int, dict[str, JsonValue]] = {}
        for offset in range(5):
            response: Any = responses[detail_index + offset]
            detail: dict[str, JsonValue] = response[1]
            ident = detail.get("id")
            if type(ident) is not int:
                raise AssertionError("detail fixture is malformed")
            details[ident] = detail
        responses[detail_index : detail_index + 5] = [
            (200, copy.deepcopy(details[ident])) for ident in order
        ]
    subject, _ = hosted_configuration_fixtures._subject(responses)
    return subject.verify_with_provenance()


def test_builder_requires_authenticated_writer_wrapper_and_exact_observer_trace() -> None:
    observer, configuration = _observer()
    bare_diagnostic = _writer().result
    with pytest.raises(TypeError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(
            bare_diagnostic,  # type: ignore[arg-type]
            observer,
            configuration,
        )
    one_request = replace(observer.provenance, requests=(observer.provenance.requests[0],))
    with pytest.raises(ValueError, match="seven-request"):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(
            _writer(), GitHubReadWithProvenance(observer.result, one_request), configuration
        )


def test_writer_safety_ruleset_request_cannot_be_skipped() -> None:
    writer = _writer()
    requests = list(writer.provenance.requests)
    requests[11] = requests[12]
    tampered = replace(writer.provenance, requests=tuple(requests))
    observer, configuration = _observer()
    # The changed provenance has a fresh digest but fails the exact safety slot.
    with pytest.raises(ValueError, match="ruleset identities"):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(
            GitHubReadWithProvenance(writer.result, tampered), observer, configuration
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rollback_ruleset_id", 304),
        ("rollback_ruleset_name", "other rollback namespace"),
        ("rollback_ruleset_digest", "sha256:" + "f" * 64),
    ],
)
def test_writer_rollback_identity_tamper_is_revalidated(
    field: str, value: object
) -> None:
    writer = _writer()
    tampered = writer.result.model_copy(update={field: value})
    observer, configuration = _observer()
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(
            GitHubReadWithProvenance(tampered, writer.provenance), observer, configuration
        )


def test_writer_rollback_request_must_bind_to_diagnostic_id() -> None:
    writer = _writer()
    requests = list(writer.provenance.requests)
    requests[13] = GitHubReadRequest(
        "GET", "/repos/vandyand/avo-c8/rulesets/304", "owner_admin_token"
    )
    tampered = GitHubReadWithProvenance(
        writer.result,
        replace(writer.provenance, requests=tuple(requests)),
    )
    observer, configuration = _observer()
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(tampered, observer, configuration)


def test_verifier_to_bundle_accepts_summary_order_permutation() -> None:
    writer = _verified_writer_with_summary_order((202, 101, 303, 404, 505))
    observer, configuration = _observer(
        owner_id=77,
        writer_app_id=88,
        writer_installation_id=99,
    )
    bundle = MainPersonalExactCasHostedIdentityEvidenceBundle.build(
        writer, observer, configuration
    )
    assert bundle.writer_rollback_ruleset_id == 303


def test_verifier_to_bundle_rejects_pass_ruleset_order_drift() -> None:
    writer = _verified_writer_with_summary_order((202, 101, 303, 404, 505))
    requests = list(writer.provenance.requests)
    requests[27:30] = [requests[28], requests[27], requests[29]]
    tampered = GitHubReadWithProvenance(
        writer.result,
        replace(writer.provenance, requests=tuple(requests)),
    )
    observer, configuration = _observer(
        owner_id=77,
        writer_app_id=88,
        writer_installation_id=99,
    )
    with pytest.raises(ValueError, match="order drifted"):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(
            tampered, observer, configuration
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("duplicate-diagnostic-ruleset", "ruleset identities"),
        ("trace-shape", "trace shape"),
        ("wrong-ruleset-credential", "ruleset request"),
        ("duplicate-ruleset-path", "ruleset identities"),
        ("missing-ref-fence", "main fence"),
        ("endpoint-digest", "endpoint binding"),
    ],
)
def test_hosted_provenance_rejects_candidate_trace_and_identity_tampering(
    mutation: str, message: str
) -> None:
    writer = _writer()
    observer, configuration = _observer()
    if mutation == "duplicate-diagnostic-ruleset":
        diagnostic = writer.result.model_copy(
            update={"candidate_immutable_ruleset_id": writer.result.candidate_creation_ruleset_id}
        )
        with pytest.raises(ValueError, match=message):
            validate_hosted_configuration_provenance(diagnostic, writer.provenance)
        return
    else:
        requests = list(writer.provenance.requests)
        if mutation == "trace-shape":
            requests[1] = GitHubReadRequest("GET", "/wrong", "owner_admin_token")
        elif mutation == "wrong-ruleset-credential":
            requests[11] = GitHubReadRequest(
                "GET", requests[11].path, "installation_token"
            )
        elif mutation == "duplicate-ruleset-path":
            requests[14] = requests[13]
        elif mutation == "missing-ref-fence":
            requests[0] = GitHubReadRequest("GET", "/wrong", "owner_admin_token")
        else:
            endpoints = list(writer.provenance.endpoint_observation_digests)
            endpoints[0] = (endpoints[0][0], "sha256:" + "f" * 64)
            tampered = replace(
                writer.provenance, endpoint_observation_digests=tuple(endpoints)
            )
            with pytest.raises(ValueError, match=message):
                MainPersonalExactCasHostedIdentityEvidenceBundle.build(
                    GitHubReadWithProvenance(writer.result, tampered), observer, configuration
                )
            return
        tampered = replace(writer.provenance, requests=tuple(requests))
        writer_value = GitHubReadWithProvenance(writer.result, tampered)
    with pytest.raises(ValueError, match=message):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(
            writer_value, observer, configuration
        )


def test_writer_provenance_digest_is_retained_and_tamper_fails_closed() -> None:
    bundle = _bundle()
    assert bundle.writer_provenance_digest == _writer().provenance.provenance_digest
    object.__setattr__(bundle, "writer_provenance_digest", "sha256:" + "f" * 64)
    with pytest.raises(ValueError, match="digest"):
        bundle.assert_valid()


def test_writer_model_copy_and_construct_are_revalidated() -> None:
    writer = _writer()
    observer, configuration = _observer()
    copied = writer.result.model_copy(update={"rollback_ruleset_id": True})
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(
            GitHubReadWithProvenance(copied, writer.provenance), observer, configuration
        )
    constructed_values = writer.result.model_dump()
    constructed_values["rollback_ruleset_digest"] = "not-a-digest"
    constructed = MainPersonalExactCasHostedConfigurationDiagnostic.model_construct(
        **constructed_values
    )
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(
            GitHubReadWithProvenance(constructed, writer.provenance), observer, configuration
        )


def test_bundle_is_deterministic_scalar_and_non_authoritative() -> None:
    first = _bundle()
    second = _bundle()
    assert first == second
    assert first.bundle_digest == second.bundle_digest
    assert first.writer_provenance_digest == _writer().provenance.provenance_digest
    assert first.writer_rollback_ruleset_id == 303
    assert first.writer_rollback_ruleset_name == "C8 rollback namespace"
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
    observer, configuration = _observer()
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(
            _writer(**changes), observer, configuration
        )


@pytest.mark.parametrize("field", ["writer_app_id", "writer_installation_id"])
def test_observer_writer_identity_mismatch_fails_closed(field: str) -> None:
    observer, configuration = _observer()
    provenance = replace(observer.provenance, **{field: 123456})
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(
            _writer(), GitHubReadWithProvenance(observer.result, provenance), configuration
        )


@pytest.mark.parametrize("field", ["app_id", "app_slug"])
def test_observer_identity_mismatch_fails_closed(field: str) -> None:
    observer, configuration = _observer()
    value: object = OBSERVER_APP_ID + 1 if field == "app_id" else "other-observer"
    provenance = replace(observer.provenance, **{field: value})
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(
            _writer(), GitHubReadWithProvenance(observer.result, provenance), configuration
        )


@pytest.mark.parametrize("field", ["owner", "repo"])
def test_observer_configuration_repository_mismatch_fails_closed(field: str) -> None:
    observer, configuration = _observer()
    changes = {field: "other"}
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(
            _writer(), observer, replace(configuration, **changes)
        )


@pytest.mark.parametrize("field", ["requested_permissions", "observed_permissions"])
def test_observer_scope_mismatch_fails_closed(field: str) -> None:
    observer, configuration = _observer()
    object.__setattr__(observer.provenance, field, ("contents:write",))
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(
            _writer(), observer, configuration
        )


def test_reflective_nested_tampering_is_revalidated() -> None:
    writer = _writer()
    object.__setattr__(writer.result, "writer_app_id", WRITER_APP_ID + 1)
    observer, configuration = _observer()
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(writer, observer, configuration)

    observer, configuration = _observer()
    object.__setattr__(observer.result, "commit", "c" * 40)
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(_writer(), observer, configuration)

    object.__setattr__(observer.provenance, "app_id", OBSERVER_APP_ID + 1)
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(_writer(), observer, configuration)


def test_bundle_reflective_tamper_and_frozen_surface_fail_closed() -> None:
    bundle = _bundle()
    with pytest.raises(FrozenInstanceError):
        bundle.main_commit = "c" * 40  # type: ignore[misc]
    object.__setattr__(bundle, "main_commit", "c" * 40)
    with pytest.raises(ValueError, match="digest"):
        bundle.assert_valid()


def test_secret_canary_is_not_accepted_or_retained() -> None:
    writer = _writer()
    object.__setattr__(writer.result, "secret_canary", "admin-token-secret-canary")
    observer, configuration = _observer()
    with pytest.raises(ValueError):
        MainPersonalExactCasHostedIdentityEvidenceBundle.build(writer, observer, configuration)
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
