"""Adversarial tests for the concrete App-authenticated main base reader."""
# pyright: reportPrivateUsage=false, reportUnknownMemberType=false

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from typing import Any, ClassVar

import pytest

from avo_correlate.adapters.hosted_git.github import github_repository_digest
from avo_correlate.adapters.hosted_git.github_main_base_reader import (
    GitHubMainBaseReader,
    GitHubMainBaseReaderConfiguration,
    GitHubMainBaseReaderCredentials,
    GitHubMainBaseReaderError,
)

OWNER = "vandyand"
OWNER_ID = 100_001
REPO = "avo-c8"
REPOSITORY_ID = 1_354_880_741
APP_ID = 91_001
INSTALLATION_ID = 92_002
WRITER_APP_ID = 4_817_867
WRITER_INSTALLATION_ID = 158_775_763
APP_SLUG = "avo-c8-main-observer-vandyand"
APP_NAME = "AVO C8 Main Observer"
COMMIT = "a" * 40
TREE = "b" * 40
NOW = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)


class FakeTransport:
    instances: ClassVar[list[FakeTransport]] = []
    responses: ClassVar[list[tuple[int, object]]] = []

    def __init__(self, **kwargs: object) -> None:
        self.constructor = kwargs
        self.calls: list[tuple[str, str, object, dict[str, str]]] = []
        self._responses = list(type(self).responses)
        type(self).instances.append(self)

    def __call__(
        self, method: str, url: str, body: object, headers: dict[str, str]
    ) -> tuple[int, Any]:
        self.calls.append((method, url, body, headers))
        if not self._responses:
            raise AssertionError("unexpected hosted call")
        status, response = self._responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return status, response


def _configuration(**changes: object) -> GitHubMainBaseReaderConfiguration:
    values: dict[str, object] = {
        "owner": OWNER,
        "owner_id": OWNER_ID,
        "repo": REPO,
        "repository_id": REPOSITORY_ID,
        "repository_digest": github_repository_digest(OWNER, REPO),
        "observer_identity": APP_SLUG,
        "observer_app_name": APP_NAME,
        "observer_app_id": APP_ID,
        "observer_installation_id": INSTALLATION_ID,
        "writer_app_id": WRITER_APP_ID,
        "writer_installation_id": WRITER_INSTALLATION_ID,
        "timeout_seconds": 17.5,
        "max_response_bytes": 1024,
    }
    values.update(changes)
    return GitHubMainBaseReaderConfiguration(**values)  # type: ignore[arg-type]


def _credentials(**changes: object) -> GitHubMainBaseReaderCredentials:
    values: dict[str, object] = {
        "app_jwt": "short-lived-app-jwt",
    }
    values.update(changes)
    return GitHubMainBaseReaderCredentials(**values)  # type: ignore[arg-type]


def _responses(
    *,
    commit: str = COMMIT,
    fence: str = COMMIT,
    tree: str = TREE,
) -> list[tuple[int, object]]:
    ref = {"ref": "refs/heads/main", "object": {"type": "commit", "sha": commit}}
    return [
        (
            200,
            {
                "id": APP_ID,
                "slug": APP_SLUG,
                "name": APP_NAME,
                "owner": {"login": OWNER, "id": OWNER_ID, "type": "User"},
                "permissions": {"contents": "read", "metadata": "read"},
                "events": [],
                "public": False,
                "webhook_active": False,
            },
        ),
        (
            200,
            {
                "id": INSTALLATION_ID,
                "app_id": APP_ID,
                "app_slug": APP_SLUG,
                "repository_selection": "selected",
                "target_id": OWNER_ID,
                "target_type": "User",
                "suspended_at": None,
                "account": {"login": OWNER, "id": OWNER_ID, "type": "User"},
                "permissions": {"contents": "read", "metadata": "read"},
                "events": [],
            },
        ),
        (
            201,
            {
                "token": "reader-minted-installation-token",
                "expires_at": "2026-09-02T13:00:00Z",
                "permissions": {"contents": "read", "metadata": "read"},
                "repository_selection": "selected",
                "repositories": [
                    {
                        "id": REPOSITORY_ID,
                        "name": REPO,
                        "full_name": f"{OWNER}/{REPO}",
                        "owner": {"login": OWNER, "id": OWNER_ID, "type": "User"},
                    }
                ],
            },
        ),
        (
            200,
            {
                "id": REPOSITORY_ID,
                "name": REPO,
                "full_name": f"{OWNER}/{REPO}",
                "owner": {"login": OWNER, "id": OWNER_ID, "type": "User"},
            },
        ),
        (200, ref),
        (
            200,
            {
                "sha": commit,
                "tree": {"sha": tree},
                "parents": [{"sha": "c" * 40}],
            },
        ),
        (
            200,
            {"ref": "refs/heads/main", "object": {"type": "commit", "sha": fence}},
        ),
    ]


def _reader(monkeypatch: pytest.MonkeyPatch, responses: list[tuple[int, object]]) -> Any:
    from avo_correlate.adapters.hosted_git import github_main_base_reader as module

    FakeTransport.instances.clear()
    FakeTransport.responses = responses
    monkeypatch.setattr(module, "GitHubJsonTransport", FakeTransport)
    monkeypatch.setattr(module, "_utc_now", lambda: NOW)
    return GitHubMainBaseReader(_configuration(), _credentials())


def test_configuration_is_frozen_secret_safe_and_digest_binds_stable_state() -> None:
    config = _configuration()
    credentials = _credentials()
    assert "short-lived-app-jwt" not in repr(credentials)
    assert config.configuration_digest.startswith("sha256:")
    with pytest.raises(FrozenInstanceError):
        config.owner = "other"  # type: ignore[misc]

    variations = (
        {"repository_id": REPOSITORY_ID + 1},
        {"owner_id": OWNER_ID + 1},
        {"observer_identity": "other-observer"},
        {"observer_app_name": "Other Observer"},
        {"observer_app_id": APP_ID + 1},
        {"observer_installation_id": INSTALLATION_ID + 1},
        {"writer_app_id": WRITER_APP_ID + 1},
        {"writer_installation_id": WRITER_INSTALLATION_ID + 1},
        {"timeout_seconds": 18.0},
        {"max_response_bytes": 2048},
    )
    for changes in variations:
        assert _configuration(**changes).configuration_digest != config.configuration_digest

    renamed = _configuration(
        repo="avo-c8-renamed",
        repository_digest=github_repository_digest(OWNER, "avo-c8-renamed"),
    )
    assert renamed.configuration_digest != config.configuration_digest
    new_owner = _configuration(
        owner="vandyand2",
        owner_id=OWNER_ID + 1,
        repository_digest=github_repository_digest("vandyand2", REPO),
    )
    assert new_owner.configuration_digest != config.configuration_digest


@pytest.mark.parametrize(
    "changes",
    [
        {"repository_id": True},
        {"owner_id": True},
        {"repository_digest": "sha256:" + "0" * 64},
        {"observer_identity": "Not-A-Slug"},
        {"observer_app_name": ""},
        {"observer_app_id": True},
        {"observer_installation_id": 0},
        {"writer_app_id": True},
        {"writer_installation_id": False},
        {"writer_app_id": 0},
        {"writer_installation_id": -1},
        {"timeout_seconds": float("nan")},
        {"timeout_seconds": 61},
        {"max_response_bytes": 4 * 1024 * 1024 + 1},
    ],
)
def test_configuration_rejects_malformed_or_unbounded_state(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _configuration(**changes)


def test_exact_authenticated_request_sequence_and_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _reader(monkeypatch, _responses())
    snapshot = reader.fresh_main_base()
    transport = FakeTransport.instances[0]
    assert transport.constructor == {
        "origin": "https://api.github.com",
        "timeout_seconds": 17.5,
        "max_response_bytes": 1024,
    }
    assert [call[:3] for call in transport.calls] == [
        ("GET", "https://api.github.com/app", None),
        ("GET", f"https://api.github.com/app/installations/{INSTALLATION_ID}", None),
        (
            "POST",
            f"https://api.github.com/app/installations/{INSTALLATION_ID}/access_tokens",
            {"repository_ids": [REPOSITORY_ID], "permissions": {"contents": "read"}},
        ),
        ("GET", f"https://api.github.com/repositories/{REPOSITORY_ID}", None),
        ("GET", f"https://api.github.com/repos/{OWNER}/{REPO}/git/ref/heads/main", None),
        ("GET", f"https://api.github.com/repos/{OWNER}/{REPO}/git/commits/{COMMIT}", None),
        ("GET", f"https://api.github.com/repos/{OWNER}/{REPO}/git/ref/heads/main", None),
    ]
    for index, (_method, _url, _body, headers) in enumerate(transport.calls):
        expected_headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer "
            + ("short-lived-app-jwt" if index < 3 else "reader-minted-installation-token"),
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if index == 2:
            expected_headers["Content-Type"] = "application/json"
        assert headers == expected_headers
    assert snapshot.repository_digest == github_repository_digest(OWNER, REPO)
    assert snapshot.target_ref == "refs/heads/main"
    assert (snapshot.commit, snapshot.tree) == (COMMIT, TREE)


def test_optional_app_privacy_and_webhook_fields_are_checked_when_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = _responses()
    app = responses[0][1]
    assert isinstance(app, dict)
    del app["public"]
    del app["webhook_active"]
    assert _reader(monkeypatch, responses).fresh_main_base().commit == COMMIT


@pytest.mark.parametrize(
    "changes",
    [
        {"writer_app_id": APP_ID},
        {"writer_installation_id": INSTALLATION_ID},
    ],
)
def test_observer_identity_cannot_overlap_writer_identity(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="distinct"):
        _configuration(**changes)


@pytest.mark.parametrize(
    ("response_index", "update"),
    [
        (0, {"id": APP_ID + 1}),
        (0, {"slug": "other-observer"}),
        (0, {"name": "Other Observer"}),
        (0, {"owner": {"login": "other", "id": OWNER_ID, "type": "User"}}),
        (0, {"owner": {"login": OWNER, "id": OWNER_ID + 1, "type": "User"}}),
        (0, {"owner": {"login": OWNER, "id": OWNER_ID, "type": "Organization"}}),
        (0, {"permissions": {"contents": "read", "metadata": "read", "issues": "read"}}),
        (0, {"events": ["push"]}),
        (0, {"public": True}),
        (0, {"webhook_active": True}),
        (1, {"id": INSTALLATION_ID + 1}),
        (1, {"app_id": APP_ID + 1}),
        (1, {"app_slug": "other-observer"}),
        (1, {"repository_selection": "all"}),
        (1, {"target_id": OWNER_ID + 1}),
        (1, {"suspended_at": "2026-09-02T00:00:00Z"}),
        (1, {"permissions": {"contents": "write"}}),
        (1, {"permissions": {"contents": "read", "metadata": "read", "issues": "read"}}),
        (1, {"events": ["push"]}),
        (1, {"account": {"login": "other", "id": OWNER_ID, "type": "User"}}),
        (1, {"account": {"login": OWNER, "id": OWNER_ID + 1, "type": "User"}}),
        (1, {"account": {"login": OWNER, "id": OWNER_ID, "type": "Organization"}}),
    ],
)
def test_installation_and_repository_identity_mismatches_fail_closed(
    monkeypatch: pytest.MonkeyPatch, response_index: int, update: dict[str, object]
) -> None:
    responses = _responses()
    body = responses[response_index][1]
    assert isinstance(body, dict)
    body.update(update)
    reader = _reader(monkeypatch, responses)
    with pytest.raises(GitHubMainBaseReaderError) as error:
        reader.fresh_main_base()
    assert str(error.value) == "trusted_main_base_unresolved"
    assert len(FakeTransport.instances[0].calls) == response_index + 1


@pytest.mark.parametrize(
    "mutation",
    [
        "drift",
        "bad_ref",
        "bad_ref_type",
        "bad_commit",
        "bad_tree",
        "bad_parent",
        "status",
        "transport",
    ],
)
def test_topology_drift_malformed_and_transport_errors_fail_closed(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    responses = _responses()
    if mutation == "drift":
        responses[-1] = _responses(fence="d" * 40)[-1]
    elif mutation == "bad_ref":
        responses[4] = (200, {"ref": "refs/heads/dev", "object": {"type": "commit", "sha": COMMIT}})
    elif mutation == "bad_ref_type":
        responses[4] = (200, {"ref": "refs/heads/main", "object": {"type": "tag", "sha": COMMIT}})
    elif mutation == "bad_commit":
        body = responses[5][1]
        assert isinstance(body, dict)
        body["sha"] = "d" * 40
    elif mutation == "bad_tree":
        body = responses[5][1]
        assert isinstance(body, dict)
        body["tree"] = {"sha": "bad"}
    elif mutation == "bad_parent":
        body = responses[5][1]
        assert isinstance(body, dict)
        body["parents"] = [{"sha": "bad"}]
    elif mutation == "status":
        responses[0] = (403, {})
    else:
        responses[0] = (200, RuntimeError("token=short-lived-app-jwt"))
    reader = _reader(monkeypatch, responses)
    with pytest.raises(GitHubMainBaseReaderError) as error:
        reader.fresh_main_base()
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "token" not in repr(error.value)


@pytest.mark.parametrize(
    "repository",
    [
        {
            "id": REPOSITORY_ID + 1,
            "name": REPO,
            "full_name": f"{OWNER}/{REPO}",
            "owner": {"login": OWNER, "id": OWNER_ID, "type": "User"},
        },
        {
            "id": REPOSITORY_ID,
            "name": "other",
            "full_name": f"{OWNER}/{REPO}",
            "owner": {"login": OWNER, "id": OWNER_ID, "type": "User"},
        },
        {
            "id": REPOSITORY_ID,
            "name": REPO,
            "full_name": f"{OWNER}/other",
            "owner": {"login": OWNER, "id": OWNER_ID, "type": "User"},
        },
        {
            "id": REPOSITORY_ID,
            "name": REPO,
            "full_name": f"{OWNER}/{REPO}",
            "owner": {"login": "other", "id": OWNER_ID, "type": "User"},
        },
        {
            "id": REPOSITORY_ID,
            "name": REPO,
            "full_name": f"{OWNER}/{REPO}",
            "owner": {"login": OWNER, "id": OWNER_ID + 1, "type": "User"},
        },
        {
            "id": REPOSITORY_ID,
            "name": REPO,
            "full_name": f"{OWNER}/{REPO}",
            "owner": {"login": OWNER, "id": OWNER_ID, "type": "Organization"},
        },
    ],
)
def test_repository_identity_fields_are_exact(
    monkeypatch: pytest.MonkeyPatch, repository: dict[str, object]
) -> None:
    responses = _responses()
    responses[3] = (200, repository)
    with pytest.raises(GitHubMainBaseReaderError):
        _reader(monkeypatch, responses).fresh_main_base()


@pytest.mark.parametrize(
    "update",
    [
        {"token": ""},
        {"permissions": {"contents": "write"}},
        {"permissions": {"contents": "read"}},
        {"permissions": {"contents": "read", "issues": "read"}},
        {"repository_selection": "all"},
        {"expires_at": "2026-09-02T11:59:59Z"},
        {"expires_at": "2026-09-02T14:00:00Z"},
        {"expires_at": "not-a-timestamp"},
        {"repositories": []},
        {"repositories": [{"id": REPOSITORY_ID + 1}]},
        {
            "repositories": [
                {
                    "id": REPOSITORY_ID,
                    "name": REPO,
                    "full_name": f"{OWNER}/{REPO}",
                    "owner": {"login": OWNER, "id": OWNER_ID, "type": "User"},
                },
                {
                    "id": REPOSITORY_ID + 1,
                    "name": "other",
                    "full_name": f"{OWNER}/other",
                    "owner": {"login": OWNER, "id": OWNER_ID, "type": "User"},
                },
            ]
        },
    ],
)
def test_minted_installation_token_scope_and_expiry_are_exact(
    monkeypatch: pytest.MonkeyPatch, update: dict[str, object]
) -> None:
    responses = _responses()
    body = responses[2][1]
    assert isinstance(body, dict)
    body.update(update)
    with pytest.raises(GitHubMainBaseReaderError) as error:
        _reader(monkeypatch, responses).fresh_main_base()
    assert error.value.__cause__ is None and error.value.__context__ is None
    assert len(FakeTransport.instances[0].calls) == 3


def test_no_foreign_or_presupplied_installation_token_can_be_constructed() -> None:
    with pytest.raises(ValueError):
        _credentials(app_jwt="")
    credentials_type: Any = GitHubMainBaseReaderCredentials
    with pytest.raises(TypeError):
        credentials_type(
            app_jwt="short-lived-app-jwt",
            installation_token="foreign-token",
        )


def test_hostile_transport_exception_is_not_retained_or_emitted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    reader = _reader(
        monkeypatch,
        [(200, RuntimeError("secret=short-lived-app-jwt"))],
    )
    with pytest.raises(GitHubMainBaseReaderError) as error:
        reader.fresh_main_base()
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert "secret" not in repr(error.value)
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


def test_reader_has_no_generic_or_mutating_public_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = _reader(monkeypatch, _responses())
    public = {name for name in dir(reader) if not name.startswith("_")}
    assert public == {
        "configuration_digest",
        "fresh_main_base",
        "fresh_main_base_with_provenance",
        "repository_digest",
    }
    for name in ("post", "put", "patch", "delete", "exchange", "dispatch", "mutate"):
        assert not hasattr(reader, name)
    with pytest.raises(FrozenInstanceError):
        reader._configuration = _configuration()  # pyright: ignore[reportAttributeAccessIssue]


def test_transient_token_rotation_does_not_change_stable_configuration_digest() -> None:
    config = _configuration()
    credentials = _credentials()
    rotated = replace(
        credentials,
        app_jwt="rotated-app-jwt",
    )
    assert rotated == credentials
    assert _configuration().configuration_digest == config.configuration_digest


def test_authenticated_read_provenance_is_canonical_frozen_and_secret_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed = _reader(monkeypatch, _responses()).fresh_main_base_with_provenance()
    provenance = observed.provenance
    assert observed.result.commit == COMMIT
    assert provenance.provenance_digest.startswith("sha256:")
    assert provenance.requests[0].credential_role == "app_jwt"
    assert provenance.requests[2].method == "POST"
    assert provenance.writer_app_id == WRITER_APP_ID
    assert provenance.writer_installation_id == WRITER_INSTALLATION_ID
    assert provenance.requests[-1].path.endswith("/git/ref/heads/main")
    text = repr(provenance)
    assert "short-lived-app-jwt" not in text
    assert "reader-minted-installation-token" not in text
    assert "rotated-secret-canary" not in text

    rotated = _responses()
    token_body = rotated[2][1]
    assert isinstance(token_body, dict)
    token_body["token"] = "rotated-secret-canary"
    rotated_observed = _reader(monkeypatch, rotated).fresh_main_base_with_provenance()
    assert rotated_observed.provenance.provenance_digest == provenance.provenance_digest

    assert (
        replace(provenance, app_id=APP_ID + 1).provenance_digest
        != provenance.provenance_digest
    )
    with pytest.raises(FrozenInstanceError):
        provenance.app_id = APP_ID + 1  # type: ignore[misc]

    tampered = replace(provenance, writer_app_id=WRITER_APP_ID + 1)
    assert tampered.provenance_digest != provenance.provenance_digest
    object.__setattr__(tampered, "writer_app_id", WRITER_APP_ID + 2)
    with pytest.raises(ValueError, match="digest"):
        tampered.assert_valid()

    tampered = replace(provenance, writer_app_id=WRITER_APP_ID + 1)
    object.__setattr__(tampered, "writer_installation_id", INSTALLATION_ID)
    with pytest.raises(ValueError, match="distinct"):
        tampered.assert_valid()


def test_ref_provenance_ignores_unvalidated_response_extra_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = _reader(monkeypatch, _responses()).fresh_main_base_with_provenance()
    responses = _responses()
    for index in (4, 6):
        ref = responses[index][1]
        assert isinstance(ref, dict)
        ref["secret_canary"] = "admin-token-secret-canary"
    changed = _reader(monkeypatch, responses).fresh_main_base_with_provenance()
    assert changed.result == baseline.result
    assert changed.provenance.initial_ref_digest == baseline.provenance.initial_ref_digest
    assert changed.provenance.final_ref_digest == baseline.provenance.final_ref_digest
    assert changed.provenance.provenance_digest == baseline.provenance.provenance_digest
    assert "admin-token-secret-canary" not in repr(changed.provenance)


def test_post_construction_configuration_tamper_fails_on_every_reader_boundary() -> None:
    config = _configuration()
    reader = GitHubMainBaseReader(config, _credentials())
    object.__setattr__(config, "repository_id", REPOSITORY_ID + 1)
    with pytest.raises(ValueError, match="configuration was modified"):
        _ = reader.configuration_digest
    with pytest.raises(ValueError, match="configuration was modified"):
        _ = reader.repository_digest
    with pytest.raises(GitHubMainBaseReaderError):
        reader.fresh_main_base()
