# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportArgumentType=false, reportAttributeAccessIssue=false, reportIndexIssue=false, reportUnnecessaryCast=false, reportInvalidTypeForm=false, reportGeneralTypeIssues=false, reportOptionalMemberAccess=false, reportPrivateUsage=false, reportMissingImports=false, reportUnusedImport=false

"""Filesystem-backed C4 completion and recovery tests.

The preparation fixture builds the C2 records from a real temporary Git
checkout and persists them through ``MainGraduationJournal``.  This module
adds only the C4 provider boundary: the hold and release capabilities are
separate objects, while observations remain read-only.
"""

from __future__ import annotations

import hashlib
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from avo_correlate.adapters.artifacts.main_graduation_journal import MainGraduationJournal
from avo_correlate.adapters.hosted_git.protected_main import MainMergeGroupObservation
from avo_correlate.application.main_graduation_completion_coordinator import (
    MainGraduationCompletionCoordinator,
)
from avo_correlate.contracts.main_graduation import (
    MainAttestationManifest,
    MainCheckObservation,
    MainCompletionPackage,
    MainMergeGroupWebhookReceipt,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.c4_coordinator_test_support import MAIN_OPERATION, REPOSITORY, git
from tests.unit.phase_a_test_support import TEST_PHASE_A_AUTHORITY
from tests.unit.test_main_graduation_coordinator_preparation import (
    CONFIG,
    NOW,
    Authority,
    Fence,
    Provider,
    _coordinator,
    _fixture,
    _fresh_journal,
)

GROUP_DELIVERY = "completion-fixture-delivery"


class MutableClock:
    def __init__(self, current: datetime = NOW) -> None:
        self.current = current

    def now(self) -> datetime:
        return self.current


class HoldCapability:
    """The only mutation capability exposed to the group-hold executor."""

    provider_identity = "fixture-provider"
    provider_api_version = "v1"

    def __init__(self, provider: CompletionProvider) -> None:
        self.provider = provider

    def issue_group_hold(self, request: Any) -> Any:
        return self.provider.issue_group_hold(request)


class ReleaseCapability:
    """The only capability that can cross the protected release boundary."""

    provider_identity = "fixture-provider"
    provider_api_version = "v1"

    def __init__(self, provider: CompletionProvider) -> None:
        self.provider = provider

    def issue_release(self, request: Any) -> Any:
        return self.provider.issue_release(request)


class ObservationCapability:
    """Read-only release recovery capability."""

    provider_identity = "fixture-provider"
    provider_api_version = "v1"

    def __init__(self, provider: CompletionProvider) -> None:
        self.provider = provider

    def observe_release(self, request: Any) -> Any:
        return self.provider.observe_release(request)


class CompletionProvider(Provider):
    """Deterministic C2 provider with an authenticated merge-group receipt."""

    def __init__(self, base: str, tree: str, candidate: str, candidate_tree: str) -> None:
        super().__init__(base, tree, candidate, candidate_tree)
        self.clock: MutableClock = MutableClock()
        self.group_sha = ""
        self.group_tree = ""
        self.hold_calls = 0
        self.release_calls = 0
        self.release_observation_calls = 0
        self.group_observation_calls = 0
        self.group_check_calls = 0
        self.applied = False
        self.no_result = False
        self.main_commit = base
        self.main_tree = tree
        self.hold_capability = HoldCapability(self)
        self.release_capability = ReleaseCapability(self)
        self.observation_capability = ObservationCapability(self)

    def observe_main(self) -> Any:
        parents = [self.base]
        response_digest = canonical_digest(
            {"commit": self.main_commit, "tree": self.main_tree, "parents": parents}
        )
        return type(
            "Main",
            (),
            {
                "repository_digest": REPOSITORY,
                "ref": "refs/heads/main",
                "commit": self.main_commit,
                "tree": self.main_tree,
                "parents": parents,
                "response_digest": response_digest,
                "observed_at": self.clock.now(),
            },
        )()

    def observe_merge_group(
        self,
        group_sha: str,
        *,
        webhook_body: bytes | None = None,
        webhook_headers: dict[str, str] | None = None,
        queue: Any | None = None,
        pull_request_number: int | None = None,
    ) -> MainMergeGroupObservation:
        del webhook_body, webhook_headers
        self.group_observation_calls += 1
        assert group_sha == self.group_sha
        assert queue is not None
        assert pull_request_number == self.pr_number
        body = b'{"action":"checks_requested"}'
        values = {
            "schema_version": 1,
            "repository_digest": REPOSITORY,
            "target_ref": "refs/heads/main",
            "operation_id": MAIN_OPERATION,
            "group_sha": self.group_sha,
            "group_tree": self.group_tree,
            "group_parents": [self.base, self.candidate],
            "pull_request_number": self.pr_number,
            "queue_generation_digest": queue.queue_generation_digest,
            "delivery_id": GROUP_DELIVERY,
            "body_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
            "observed_at": self.clock.now().astimezone(UTC).isoformat().replace("+00:00", "Z"),
        }
        receipt = MainMergeGroupWebhookReceipt.model_validate(
            values | {"receipt_digest": canonical_digest(values)}
        )
        return MainMergeGroupObservation(
            REPOSITORY,
            self.group_sha,
            self.group_tree,
            (self.base, self.candidate),
            (self.pr_number,),
            queue.queue_generation_digest,
            receipt.observed_at,
            receipt,
        )

    def observe_merge_group_checks(
        self, group_sha: str, *, freshness_cutoff: datetime
    ) -> list[MainCheckObservation]:
        self.group_check_calls += 1
        assert group_sha == self.group_sha
        return [
            MainCheckObservation(
                name="independent-validation",
                context="avo-independent-validation",
                app_id=15368,
                sha=group_sha,
                status="completed",
                conclusion="success",
                run_id="validation-run",
                nonce="validation-nonce",
                observed_at=max(self.clock.now(), freshness_cutoff),
            )
        ]

    def issue_group_hold(self, request: Any) -> Any:
        from avo_correlate.application.c4_capabilities import GroupHoldIssueResult

        self.hold_calls += 1
        return GroupHoldIssueResult.build(
            **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
            outcome="applied",
            response_digest=CONFIG,
            observed_at=self.clock.now(),
            dispatch_started=True,
        )

    def issue_release(self, request: Any) -> Any:
        self.release_calls += 1
        if self.release_calls != 1:
            raise AssertionError("release authorization was reused")
        self.applied = True
        self.main_commit = self.candidate
        self.main_tree = self.candidate_tree
        # The transport has applied the exact one-parent C2 result, but the
        # caller loses the response.  Recovery must prove this by observation.
        raise TimeoutError("release response lost after provider applied result")

    def observe_release(self, request: Any) -> Any:
        from avo_correlate.application.c4_capabilities import ReleaseObservationResult

        self.release_observation_calls += 1
        # The first read models a transport/process boundary where the
        # provider cannot yet return authoritative post-state, even though
        # the release may already have applied.  A later fresh-process read
        # can observe the applied state; the explicit no-result fixture keeps
        # that state ambiguous forever.
        outcome = (
            "ambiguous"
            if self.no_result or not self.applied or self.release_observation_calls == 1
            else "observed"
        )
        main = self.observe_main()
        post_values = {
            "schema_version": 1,
            "repository_digest": REPOSITORY,
            "target_ref": "refs/heads/main",
            "operation_id": MAIN_OPERATION,
            "release_authorization_digest": request.release_authorization_digest,
            "provider_identity": self.provider_identity,
            "provider_api_version": self.provider_api_version,
            "result_commit": main.commit,
            "result_tree": main.tree,
            "result_parents": [self.base],
            "response_digest": main.response_digest,
            "observed_at": main.observed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "authoritative": True,
        }
        evidence = canonical_digest(post_values)
        return ReleaseObservationResult.build(
            **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
            outcome=outcome,
            evidence_digest=evidence,
            observed_at=self.clock.now(),
        )


class ExpiringJournal(MainGraduationJournal):
    """Advance the trusted test clock only after the release claim is durable."""

    def __init__(self, *args: Any, release_clock: MutableClock, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.release_clock = release_clock

    def record_release_claim(self, record: Any) -> Any:
        result = super().record_release_claim(record)
        self.release_clock.current = record.authorization_expires_at + timedelta(seconds=1)
        return result


def _make_group(provider: CompletionProvider, checkout: Path) -> None:
    result = subprocess.run(
        [
            "git",
            "commit-tree",
            provider.candidate_tree,
            "-p",
            provider.base,
            "-p",
            provider.candidate,
        ],
        cwd=checkout,
        input="authenticated merge group\n",
        capture_output=True,
        text=True,
        check=True,
    )
    provider.group_sha = result.stdout.strip()
    provider.group_tree = git(checkout, "rev-parse", f"{provider.group_sha}^{{tree}}")
    assert provider.group_tree == provider.candidate_tree
    assert provider.group_sha != provider.candidate


def _attestation(journal: MainGraduationJournal) -> None:
    plan_value = journal.read_plan(MAIN_OPERATION)
    assert plan_value is not None
    plan = plan_value[0]
    journal.record_attestation_manifest(
        MainAttestationManifest(
            operation_id=MAIN_OPERATION,
            repository_digest=REPOSITORY,
            target_ref="refs/heads/main",
            package_digest=plan.package.package_digest,
            composition_digest=plan.composition.composition_digest,
            policy_epoch=plan.policy_epoch,
            reviewer_identity="reviewer",
            reviewer_evidence_digest=CONFIG,
            evaluator_identity="evaluator",
            evaluator_evidence_digest=CONFIG,
        )
    )


def _completion_fixture(root: Path) -> tuple[MainGraduationJournal, CompletionProvider]:
    journal, provider = _fixture(root, CompletionProvider)
    return journal, cast(CompletionProvider, provider)


def _completion_coordinator(
    journal: MainGraduationJournal, provider: CompletionProvider, clock: MutableClock
) -> MainGraduationCompletionCoordinator:
    return MainGraduationCompletionCoordinator(
        journal=journal,
        clock=clock,
        lease_fence=Fence(),
        provider=provider,
        hold_capability=provider.hold_capability,
        release_capability=provider.release_capability,
        observation_capability=provider.observation_capability,
        authority_verifier=Authority(),
        attester=None,
    )


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }


def test_timeout_then_expired_fresh_recovery_completes_read_only_and_replays_exactly(
    tmp_path: Path,
) -> None:
    journal, provider = _completion_fixture(tmp_path)
    provider.clock = MutableClock(NOW)
    _make_group(provider, tmp_path / "checkout")
    prepared = _coordinator(journal, provider).prepare(MAIN_OPERATION)
    assert prepared.state == "queued", prepared
    _attestation(journal)

    first = _completion_coordinator(journal, provider, provider.clock).complete(
        MAIN_OPERATION, group_sha=provider.group_sha, pull_request_number=provider.pr_number
    )
    assert first.state == "reconciliation_required", first.reason
    assert provider.hold_calls == 1
    assert provider.release_calls == 1
    assert provider.release_observation_calls == 1
    assert journal.read_completion(MAIN_OPERATION) is None
    intent = journal.read_mutation_intent_by_operation_stage(
        MAIN_OPERATION, "release_transition"
    )
    assert intent is not None
    assert journal.read_mutation_fence_resolution_by_intent(intent[0].intent_digest) is None

    provider.clock.current = NOW + timedelta(minutes=10)
    fresh = _fresh_journal(journal)
    provider.journal = fresh
    recovered = _completion_coordinator(fresh, provider, provider.clock).complete(MAIN_OPERATION)
    assert recovered.state == "completed", recovered
    assert recovered.package is not None
    assert provider.release_calls == 1
    assert provider.release_observation_calls == 2
    assert fresh.read_provider_receipt(MAIN_OPERATION) is not None
    assert fresh.read_reconciliation(MAIN_OPERATION) is not None
    assert fresh.read_completion(MAIN_OPERATION) is not None

    package = recovered.package
    validated = MainCompletionPackage.model_validate(package.model_dump(mode="json"))
    auth_id = validated.release_authorization.authorization_digest
    assert {
        validated.transition_receipt.release_authorization_digest,
        validated.provider_receipt.release_authorization_digest,
        validated.provider_post_state_observation.release_authorization_digest,
        validated.claimed_transition_receipt.release_authorization_digest,
        validated.release_transition_intent.release_authorization_digest,
        validated.release_transition_mutation_receipt.release_authorization_digest,
    } == {auth_id}
    assert (
        cast(Any, fresh.read_release_transition(MAIN_OPERATION))[0]
        .release_authorization_digest
        == auth_id
    )
    assert (
        cast(Any, fresh.read_provider_receipt(MAIN_OPERATION))[0]
        .release_authorization_digest
        == auth_id
    )
    digest = canonical_digest(package)
    before = _snapshot(tmp_path)
    replay_journal = _fresh_journal(fresh)
    provider.journal = replay_journal
    replay = _completion_coordinator(replay_journal, provider, provider.clock).complete(
        MAIN_OPERATION
    )
    assert replay.state == "completed"
    assert replay.package == package
    assert replay.package is not None
    assert canonical_digest(replay.package) == digest
    assert provider.release_calls == 1
    assert provider.release_observation_calls == 2
    assert _snapshot(tmp_path) == before


def test_no_result_ambiguity_remains_reconciliation_required_after_expiry(tmp_path: Path) -> None:
    journal, provider = _completion_fixture(tmp_path)
    provider.clock = MutableClock(NOW)
    provider.no_result = True
    _make_group(provider, tmp_path / "checkout")
    assert _coordinator(journal, provider).prepare(MAIN_OPERATION).state == "queued"
    _attestation(journal)

    first = _completion_coordinator(journal, provider, provider.clock).complete(
        MAIN_OPERATION, group_sha=provider.group_sha, pull_request_number=provider.pr_number
    )
    assert first.state == "reconciliation_required"
    provider.clock.current = NOW + timedelta(minutes=10)
    fresh = _fresh_journal(journal)
    provider.journal = fresh
    second = _completion_coordinator(fresh, provider, provider.clock).complete(MAIN_OPERATION)
    assert second.state == "reconciliation_required"
    assert second.package is None
    assert provider.release_calls == 1
    assert provider.release_observation_calls == 2
    assert fresh.read_completion(MAIN_OPERATION) is None
    assert fresh.read_provider_receipt(MAIN_OPERATION) is None
    assert fresh.read_reconciliation(MAIN_OPERATION) is None


def test_authorization_expiry_before_dispatch_makes_zero_release_calls(tmp_path: Path) -> None:
    base_journal, provider = _completion_fixture(tmp_path)
    clock = MutableClock(NOW)
    expiring = ExpiringJournal(
        base_journal.root,
        release_issuer_binding=base_journal._release_issuer_binding,
        policy_epoch=base_journal._policy_epoch,
        composition_root=base_journal._composition_root,
        repository_digest=base_journal._composition_repository_digest,
        base_reader=base_journal._composition_base_reader,
        phase_a_authority_verifier=TEST_PHASE_A_AUTHORITY,
        release_clock=clock,
    )
    provider.journal = expiring
    _make_group(provider, tmp_path / "checkout")
    assert _coordinator(expiring, provider).prepare(MAIN_OPERATION).state == "queued"
    _attestation(expiring)

    result = _completion_coordinator(expiring, provider, clock).complete(
        MAIN_OPERATION, group_sha=provider.group_sha, pull_request_number=provider.pr_number
    )
    assert result.state == "quarantined", result
    assert result.reason is not None and "expired" in result.reason
    assert provider.release_calls == 0
    assert provider.release_observation_calls == 0
    assert expiring.read_release_authorization(MAIN_OPERATION) is not None
    assert expiring.read_mutation_intent_by_operation_stage(
        MAIN_OPERATION, "release_transition"
    ) is None
    assert expiring.read_release_transition(MAIN_OPERATION) is None
    assert expiring.read_provider_receipt(MAIN_OPERATION) is None
    assert expiring.read_reconciliation(MAIN_OPERATION) is None
    authorization = expiring.read_release_authorization(MAIN_OPERATION)
    assert authorization is not None
    assert (
        expiring.read_release_claim_for_authorization(MAIN_OPERATION, authorization[0])
        is not None
    )
