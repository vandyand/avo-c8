"""Filesystem-backed tests for the C4 single-stage durable kernel."""
# pyright: reportPrivateUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportArgumentType=false, reportCallIssue=false, reportMissingImports=false, reportUntypedFunctionDecorator=false

from __future__ import annotations

import json
import subprocess
import sys
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Event, Thread
from typing import Any

import pytest
from pydantic import ValidationError

import avo_correlate.application.c4_stage_executor as c4_kernel
from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.adapters.git.main_composition import MainBaseSnapshot, MainCompositionAdapter
from avo_correlate.application.c4_capabilities import (
    CandidateObservationRequest,
    CandidateObservationResult,
    CandidatePublicationRequest,
    CandidatePublicationResult,
)
from avo_correlate.application.c4_stage_executor import (
    C4StageExecutionError,
    C4StageExecutor,
)
from avo_correlate.contracts.main_graduation import (
    MainExternalIdentity,
    MainGraduationPlan,
    MainPreparationAuthorization,
    MainReleaseIssuerBinding,
)
from avo_correlate.contracts.main_graduation_phase_a import (
    MainLeaseEvidenceRecord,
    MainMutationIntent,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.phase_a_test_support import TEST_PHASE_A_AUTHORITY
from tests.unit.test_main_graduation_c4_validated_fixture import (
    MAIN_OPERATION,
    REPOSITORY,
    _git,
    _source,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)
D = "sha256:" + "1" * 64
LEASE_DIGEST = "sha256:" + "2" * 64
CONFIG = "sha256:" + "3" * 64
POLICY = canonical_digest({"controller_config_digest": CONFIG, "main_policy": "ordinary"})
CANDIDATE = "a" * 40


class Clock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def now(self) -> datetime:
        return self.value


class Fence:
    def __init__(self, stale: bool = False) -> None:
        self.calls = 0
        self.stale = stale

    def assert_current(self, **_: object) -> None:
        self.calls += 1
        if self.stale:
            raise RuntimeError("stale lease")


class Authority:
    provider_identity = "strict-test-provider"
    provider_api_version = "v1"

    def verify_lease_evidence(self, record: Any) -> None:
        TEST_PHASE_A_AUTHORITY.verify_lease_evidence(record)

    def verify_mutation_receipt(self, receipt: Any, intent: Any) -> None:
        TEST_PHASE_A_AUTHORITY.verify_mutation_receipt(receipt, intent)

    def verify_fence_resolution(self, resolution: Any, receipt: Any) -> None:
        TEST_PHASE_A_AUTHORITY.verify_fence_resolution(resolution, receipt)

    def verify_provider_post_state(self, *args: Any) -> None:
        TEST_PHASE_A_AUTHORITY.verify_provider_post_state(*args)

    def verify_stage_result(self, result: Any, request: Any, intent: Any) -> None:
        if (
            result.request_digest != request.request_digest
            or result.external_identity != intent.external_identity.identity_digest
        ):
            raise ValueError("wrong provider result")

    def verify_stage_observation(self, result: Any, request: Any, intent: Any) -> None:
        if result.request_digest != request.request_digest:
            raise ValueError("wrong provider observation")


class KernelJournal(MainGraduationJournal):
    """Real filesystem journal with only C1-C2 chronology out of scope."""

    def _require_preparation_chain(self, preparation: Any) -> None:
        return None


class CandidateProvider:
    provider_identity = Authority.provider_identity
    provider_api_version = Authority.provider_api_version

    def __init__(
        self, *, ambiguous: bool = False, reject: bool = False, error: bool = False
    ) -> None:
        self.calls = 0
        self.ambiguous = ambiguous
        self.reject = reject
        self.error = error

    def publish_candidate(self, request: CandidatePublicationRequest) -> CandidatePublicationResult:
        self.calls += 1
        if self.error:
            raise TimeoutError("provider timed out after dispatch")
        return CandidatePublicationResult.build(
            **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
            outcome="rejected" if self.reject else ("ambiguous" if self.ambiguous else "applied"),
            response_digest=D,
            observed_at=NOW,
            dispatch_started=not self.reject,
        )


class Observation:
    def __init__(self, result: CandidateObservationResult) -> None:
        self.result = result
        self.calls = 0

    def observe_candidate(self, _: Any) -> CandidateObservationResult:
        self.calls += 1
        return self.result


def _digest(model: type[Any], values: dict[str, Any], field: str) -> Any:
    probe = model.model_construct(**values, **{field: D})
    return model.model_validate(
        values | {field: canonical_digest(probe.model_dump(exclude={field}, mode="json"))}
    )


def _fixture(
    tmp_path: Path,
) -> tuple[MainGraduationJournal, MainMutationIntent, CandidatePublicationRequest, Authority]:
    source = _source(tmp_path)
    issuer_values = {
        "operation_id": MAIN_OPERATION,
        "repository_digest": REPOSITORY,
        "target_ref": "refs/heads/main",
        "controller_config_digest": CONFIG,
        "issuer_id": "isolated-release",
        "app_id": 9001,
        "isolation_digest": D,
        "issuer_domain": "isolated-release-check",
        "trusted_source_issuer": source.source_issuer,
        "trusted_source_domain": source.source_domain,
    }
    issuer = MainReleaseIssuerBinding.model_validate(
        issuer_values | {"binding_digest": canonical_digest(issuer_values | {"schema_version": 1})}
    )

    class Reader:
        def fresh_main_base(self) -> MainBaseSnapshot:
            return MainBaseSnapshot(
                REPOSITORY,
                source.source_result_parent,
                _git(tmp_path / "checkout", "rev-parse", f"{source.source_result_parent}^{{tree}}"),
            )

    seed = KernelJournal(
        tmp_path,
        release_issuer_binding=issuer,
        composition_root=tmp_path / "checkout",
        repository_digest=REPOSITORY,
        base_reader=Reader(),
        phase_a_authority_verifier=Authority(),
    )
    seed.record_release_issuer_binding(issuer)
    seed.record_source_package(source)
    composition = MainCompositionAdapter(
        tmp_path / "checkout",
        seed,
        repository_digest=REPOSITORY,
        base_reader=Reader(),
        controller_config_digest=CONFIG,
        policy_epoch=POLICY,
    ).compose(source)
    plan = MainGraduationPlan.model_validate(
        {
            "operation_id": MAIN_OPERATION,
            "repository_digest": REPOSITORY,
            "target_ref": "refs/heads/main",
            "package": source,
            "delta": composition.delta,
            "composition": composition.composition,
            "composition_proof": composition.proof,
            "composition_proof_artifact": composition.proof_artifact,
            "policy_epoch": POLICY,
            "controller_config_digest": CONFIG,
            "release_issuer_binding": issuer,
            "evidence_artifacts": [source.package_artifact, *source.child_artifacts],
        }
    )
    seed.record_plan(plan)
    lease_values = {
        "repository_digest": REPOSITORY,
        "target_ref": "refs/heads/main",
        "operation_id": MAIN_OPERATION,
        "owner": "lease",
        "policy_epoch": POLICY,
        "lease_epoch_digest": LEASE_DIGEST,
        "acquired_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(hours=1),
    }
    lease_probe = MainLeaseEvidenceRecord.model_construct(
        **lease_values, lease_digest=D, evidence_digest=D
    )
    lease_values["lease_digest"] = canonical_digest(
        lease_probe.model_dump(exclude={"lease_digest", "evidence_digest"}, mode="json")
    )
    lease_probe = MainLeaseEvidenceRecord.model_construct(**lease_values, evidence_digest=D)
    lease = MainLeaseEvidenceRecord.model_validate(
        lease_values
        | {
            "evidence_digest": canonical_digest(
                lease_probe.model_dump(exclude={"evidence_digest"}, mode="json")
            )
        }
    )
    auth_values = {
        "operation_id": MAIN_OPERATION,
        "repository_digest": REPOSITORY,
        "target_ref": "refs/heads/main",
        "plan_digest": canonical_digest(plan),
        "intent_digest": D,
        "package_digest": source.package_digest,
        "composition_digest": composition.composition.composition_digest,
        "base_commit": source.source_result_parent,
        "base_tree": composition.composition.base_tree,
        "candidate_commit": CANDIDATE,
        "candidate_tree": composition.composition.candidate_tree,
        "lease_identity": "lease",
        "lease_digest": lease.lease_digest,
        "policy_epoch": POLICY,
        "authorized_at": NOW - timedelta(minutes=1),
    }
    prep = _digest(MainPreparationAuthorization, auth_values, "authorization_digest")
    seed.record_lease_evidence_record(lease)
    seed.record_preparation_authorization(prep)
    journal = KernelJournal(
        tmp_path, release_issuer_binding=issuer, phase_a_authority_verifier=Authority()
    )
    request = CandidatePublicationRequest.build(
        operation_id=MAIN_OPERATION,
        repository_digest=REPOSITORY,
        lease_epoch_digest=LEASE_DIGEST,
        candidate_ref="refs/heads/avo/candidate/" + MAIN_OPERATION.removeprefix("sha256:"),
        candidate_commit=CANDIDATE,
        preparation_authorization_digest=prep.authorization_digest,
    )
    external = MainExternalIdentity(
        operation_id=MAIN_OPERATION,
        repository_digest=REPOSITORY,
        target_ref="refs/heads/main",
        stage="candidate_publication",
        external_key=request.external_key,
        identity_digest=request.external_identity,
    )
    intent_values = {
        "repository_digest": REPOSITORY,
        "target_ref": "refs/heads/main",
        "operation_id": MAIN_OPERATION,
        "stage": "candidate_publication",
        "lease_identity": "lease",
        "lease_digest": lease.lease_digest,
        "lease_epoch_digest": LEASE_DIGEST,
        "policy_epoch_digest": POLICY,
        "controller_config_digest": CONFIG,
        "preparation_authorization_digest": prep.authorization_digest,
        "external_identity": external,
        "request_digest": request.request_digest,
        "recorded_at": NOW,
    }
    intent = _digest(MainMutationIntent, intent_values, "intent_digest")
    return journal, intent, request, Authority()


def _executor(
    journal: MainGraduationJournal,
    provider: CandidateProvider,
    clock: Clock,
    fence: Fence,
    authority: Authority,
    observation: Any = None,
) -> C4StageExecutor:
    return C4StageExecutor(
        journal=journal,
        clock=clock,
        lease_fence=fence,
        capability=provider,
        observation_capability=observation,
        authority_verifier=authority,
        provider_identity=authority.provider_identity,
        provider_api_version=authority.provider_api_version,
    )


def test_intent_before_mutation_and_terminal_replay(tmp_path: Path) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    provider = CandidateProvider()

    class Checking(CandidateProvider):
        def publish_candidate(
            self, request: CandidatePublicationRequest
        ) -> CandidatePublicationResult:
            assert journal.read_mutation_intent(intent.intent_digest) is not None
            return super().publish_candidate(request)

    provider = Checking()
    executor = _executor(journal, provider, Clock(), Fence(), authority)
    receipt = executor.execute(intent, request)
    assert receipt.outcome == "applied" and provider.calls == 1
    assert journal.read_mutation_dispatch_owner(intent.intent_digest) is not None
    assert executor.execute(intent, request) == receipt and provider.calls == 1


def test_dispatch_owner_marker_crash_requires_recovery(tmp_path: Path) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    journal.record_mutation_intent(intent)
    provider = CandidateProvider()
    executor = _executor(journal, provider, Clock(), Fence(), authority)
    assert executor._claim_dispatch_owner(intent, request) is True
    with pytest.raises(C4StageExecutionError, match="recovery"):
        executor.execute(intent, request)
    assert provider.calls == 0
    marker = journal.read_mutation_dispatch_owner(intent.intent_digest)
    assert marker is not None
    assert marker.request_digest == request.request_digest


def test_dispatch_owner_recovery_observes_once_after_marker_crash(tmp_path: Path) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    journal.record_mutation_intent(intent)
    provider = CandidateProvider()
    executor = _executor(journal, provider, Clock(), Fence(), authority)
    assert executor._claim_dispatch_owner(intent, request) is True
    observation_request = CandidateObservationRequest.build(
        **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
        object_id=request.candidate_ref,
    )
    observation_result = CandidateObservationResult.build(
        **observation_request.model_dump(
            exclude={"request_digest", "external_key", "external_identity"}
        ),
        outcome="observed",
        evidence_digest=D,
        observed_at=NOW,
    )
    observer = Observation(observation_result)
    recovery_executor = _executor(
        journal, provider, Clock(), Fence(), authority, observer
    )
    recovery_executor.recover(intent, observation_request, original_request=request)
    assert provider.calls == 0 and observer.calls == 1


def test_clock_or_lease_change_after_owner_marker_stops_before_provider(
    tmp_path: Path,
) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    clock = Clock()

    class AdvancingFence(Fence):
        def assert_current(self, **kwargs: object) -> None:
            super().assert_current(**kwargs)
            if self.calls == 1:
                clock.value = NOW + timedelta(hours=2)
            else:
                raise RuntimeError("lease expired while claiming dispatch")

    provider = CandidateProvider()
    executor = _executor(journal, provider, clock, AdvancingFence(), authority)
    with pytest.raises(C4StageExecutionError):
        executor.execute(intent, request)
    assert provider.calls == 0
    assert journal.read_mutation_dispatch_owner(intent.intent_digest) is not None


def test_independent_executors_have_one_dispatch_owner_and_loser_recovers(
    tmp_path: Path, monkeypatch: Any
) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    journal2 = KernelJournal(
        tmp_path,
        release_issuer_binding=journal._release_issuer_binding,
        phase_a_authority_verifier=authority,
    )
    entered = Event()
    release = Event()

    class BlockingProvider(CandidateProvider):
        def publish_candidate(
            self, request: CandidatePublicationRequest
        ) -> CandidatePublicationResult:
            self.calls += 1
            entered.set()
            assert release.wait(10)
            return CandidatePublicationResult.build(
                **request.model_dump(
                    exclude={"request_digest", "external_key", "external_identity"}
                ),
                outcome="applied",
                response_digest=D,
                observed_at=NOW,
                dispatch_started=True,
            )

    provider = BlockingProvider()
    first = _executor(journal, provider, Clock(), Fence(), authority)
    second = _executor(journal2, provider, Clock(), Fence(), authority)

    def unlocked(_: str) -> Any:
        return nullcontext()

    monkeypatch.setattr(c4_kernel, "_operation_lock", unlocked)
    first_result: list[Any] = []
    loser_errors: list[Exception] = []

    def run_first() -> None:
        first_result.append(first.execute(intent, request))

    def run_second() -> None:
        try:
            second.execute(intent, request)
        except Exception as exc:
            loser_errors.append(exc)

    first_thread = Thread(target=run_first)
    first_thread.start()
    assert entered.wait(10)
    second_thread = Thread(target=run_second)
    second_thread.start()
    second_thread.join(10)
    release.set()
    first_thread.join(10)
    assert len(first_result) == 1 and first_result[0].outcome == "applied"
    assert len(loser_errors) == 1 and "recovery" in str(loser_errors[0])
    assert provider.calls == 1


def test_dispatch_owner_cas_has_one_winner_across_independent_journals(
    tmp_path: Path,
) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    journal.record_mutation_intent(intent)
    barrier = Barrier(2)
    winners: list[bool] = []

    def claim() -> None:
        independent = KernelJournal(
            tmp_path,
            release_issuer_binding=journal._release_issuer_binding,
            phase_a_authority_verifier=authority,
        )
        barrier.wait()
        winners.append(
            independent.claim_mutation_dispatch(
                operation_id=intent.operation_id,
                intent_digest=intent.intent_digest,
                request_digest=request.request_digest,
                stage=intent.stage,
                repository_digest=intent.repository_digest,
                target_ref=intent.target_ref,
                external_identity_digest=intent.external_identity.identity_digest,
                lease_identity=intent.lease_identity,
                lease_digest=intent.lease_digest,
                lease_epoch_digest=intent.lease_epoch_digest,
                recorded_at=NOW,
            )
        )

    threads = [Thread(target=claim), Thread(target=claim)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(winners) == [False, True]
    assert journal.read_mutation_dispatch_owner(intent.intent_digest) is not None


def test_ambiguous_recovery_is_read_only_across_fresh_executor(tmp_path: Path) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    provider = CandidateProvider(ambiguous=True)
    first = _executor(journal, provider, Clock(), Fence(), authority)
    receipt = first.execute(intent, request)
    observation_request = CandidateObservationRequest.build(
        **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
        object_id=request.candidate_ref,
    )
    observation_result = CandidateObservationResult.build(
        **observation_request.model_dump(
            exclude={"request_digest", "external_key", "external_identity"}
        ),
        outcome="observed",
        evidence_digest=D,
        observed_at=NOW,
    )
    observer = Observation(observation_result)
    fresh = KernelJournal(
        tmp_path,
        release_issuer_binding=journal._release_issuer_binding,  # pyright: ignore[reportPrivateUsage]
        phase_a_authority_verifier=authority,
    )
    recovered = _executor(
        fresh, CandidateProvider(), Clock(), Fence(), authority, observer
    ).recover(intent, observation_request, original_request=request)
    assert recovered == receipt and provider.calls == 1 and observer.calls == 1


@pytest.mark.parametrize("outcome", ["observed", "not_found"])
def test_resolution_replay_is_verified_and_does_not_reobserve(
    tmp_path: Path, outcome: str
) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    receipt = _executor(
        journal, CandidateProvider(ambiguous=True), Clock(), Fence(), authority
    ).execute(intent, request)
    observation_request = CandidateObservationRequest.build(
        **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
        object_id=request.candidate_ref,
    )
    observation_result = CandidateObservationResult.build(
        **observation_request.model_dump(
            exclude={"request_digest", "external_key", "external_identity"}
        ),
        outcome=outcome,
        evidence_digest=D,
        observed_at=NOW,
    )
    first_observer = Observation(observation_result)
    first = _executor(
        journal,
        CandidateProvider(),
        Clock(),
        Fence(),
        authority,
        first_observer,
    )
    assert first.recover(intent, observation_request, original_request=request) == receipt
    assert first_observer.calls == 1

    # The active fence has been closed.  The public read-by-fence contract
    # still verifies the durable resolution, and the intent lookup lets a
    # fresh executor replay it without reopening a fence.
    resolution = journal.read_mutation_fence_resolution_by_intent(intent.intent_digest)
    assert resolution is not None
    assert journal.read_mutation_fence_resolution_by_fence(resolution[0].fence_digest) == resolution
    second_observer = Observation(observation_result)
    fresh = KernelJournal(
        tmp_path,
        release_issuer_binding=journal._release_issuer_binding,
        phase_a_authority_verifier=authority,
    )
    replay = _executor(
        fresh,
        CandidateProvider(),
        Clock(),
        Fence(),
        authority,
        second_observer,
    ).recover(intent, observation_request, original_request=request)
    assert replay == receipt
    assert second_observer.calls == 0


def test_recover_effective_exposes_resolution_without_rewriting_source_receipt(
    tmp_path: Path,
) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    receipt = _executor(
        journal, CandidateProvider(ambiguous=True), Clock(), Fence(), authority
    ).execute(intent, request)
    observation_request = CandidateObservationRequest.build(
        **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
        object_id=request.candidate_ref,
    )
    observation_result = CandidateObservationResult.build(
        **observation_request.model_dump(
            exclude={"request_digest", "external_key", "external_identity"}
        ),
        outcome="observed",
        evidence_digest=D,
        observed_at=NOW,
    )
    effective = _executor(
        journal,
        CandidateProvider(),
        Clock(),
        Fence(),
        authority,
        Observation(observation_result),
    ).recover_effective(intent, observation_request, original_request=request)

    resolution = journal.read_mutation_fence_resolution_by_intent(intent.intent_digest)
    assert resolution is not None
    assert effective.receipt == receipt
    assert effective.receipt.outcome == "ambiguous"
    assert effective.effective_outcome == "already_applied"
    assert effective.has_authoritative_resolution
    assert effective.can_advance_parent
    assert effective.parent_resolution_digest == resolution[0].resolution_digest
    source_prior = journal.read_mutation_receipt(receipt.receipt_digest)
    assert source_prior is not None and source_prior[0] == receipt


def test_fresh_process_crash_after_dispatch_recovers_effective_resolution(
    tmp_path: Path,
) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    provider = CandidateProvider()
    journal.record_mutation_intent(intent)
    executor = _executor(journal, provider, Clock(), Fence(), authority)
    assert executor._claim_dispatch_owner(intent, request) is True
    # The provider crossed the boundary, but this process dies before receipt
    # publication.  The child below must recover by observation only.
    provider.publish_candidate(request)

    observation_request = CandidateObservationRequest.build(
        **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
        object_id=request.candidate_ref,
    )
    observation_result = CandidateObservationResult.build(
        **observation_request.model_dump(
            exclude={"request_digest", "external_key", "external_identity"}
        ),
        outcome="observed",
        evidence_digest=D,
        observed_at=NOW,
    )
    issuer = journal._release_issuer_binding  # pyright: ignore[reportPrivateUsage]
    assert issuer is not None
    script = """
import json
import sys
from pathlib import Path

from tests.unit.test_c4_stage_executor import (
    Authority,
    CandidateObservationRequest,
    CandidateObservationResult,
    CandidateProvider,
    Clock,
    Fence,
    KernelJournal,
    Observation,
)
from avo_correlate.application.c4_stage_executor import C4StageExecutor
from avo_correlate.contracts.main_graduation_phase_a import MainMutationIntent
from avo_correlate.application.c4_capabilities import CandidatePublicationRequest
from avo_correlate.contracts.main_graduation import MainReleaseIssuerBinding

root = Path(sys.argv[1])
intent = MainMutationIntent.model_validate_json(sys.argv[2])
request = CandidatePublicationRequest.model_validate_json(sys.argv[3])
observation_request = CandidateObservationRequest.model_validate_json(sys.argv[4])
observation_result = CandidateObservationResult.model_validate_json(sys.argv[5])
issuer = MainReleaseIssuerBinding.model_validate_json(sys.argv[6])
journal = KernelJournal(
    root,
    release_issuer_binding=issuer,
    phase_a_authority_verifier=Authority(),
)
observer = Observation(observation_result)
executor = C4StageExecutor(
    journal=journal,
    clock=Clock(),
    lease_fence=Fence(),
    capability=CandidateProvider(),
    observation_capability=observer,
    authority_verifier=Authority(),
    provider_identity=Authority.provider_identity,
    provider_api_version=Authority.provider_api_version,
)
result = executor.recover_effective(
    intent,
    observation_request,
    original_request=request,
)
print(json.dumps({
    "receipt": result.receipt.receipt_digest,
    "outcome": result.effective_outcome,
    "parent_resolution_digest": result.parent_resolution_digest,
    "observer_calls": observer.calls,
}))
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(tmp_path),
            intent.model_dump_json(),
            request.model_dump_json(),
            observation_request.model_dump_json(),
            observation_result.model_dump_json(),
            issuer.model_dump_json(),
        ],
        cwd=Path.cwd(),
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["outcome"] == "already_applied"
    assert result["observer_calls"] == 1
    assert result["receipt"] is not None
    assert result["parent_resolution_digest"].startswith("sha256:")
    source_prior = journal.read_mutation_receipt(result["receipt"])
    assert source_prior is not None and source_prior[0].outcome == "ambiguous"


def test_fence_resolution_reader_fails_closed_when_authority_is_tampered(
    tmp_path: Path,
) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    receipt = _executor(
        journal, CandidateProvider(ambiguous=True), Clock(), Fence(), authority
    ).execute(intent, request)
    observation_request = CandidateObservationRequest.build(
        **request.model_dump(exclude={"request_digest", "external_key", "external_identity"}),
        object_id=request.candidate_ref,
    )
    result = CandidateObservationResult.build(
        **observation_request.model_dump(
            exclude={"request_digest", "external_key", "external_identity"}
        ),
        outcome="observed",
        evidence_digest=D,
        observed_at=NOW,
    )
    observer = Observation(result)
    executor = _executor(journal, CandidateProvider(), Clock(), Fence(), authority, observer)
    assert executor.recover(intent, observation_request, original_request=request) == receipt
    resolution = journal.read_mutation_fence_resolution_by_intent(intent.intent_digest)
    assert resolution is not None

    class TamperedAuthority(Authority):
        def verify_fence_resolution(self, resolution: Any, receipt: Any) -> None:
            raise ValueError("tampered verifier")

    tampered = KernelJournal(
        tmp_path,
        release_issuer_binding=journal._release_issuer_binding,
        phase_a_authority_verifier=TamperedAuthority(),
    )
    with pytest.raises(Exception, match="tampered verifier"):
        tampered.read_mutation_fence_resolution_by_fence(resolution[0].fence_digest)


def test_rejection_expiry_stale_lease_and_existing_intent_fail_closed(tmp_path: Path) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    rejected = _executor(
        journal, CandidateProvider(reject=True), Clock(), Fence(), authority
    ).execute(intent, request)
    assert rejected.outcome == "rejected" and rejected.dispatch_started is False
    journal2, intent2, request2, authority2 = _fixture(tmp_path / "two")
    provider = CandidateProvider()
    expired = Clock(NOW)
    with pytest.raises(C4StageExecutionError):
        _executor(journal2, provider, expired, Fence(stale=True), authority2).execute(
            intent2, request2
        )
    assert provider.calls == 0
    journal3, intent3, request3, authority3 = _fixture(tmp_path / "three")
    journal3.record_mutation_intent(intent3)
    with pytest.raises(C4StageExecutionError, match="recovery"):
        _executor(journal3, CandidateProvider(), Clock(), Fence(), authority3).execute(
            intent3, request3
        )


def test_transport_timeout_persists_ambiguity_and_fence(tmp_path: Path) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    provider = CandidateProvider(error=True)
    receipt = _executor(journal, provider, Clock(), Fence(), authority).execute(intent, request)
    assert receipt.outcome == "ambiguous" and receipt.dispatch_started
    with pytest.raises(MainGraduationJournalError):
        journal.assert_no_unresolved_mutation_fence(REPOSITORY, "refs/heads/main")


def test_wrong_request_fails_before_provider_call(tmp_path: Path) -> None:
    journal, intent, request, authority = _fixture(tmp_path)
    provider = CandidateProvider()
    bad_request = request.model_copy(update={"candidate_commit": "b" * 40})
    with pytest.raises(ValidationError):
        _executor(journal, provider, Clock(), Fence(), authority).execute(intent, bad_request)
    assert provider.calls == 0
