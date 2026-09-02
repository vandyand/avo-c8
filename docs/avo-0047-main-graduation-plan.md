# AVO-004.7 protected-main graduation implementation plan

Status: implementation plan; C4 complete on 2026-09-01 at HEAD
`82ace056cf9f0453b43c71845179c437914a041b` and C5 complete for offline acceptance on
2026-09-01 at HEAD `e38d0b826f94f3f559fb2e3ef0b26d1d17128c53` with Terra APPROVE and combined
24 passed; the separately reviewed personal exact-CAS boundary is approved offline at
`9e59638` and hosted canonical CI passes the unchanged 85% coverage floor. Live `main` mutation remains blocked until final
writer-restricting protections,
an isolated writer principal, and a durable controller/journal are provisioned.
C6 is complete for offline acceptance at final code HEAD `e6db424cc671d7a5d63b9b8a7246a316c4867f91`;
C7 deterministic offline gate is complete for offline acceptance at final code HEAD
`9c70c36074810606692f8c2030b25ce83c10a1e4`; see the [C7 result](avo-0047-c7-result.md).
The 47 exact frozen case/vector entries passed, replay used `executor_calls=0` and `clock_calls=0`, and
`deploy_performed=false`. The organization/merge-queue blocker is superseded only for the
separately reviewed personal exact-CAS protocol; queue remains an alternate, not-selected path.

C8 local Wave 1/2 foundations are Terra-approved through commits `ecd773c`, `935363c`, and
`49fb84e`; see the [local-foundations result](avo-0047-c8-local-foundations-result.md).
The bounded pinned/no-redirect GitHub transport is now the actual provider default, and
controller-rooted activation plus raw-proof CAS/legacy-compatible ledger schema support are
implemented locally. Phase 1 is now also accepted at `daeff01` through `f38840d`: its immutable
single-flight snapshot performs five authenticated GETs (repository, main ref, commit, workflow
blob, final main fence), verifies blob binding, and has 52 focused tests. This remains diagnostic
only: the final writer ruleset, queue/issuer authority, and rollback ACL remain unsupported;
validation-principal diagnostics are covered by the later accepted diagnostic gate below.
The rollback and activation preparers are explicitly non-consumable drafts; there
is no live execution, concrete trust root, authority-bearing adapter, runner, readiness, or
hosted mutation.

The workflow-semantics and env-only diagnostic CLI gate is Terra-approved at
`7ded390436010844f6044151c59b05a02c74b810` with 69 Terra-focused tests and 125 focused parent
tests. It pins PyYAML 6.0.3/YAML 1.2 `on`, rejects unsafe YAML features and unbounded input,
validates static PR/merge_group checks-requested facts and exact lowercase 40-hex `github.sha`
checkout refs with `persist-credentials=false`, and exposes only a fixed-origin, no-redirect,
sanitized, read-only env-only `GITHUB_TOKEN` diagnostic. No live run occurred because the token is
absent; validation identity, issuer, and rollback remain unsupported.

The atomic authenticated Phase 2 snapshot is Terra-approved at `1d911e3` with 30 snapshot/parser
review tests and 82 combined focused checks: two-pass mutable-configuration and final main-ref
fences, bounded rules pagination, REST/GraphQL cross-binding, SHA-1/SHA-256 binding, and failure
caching. App checks are configuration-only, not issuer authority. Workflow semantics and
validation-principal identity diagnostics are approved and provider-evidenced when available.
The diagnostic is accepted at exact commit `a8af4341be413981da348c772b9d51e1e6f9f27e`; it
integrates the pure bounded parser with the atomic read-only snapshot, exact main SHA, at most 10
pages/1000 check runs, stable cardinality/unique IDs, exact required contexts, App 15368 metadata,
run-ID and two-pass raw-page digests, unrelated in-progress tolerance, and final freshness
blockers for success/wrong-App/failure/duplicate. It is secret-safe and non-authoritative.
Terra APPROVE found no P0/P1 issues; 149 focused parent/Terra tests passed and Ruff/scoped
Pyright/diff were clean. No further local diagnostic leaf is currently authority-sufficient;
issuer and rollback remain unsupported.

The public personal repository [vandyand/avo-c8](https://github.com/vandyand/avo-c8) was
created and seeded while [vandyand/avo](https://github.com/vandyand/avo) remained unchanged.
Strict Pyright baseline repair is recorded at `a0d1a7d`; the Terra-approved offline exact-CAS
boundary is at `9e59638`, pushed to the personal repository. Hosted run
[33668978939](https://github.com/vandyand/avo-c8/actions/runs/33668978939) closed at 82.52%
coverage after exposing two portability assertions; `a624a8a` fixes those assertions. Canonical
hosted run [33688935928](https://github.com/vandyand/avo-c8/actions/runs/33688935928) on exact
commit `2f35d65381774b83fdbe622539ef7185d2b465ff` subsequently passed Ubuntu (2,600 passed,
two skipped, 85.20% with the literal floor enforced) and Windows (2,589 passed, six skipped).
Commits `bbc4d827` and `2f35d653` enforce the unchanged threshold and add meaningful adversarial
coverage without excluding production files. It fixes `PATCH` `main` with `force=false`, exact B-to-C sole-parent topology,
durable request ID, 409-only conflicts, conservative 422 handling, and no force/delete/
generic-ref capability. No live CAS attempt or rollback occurred. Bootstrap `main` branch
protection on `vandyand/avo-c8` is live with `enforce_admins=true`,
`required_linear_history=true`, `allow_force_pushes=false`, `allow_deletions=false`, and no
PR/status requirements; Terra reviewed it as a topology guard only, not writer isolation or
readiness. The final writer-restricting ruleset, isolated writer
principal, hosted denial tests, and live controller/transport integration are not provisioned. The
read-only trusted-source adapter is Terra-approved at `ae65b73`, the fail-closed durable-
backend gate at `d9f6d3d`, and the offline exact-CAS contracts/journal at `a26fd7a` (15 passed,
two Windows symlink-privilege skips). None enables provider/HTTP mutation. The live controller/
transport remains next, followed by protected hosted rollback, ledger activation, and
12 consecutive eligible successes.

This plan is subordinate to the [authoritative roadmap](roadmap.md) and
[ADR 0011](adr/0011-protected-main-graduation.md). It describes implementation-ready
work for the declared single-host, trusted-team boundary. It authorizes no repository
transfer, protection/queue mutation, deployment, or live `main` write.

## Outcome and non-goals

AVO-004.7 will graduate a trusted successful integration campaign result to protected
`main` by applying only its exact result delta to a fresh main base, with durable evidence,
recovery, and a separate main rollback authority. Completion requires the preregistered
12-of-12 eligible hosted threshold and both main-specific rollback evidence classes.

Out of scope are deployment, release promotion, secrets, production effects, hostile-code
containment, multi-host coordination, and any widening of integration-only contracts or
providers. Human authority remains available for exceptions and constitutional changes,
not routine approvals.

## C4 — coordinator and recovery

C4 is complete at the recorded HEAD; see the [final C4 result](avo-0047-c4-result.md). The
historical [Phase A result](avo-0047-c4-phase-a-result.md) remains immutable. C5 is complete for
offline acceptance at HEAD
`e38d0b826f94f3f559fb2e3ef0b26d1d17128c53` with Terra APPROVE and combined 24 passed. The next
C7 is now complete; see the [C7 result](avo-0047-c7-result.md). C4–C7 are offline
evidence and do not establish hosted/live readiness or complete AVO-004.7.

Phase A freezes the coordinator and recovery contracts before any provider implementation.
It is documentation, schema, journal, and test-contract work only: it creates no candidate,
PR, queue entry, check run, hold, release transition, or other remote mutation. The
coordinator is deliberately orchestration-only and has no merge, ref-update, check-write,
or release-issuer capability. Capabilities are injected through narrow interfaces with
separate publication, PR, enqueue, admission-issuer, and release-issuer roles; a DTO or
caller-supplied observation cannot confer authority.

The Phase A journal defines one append-only chronology for every externally meaningful
boundary: attempt start, preparation authorization, each mutation intent, its provider
receipt or reconciliation, admission and hold observations, release claim, release
transition, authoritative post-state, cleanup, and completion. For every mutation, the
target-scoped unresolved-external-mutation slot/fence is durably reserved in the same
journal transaction as the mutation intent, before any provider capability is dispatched.
Thus there is no crash window in which a provider may have been called but the fence has
not yet been recorded. Successful or rejected authoritative observation, or later
reconciliation that conclusively establishes the outcome, resolves that reservation;
ambiguous or incomplete observation leaves it open. Receipts are create-once, and
conflicting duplicates remain unresolved rather than being overwritten. The journal also
exposes durable main-lease evidence (including owner, operation, target, policy epoch,
and expiry). While the fence is open, a new attempt cannot overlap or issue a new write;
recovery is read-only until the ambiguity is resolved.

The Phase A coordinator does not treat provider or lease evidence DTOs as authority.
Verifier capabilities are injected into the journal/coordinator boundary and must be
controller-owned, independently configured capabilities that authenticate and verify
those records. A caller-supplied DTO, serialized observation, lease snapshot, or claimed
issuer identity can be input to verification but cannot authorize a mutation by itself.
This rule applies to every mutation receipt, including both terminal and ambiguous
receipts: each remains a DTO until the mandatory controller-owned verifier authenticates
it at record, recovery, and use time. No receipt, regardless of its reported outcome, may
clear the target-scoped unresolved-mutation reservation or authorize a parent-stage
transition without that verifier result. A receipt that cannot be authenticated remains
unresolved and fail-closed.

The release boundary has an atomic, durable, create-once claim keyed by the exact
authorization digest, hold run/nonce, group, lease epoch, and issuer. Claiming is distinct
from dispatch: after dispatch may have begun, recovery must never issue a second release
transition, even when the receipt is lost. Release authorization expiry is bounded by the
lease expiry and configured maximum TTL.
The release-transition intent must be durably recorded before provider dispatch. If the
release authorization or one-use claim expires before that intent is durable, the attempt
quarantines with zero release mutation and a fresh attempt is required. If the intent is
already durable, later expiry permits only read-only reconciliation; it never authorizes a
second dispatch. Any live executor must use a trusted controller clock to recheck
authorization validity, lease validity, and issuer scope immediately before dispatching
the provider transition; a caller-supplied time or stale preflight check is insufficient.

Admission and group-hold identities are deterministic and operation-bound (including the
exact PR/group, queue generation, source/head identity, and nonce derivation inputs), so a
success cannot transfer to a regenerated candidate, PR, or merge group. If an external
write may have happened but cannot be authoritatively observed, recovery only reads and
reconciles; it never retries admission, hold, release, enqueue, or publication by guessing.
Phase A does not add provider writes or grant the coordinator release authority.

## Dependency-ordered task graph

The IDs below are stable leaf IDs. A leaf may not be accepted until every dependency is
accepted and its write scope is reviewed.

| ID | Leaf | Depends on | Write scope | Acceptance checks |
| --- | --- | --- | --- | --- |
| AVO-004.7-C1 | Main contracts and journal | AVO-004.6 | New `main_graduation` contract models, canonical serializers, schema exports, and a dedicated journal/artifact namespace. No integration contract edits. | Strict models include `MainPreparationAuthorization`, `MainQueueAdmissionObservation`, `MainReleaseHoldObservation`, and one-use `MainReleaseAuthorization` with two SHA-specific states of the pinned `avo-main-release` context, exact hold/admission run ID/nonce, queue-generation identity, issuer/isolation contract, and App 15368 validation identity. Reject extras, mutable integration heads, wrong target, missing children, production/constitutional paths, `deploy=true`, duplicate evidence, and stale epochs. Plan/lease/intent/preparation-auth/admission/hold/release-auth/receipt/completion digests replay identically. |
| AVO-004.7-C2 | Deterministic composition adapter | AVO-004.7-C1 | New composition module and tests only. Reads the trusted package and a fresh main base; writes immutable candidate/tree/path-manifest artifacts. | Recomputes the exact sole-parent-to-result delta; applies it deterministically to a fresh base; proves exact tree and parent; rejects multi-parent, mutable-head, path-manifest drift, ordinary-risk drift, and disallowed paths. |
| AVO-004.7-C3 | Protected-main provider and attester | AVO-004.7-C1 | New provider/attester adapter and fixtures; no live provider configuration mutation. | Parses exact repository, main base, PR, queue, queue generation, merge-group, protection/ruleset, admission, hold, check, and receipt observations; accepts PR-head admission success only from the isolated issuer after verifying PR/base/head, active required queue, max entries per group=1, expected base/merge method, no bypass/direct merge, issuer identity, and all admission evidence; after enqueue accepts group evidence only for exact sole-PR membership and exact group tree/topology; accepts group release transition only from the isolated issuer; App 15368 is validation-only; rejects stale/reused PR-head status, head/group transfer, wrong-SHA/App, stale, incomplete, duplicate, queue-disabled, unrelated queued PR, tree/topology mismatch, retargeted, direct-merge/bypass, and protection-drift observations. |
| AVO-004.7-C4 | Coordinator and recovery | AVO-004.7-C2, AVO-004.7-C3 | Phase A freezes contracts, append-only journal records, durable lease/fence/claim indexes, deterministic external identities, injected verifier capabilities, and narrow mutation capability protocols; later phases add the coordinator/recovery adapter and focused tests. No provider writes in Phase A. | Phase A proves each mutation intent and target-scoped unresolved-mutation reservation are committed atomically before provider dispatch; create-once receipts and atomic one-use release claim; durable main-lease expiry and fencing; deterministic admission/hold identities; capability separation with no coordinator merge authority; and read-only reconciliation after ambiguous dispatch. Successful/rejected authoritative observations resolve a reservation, while ambiguity keeps it open. The completed C4 implementation must enforce preparation-auth → publish/PR → isolated PR-head admission observation + successful non-release check → enqueue → distinct group pending-hold observation → one-use release-auth → last-moment issuer revalidation → isolated hold-success chronology; no provider queue/merge request follows release-auth; duplicate callers lease-fence; crash/timeout around admission/enqueue/auth/hold success reconciles read-only; regeneration creates a new attempt/composition and never transfers auth; successful replay is read-only. |
| AVO-004.7-C5 | Main rollback authority | AVO-004.7-C1, AVO-004.7-C3, AVO-004.7-C4 | New `MainRollbackAuthority`, inverse-delta contracts, and tests. No reset, force update, or direct ref update. | Offline acceptance complete at HEAD `e38d0b826f94f3f559fb2e3ef0b26d1d17128c53`: Terra APPROVE, combined 24 passed. Covers aggregate orchestration, terminal cleanup/closure, crash/replay, and adversarial recovery. No hosted/provider/main/deploy mutation. [Result](avo-0047-c5-result.md) |
| AVO-004.7-C6 | Campaign runner and eligibility ledger | AVO-004.7-C4, AVO-004.7-C5 | New runner, frozen activation record, eligibility ledger, threshold accumulator, and evidence package writer. | Complete for offline acceptance at `e6db424`; [result](avo-0047-c6-result.md). Enforces gap-free scheduler sequence after watermark, exactly one next-sequence admission with no speculative tail, ordinary nonempty eligibility from submission, terminal upstream failure/reset, and exact unresolved-tail closure. Hosted activation remains gated by C8 prerequisites and a fresh hosted rollback drill. |
| AVO-004.7-C7 | Deterministic offline gate | AVO-004.7-C1 through AVO-004.7-C6 | Offline harness, fault matrix, and result artifact only. No hosted mutation. | Complete at code HEAD `9c70c36074810606692f8c2030b25ce83c10a1e4`: 47 exact frozen case/vector entries passed, replay returned the exact same result with `executor_calls=0` and `clock_calls=0`, and `deploy_performed=false`. Two truthful failed-closed dry attempts exposed datetime-canonicalization and semantic-versus-artifact verifier bugs; both were remediated and reviewed. [Result](avo-0047-c7-result.md) |
| AVO-004.7-C8 | Hosted personal exact-CAS gate | AVO-004.7-C7 | Terra-approved local foundations plus hosted workflow/configuration and operator-controlled state root only after explicit authority. | The organization/merge-queue protocol remains alternate/not selected. Terra approved the personal exact-CAS boundary offline at `9e59638`; [vandyand/avo-c8](https://github.com/vandyand/avo-c8) was created/seeded and [vandyand/avo](https://github.com/vandyand/avo) remained unchanged. Canonical hosted run [33688935928](https://github.com/vandyand/avo-c8/actions/runs/33688935928) on exact commit `2f35d653` passed Ubuntu and Windows with the unchanged 85% floor enforced (85.20% total). The [personal exact-CAS result](avo-0047-c8-personal-exact-cas-result.md) records the fixed no-force/no-delete protocol and no live CAS/rollback. Offline trusted-source (`ae65b73`), durable-backend (`d9f6d3d`), and exact-CAS journal (`a26fd7a`) leaves are Terra-approved, but expose no provider/HTTP writer. Bootstrap protection remains topology-only; the live controller/transport, final writer ruleset/principal, and hosted denial tests are incomplete. Then a protected hosted rollback drill, ledger activation, and 12 consecutive eligible successes with 0 failures/boundary violations remain. |

## Contract and evidence boundary

The main namespace should expose typed equivalents of these records, with canonical JSON
and content-addressed child artifacts:

* `MainGraduationPlan`, `MainGraduationEligibilityRecord`, and `MainGraduationAttempt`;
* `MainSourcePackageBinding` for the canonical integration package and every child;
* `MainDeltaManifest` for sole parent/result identities, changed paths, exact tree, and
  ordinary-risk recomputation;
* `MainCompositionArtifact` for fresh main base and deterministic output;
* `MainQueueAdmissionObservation`, `MainQueueObservation`, `MainProtectionManifest`,
  `MainMergeGroupChecks`, `MainReleaseHoldObservation`, and `MainAttestationManifest`;
* `MainGraduationIntent`, reversible `MainPreparationAuthorization`, durable one-use
  `MainQueueAdmissionObservation`, one-use `MainReleaseAuthorization` (exact release-check
  run ID/nonce and queue generation), release-transition receipt, provider receipt,
  reconciliation, and completion package; and
* `MainRollbackAuthorization`, `MainRollbackIntent`, inverse artifact, receipt, and
  completion package.

All records bind the fixed repository/target identity, package and policy digests, exact
base and result topology, issuer/attester identities, isolation contract, operation and
lease IDs, and `deploy_performed: false`. The candidate cannot provide any authority-bearing
field. App 15368 is validation-only; the release issuer is a distinct mandatory isolated
principal.

## Phase gates

### Gate P0 — boundary freeze

Accept ADR 0011, freeze the target/ref/provider configuration, define the final protocol
assumptions, and record that current user-owned hosting blocks live main mutation. No
repository transfer or protection change is part of P0.

### Gate P1 — contract and composition proof

Accept C1–C3 only after schema, canonicalization, path/risk, package-child, and exact
composition tests pass. A composition result is not eligible for a hosted attempt until
provider and attester evidence can bind the exact merge group.

### Gate P2 — coordinator/recovery proof

Accept the live C4–C6 implementation after each durable boundary has crash/restart tests,
including the required end-to-end on-disk recovery fixture, duplicate-runner tests,
stale-base tests, and immutable artifact replay. The runner must emit a durable eligibility
ledger before counting any attempt toward the threshold.

### Gate P3 — offline rollback gate

C7 is accepted at code HEAD `9c70c36074810606692f8c2030b25ce83c10a1e4`: all 47 exact
frozen case/vector entries passed, including the main-specific inverse-delta rollback
authority, and replay returned the exact same result without executor or clock calls. The
completed AVO-004.6 integration rollback package was prerequisite input, never a substitute.
See the [C7 result](avo-0047-c7-result.md). This gate produced no hosted mutation.

### Gate P4 — hosting and release-hold activation

P4 now follows the separately reviewed personal exact-CAS route recorded in the [C8 personal
exact-CAS result](avo-0047-c8-personal-exact-cas-result.md). Its offline boundary is approved
at `9e59638`, but activation remains blocked until repository protections, a dedicated isolated
writer principal, and a durable controller/journal are provisioned and independently checked.
The activation record must pin repository identity, protection/ruleset configuration, workflow
and validation identity, writer isolation contract, rollback authority, and exact-CAS protocol
epoch. The organization-owned max-one-entry merge-queue protocol is an alternate, not-selected
path. No current-host mutation or App 15368 action may work around the missing authority.

### Gate P5 — rollback drill, hosted threshold, and audit

After P4, run and pass the fresh hosted main rollback drill under the final protocol before
freezing ledger activation. Then freeze the campaign and enforce a gap-free scheduler
sequence: every post-watermark submission receives an eligible attempt or a terminal,
durable disposition. Count every eligible ordinary nonempty candidate; require 12
consecutive successes, 0 failures, and 0 boundary violations, complete per-attempt
evidence, final audit, and idempotent replay before declaring AVO-004.7 complete.

## Cross-cutting acceptance rules

* Any changed base, package, result, path manifest, policy/configuration, protection,
  queue, workflow, check identity, or attestation invalidates the current attempt.
  Regeneration, reorder, rerun, stale success, duplicate delivery, lost release receipt,
  or wrong release issuer invalidates the old release authorization; create a new pending
  hold and new attempt/composition. Never rerun release success. A stale/reused PR-head
  admission success cannot satisfy or transfer to a regenerated group.
* Any eligible failure, including failure before canonical integration package creation,
  timeout, quarantine, ambiguity, operator intervention, reset condition, or boundary
  violation resets the threshold streak to zero while preserving all evidence. Material
  protocol/configuration changes begin a new campaign.
* No result is complete from a provider success alone: exact main commit/tree/topology,
  queue/PR/check/protection receipts, cleanup, and replay must be durable.
* No ordinary path may include deployment or constitutional scope. Human intervention is
  recorded as an exception and prevents counting that attempt as a success.
* AVO-004.7 documentation and offline work can proceed while hosted exact-CAS activation is
  blocked; the current
  repository must remain unchanged by this gate.

The GitHub REST ref-delete endpoint has no expected-SHA CAS precondition. Before hosted use,
the `avo/main-rollback/*` namespace must be protected by exclusive ACL/ruleset authority;
cleanup must verify authoritative post-state and cannot treat a delete response as an
expected-SHA proof.

## Required offline fault matrix

The deterministic gate must exercise, with durable expected outcomes, a crash immediately
before/after enqueue, immediately before/after preparation authorization, immediately
before/after release authorization, and immediately after isolated hold success. It must
also cover all other checks green before release authorization; merge-group regeneration,
queue reorder, check rerun, stale successful hold, duplicate delivery, lost release
receipt, wrong issuer, candidate-controlled fake hold/check, admission success, stale or
reused PR-head status, direct-merge/bypass refusal, exact PR-head/group separation,
unrelated queued PR, singleton violation, group-tree/topology mismatch, issuer last-moment
drift/expiry, rollback chronology, and upstream integration failure/reset/gap blocking.
The expected result is fail-closed reconciliation or a read-only completed replay; no test
may call release success twice or use App 15368 as the release issuer.

## Verification artifacts

Each accepted leaf supplies immutable links in the aggregate plan/result. The final audit
must be able to reconstruct the source package, exact delta, composition, queue/check
observation, lease/intent/authorization sequence, main result, rollback result, cleanup,
threshold ledger, resets/exclusions, and replay from the journal root without mutable
integration state.

See the [AVO-004.7 runbook](avo-0047-main-graduation-runbook.md) for the operator protocol.
