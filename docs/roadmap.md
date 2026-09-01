# AVO Roadmap

Status date: 2026-09-01.

Review date: 2026-09-01.

Authority: This file is AVO's sole authority for outcomes, priority, sequencing, milestone status, and decision gates.

## Authority and maintenance

This roadmap governs what AVO should do next and what “complete” means. Implementation packets,
integration plans, ADRs, release records, and experiment results provide durable evidence but do not
override this file's current priority or status. Any execution view remains derived from this file
and cannot change its authority.

Every material roadmap update must preserve stable milestone IDs, link its evidence, update the
status date, and pass the project-local `avo-roadmap` validator. Review date records a deliberate
evidence audit and must be refreshed at least every 45 days. A candidate cannot mark its own
milestone complete: completion follows independent verification and the applicable promotion gate.

## North star

Make AVO a robust, reliable, performant, and capable evaluator-grounded system for sustained
autonomous software improvement. AVO should maximize useful improvement per unit of time, model
budget, and operator attention while keeping evaluation, policy, provenance, promotion, and
production authority outside the proposing agent's control.

## Current position

- Draft 3 phases 0–3 are complete for the declared single-host, trusted-team reference boundary;
  production hardening is selective and explicitly not a hostile-code security claim.
- Codex is the primary high-value variation runtime. The frozen one-repetition comparison admitted
  8/8 Codex candidates and 6/8 native/OpenRouter candidates; this is architecture evidence, not a
  statistical superiority result.
- The first full sanitized AVO-on-AVO candidate passed public and private evaluation, admission,
  exact reconstruction, and provenance verification. Its historical patch remains unapplied.
- Strict-JSON Luna advisory inference passed one bounded live canary and a ten-case offline gate;
  repeated live reliability remains unproven.
- The Windows workspace is now the controlling repository and has a public authenticated remote,
  a tagged clean baseline, a successful disposable-clone recovery rehearsal, and enforced
  server-side protection on `main`. Candidate workspaces remain intentionally VCS-free.
- Trusted hosted CI is green on Ubuntu and Windows. The canonical Linux gate passes all 373 tests
  at 85.40% branch coverage, and the native Windows portability gate passes 365 tests with one
  expected platform skip.
- The sanitized AVO-004.5 live gate completed on 2026-08-28: PR #5 passed independent Luna and
  Terra review, a separate full candidate suite (757 passed / 7 skipped), private evaluation, exact Ubuntu/Windows
  checks from App 15368, protected integration promotion, one-parent topology reconciliation,
  duplicate-runner fail-closed behavior, and completed-state replay. The [durable live result](avo-0045-sanitized-live-result.md)
  records the immutable commit identities and digests.
- AVO-004.6 completed the eight-case offline failure package and a real protected live failure/
  rollback on 2026-08-29. The pinned GitHub Actions App 15368 check identity executing the
  base-controlled exact-SHA workflow, failed integration
  soak, separately authorized PR-native rollback, exact one-parent restore topology, immutable
  cleanup evidence, and completed-state replay all passed with `main` unchanged and no deployment.
  The [live drill result](avo-0046-live-failure-drill-result.md) records the exact identities,
  quarantined stale attempts, and follow-up reliability findings.
- AVO-004.7 has begun on 2026-08-29. C1 contracts/journaling, C2 deterministic composition,
  and the C3 read-only protected-main provider/attester are complete through protected
  PR #47, PR #48, and PR #49. The C3 boundary authenticates native
  merge-group webhooks, resolves effective repository/organization rulesets, reads complete
  exact-SHA checks, and durably binds queue generation, PR identity, delivery identity, and
  isolated-App transition evidence. C4 coordinator and recovery is complete at code HEAD
  `82ace056cf9f0453b43c71845179c437914a041b`, with Terra approval and the final offline
  acceptance matrix. The [durable C4 result](avo-0047-c4-result.md) records 358 passed tests,
  green Ruff, clean scoped production Pyright, schema parity, and roadmap validation. This is
  not hosted or live readiness. C5 main rollback authority is complete for offline acceptance at
  HEAD `e38d0b826f94f3f559fb2e3ef0b26d1d17128c53` with Terra APPROVE and combined 24 passed.
  Its durable result records rollback contracts/journaling, deterministic inverse composition,
  authority verification, aggregate orchestration, terminal cleanup/closure, crash/replay, and
  adversarial recovery evidence. The preregistered 12-success threshold remains future hosted work.
  C6 campaign runner and eligibility ledger is complete for offline acceptance at final code
  HEAD `e6db424cc671d7a5d63b9b8a7246a316c4867f91`; 47 focused/parity tests passed, scoped
  production Pyright reported 0 errors, Ruff and diff-check were clean, and Terra APPROVE had
  no P0/P1 findings. The [durable C6 result](avo-0047-c6-result.md) records the exact scope,
  invariants, remediations, and no-live boundary. C6 does not establish hosted/live readiness.
  C7 deterministic offline gate is complete at code HEAD `9c70c36074810606692f8c2030b25ce83c10a1e4`:
  all 47 exact frozen case/vector entries passed, replay returned the exact same result with
  `executor_calls=0` and `clock_calls=0`, and `deploy_performed=false`. The [durable C7
  result](avo-0047-c7-result.md) records the immutable operation and artifact identities,
  two truthful failed-closed dry attempts that exposed datetime-canonicalization and
  semantic-versus-artifact verifier bugs, their reviewed remediations, and the no-live
  boundary. C7 does not establish hosted/live readiness.
  C8 local Wave 1/2 foundations are now Terra-approved through commits `ecd773c`, `935363c`,
  and `49fb84e`: bounded pinned/no-redirect GitHub transport is the actual provider default;
  controller-rooted activation and raw-proof CAS/legacy-compatible ledger schema support are
  locally implemented. Phase 1 diagnostic preflight is accepted at `daeff01` through `f38840d`:
  one single-flight immutable snapshot performs five authenticated GETs for repository/main/
  workflow data with a final main fence, verifies blob binding, and passed 52 focused tests.
  The pure Phase 2 parser gate is Terra-approved at `e154726` with 19 parser tests and 71
  combined focused checks, covering bounded raw effective/resolved rulesets, conditions and rule
  multisets, strict required contexts/App configuration, and bounded queue parsing. The atomic
  authenticated Phase 2 snapshot is Terra-approved at `1d911e3` (30 snapshot/parser review
  tests; 82 combined focused checks), with two-pass mutable-configuration and final main-ref
  fencing, bounded rules pagination, REST/GraphQL cross-binding, SHA-1/SHA-256 binding, and
  failure caching. App configuration is not validation-principal identity. It is diagnostic-only:
  workflow semantics and validation-principal identity remain unverifiable; issuer and rollback
  remain unsupported, with no CLI/live execution, authority, or readiness.
  There is no CLI/live execution, concrete trust root, authority-bearing adapter, runner,
  readiness, or hosted mutation. The rollback and activation preparers remain explicitly
  non-consumable drafts.
  Live `main` mutation is currently blocked on both required capabilities: the preferred
  merge-queue protocol needs an organization-owned repository with max-one-entry queue and
  exact admission/hold capability, while the current public repository is user-owned, and no
  isolated release-hold issuer/operator authority exists. No transfer, protection/queue
  mutation, admission or release transition, or main write is authorized until both hosting
  authority and admission/hold authority are explicitly resolved. GitHub REST ref deletion has no
  expected-SHA CAS; before hosted use, the `avo/main-rollback/*` namespace must have exclusive
  ACL/ruleset authority for rollback cleanup.

## Milestone register

| ID | Horizon | Status | Risk | Outcome | Exit gate | Depends on | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| AVO-001 | done | complete | protected | Deliver the evaluator-grounded local reference architecture through bounded agentic variation. | Draft 3 phases 0–3 pass their contract, security, recovery, parity, and end-to-end acceptance evidence. | — | [Implementation status](implementation-status.md), [Draft 3 packet](avo-correlate-implementation-packet-v3.md) |
| AVO-002 | done | complete | protected | Integrate Codex as a durable, subscription-authenticated coding-agent variation runtime. | The lifecycle, comparison, terminal-budget replay, recursive admission, reconstruction, and provenance gates pass. | AVO-001 | [Integration plan and result](avo-coding-agent-integration-plan-v2.md), [Recursive capstone](avo-improves-avo-capstone-v2-result.md) |
| AVO-003 | done | complete | standard | Establish a bounded strict-JSON inference boundary for inexpensive typed advisory operations. | The live canary and frozen offline corpus pass without granting policy, admission, mutation, or lifecycle authority. | AVO-001 | [Structured inference](structured-inference.md), [Offline evaluation result](structured-inference-evaluation-v2-result.md) |
| AVO-004 | now | in_progress | protected | Establish authoritative roadmap governance and human-on-exception autonomous source promotion. | Ordinary changes can progress from a clean Git base through protected deterministic and adversarial gates, integration soak, verified merge, and rollback evidence without routine operator approval. | AVO-002 | [Threat model](threat-model.md), [Git baseline v1](avo-004-git-baseline-v1-result.md), [Promotion policy ADR](adr/0007-promotion-policy.md), [Dry-run result](avo-004-promotion-dry-run-v1-result.md) |
| AVO-005 | next | ready | standard | Version the existing hybrid archive and population strategies and compare them under equal budgets. | ExperimentSpec v2 and an ADR freeze both methods, and a preregistered comparison determines whether either should change the default. | AVO-004 | [Search extension ADR](adr/0004-search-method-extension-gate.md), [Draft 3 roadmap](avo-correlate-implementation-packet-v3.md) |
| AVO-006 | next | planned | protected | Run bounded multi-generation AVO-on-AVO campaigns without making the operator the routine merge bottleneck. | Plateau detection, lineage limits, private regression promotion, autonomous ordinary-change promotion, and exception escalation pass a frozen campaign. | AVO-004, AVO-005 | [Recursive milestone](avo-improves-avo-milestone.md), [Integration plan](avo-coding-agent-integration-plan-v2.md) |
| AVO-007 | later | deferred | standard | Improve the native/OpenRouter coding loop only when portability, cost, or model-selection evidence justifies it. | A frozen trigger and targeted protocol evaluation show that the work resolves an observed decision-relevant limitation. | AVO-002 | [Comparison results](comparison-v2-results.md), [OpenRouter interface](openrouter-interface.md) |
| AVO-008 | gated | gated | production | Add distributed storage, orchestration, observability, policy distribution, and stronger isolation only at their production triggers. | Load, multi-host, trust-domain, recovery, observability, or hostile-code requirements activate the adapter-specific promotion criteria and all production release blockers pass. | AVO-004, AVO-006 | [Production boundary](implementation-status.md), [Threat model](threat-model.md) |

## Active milestone: AVO-004

### Objective

Replace routine human approval of AVO-on-AVO source improvements with a fail-closed, auditable,
risk-tiered promotion path. The operator handles exceptions and constitutional changes rather than
approving every ordinary patch.

### Delivery gates

| Gate | Status | Deliverable | Verification |
| --- | --- | --- | --- |
| AVO-004.1 | complete | Canonical `docs/roadmap.md`, project-local `avo-roadmap` skill, deterministic validation, and CI freshness enforcement. | Skill validation, roadmap validator tests, link audit, Ruff, and strict Pyright. |
| AVO-004.2 | complete | Green trusted CI baseline plus a controlling Git repository and remote, with candidate workspaces still VCS-free. | Hosted Linux/Windows CI, public repository, tagged commit/tree baseline, disposable-clone recovery, and enforced server-side `main` protection pass. |
| AVO-004.3 | complete | ADR defining risk classes, constitutional paths, reviewer independence, exception policy, and rollback limits. | ADR 0007, exported strict schemas, 85 focused policy tests, independent adversarial review, and the full trusted suite pass. |
| AVO-004.4 | complete | Dry-run promotion controller producing a content-addressed promotion bundle without merging. | [ADR 0008](adr/0008-dry-run-promotion-controller.md) and the [v1 result](avo-004-promotion-dry-run-v1-result.md) pass deterministic replay, trusted-base evaluation, provenance, adversarial review, coverage, and compare-and-swap checks. |
| AVO-004.5 | complete | Controller-driven ordinary-change promotion to a protected integration branch under the documented temporary exact-validation bridge. | The sanitized live campaign passes required trusted checks, independent review quorum, private regression evaluation, exact synthetic reconstruction, integration soak, protected merge, and durable recovery evidence. [Result](avo-0045-sanitized-live-result.md) |
| AVO-004.6 | complete | Rollback and failure drills with immutable evidence, plus production-grade exact-SHA attestation for the declared trusted-repository boundary. | The offline eight-case package and live protected canary/rollback fail closed, reconstruct, clean up, and replay idempotently through the pinned GitHub Actions App 15368 check identity executing the base-controlled exact-SHA workflow, with `main` unchanged and no deployment. [Result](avo-0046-live-failure-drill-result.md) |
| AVO-004.7 | in_progress | Graduate ordinary changes from integration to automatic protected-main promotion through a dedicated, queue-aware main boundary with one-use PR-head admission and isolated group release hold. | The offline architecture and rollback matrix pass; then, after both organization-hosting/merge-queue capability (max one entry per group) and isolated admission/hold authority unblock the live protocol, a fresh hosted main rollback drill passes before ledger activation, followed by 12 consecutive eligible attempts with 0 failures and 0 boundary violations. [ADR](adr/0011-protected-main-graduation.md), [plan](avo-0047-main-graduation-plan.md), and [runbook](avo-0047-main-graduation-runbook.md). |

#### AVO-004.7 implementation sequence

| Stage | Status | Evidence / next boundary |
| --- | --- | --- |
| C1 — main contracts and journal | complete | Protected PR #47; strict contracts, schemas, controller-rooted issuer binding, lease evidence, and duplicate-context rejection pass. See the [implementation plan](avo-0047-main-graduation-plan.md). |
| C2 — deterministic composition | complete | Protected PR #48; exact sole-parent delta composition and durable controller-rooted composition proof pass. See the [implementation plan](avo-0047-main-graduation-plan.md). |
| C3 — protected-main provider and attester | complete | Protected PR #49; signed merge-group provenance, effective ruleset/bypass verification, complete check pagination, exact PR/queue/topology binding, durable delivery replay protection, and isolated-App transition observation pass independent Terra review and hosted Ubuntu/Windows checks. See the [runbook](avo-0047-main-graduation-runbook.md). |
| C4 — coordinator and recovery | complete | Final offline coordinator/recovery acceptance passed at HEAD `82ace056cf9f0453b43c71845179c437914a041b` with Terra approval: 358 passed, 0 failed, filesystem recovery and replay covered, Ruff/scoped production Pyright/schema parity/roadmap validation green. No hosted or live mutation occurred. [Result](avo-0047-c4-result.md) |
| C5 — main rollback authority | complete | Offline acceptance passed at HEAD `e38d0b826f94f3f559fb2e3ef0b26d1d17128c53` with Terra APPROVE and combined 24 passed, covering rollback contracts/journaling, inverse composition, authority verification, aggregate orchestration, terminal cleanup/closure, crash/replay, and adversarial recovery. No hosted/provider/main/deploy mutation occurred. [Result](avo-0047-c5-result.md) |
| C6 — campaign runner and eligibility ledger | complete | Offline acceptance complete at final code HEAD `e6db424cc671d7a5d63b9b8a7246a316c4867f91`; [result](avo-0047-c6-result.md). Hosted ledger activation still requires blocked C8 prerequisites and a fresh hosted rollback drill. |
| C7 — deterministic offline gate | complete | Offline acceptance complete at code HEAD `9c70c36074810606692f8c2030b25ce83c10a1e4`; 47 exact frozen case/vector entries passed, replay used `executor_calls=0` and `clock_calls=0`, and `deploy_performed=false`. [Result](avo-0047-c7-result.md). No hosted mutation. |
| C8 — hosted organization/queue/release gate | blocked | Terra-approved local foundations and Phase 1 snapshot are recorded in the [C8 local-foundations result](avo-0047-c8-local-foundations-result.md). The Phase 2 atomic authenticated snapshot is Terra-approved at `1d911e3` with 30 snapshot/parser review tests and 82 combined focused checks, covering two-pass mutable-configuration/final-main fences, bounded rules pagination, REST/GraphQL cross-binding, SHA-1/SHA-256 binding, failure caching, and configuration-only App checks. Workflow semantics and validation-principal identity remain unverifiable; issuer and rollback remain unsupported. No CLI/live execution, authority, or readiness exists. The next local leaf is safe workflow semantic parsing plus a bounded read-only diagnostic entrypoint. Hosted completion still requires organization-owned required max-one merge queue, a separate isolated issuer (not App 15368), exclusive controller create/delete authority for `avo/main-rollback/*`, a fresh hosted main rollback drill, then ledger activation and 12 consecutive eligible successes with 0 failures/boundary violations. |

The roadmap gate was completed first because the operator explicitly authorized it. The green test
and coverage baseline, controlling repository, public remote, baseline tag, recovery rehearsal, and
server-side `main` protection now pass. AVO-004.4's no-merge controller passed independent
adversarial review and protected Ubuntu/Windows CI before merging. AVO-004.5 then completed one
sanitized live promotion to the protected integration branch without changing `main`. AVO-004.6
then completed deterministic failure injection and a real failed-soak/authorized-rollback cycle
with immutable exact-SHA evidence. AVO-004.7 C1–C3 are now complete through protected PRs
#47–#49; C4 coordinator and recovery is complete at HEAD
`82ace056cf9f0453b43c71845179c437914a041b` with Terra approval and the final offline acceptance
matrix. C5 main rollback authority is complete for offline acceptance at HEAD
`e38d0b826f94f3f559fb2e3ef0b26d1d17128c53`, with Terra APPROVE and combined 24 passed; see the
[C5 result](avo-0047-c5-result.md). C5 evidence covers aggregate orchestration, terminal closure,
adversarial recovery, and replay. C6 campaign runner and eligibility ledger is complete for
offline acceptance at final code HEAD `e6db424`; see the [C6 result](avo-0047-c6-result.md).
C4–C7 offline evidence do not establish hosted/live readiness, and AVO-004.7 remains in
progress. C7 deterministic offline gate is complete; see the [C7 result](avo-0047-c7-result.md).
The clean-run threshold
and main-specific rollback evidence remain preregistered in the linked ADR, plan, and runbook. The
later live gate is blocked by two hosting/authority prerequisites: the preferred required merge queue
with max one entry per group and exact PR-head admission/group-hold capability is available for
an organization-owned public repository, but the current public repository is user-owned; and
a dedicated isolated release issuer has not been authorized. No repository transfer,
protection/queue mutation, admission or hold-success transition, or live `main` write is
authorized until both boundaries are explicitly resolved (or an exact-CAS writer design is
separately reviewed). GitHub REST ref deletion has no expected-SHA CAS; before hosted use, the
`avo/main-rollback/*` namespace must have exclusive ACL/ruleset authority for rollback cleanup.

### AVO-004.6 failure-drill sequence

Run each drill from a clean, trusted base and retain immutable evidence for the decision and
reconciliation outcome:

1. Replay the same operation concurrently with duplicate runners; exactly one may own the lease,
   and every duplicate must fail closed or return the durable completed result.
2. Present a stale base and a changed protected-branch head; compare-and-swap must refuse the
   promotion without creating a merge or mutating `main`.
3. Remove, stale, or mismatch one required Ubuntu/Windows check, including a check attached only
   to the PR head rather than the exact synthetic SHA; the attester must reject it.
4. Supply reviewer disagreement, insufficient quorum, and a failed private evaluation; no merge
   may occur and the rejection must reconstruct from the receipt.
5. Interrupt the provider/authentication boundary and restart from durable intent; recovery must
   be idempotent, with no duplicate merge or lost receipt.
6. Supply an external two-parent result or incorrect parent/tree identity; topology reconciliation
   must reject it and preserve the target branch.
7. Exercise integration soak failure and an authorized rollback; both must produce durable,
   content-addressed evidence and leave protected `main` unchanged.
8. Replace the temporary exact-validation ref/workflow-dispatch bridge with a base-controlled
   exact-SHA attestation or dedicated GitHub App, then repeat the check-identity drills.

The gate exited on 2026-08-29 after every injected failure failed closed, successful recovery was
idempotent, the result and rollback records reconstructed, and repeatable exact-SHA checks were
produced by the pinned GitHub Actions App 15368 check identity executing the
base-controlled workflow. See the
[live result](avo-0046-live-failure-drill-result.md).

### Promotion policy target

- Low-risk documentation, tests, and internal refactors may promote automatically after their
  declared deterministic gates and an independent review.
- Ordinary behavioral changes require the complete trusted CI suite, frozen private evaluation,
  provenance reconstruction, two independent reviews, integration soak, and base-head
  compare-and-swap.
- Constitutional changes—including admission, policy, lifecycle, budgets, provenance, private
  evaluators, schemas, CI rules, dependencies, migrations, sandboxing, credentials, or the
  promotion controller—cannot approve themselves. They enter a separately authorized maintenance
  path and notify the operator only when the independent policy cannot resolve them safely.
- Production deployment and irreversible external effects remain outside autonomous source
  promotion until AVO-008 is activated and completed.

### Exit criteria

AVO-004 completes only when a clean controlling Git repository exists; roadmap drift fails CI;
ordinary changes can be classified, independently evaluated, reviewed, promoted, soaked, and
reverted through immutable evidence; protected changes fail closed into exception handling; and a
frozen evidence set demonstrates that the proposing agent cannot modify or bypass its own judge.

## Decision gates

- Start AVO-005 after the Git foundation and promotion-policy ADR make generated experimental
  changes recoverable and reviewable.
- Start AVO-006 only after AVO-004 and AVO-005 complete; multi-generation search magnifies weak
  promotion rules and should not precede them.
- Activate AVO-007 only for a concrete portability, model-choice, or cost decision.
- Activate AVO-008 only when its documented production trigger exists. Standard Docker remains a
  trusted-team isolation aid, not hostile-code containment.
