# AVO-004.7 C4 coordinator and recovery result

Status: complete as of 2026-09-01 at code HEAD `82ace056cf9f0453b43c71845179c437914a041b`.
This is an offline acceptance result; it does not authorize hosted `main` mutation or establish
live readiness.

## Decision

C4 is complete. The final code/test commit is `e7f284fab2bbf0d2e21a87c54d5de75764905a90`.
The invariant-documentation follow-up is current HEAD `82ace056cf9f0453b43c71845179c437914a041b`.
Terra approved the closeout at that head.

The bounded C4 acceptance matrix collected 358 tests and produced 358 passed, 0 failed, and
3 expected Pydantic serializer warnings in 599.97 seconds. It covered the main graduation
contracts and contract coverage, Phase A contracts and journal, lease migration, GitHub boundary,
coordinator preparation, C4 completion and gates, validated fixtures, filesystem recovery,
remediation, journal coverage, protected-main adversarial and coverage suites, schema parity, and
roadmap validation. Ruff passed. Scoped Pyright for the C4 production modules passed with 0 errors,
warnings, or informations. The wider production-plus-test Pyright run reported 31 existing
strict-test-fixture typing diagnostics in test harness code; these do not indicate production
module errors.

The evidence proves durable intent/fence ordering, create-once receipts and release claims, lease
expiry and fencing, deterministic external identities, capability separation, read-only
reconciliation after ambiguous dispatch, restart/replay behavior, filesystem recovery, and the
complete preparation → publication/PR → PR-head admission → enqueue → distinct group pending hold
→ one-use release authorization → last-moment issuer revalidation → hold-success chronology.
The expiry-before-intent invariant is explicit: if authorization or its claim expires before
release-transition intent is durable, the attempt quarantines with zero release mutation; if intent
is already durable, later expiry permits only read-only reconciliation and never a second dispatch.

No hosted queue, protection, admission, hold, release, merge, repository, or `main` mutation was
performed, and no live readiness claim is made. C8 remains blocked pending organization-owned
hosting/merge-queue capability and separately authorized isolated release-hold authority. The
preregistered 12 consecutive eligible successes with 0 failures and 0 boundary violations remains
future work.

## Supersession

This record supersedes the Phase A status boundary for overall C4 completion. The historical
[Phase A result](avo-0047-c4-phase-a-result.md) remains immutable and records only the earlier
contract/journal gate; its claims and code-head reference are not rewritten.

## Related authority

* [AVO roadmap](roadmap.md)
* [AVO-004.7 implementation plan](avo-0047-main-graduation-plan.md)
* [AVO-004.7 runbook](avo-0047-main-graduation-runbook.md)
* [ADR 0011](adr/0011-protected-main-graduation.md)
