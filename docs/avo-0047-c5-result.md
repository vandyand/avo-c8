# AVO-004.7 C5 main rollback authority result

Status: complete for offline acceptance as of 2026-09-01 at code HEAD
`e38d0b826f94f3f559fb2e3ef0b26d1d17128c53` (`e38d0b8`). Terra review: APPROVE.

The combined C5 acceptance run passed 24 tests. The accepted evidence covers the
rollback-specific contracts and journal bindings, deterministic inverse composition,
controller-owned authority verification, aggregate coordinator/recovery, terminal
cleanup and closure, crash/replay behavior, and adversarial recovery boundaries.

This is offline evidence only. No hosted/provider/main/deploy mutation occurred, and
this result does not establish hosted or live readiness. AVO-004.7 remains in progress.
C6 campaign-runner and eligibility-ledger work is the next ready gate. C8 remains blocked
on organization-owned hosting with a required merge queue limited to one entry per group
and separately authorized isolated release-hold authority.

## Boundary findings

The GitHub REST ref-delete endpoint has no expected-SHA compare-and-swap (CAS)
precondition. A delete response therefore cannot by itself prove that the intended ref
was deleted without a race; cleanup must remain intent-before-dispatch, exact-ref scoped,
and close only after authoritative post-state observation. Before any hosted use, the
`avo/main-rollback/*` namespace must be protected by exclusive ACL/ruleset authority so
only the rollback authority may create or delete those refs. This limitation and control
are prerequisites, not hosted evidence.
