# AVO-004.7 C6 offline acceptance result

Status: immutable offline acceptance record; accepted 2026-09-01.

## Scope and boundary

C6 delivered and accepted the offline campaign runner and eligibility ledger for the
single-host, trusted-team AVO-004.7 boundary. The final code HEAD is
`e6db424cc671d7a5d63b9b8a7246a316c4867f91`; the reviewed core was `a6f7897`, followed by
`0a4fb9f` restoring exporter registration/schema parity and `e6db424` typing-only fixes.
This record covers submission admission, durable attempt/ledger state, threshold accumulation,
terminal outcomes, recovery, and evidence export. It does not authorize hosted activation,
provider writes, repository or protection changes, queue changes, release-hold issuance,
`main` mutation, deployment, or live readiness.

## Architecture and invariants

The ledger records scheduler submission and sequence before reading candidate content. Every
ordinary, nonempty submission is eligible from submission, including an upstream
integration/package failure; it receives an attempt and terminal durable failure/reset
disposition. Only independently classified empty or non-ordinary inputs may be excluded.
The scheduler sequence is gap-free after the activation watermark: exactly one next sequence
may be admitted, later sequences cannot count while an earlier one is unresolved, and no
speculative tail may be admitted. Unresolved boundary evidence closes only at the exact
expected sequence; terminal journal transitions are fenced, immutable, and replay-safe.
Threshold completion is irreversible and derives only from durable ledger state and eligible
outcomes.

## Evidence and review

The final integrated focused/parity acceptance set passed 47 tests. Scoped production
Pyright reported 0 errors, Ruff was clean, and `git diff --check` was clean. Terra's final
independent verdict on the reviewed core at `a6f7897` was APPROVE with no P0/P1 findings;
`0a4fb9f` and `e6db424` do not alter authority or runtime behavior. Prior blockers were
remediated: threshold completion is irreversible, journal terminal mutations are fenced,
admission is exact single-next-sequence with no speculative tail, and unresolved-tail /
boundary closure is exact.

## Remaining sequence

C6 is complete for offline acceptance. C7 deterministic offline gate is the next ready gate
and must exercise the complete crash/adversarial matrix, including rollback and replay, with
`main` unchanged and no deployment. C8 hosted organization/queue/release gate remains blocked
by both required prerequisites: organization-owned hosting with the required max-one-entry
merge queue and exact admission/hold behavior, and a dedicated isolated release-hold issuer.
A fresh hosted main rollback drill is required before hosted ledger activation. The
preregistered 12-success threshold has not run and is not satisfied.
