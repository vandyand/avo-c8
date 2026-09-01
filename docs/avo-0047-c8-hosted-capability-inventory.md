# AVO-004.7 C8 hosted-capability inventory

Status: read-only provider inventory; C8 remains blocked and AVO-004.7 remains in progress.

Inventory date: 2026-09-01.

This record captures the hosted-capability boundary observed during the C8 diagnostic. It is
evidence for the roadmap's current position, not a readiness result, authority grant, or live
execution result.

## Confirmed read-only facts

- The configured remote is `https://github.com/vandyand/avo.git`.
- The repository is public, its owner type is `User`, and its default branch is `main`.
- The observed remote default is `origin/main`; `main` is protected.
- An unauthenticated request to `/repos/vandyand/avo/rulesets` returned HTTP 200 with an empty
  array (`[]`). This records the response only; it does not establish that all effective
  repository or organization policy is represented by that endpoint.
- The repository has zero configured environments.
- An unauthenticated request to `/orgs/vandyand` returned HTTP 404. This is a provider response,
  not proof that no organization target or organization-level capability can be authorized.
- No external or filesystem mutation was performed. The worktree was clean before and after the
  inventory.

## Permission-limited unknowns

- `gh` is not installed and `GITHUB_TOKEN` is absent.
- `/user`, `/user/orgs`, branch-protection details, installation details, Actions permissions or
  variables returned HTTP 401, so the inventory could not authenticate the caller or inspect those
  controls.
- A merge-queue endpoint returned HTTP 404. That response is inconclusive and must not be treated
  as evidence that merge queues are absent.
- The inventory therefore does not establish effective organization rulesets, queue configuration
  or generation behavior, bypass permissions, workflow configuration, validation-principal
  identity, issuer identity, or rollback-namespace ACLs.

## Prohibited or not-authorized conclusions and mutations

This read-only inventory does not authorize repository transfer, protection or queue changes,
admission or release-hold transitions, ref creation/deletion, `main` writes, App 15368 actions, or
any other hosted mutation. It does not self-declare a trust root, isolated issuer adapter, C8
capability evidence writer, live runner, or readiness. Existing local diagnostics and the
coordination, rollback, activation, and ledger foundations remain non-authoritative until the real
external authority is available.

## Exact next operator dependencies

Before hosted C8 work can proceed, an operator must explicitly provide and authorize:

1. An organization-owned repository target and authorization for the required merge queue, with
   max one entry per group.
2. An isolated non-App-15368 issuer authority for one-use PR-head admission and group release hold.
3. Exclusive rollback namespace ACL/ruleset authority for controller create/delete operations under
   `avo/main-rollback/*`, with authoritative post-state cleanup checks.
4. An authenticated token channel that permits the required read and narrowly scoped write
   observations/actions.

Only after those dependencies are satisfied may the operator run a fresh hosted rollback and
activation sequence; then ledger activation and the preregistered 12 consecutive eligible
successes with 0 failures and 0 boundary violations remain required.

## Related evidence

- [AVO roadmap](roadmap.md)
- [C8 local-foundations result](avo-0047-c8-local-foundations-result.md)
- [AVO-004.7 implementation plan](avo-0047-main-graduation-plan.md)
- [AVO-004.7 runbook](avo-0047-main-graduation-runbook.md)
