# AVO-004.7 C8 hosted-capability inventory

Status: read-only provider inventory; C8 remains blocked and AVO-004.7 remains in progress.

Initial inventory date: 2026-09-01.

Authenticated update date: 2026-09-02.

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

## Authenticated update — 2026-09-02

- Windows `gh` 2.98.0 was authenticated as `vandyand` through the keyring; WSL was also active as
  `vandyand`.
- `vandyand/avo` is public, user-owned, and the authenticated identity has confirmed admin/push
  access.
- Read-only `avoctl c8 preflight --owner vandyand --repo avo` used a transient keyring-derived
  credential and returned the non-authoritative, non-consumable result `unverifiable` (exit 2),
  digest `sha256:c25e4c97b5a17c9dbceab0d0250d54be24085d48ca566221d48c30d4330fa9c2`. All seven read
  categories were unverifiable; no mutation occurred.
- The visible `kikker-stickers` organization is on the Free plan; `vandyand` is an active admin,
  repository creation is enabled, and the organization has two repositories. No AVO-named target
  exists there. Its existing public organization repository is master/unprotected with no
  repository rulesets and is not an AVO target.
- Organization rule/action-policy inspection requires `admin:org`; the current credential scopes
  include `read:org`, `repo`, and `workflow` but not `admin:org`. The organization installation
  list shows only Netlify app 13473, not App 15368.
- No organization target was selected or created, and no transfer, ruleset, protection, queue,
  app, branch, or ref mutation occurred.

## Official capability research — 2026-09-02

The following capability distinctions are based on the official GitHub documentation:

- **Supported:** Merge queues are supported for public repositories owned by an organization,
  including GitHub Free, and merge-group size can be configured to one. See [Managing a merge
  queue](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/managing-a-merge-queue).
- **Supported with scope limits:** Public repositories can use repository rulesets on GitHub Free;
  organization-level rulesets require Team or Enterprise. See [About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets).
- **Ambiguous for AVO:** A repository-level ruleset can target `avo/main-rollback/*` and restrict
  ref creation/deletion. Strict controller-only authority is nevertheless unproven and may be
  incompatible with administrator/organization-owner authority and bypass semantics. This must
  be experimentally proven on the selected target before hosted rollback.
- **Technically supported but not authorized:** A custom isolated GitHub App with Checks:write
  permission is supported, but AVO still needs nonce, one-use, and replay protection semantics;
  no such App is installed or authorized. See [Repository permissions for GitHub Apps](https://docs.github.com/en/rest/using-the-rest-api/permissions-required-for-github-apps).
- **Not established:** The current evidence does not select an organization target or authorize
  using `kikker-stickers`; the recommended direction is a newly selected and explicitly authorized
  public organization repository rather than silently transferring `vandyand/avo`.

## Permission-limited unknowns

- The authenticated credential lacks `admin:org` (or an equivalent least-privilege capability),
  so effective organization rules and action policies could not be inspected. This does not mean
  `admin:org` is required for repository-local queue/rules provisioning: a least-privilege,
  fine-grained repository Administration channel is preferable for the selected target.
- Some unauthenticated `/user`, `/user/orgs`, branch-protection, installation, Actions permission,
  or variable probes returned HTTP 401; those responses do not override the authenticated facts
  above.
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
4. An authenticated least-privilege channel for the selected repository's Administration controls
   and required read/write observations; `admin:org` is needed only if organization-level policy
   inspection or provisioning is selected.

Only after those dependencies are satisfied may the operator run a fresh hosted rollback and
activation sequence; then ledger activation and the preregistered 12 consecutive eligible
successes with 0 failures and 0 boundary violations remain required.

## Related evidence

- [AVO roadmap](roadmap.md)
- [C8 local-foundations result](avo-0047-c8-local-foundations-result.md)
- [AVO-004.7 implementation plan](avo-0047-main-graduation-plan.md)
- [AVO-004.7 runbook](avo-0047-main-graduation-runbook.md)
