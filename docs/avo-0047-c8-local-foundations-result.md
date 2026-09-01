# AVO-004.7 C8 local-foundations result

Status: Terra-approved local Wave 1/2 foundations; C8 remains blocked and AVO-004.7 remains
in progress. This record is supporting evidence for the [authoritative roadmap](roadmap.md).

## Scope accepted

The following local foundations are recorded by the cited commits:

- Exact-SHA checkout identity and clean-WSL workspace checks are hardened in CI (`31f9867`,
  `83698aa`).
- Local hosted-main rollback and ledger-activation preparation scripts remain explicitly
  non-consumable drafts (`bdce27c`, `7f2dd20`, `6a96342`). They cannot authorize activation,
  release, or rollback.
- The bounded pinned/no-redirect GitHub JSON transport is the actual default provider transport
  (`ecd773c`), with the preceding transport-boundary work retained as implementation history.
- Controller-rooted hosted ledger activation is locally implemented (`49fb84e`), with raw proof
  CAS binding and legacy-compatible schema regeneration (`935363c`).
- The Terra-approved Phase 1 diagnostic preflight core is recorded at `daeff01`: one
  single-flight, immutable snapshot performs exactly five authenticated GETs for the repository,
  `main` ref, pointed-to commit, pinned workflow blob, and final `main` ref fence. It binds the
  responses canonically, verifies the workflow's Git blob identity, and caches the result for
  replay. The Phase 1 focused suite contains 52 passing tests through `f38840d`.
- The pure Phase 2 parser gate is Terra-approved at `e154726`, with 19 parser tests and 71
  combined focused checks. Its bounded scope is raw effective plus resolved rulesets and
  conditions/rule multisets, strict required-context/App configuration, and bounded merge-queue
  parsing. It is parser-only: no transport integration, live or CLI execution, authority, or
  readiness evidence is provided.
- The atomic authenticated Phase 2 snapshot is Terra-approved at `1d911e3` (30 snapshot/parser
  review tests; 82 combined focused checks). It performs a two-pass mutable-configuration fence,
  final `main` ref fence, bounded rules pagination, REST/GraphQL cross-binding, SHA-1/SHA-256
  object binding, and failure caching. App configuration is recorded only as configuration, not
  validation-principal identity or issuer authority.
- The workflow-semantics and env-only diagnostic CLI gate is Terra-approved at
  `7ded390436010844f6044151c59b05a02c74b810` (69 Terra-focused tests; 125 focused parent tests;
  Ruff, scoped Pyright, uv lock, and diff checks clean). It uses pinned PyYAML 6.0.3 with YAML
  1.2 `on`, bounded parsing, rejects duplicate keys/aliases/anchors/tags/merges/multidocuments,
  and requires static PR/merge_group checks-requested facts, every checkout `uses` pinned to a
  lowercase full 40-hex commit, `with.ref` exactly `${{ github.sha }}`, and
  `persist-credentials=false`.
- `avoctl c8 preflight` is read-only and accepts `GITHUB_TOKEN` only from the environment, with
  fixed origin/defaults, no redirects, sanitized JSON/fixed failures, and no persistence or writer
  options. No App/runtime/check/issuer authority is claimed; no live execution occurred because
  `GITHUB_TOKEN` is absent in the current shell.
- The validation-principal diagnostic is accepted at exact commit
  `a8af4341be413981da348c772b9d51e1e6f9f27e`. It integrates the pure bounded parser with the
  atomic read-only snapshot and records the exact main SHA, bounded check-run pages (at most 10
  pages / 1000 check runs), stable total/page cardinality and unique run IDs, exact required
  contexts, and App 15368 GitHub Actions metadata. It binds a run-ID digest and two-pass raw
  page digests, tolerates unrelated in-progress runs, and applies final freshness binding for
  success, wrong-App, failure, and duplicate blockers. The diagnostic is secret-safe and
  non-authoritative. Terra APPROVE found no P0/P1 issues; 149 focused tests passed (parent and
  Terra), with Ruff, scoped Pyright, and diff checks clean.

## Boundary and disposition

The Phase 1 snapshot was authenticated transport and immutable diagnostic evidence only; its
historical boundary did not verify workflow semantics or validation check identity. The later
parser, atomic snapshot, workflow-semantics CLI, and validation-principal diagnostic now provide
provider-evidenced observations when available, but remain read-only and non-authoritative. No
live execution, hosted mutation, concrete trust root, authority-bearing adapter, or readiness
evidence is delivered, and no hosted repository, queue, check, release, ledger, or `main`
mutation occurred. C8 therefore
remains blocked on the external protocol prerequisites: organization-owned required max-one merge
queue; a separate isolated release
issuer, not App 15368; exclusive controller create/delete ruleset/ACL authority for
`avo/main-rollback/*`; a fresh hosted main rollback drill; then frozen ledger activation and 12
consecutive eligible successes with 0 failures or boundary violations.

Workflow semantics and validation-principal identity diagnostics are approved and
provider-evidenced when available. Issuer and rollback observations remain unsupported. No live
run occurred because `GITHUB_TOKEN` is absent; no authority or readiness exists.
