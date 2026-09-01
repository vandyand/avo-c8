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

## Boundary and disposition

The Phase 1 snapshot is authenticated transport and immutable diagnostic evidence only. It does
not verify workflow semantics, validation check identity, effective protection, queue
configuration, isolated issuer, or rollback namespace ACLs; those observations remain
unverifiable. No CLI or live execution, hosted mutation, concrete trust root, authority-bearing
adapter, or readiness evidence is delivered, and no hosted repository, queue, check, release,
ledger, or `main` mutation occurred. C8 therefore remains blocked on the external protocol
prerequisites: organization-owned required max-one merge queue; a separate isolated release
issuer, not App 15368; exclusive controller create/delete ruleset/ACL authority for
`avo/main-rollback/*`; a fresh hosted main rollback drill; then frozen ledger activation and 12
consecutive eligible successes with 0 failures or boundary violations.

The next local leaf is atomic authenticated Phase 2 snapshot composition. C8 remains blocked
externally pending hosting and isolated authority prerequisites.
