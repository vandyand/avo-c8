# AVO-004.7 C8 hosted writer setup result

Status: candidate hosted-configuration evidence; external controls provisioned on 2026-09-03;
independent source review and hosted CI remain required. This result does not authorize a live
`main` CAS, rollback, ledger activation, or deployment.

## Exact hosted state

The operator created the private GitHub App `avo-c8-main-writer-vandyand` under the personal
`vandyand` account and installed it only on `vandyand/avo-c8`:

- App ID: `4817867`
- installation ID: `158775763`
- repository ID: `1354880741`
- repository selection: selected, exactly `vandyand/avo-c8`
- permissions: Contents write and mandatory Metadata read
- subscribed events: none
- webhook delivery: disabled

The private key is stored outside every repository with a user-only Windows ACL. No JWT,
installation token, owner token, cookie, or private-key byte is recorded in this repository.

Three active repository rulesets are present:

1. `AVO C8 main safety` (`22197248`) targets exactly `refs/heads/main`, has deletion,
   non-fast-forward, and required-linear-history rules, and has no bypass actor.
2. `AVO C8 main writer` (`22197250`) targets exactly `refs/heads/main`, has the update rule,
   and has exactly App `4817867` as its sole `Integration`/`always` bypass.
3. `AVO C8 rollback namespace` (`22197324`) targets exactly
   `refs/heads/avo/main-rollback/*`, restricts creation, update, deletion, and non-fast-forward
   changes, and has the same sole App bypass.

Bootstrap branch protection remains enabled on `main`: administrators are enforced, linear
history is required, force pushes and deletions are disabled, and no PR/status requirement was
added. The branch remained exactly
`599242b33ab3b4d40b848daaae44da572ae0e726` throughout setup and verification.

## Live verification

The App JWT path returned the exact App and installation, minted a selected-repository
installation token, and read repository `1354880741`. The token response exposed exactly one
repository with Contents write/Metadata read and no subscribed events. Tokens were kept only in
process memory and cleared after each probe.

A disposable non-`main` ruleset probe exercised the same protected non-force PATCH shape:

- the normal `vandyand` credential received `422 Repository rule violations found`;
- App `4817867` performed the same `force=false` update with HTTP `200`;
- the exact candidate was observed on the disposable ref;
- the App deleted the disposable branch and the operator deleted the temporary ruleset, both with
  HTTP `204`.

A normal-credential attempt to create a correctly shaped ref below
`refs/heads/avo/main-rollback/*` was denied with HTTP `422`. No rollback ref was created. A final
read found no `refs/heads/avo/*` residue and no open pull request. None of these probes touched
`main` or deployment state.

## Live-shape verifier remediation

GitHub's pinned REST response differs from the prior offline fixture in three fail-closed ways:

- repository-ruleset summaries include `target: branch` and `enforcement: active`;
- an active update rule is returned as `{ "type": "update" }`, omitting the optional parameter
  object even when the create request supplied `update_allows_fetch_and_merge=false`;
- disabled branch-protection subobjects are omitted instead of returned as explicit JSON nulls.

Commit `5e02ea1` updates only the read-only, non-authoritative hosted verifier and adversarial tests.
It now requires the exact two `main` rulesets plus the exact rollback-namespace ruleset, accepts an
omitted update parameter only after verifying that the selected repository is not a fork, and
continues to reject an explicit `true`, extra parameter, extra/missing rule or ruleset, broader
target, wrong App, wrong bypass, or branch-protection drift.

The focused hosted-configuration and isolated-base-reader suites passed `106` tests. Full Ruff,
scoped production Pyright, schema-export parity, and diff-check passed. A live two-pass run then
returned `verification_status=matched`, `is_authoritative=false`,
`readiness_authorized=false`, and `deploy_performed=false`, with:

- observation digest:
  `sha256:6b627f9781f881a2102df5a7b4377f21b4039a69c7e4a55faac52ec2d1e51b86`
- source digest:
  `sha256:28663654ef54c1a7791a99019188d9f5540c2eb8d66f4f57415046e843f2b0f7`

The normal `uv run` validator remains locally obstructed by the pre-existing inaccessible
`.venv/lib64`; the stable `.venv-win` interpreter ran the roadmap validator successfully.

## Remaining gate

This setup closes the external App, main ruleset, and rollback-namespace provisioning blockers.
It does not close C8. Commit `5e02ea1` still needs independent review, protected hosted CI, and
promotion through the applicable gate. The live controller must then compose the exact credential
root, durable journal, response evidence, post-state observation, and recovery verifier before any
`main` dispatch. A fresh protected hosted rollback drill must pass before ledger activation, then
the preregistered 12 consecutive eligible successes with zero failures and zero boundary violations
remain.
