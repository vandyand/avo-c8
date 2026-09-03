# AVO-004.7 C8 personal exact-CAS result

Status: Terra-approved offline personal-repository exact-CAS boundary; hosted canonical CI
passes the unchanged 85% coverage floor.
No live `main` CAS attempt or rollback occurred.

## Boundary and evidence

The public personal repository [vandyand/avo-c8](https://github.com/vandyand/avo-c8) was
created and seeded. The original [vandyand/avo](https://github.com/vandyand/avo) repository
is unchanged. The strict Pyright baseline was repaired at commit `a0d1a7d`.

Terra approved the offline personal exact-CAS boundary at commit `9e59638`, which was pushed
to the personal repository. The boundary specifies a fixed `PATCH` of `refs/heads/main` with
`force=false`, exact `B` to `C` sole-parent topology, no force/delete/generic-ref capability,
a durable request ID, `409`-only conflict handling, and conservative `422` handling.

The first hosted CI run
[33656104468](https://github.com/vandyand/avo-c8/actions/runs/33656104468) exposed portability
and coverage gaps. The expanded run
[33668978939](https://github.com/vandyand/avo-c8/actions/runs/33668978939), on exact commit
`4dd1ce3`, passed roadmap, Ruff, Pyright, image-build, and platform-overhead checks, then
reported 2,172 Ubuntu tests passing, two new portability-assertion failures, and 82.52% coverage
against the unchanged 85% floor; Windows reported 2,164 passing, four skips, and one of the
same portability failures. Commit `a624a8a` fixes those assertions without changing production
behavior. The canonical hosted run
[33688935928](https://github.com/vandyand/avo-c8/actions/runs/33688935928), on exact commit
`2f35d65381774b83fdbe622539ef7185d2b465ff`, then passed both required platform legs. Ubuntu
reported 2,600 passed, two skipped, and an exactly enforced total of 85.20%; Windows reported
2,589 passed and six skipped. Roadmap validation, Ruff, Pyright, image-build, platform-overhead,
and schema-parity checks also passed. Commit `bbc4d827` makes the literal
`--cov-fail-under=85` threshold explicit in all three authoritative Linux/WSL coverage commands,
and `2f35d653` adds meaningful adversarial coverage. The floor was not lowered and production
files were not excluded.

Follow-on C8 leaves are also Terra-approved. Commit `7dd0ba8` adds a read-only hosted-configuration
diagnostic and an isolated App-authenticated GitHub `main`-base reader; hosted run
[33707053367](https://github.com/vandyand/avo-c8/actions/runs/33707053367) passed Ubuntu and
Windows on that exact commit. Commit `ae4aaa8` adds pure offline, non-authoritative evidence
composition; hosted run [33709514612](https://github.com/vandyand/avo-c8/actions/runs/33709514612)
passed Ubuntu and Windows on exact commit `ae4aaa8242758e664d4acc2252579ff76999e2b0`. Their
review and tests made no live GitHub calls or repository/ref mutations; no writer App or final
writer ruleset is provisioned or authorized, and they establish no live CAS, rollback, or readiness.

This result records a reviewed protocol boundary, not hosted readiness or successful mutation.
Bootstrap `main` branch protection is live on `vandyand/avo-c8` with
`enforce_admins=true`, `required_linear_history=true`, `allow_force_pushes=false`,
`allow_deletions=false`, and no PR/status requirements. Terra reviewed it as a topology guard
only, not writer isolation or readiness. The final ruleset restricting updates/deletions to
the dedicated writer GitHub App as the only Always bypass, hosted denial tests, and the durable
live controller/transport integration is not yet provisioned. The real read-only trusted-source adapter is
Terra-approved offline at `ae65b73`, and the fail-closed durable-backend gate is Terra-approved
offline at `d9f6d3d`; the latter rejects native Windows, all WSL kernels, network/overlay/tmpfs,
and unknown filesystems. Neither leaf imports or enables a provider or HTTP mutation path.
The offline personal exact-CAS contracts and journal are Terra-approved at `a26fd7a`: 15 focused
tests passed with two Windows symlink-privilege skips. The journal independently reopens the
pinned trusted-source reader on every authority-dependent write/read, permits only exact applied
or reconciled completion arms, and durably orders object-directory fsync before create-once index
publication on the same qualified mount/device. It still exposes no provider, HTTP, token, or
hosted writer surface. The live controller/transport remains unimplemented. After that boundary,
provision the ruleset and writer identity, then run a protected hosted rollback drill,
ledger activation, and then 12 consecutive eligible successes with zero failures and zero
boundary violations.

## Supersession and alternatives

The organization-owned repository/merge-queue blocker is superseded only for this separately
reviewed personal exact-CAS protocol. The queue protocol remains an alternate, not-selected
path, and its requirements are unchanged. This result does not authorize a live write, waive
repository protections, or provide writer authority.
