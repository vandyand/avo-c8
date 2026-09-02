# AVO-004.7 C8 personal exact-CAS result

Status: Terra-approved offline personal-repository exact-CAS boundary; hosted coverage
remediation in progress.
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
same portability failures. Commit `a624a8a` fixes those assertions locally without changing
production behavior. Additional meaningful recovery/authority coverage remains in progress;
the floor was not lowered and production files were not excluded.

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
