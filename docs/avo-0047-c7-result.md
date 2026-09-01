# AVO-004.7 C7 deterministic offline gate result

Status: complete for offline acceptance as of 2026-09-01 at code HEAD
`9c70c36074810606692f8c2030b25ce83c10a1e4`. Terra code reviews approved the final
implementation and closeout remediations.

## Decision

C7 is complete. The authority-owned, hermetic gate passed all 47 exact fault-matrix
cases, including crash, adversarial, rollback, cleanup, and replay boundaries. Replay
returned the exact same result with `executor_calls=0` and `clock_calls=0`. The result
records `deploy_performed: false`; no hosted/provider/queue/protection/`main` mutation
occurred.

Two truthful failed-closed dry acceptance attempts produced no completion indexes and
exposed datetime canonicalization and semantic-versus-artifact verifier binding bugs.
Both were remediated, covered by regression tests, and reviewed before this acceptance.

## Immutable identities

| Identity | Digest |
| --- | --- |
| Final operation | `ccbff909ce068b9287ff8fd404c953eeaa4e129002ee56322287d8d3b4d216d3` |
| Authority (semantic) | `e740df3362d16e65374e7083ddc7897c0323c4660aaa5596dbd386d96c14e98d` |
| Authority (artifact) | `25216680fe622f3970af82907bad6a7261a59482af43b47848e1203b93b14b50` |
| Controller root (raw artifact) | `2f164d65cb6437d84aa1d96a9d46aa12c76b3fada0c47eee9a1794f8e3a08aee` |
| Plan | `dced9a0cb20c2bcdbb4e8428580fbbf325427a9b80d86058b3f161e378a36843` |
| Execution report (artifact) | `0919b53e4887803af796f4c121d85c771076341167ca2c043421d2ec6d5922e1` |
| Aggregate result | `ab9a6a56f11e284f463c84154079078da8d95f3a2fdd2d3636972dc512d792a9` |

C7 is offline evidence only. C8 remains blocked pending organization-owned hosting with
the required max-one-entry merge queue and exact admission/hold behavior, plus separately
authorized isolated release-hold authority. AVO-004.7 remains in progress; the hosted
rollback drill and 12 consecutive eligible hosted successes remain future work.

## Related authority

* [AVO roadmap](roadmap.md)
* [AVO-004.7 implementation plan](avo-0047-main-graduation-plan.md)
* [AVO-004.7 runbook](avo-0047-main-graduation-runbook.md)
* [ADR 0011](adr/0011-protected-main-graduation.md)
