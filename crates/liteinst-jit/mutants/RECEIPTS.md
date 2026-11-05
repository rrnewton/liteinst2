# Required mutation chains — execution receipts

[who-am-i: musejit, host withheld. Owner: musejit (muse, devbig030) since 2026-11-05T12:03:34Z]

Command: `sh crates/liteinst-jit/mutants/run.sh` from the
workspace root, 2026-11-05T14:25Z, on liteinst2 branch
`musejit/work-20261105` at base head `28bb2ba87c0ef5f5b2041a68d050aa7cc7523f13`
(the patches in this directory, applied and reversed one at a
time; the script first requires a green baseline, then requires
each mutant run to fail with its named causal assertion — a
compile/infrastructure error is explicitly not a kill — and each
restoration to return green on a clean tree). Script exit code:
**0**.

Patch SHA-256: `01` `1d2935166a9e…`, `02` `a106a28b9c96…`,
`03` `06f4fe481ff1…`, `04` `d4876c7daec4…`, `05` `f13746f838ff…`
(full values printed by the script at every run).

| Mutant | Defect simulated | Killing evidence (mutant run) | Restored |
|---|---|---|---|
| `01-pending-credit-loss` | Recovery drops the pending branch credit at stub boundaries before the credit store | `branch_stub_credit_timing_and_spill_recovery` FAILED: `retired branch credited exactly once` | green |
| `02-missing-fallthrough-credit` | Jcc fallthrough edge bypasses its count stub | O1 integration FAILED: `sum_loop: branches` | green |
| `03-disabled-invalidation` | `Executable::invalidate` leaves the executable runnable | O1 integration FAILED: expected `StaleGeneration` refusal | green |
| `04-cache-pc-fault` | Fault reports the raw generated PC | O1 integration FAILED at the checked range assertion (`pc … outside source range from …`), before offset comparison — no subtraction overflow | green |
| `05-before-retirement-emission` | Branch credit emitted at block entry (successor stubs credit a dead field) | O1 integration FAILED: `fault_before_branch branches` left 1, right 0 — a fault before the branch must not credit it | green |

Mutant 01 is the pending-credit recovery control (renamed from
its earlier misleading filename); mutant 05 is the actual
before-retirement emission defect, observed through executed
fault behavior against the independent O1 oracle. Per-mutant
logs are written to `/tmp/mutant-<name>.log` and
`/tmp/mutant-<name>-restored.log` on the measuring host (not
committed; the script regenerates and hashes-bound outputs are
reproducible by re-running it). No assertion, tolerance, or
comparator was changed to produce these results.
