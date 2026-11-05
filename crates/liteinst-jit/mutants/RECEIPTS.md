# Required mutation chains — execution receipts

[who-am-i: musejit, host withheld. Owner: musejit (muse, host withheld) since 2026-11-05T12:03:34Z]

Command: `sh crates/liteinst-jit/mutants/run.sh` from the
workspace root, 2026-11-05; last re-executed for the P1b I1-A
recovery-core extraction on liteinst2 branch
`musejit/i1a-20261105` (off main
`46e6e8f3cc6a5cfce0e4b1bf4d7aec93a0e0f336`), after mutants 01
and 04 were regenerated against the moved recovery code in
`src/recovery.rs` — same one-line defects, new file/context
(the patches in this directory, applied and reversed one at a
time; the script first requires a green baseline, then requires
each mutant run to fail with its named causal assertion — a
compile/infrastructure error is explicitly not a kill — and each
restoration to return green on a clean tree). Script exit code:
**0**.

Patch SHA-256 are printed by the script at every run and were re-verified at this head (mutants 01 and 04 regenerated for the recovery-core move; same one-line defects).

| Mutant | Defect simulated | Killing evidence (mutant run) | Restored |
|---|---|---|---|
| `01-pending-credit-loss` | Recovery drops the pending branch credit at stub boundaries before the credit store | `branch_stub_credit_timing_and_spill_recovery` FAILED: `retired branch credited exactly once` | green |
| `02-missing-fallthrough-credit` | Jcc fallthrough edge bypasses its count stub | Two invocations prove different things: (1) the full-suite `run.sh` stops first at `tests/custody.rs:89` (`sum_loop: branches`, 1 vs 17) in the custody Ok test — that is this script's kill evidence, **not** O1 evidence; (2) a separate targeted invocation with only this mutant applied, `cargo test --locked -p liteinst-jit --test o1_compare`, FAILED at `tests/o1_compare.rs:117` (`sum_loop: branches`, 1 vs 17, rc 101) — that is the O1 kill evidence. The targeted patch was reversed and the tree verified clean before the full script ran. | green |
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
