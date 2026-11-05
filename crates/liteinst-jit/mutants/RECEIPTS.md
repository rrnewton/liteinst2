# Required mutation chains — execution receipts

[who-am-i: musejit, host withheld. Owner: musejit (muse, devbig030) since 2026-11-05T12:03:34Z]

Command: `sh crates/liteinst-jit/mutants/run.sh` from the
workspace root, 2026-11-05T13:41Z, on liteinst2 branch
`musejit/work-20261105` at base head
`5e7b45854c0c4eaaac785858a8169d12c1d0366b` (the four patches in
this directory, applied and reversed one at a time by the script;
each restored run re-executes `cargo test --locked -p liteinst-jit`
with `CARGO_INCREMENTAL=0`). Script exit code: **0** — every
mutant was killed and every restoration returned green
(23 unit + 1 O1 integration).

| Mutant | Defect simulated | Killing evidence (mutant run) | Restored |
|---|---|---|---|
| `01-credit-before-retirement` | Recovery drops the pending branch credit at stub boundaries before the credit store | `exec::recovery_tests::branch_stub_credit_timing_and_spill_recovery` FAILED: `retired branch credited exactly once` (22 passed, 1 failed) | green |
| `02-missing-fallthrough-credit` | Jcc fallthrough edge jumps directly to the successor block, skipping its count stub | `jit_matches_o1_oracle_on_corpus_v1` FAILED: `sum_loop: branches` | green |
| `03-disabled-invalidation` | `Executable::invalidate` leaves the executable runnable | `jit_matches_o1_oracle_on_corpus_v1` FAILED: expected `StaleGeneration` refusal | green |
| `04-cache-pc-fault` | Fault reports the raw generated PC instead of the recovered source PC | `jit_matches_o1_oracle_on_corpus_v1` FAILED at the fault-PC offset assertion | green |

Full per-mutant logs were written to `/tmp/mutant-<name>.log` and
`/tmp/mutant-<name>-restored.log` by the script on the measuring
host (not committed; re-running the script regenerates them). No
assertion, tolerance, or comparator was changed to produce these
results; the patches touch only the named production mechanism.
