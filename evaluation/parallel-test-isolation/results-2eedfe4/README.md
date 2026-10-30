# RapidProbe rejection tests retain their target reservations

Source `2eedfe41efdbeee11fc2e3f748a2ea4634da9b2e` fixes two parallel-test
address-reuse races in `src/rapid.rs`. The stale-window and active-tail tests
released their placeholder pages before installation, then required the target
address to remain unmapped. Another test could map that now-unowned address.
The observed mapping did not identify a leaked RapidProbe allocation.

Both rejection paths return before trampoline allocation. The tests now keep
their own `PROT_NONE` target page reserved through installation and every error
assertion, require that reservation's exact permissions, then release it. An
allocation-first regression would encounter the occupied destination and fail
the unchanged exact error checks. No production code changes, additional locks,
workspace serialization, skips or alternate accepted errors are introduced.

All five mutated-byte cases retain their exact opcode/window payload checks.
The tail-overlap case retains its active writer, original-byte restoration and
exact `OverlappingPatchSite` assertion. Despite its historical name, that test
exercises preallocation rejection; it does not prove postallocation discard.
Independent source review approves the exact afterimage recorded in the receipt.

The targeted live RapidProbe suite passes nine tests, with zero failures and
one existing release benchmark ignored. `receipt.json` and `checks.csv` record
the full parallel workspace, strict Clippy, formatting, all-target checking and
serial launch outcomes at the committed source. Every command has one declared
attempt; the workspace retains 316 harness threads in a disjoint 16-CPU
reservation and its fixed 900-second limit. Nested single-child summaries are
excluded from the workspace total. Prior allocation regressions and all
short-neighbor cases are recorded separately.

The full workspace at this revision **fails**: 3,647 passed, two failed and
37 ignored in 870.404 seconds. Both corrected RapidProbe tests, all 21
short-neighbor cases and the prior staged-drop/prefixed-pun allocation
regressions pass. The two failures are required generalized-pun fixtures in
`quiescent_oracle`, each reporting `AllocationUnavailable`; they are retained
as failures. Formatting, strict Clippy, all-target checking and serial launch
(1,039 passed) pass, with complete cleanup and no adopted descendants. A later
fixture-isolation change and its own full validation must be assessed
separately; this record is not a passing-workspace claim.

Use stable Rust 1.97.1 and the receipt's debug environment, with
`CARGO_INCREMENTAL=0`, opt-level 0, debug information disabled, assertions and
overflow checks enabled, and `LITEINST_EVALUATION=1`. Reserve four disjoint CPUs
for the targeted command and 16 for the workspace driver:

```sh
cargo test -j 4 -p liteinst2 --lib rapid::tests::live -- --nocapture
python3 -B evaluation/short-neighbor-parallel/validate.py \
  --revision 2eedfe41efdbeee11fc2e3f748a2ea4634da9b2e \
  --output ignored/rapid-rejection-parallel-reproduction
```

Hardware: AMD EPYC Zen 5 dev host. The records include exact commands, source
identity, CPU reservations, load averages, cleanup results and raw-log hashes.
Raw logs stay in ignored storage. Elapsed times are operational correctness
receipts, not performance measurements. This test fix supports claim 4's
systematic validation; it adds no new runtime capability.
