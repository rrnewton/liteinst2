# Adjacent two-byte pun planning

Claim 4 / A3 core increment: the explicit artifact API searches two adjacent
observing forward Jcc instructions together. It retains failed placements,
cumulative upper/lower image budgets, continuation budgets, original identities,
pending ownership and transactional composition. Existing engine paths are unchanged.

At merged revision `f02e6a06d9a220d02bfa7e32758f6f3fba3a5d14`, ten new control
groups pass, including all 16 condition opcodes at each role, real singleton and
pair images, inherited compositions, budget boundaries, and aggregate refusal
followed by success. The parallel workspace has **3,623 passed, 0 failed,
37 ignored**; serial launch has **1,039 passed, 0 failed**. All 21 short-neighbor
tests and the earlier trampoline/prefixed-pun allocation regressions pass.
Formatting, strict workspace Clippy and all-target checking also pass.

[receipt.json](results-f02e6a0/receipt.json), [checks.csv](results-f02e6a0/checks.csv)
and [controls.csv](results-f02e6a0/controls.csv) record the exact revisions,
commands, hardware, CPU reservations, load, source hashes and results. Both the
pre-merge and merged validation rounds are retained. Totals exclude five nested
single-child summaries already included in their outer tests. Two custom
workspace harnesses complete separately and are identified in the receipt.
Raw logs stay in ignored storage; their content hashes are recorded.

These are debug-build correctness results. Command elapsed times are operational
receipts, not performance measurements. This increment does not establish native
adjacent-pair equivalence, frontend use, full-program coverage or completion of
A3. Artifact qualification remains false.

To reproduce, use Rust 1.97.1 and Python 3.12, check out the tested revision, and
run the existing validation script inside a disjoint 16-CPU reservation. It
records affinity and load, retains 316 test threads, and uses the same bounded
commands. Choose a fresh ignored output directory for each invocation.

```sh
env CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  CARGO_PROFILE_DEV_OPT_LEVEL=0 CARGO_PROFILE_TEST_OPT_LEVEL=0 \
  CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true \
  CARGO_PROFILE_DEV_OVERFLOW_CHECKS=true CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true \
  LITEINST_EVALUATION=1 \
  python3 -B evaluation/short-neighbor-parallel/validate.py \
    --revision f02e6a06d9a220d02bfa7e32758f6f3fba3a5d14 \
    --output ignored/adjacent-b2-reproduction
```

The isolated control command in `checks.csv` is
`cargo test -j 4 -p liteinst2 --lib quiescent::adjacent_b2::tests:: -- --nocapture`.
The full workspace script executes those same ten groups as part of its suite.

The separate native-campaign runner has six passing unit tests covering eleven
fixed scenarios: one successful stub campaign and ten injected failures. They
check retained outcomes, dependent stages left unrun, source/binary guards and
mutually exclusive custody receipts. The tests use a stub command owner and
execute no native stage; they supply no native-equivalence or real-cleanup claim.
[The receipt](runner-controls-be41ea0/receipt.json) binds the exact added source
hashes atop `be41ea072a0b7168c6f8833894194ecf811b8b09`, with all
[control results](runner-controls-be41ea0/controls.csv). Reproduce them with
`python3 -B evaluation/adjacent-b2/test_native_runner.py`.
