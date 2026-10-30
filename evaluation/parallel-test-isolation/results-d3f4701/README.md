# Parallel native-oracle isolation

Source `d3f47010282d93e5d91ad4a4014998a224bed514` runs the four quiescent
native campaigns in separate, freshly executed processes. Their source pages
and retained trampoline mappings previously shared one address space with
concurrent campaigns. A fixture could therefore find its required trampoline
window already occupied by another test. The two observed allocation failures
at `2eedfe4` remain recorded in [the preceding run](../results-2eedfe4/README.md).

The change shares the existing prefixed-pun process helper with those four
campaigns. All five native bodies remain byte-identical, including exact plan,
state, error, successor-byte and retirement assertions. The helper retains its
exact test-name selector, body-completion status 102, 30-second wall bound,
20-second CPU limit, pinned child identity, two-second cleanup bound and
no-leftover-child assertion. A zero-test exit, panic, signal or timeout fails.
The single-test child filter leaves the workspace and parent harness parallel.
No production behavior, fixture, comparator, skip or accepted error changes.

Independent source review approved the three exact source images. Both oracle
binaries passed all 75 tests with 316 test threads in a four-CPU reservation.
The full parallel workspace passed 3,649 tests, with zero failures and 37
ignored, in 829.667 seconds. Formatting, strict workspace Clippy and
all-target/all-feature checking passed. Serial launch passed 1,039 tests
in 132.899 seconds. Every command completed cleanup with zero adopted
descendants. This revision adds no tests; the prior two fixture failures
now pass under the same workspace concurrency.

[receipt.json](receipt.json) and [checks.csv](checks.csv) record exact source,
body hashes, commands, environment, CPU reservations, load, outcomes and raw-log
hashes. Every command has one declared attempt. Nested child summaries are
excluded from workspace totals; custom harnesses complete separately. The
RapidProbe reservation fix, all 21 short-neighbor cases, both staged-drop
regressions and all five isolated native campaigns have explicit outcomes.
Prior failures are retained separately rather than overwritten.

Reproduce with stable Rust 1.97.1 using the receipt's debug environment:
`CARGO_INCREMENTAL=0`, opt-level 0, debug information disabled, assertions and
overflow checks enabled, and `LITEINST_EVALUATION=1`. Reserve four disjoint CPUs
for the targeted command, then 16 for the existing full validation driver:

```sh
cargo test -j 4 -p liteinst2 --test quiescent_oracle --test prefixed_pun_oracle \
  -- --test-threads=316 --nocapture
python3 -B evaluation/short-neighbor-parallel/validate.py \
  --revision d3f47010282d93e5d91ad4a4014998a224bed514 \
  --output ignored/quiescent-isolation-reproduction
```

The driver keeps 316 harness threads and the fixed 900-second workspace bound.
Hardware: AMD EPYC Zen 5 dev host. Raw logs remain in ignored storage. These
elapsed times are operational correctness receipts, not performance evidence.
The change supports claim 4's systematic validation and adds no tactic coverage.
