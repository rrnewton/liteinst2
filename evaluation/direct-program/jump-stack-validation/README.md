# Jump and register-stack correctness

The correctness campaign **passed** at `6c9e3922293dcb848cd2ab5e103ecedcbf65d23f` (tree `f56fb984b7a755cecbcebcc65875043c69416a0e`). All ten validation commands and four capacity measurements completed normally with cleanup and zero rescue reaps. [receipt.json](receipt.json) records the commands, owners, source pins, limits and complete census digests.

Workspace testing recorded **4,631 top-level passes plus 11 inherited nested passes = 4,642 raw passes**, zero failures and **43 unchanged ignores**. The complete prior contextual roster remains intact, with exactly 14 selection/policy/CLI tests and four native tests added. All 539 should-panic labels, 27 workspace critical cases, 21 short-neighbor controls and ignore reasons are preserved. The serial launch run passed the identical **1,039-case** roster, including its five critical cases and unchanged backing-cleanup records. Four Python inventory tests passed separately.

The native controls exercise all sixteen exact register PUSH/POP forms with two seeds and both existing emitters. They check the intermediate PUSH RSP word against incoming RSP, independently require POP RSP to end at its loaded value, and compare four original operand faults with valid observer scratch. Existing comparisons retain full register/defined-flag/XSAVE state and declared application memory. These finite fixtures do not establish arbitrary-stack or asynchronous transparency, complete CFG/entry ownership, whole-program corpus correctness, runtime page exemptions or performance.

The first attempt at `b9c371572578683daa1a969d7f643ec52f04ebb2` remains **FAILED**: formatting and Python passed; Clippy rejected `single_range_in_vec_init`; the seven later commands were unobserved. The sole correction constructs the same one-range vector with `std::iter::once(...).collect()` and formats that include file. Assertions, cases and limits were retained. Earlier failed profiles remain failed.

The workspace command took 839.096 seconds within its declared 1,800-second bound; serial took 130.207 seconds within 360 seconds. These are observed durations, not performance or quiet-host evidence.

## Reproduction

Use a clean checkout of the exact revision above and the recorded stable Rust toolchain. Reserve twelve disjoint CPUs externally, then set `CPUS`, absolute `TOOLCHAIN`, and a fresh absolute `OUT` under the checkout's `ignored/`. Its basename must also be unused under `target/evaluation/jump-stack-selection/`. Paths in the receipt are explicit templates.

```bash
set -euo pipefail
: "${CPUS:?reserve exactly twelve CPUs externally}"
: "${TOOLCHAIN:?absolute Rust toolchain directory}"
: "${OUT:?fresh absolute directory under the checkout ignored directory}"
test "$(git rev-parse HEAD)" = 6c9e3922293dcb848cd2ab5e103ecedcbf65d23f
test -z "$(git diff --name-only HEAD --)"
taskset --cpu-list "$CPUS" /usr/bin/python3.9 -I -B \
  evaluation/direct-program/validate_stack.py \
  --revision 6c9e3922293dcb848cd2ab5e103ecedcbf65d23f \
  --output "$OUT" --toolchain "$TOOLCHAIN"
```

The runner sets jobs and ordinary test threads to twelve, serial threads to one, offline Cargo, one target directory, zero dev/test debug information and disabled incremental compilation. It preserves the original cumulative storage ceilings and refuses incomplete cleanup. Native traces retain 20,000 steps/15 seconds and the isolated owner retains 20 CPU seconds/30 wall seconds. Reproduction is a new observation and may fail.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
