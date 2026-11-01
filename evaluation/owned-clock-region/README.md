This correctness profile relocates one owned scalar region with two backedges
sharing one clock and invocation lease. The 16 focused core controls passed at
`f7b0b87147ea14dc1eea533186632155605dfc66`. Native validation at
`9cbe5da7cbe452bb4d41b3942096c462775ac33c` is **UNRUN**; the cohort below is
expected coverage, not a measured result.

[`BackedgeClockRegion::new_owned_region`](../../src/backedge_clock.rs) safely
checks supplied bytes: 5–80 bytes, exactly two unprefixed near JNZ/JG/JB/JMP
backedges, closed direct control flow, caller-saved integer scalar operations,
and one final RET. It consumes two distinct enabled managed controls' writers
and binds one clock and mode. Existing single-site APIs remain separate.

The public unsafe
[`plan_owned_clock_region_detailed`](../../src/quiescent/clock_region.rs)
requires authenticated source generation, complete internal leaders, sole
external entry, no saved resumes or in-flight invocation, and the existing
quiescent ABI/publication contracts. It emits one whole-region image, bounded
by 256 candidates, one mapping and 8192 bytes. Structural reachability does not
prove termination: the caller must establish a finite aggregate encounter bound
and acquire one exclusive lease/call guard before entering either gate. Source,
image, controls and separate RW clock must remain live until execution drains;
the oracle callbacks authenticate site/control/PID/TID and resume before refill.

The register-only 36-byte nested 3×4 fixture has 15 branch encounters, 11 taken
edges and return value 12. Its fixed cohort expects 192 full-state comparisons
across six sibling pairs, six stopped callbacks across quanta 2/11/12, and two
actual wrong-site/wrong-count reply children. Each rejection requires a first-stop
unchanged-frame/clock witness, exit 123, EOF and ECHILD. Gate comparisons include
GPRs, flags, architectural XSAVE, application data and stack before observation
saves state. Callback/refill checks cover the saved 18-word frame and full clock
page; they do not claim full architectural equality after the callback.

The oracle holds its source/native/clock arena, then acquires the public
planner's exact vacant image once with MAP_FIXED_NOREPLACE; collision fails
without retry. It copies authenticated emitted bytes into that owned mapping.
This exercises planner/emitter/native-clock correctness, not the production
publisher, a deadline bound or performance.

From a checkout with cached Cargo dependencies, set `LI2_TOOLCHAIN` to an installed
Rust toolchain directory. The output name must be fresh. The recipe builds release
once and runs the cohort once, retaining bounded command logs:

```sh
EXPECTED_REV=9cbe5da7cbe452bb4d41b3942096c462775ac33c
mkdir -p ignored
cpuset-alloc run --cores 12 --tag li2-region-oracle -- \
  env PATH="$LI2_TOOLCHAIN/bin:/usr/bin:/bin" \
  python3 -I -B evaluation/owned-clock-region/reproduce.py \
  "$EXPECTED_REV" ignored/owned-clock-region-new
```
