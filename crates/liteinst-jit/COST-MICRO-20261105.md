# liteinst-jit P1a cost micro-report (fixtures only)

[who-am-i: musejit, host withheld. Owner: musejit (muse, host withheld) since 2026-11-05T12:03:34Z]

**Label: fixtures, not whole-program.** These numbers measure six
corpus-v1 fixture functions executed in-process, comparing the P1a
translator (branch + instruction counting on) against the same bytes
called natively. They support no whole-program, `/bin/ls`, M4, or
best-in-class claim. No DynamoRIO number appears below: at fixture
granularity there is no DR-null equivalent, so the owner DR-null
ratio is **UNMEASURED / not applicable here** and remains entirely a
future M3/M4 obligation. The comparison shown is ratio-to-native,
labelled as such.

## Provenance

- Source: liteinst2 branch `musejit/work-20261105` at `cac0ca6b`
  (+ this report's bench example, same branch).
- Machine: host withheld; AMD EPYC 9D85 158-Core Processor,
  governor `performance`, ~2.92 GHz sample, kernel
  `7.1.3-0_fbk0_0_g295ad0959f34`, x86-64 Linux. Shared multi-lane
  host, **no CPU pinning** — ambient noise is visible in the native
  IQRs and in run-to-run native medians; treat ratios as
  order-of-magnitude, not stable constants.
- Command (both measured invocations):
  `CARGO_INCREMENTAL=0 cargo run --locked --release -p liteinst-jit --example cost_micro`
  at 2026-11-05T12:49–12:50Z.
- Method (li2adm format): exactly **10 timed samples** per cell
  after 1 discarded warmup sample; each steady-state sample is
  2,000 back-to-back runs, reported as µs/run; medians and IQRs are
  over the 10 samples. Bench working set N=4096 (deliberately larger
  than the tests' n=16 so per-branch cost dominates the branchy
  cells; `rep_movsb` copies 8 KiB/run). `prepare` = translate +
  install of a fresh `Executable` (no execution). No sample was
  discarded in either invocation; both invocations are tabulated
  where they differ materially (ratio column uses invocation 1).

## Results (median µs/run, IQR in parentheses, invocation 1)

| fixture | prepare | jit | native | jit/native |
|---|---:|---:|---:|---:|
| `sum_loop` | 7.00 (2.27) | 9.79 (1.51) | 1.73 (0.49) | 5.7× |
| `branchy_even_sum` | 9.98 (1.54) | 22.21 (3.14) | 2.61 (0.85) | 8.5× |
| `call_helper` | 8.59 (1.40) | 10.61 (1.75) | 2.42 (0.19) | 4.4× |
| `loop_insn` | 4.64 (0.80) | 9.68 (0.66) | 1.56 (0.01) | 6.2× |
| `rep_movsb` | 5.95 (0.30) | 1.05 (0.08) | 0.101 (0.002) | 10.3× |
| `rip_data` | 5.46 (1.87) | 0.80 (0.02) | 0.002 (0.000) | fixed-cost cell |

Invocation 2 medians agree in shape (jit: 9.49 / 16.54 / 10.79 /
10.65 / 1.02 / 0.91 µs; native medians moved more, e.g. `sum_loop`
1.73→2.53 µs), consistent with unpinned shared-host noise rather
than translator variance.

## Reading

- **Per-branch stub cost ≈ 1.8 ns (derived estimate, not a direct
  measurement):** `sum_loop` retires 4,097 counted branches per run;
  subtracting native (1.73 µs) and the fixed per-run cost (~0.8 µs,
  from `rip_data`) from jit (9.79 µs) leaves ≈7.3 µs ≈ 1.8 ns per
  flag-neutral stub execution (two spill saves/restores + locked-free
  `inc` + jump). `branchy_even_sum` retires ~2× the branches per
  element and lands at the worst ratio, as expected.
- **Fixed per-run cost ≈ 0.8–0.9 µs:** bridge entry/exit, full-state
  transfer, `sigsetjmp` arming, and one dispatcher return exit.
  This dominates tiny fixtures (`rip_data`, `rep_movsb`) and is a
  P1a in-process embedding cost, not a per-block translation cost;
  a whole-program run pays it per dispatcher exit, not per branch.
- **Prepare is 4.6–10 µs per fixture region** (decode + emit +
  `mmap`/`mprotect`): irrelevant at fixture scale, and by design
  paid once per mapping generation, never per page at run time
  (the li2adm per-admission trap this architecture avoids).
- For orientation only (literature/context, not a comparison):
  DynamoRIO with branch counting ran ≈11× native on branch-heavy
  code in prior in-tree notes. The fixture ratios above (4.4–8.5×
  on branchy loops) are the same order, but **no DR claim is made**
  until a same-machine whole-program bake-off with a labelled DR
  counting client exists (O3, P1b/M4).

Failures retained: none in either invocation (all cells completed;
`flags_adc`, `syscall_write`, `cpuid_leaf`, `fault_load`, `jrcxz`,
`indirect_jmp` are correctness-only fixtures with no native-timing
cell because their ABI/handler needs make a naked native call
meaningless; they are covered by the O1 test, not omitted silently).

## Addendum: S3-A streaming-decoder reuse (2026-11-05)

S3-A keeps one iced decoder and one instruction-info factory for
block discovery and carries the decoded terminator forward instead
of decoding it again. The cost example gained a `translate` mode
(discovery + emission only, 1,000 translations per timed sample) so
this change can be measured separately from cache installation and
execution. Baseline production code is liteinst2 `main` at
`f229b290532f991a9ec99d98d6bee0a22f401c15`; the after run is the
same bench mode plus the S3-A decoder reuse. Command for both:
`CARGO_INCREMENTAL=0 cargo run --locked --release -p liteinst-jit --example cost_micro`.
Machine: host withheld; AMD EPYC 9D85 158-Core Processor, Linux
`7.1.3-0_fbk0_0_g295ad0959f34`, x86-64, shared and unpinned.
Exactly 10 timed samples follow one warmup sample. These are
fixture component costs only, not a whole-program or DynamoRIO
comparison.

| fixture | prepare before → after µs | prepare speedup | translate before → after µs | translate speedup |
|---|---:|---:|---:|---:|
| `sum_loop` | 8.442 → 7.662 | 1.102× | 4.522 → 4.081 | 1.108× |
| `branchy_even_sum` | 9.239 → 8.428 | 1.096× | 6.315 → 5.671 | 1.114× |
| `call_helper` | 9.088 → 8.693 | 1.045× | 6.235 → 5.546 | 1.124× |
| `rip_data` | 4.322 → 4.207 | 1.027× | 1.928 → 1.813 | 1.063× |
| `loop_insn` | 6.830 → 6.259 | 1.091× | 3.917 → 3.593 | 1.090× |
| `rep_movsb` | 5.969 → 5.918 | 1.009× | 3.475 → 3.345 | 1.039× |

Median speedup across the six fixtures is 1.068× for `prepare`
and 1.099× for `translate`. The translate IQRs were at most
0.134 µs in both runs; prepare remains noisier because each timed
sample performs one fresh executable installation. A maintained
golden-hash test pins emitted bytes, PC maps, block layout, and
decoded terminators for representative fixtures to the
pre-streaming implementation, so this is a decoder-reuse cost
change, not an emission-semantics change.
