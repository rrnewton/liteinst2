# Performance

This chapter separates three things that performance chapters too
often merge: prior project **measurements** whose receipts live
outside this repository (cited with provenance, not reproduced by any
in-tree test), numbers **cited** from the literature, and what is
**unmeasured**. Claims beyond the measurements are roadmap, not
results.

## Cited: prior project measurements (no in-tree receipt)

* **Patch-apply latency:** median ≈0.49 µs for a cache-line-aligned
  site and ≈4.15 µs for a cache-line-crossing (guarded) site,
  N = 20,000 each. Callback and context costs are excluded by design —
  this is the price of publishing the patch, not of running your hook.
* **No-op trampoline cost:** a hot loop through an empty hook runs
  12.08% (aligned) / 22.19% (crossing) slower than native at
  ~420M calls/second baselines. Your callback's own work adds linearly
  on top.

  Provenance for both bullets: measured 2026-10-18 on a project
  development host and recorded outside this repository in the
  project's patch-latency note (`2026-10-18-liteinst-patch-latency.md`,
  tree at `837456e`), as cited by the 0.2.0 checkpoint (§6). Treat
  them as *cited* values: no test or receipt in this tree reproduces
  them, and they move back to "measured" only when the benchmark
  suite below lands an in-tree reproduction. Relative to a DynamoRIO
  null client (DR-null), no same-machine ratio exists yet:
  UNMEASURED (see "Unmeasured").

* **Owned-clock throughput:** the two-backedge owned-region profile
  measures native, counting, and quantum-stop costs across 12
  independent processes (see `evaluation/` in the repository for the
  campaigns and receipts).

Performance evidence in this repository is campaign-style — ignored
stress/benchmark tests run explicitly, plus the `evaluation/` tree —
not a `cargo bench` suite. That is a known gap (below), and it is why
every number here carries its provenance.

## Cited (literature, same scale)

Per-hook interception costs from the published literature, as
collected in the project's in-place/incremental rewriting study
(2026-10-24, kept with the project's design documents, not in this
repository): ~41 ns (zpoline-style static rewrite), ~1,156 ns (SUD),
~1,342 ns (`int3`), ~31,201 ns (ptrace stop). lazypoline reports
1.23–2.38× overhead on syscall microbenchmarks. DynamoRIO's
null-client tax is reported at 1.24–14× on record-replay workloads.
These numbers orient mechanism choice; they were not measured on our
hardware against our builds, and no DR-null ratio for LiteInst exists
until the bake-off below lands.

## Unmeasured — stated plainly

* No same-machine, head-to-head comparison of LiteInst against
  e9patch, lazypoline, or DynamoRIO on shared workloads
  (syscall-dense, branch-dense, JIT) has landed yet. Building that
  bake-off harness is scheduled work, and until it lands "best in
  class" is a goal, not a claim.
* Whole-program overhead on standard suites (SPEC, coreutils, Python)
  is unmeasured for the same reason.
* Dense whole-program branch counting is unmeasured because it is
  unimplemented at this layer; it belongs to the translation roadmap.

## Practical guidance

* Prefer fewer, hotter hooks: steady-state cost is per *execution* of
  a site, so site selection dominates everything else.
* Toggle with rapid puns instead of reinstalling when a probe's duty
  cycle is high-frequency.
* Keep callbacks allocation-free and short; the trampoline preserves
  exact extended state for you, but your callback's work is on the
  guest's critical path.
* Measure first-touch separately from steady state when using page
  gates: admission faults are one-off costs and should not be averaged
  into per-call overhead.

> 🚧 **Under construction — benchmark suite.** TODO: curate the
> campaign evidence into 4–6 `cargo bench` benchmarks (toggle,
> hook steady state, first touch, offline rewrite) with a results
> table in this chapter, then land the same-machine bake-off against
> e9patch/lazypoline/DynamoRIO and replace the cited numbers with
> measured ones. <!-- UC: perf-benches -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`perf-benches`).
