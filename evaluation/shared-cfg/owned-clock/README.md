# Owned-clock shared CFG validation

At `f8785f2d7c4cc79c8d42862f177f8d54b62bed81`, both owned back-edge
clock profiles use the common CFG constructor and reachability traversal;
the two-backedge region also shares structural returnability. Their original
size, scalar, prefix, entry and backedge policies remain distinct. Four new
controls check accepted graphs, exact refusals, differing returnability rules
and supplied-scan identity. No previous tests were removed or relaxed.

The single `owned-clock-shared-cfg-correctness-1800-360-v1` attempt passed:
fmt, strict workspace/all-target/all-feature Clippy, all-feature/all-target
check, 2 graph tests, 37 clock tests, the parallel workspace suite and the
serial launcher suite. All four new controls ran exactly once in the focused
clock suite. Workspace has **4,609 top-level + 11 nested = 4,620 passes,
0 failures and 43 unchanged ignores**; serial launch **1,039 passes, 0 failures and 0 ignores**. Raw workspace
summaries include nested runs; focused/serial counts overlap workspace coverage.
The complete prior roster survives with exactly the four new controls added;
serial coverage, critical regressions, expected panics and ignore reasons are
unchanged. The independent comparison is recorded in the receipt.

[receipt.json](receipt.json) records the exact revision/tree, script hashes,
commands, bounds, outcomes, hardware, CPU reservation and loads. All 11 command
owners exited normally with complete cleanup and zero rescued descendants.
Workspace completed in 848.593 seconds under its 1,800-second bound; serial
launch in 126.222 seconds under 360. These are correctness-run durations,
not performance measurements. Earlier failed profiles in the parent report
remain failed; this separate run does not replace their results.

Reproduce on a clean checkout of the exact revision, with an offline Rust
1.97.1 toolchain in `TOOLCHAIN` and a fresh output directory:

```sh
cpuset-alloc run --cores 12 --tag owned-clock-cfg-reproduce -- \
  python3.9 -I -B evaluation/shared-cfg/validate_clock.py \
  --revision f8785f2d7c4cc79c8d42862f177f8d54b62bed81 \
  --output ignored/owned-clock-cfg-reproduce --toolchain "$TOOLCHAIN"
```

Hardware: **AMD EPYC Zen 5 dev host**. Build jobs and harness threads are 12;
serial launch uses one thread. The runner enforces the existing cumulative
storage ceilings, one target and disabled incremental/debug output. Raw
captures stay private. This refactor does not qualify broader preemption,
throughput, complete-program CFG recovery or runtime page exemptions.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
