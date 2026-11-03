# Shared disassembly-cut validation

At `fcbbb94dfe4556b1b022e6ad61628c9817d1d6d6`, local graph partitions and
the disassembly importer share one near-target query and block-cut collector.
The importer retains global executable-LOAD/head checks for cross-region
branches, CALL and XBEGIN. Local consumers retain their own target rules.
Four new controls check target distinctions, indirect following cuts, remote
block splits and first-error ordering. Existing tests and limits are unchanged.

The single `shared-disassembly-cuts-correctness-1800-360-v1` attempt passed:
fmt, strict workspace/all-target/all-feature Clippy, all-feature/all-target
check, 4 graph tests, 37 clock tests, 2 focused importer tests, the parallel
workspace suite and serial launcher suite. Workspace has **4,613 top-level +
11 nested = 4,624 passes, 0 failures and 43 unchanged ignores**. Serial launch
has **1,039 passes, 0 failures and 0 ignores**. The complete prior roster
survives with exactly four new controls; critical regressions, expected panics,
ignore reasons and harnessless records are unchanged. Focused and serial runs
overlap workspace coverage; their counts are not additional distinct tests.

[receipt.json](receipt.json) binds exact revision/tree, script hashes, commands,
bounds, hardware, reservation and loads. All 12 command owners exited normally
with complete cleanup and zero rescued descendants. Workspace completed in
936.286 seconds under 1,800; serial launch in 159.825 seconds under 360. These
are correctness-run durations, not performance measurements. Earlier failed
profiles remain failed. The new jumps/PUSH/POP profile is outside this revision
and receives no execution credit here.

Reproduce on a clean checkout of the exact revision, with an offline Rust
1.97.1 toolchain in `TOOLCHAIN` and a fresh output directory:

```sh
cpuset-alloc run --cores 12 --tag disassembly-cuts-reproduce -- \
  python3.9 -I -B evaluation/shared-cfg/validate_cuts.py \
  --revision fcbbb94dfe4556b1b022e6ad61628c9817d1d6d6 \
  --output ignored/disassembly-cuts-reproduce --toolchain "$TOOLCHAIN"
```

Hardware: **AMD EPYC Zen 5 dev host**. Build jobs and harness threads are 12;
serial launch uses one thread. The runner retains the existing storage ceilings,
one target and disabled incremental/debug output. Raw captures stay private.
This consolidation grants no complete-CFG, runtime page-exemption, broader
preemption or performance qualification.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
