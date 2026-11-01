# Published two-backedge clock client

This profile is **UNRUN**. It exercises the standalone
`examples/owned_region_clock.rs` client through the library's actual
`PlannedInstall::publish_with` path. It does not replace the earlier manually
installed region oracle or its release throughput measurements.

The authored 30-byte function computes `outer * inner * (inner + 1) / 2`.
Both dimensions must be in `1..=32`, and the quantum in `1..=32768`.
There are `outer * (inner + 1)` branch encounters and `outer * inner - 1`
taken backward branches. It keeps the current 5–80-byte, register-only,
exactly-two-backedge profile and its source ownership, complete-leader,
quiescence, signal, lifetime and per-call guard requirements.

One release build precedes six fixed, independently launched comparisons:

| Outer | Inner | Quantum | Purpose |
| ---: | ---: | ---: | --- |
| 1 | 1 | 1 | No taken edge or callback |
| 1 | 4 | 2 | Inner-site callback |
| 3 | 1 | 1 | Outer-site callbacks |
| 3 | 4 | 2 | Both sites share one clock |
| 4 | 3 | 11 | Stop on the last taken edge; distinct result for the same loop product |
| 32 | 32 | 1023 | Maximum admitted dimensions and last-taken-edge stop |

The cohort requires ten exact callbacks, six inner and four outer. Each
compares the original and published result with an independent arithmetic
formula; the controller checks exact site/count/encounter and scalar register
values, the complete clock/canary, and a one-millisecond parked interval.
Callbacks preserve all 18 saved context words and refill only after the exact
matching reply. These checks do not establish full architectural state after
callbacks. The existing two-second per-handoff backstop remains unchanged.

Eight additional processes reject zero/oversized dimensions, a zero/oversized
quantum, nonnumeric input and missing arguments before mapping. Their required
exit code is 2, with one exact diagnostic. Generic publisher failure controls
remain in the core tests; this cohort adds positive client integration, not
new fault-injection coverage for all publisher failures.

There is one attempt, no replacement or case filtering. The runner records all
commands before execution and preserves failed and undispatched outcomes.
Each positive child has 10 CPU seconds, 20 wall seconds and 64 KiB capture/file
limits; argument refusals have 2 CPU seconds and 5 wall seconds. Core files are
disabled. The release build has a 600-second wall limit and 2 MiB capture cap.
The existing process owner supplies a separate three-second cleanup budget.
Durations are operational timings, not performance measurements.

After committing the source and recipe, use an installed direct Rust toolchain
and a fresh private output directory. The allocator must reserve 12 disjoint
CPUs for the whole command; Cargo jobs and harness threads are capped at 12.

```sh
REGION_CLIENT_REV=$(git rev-parse HEAD)
mkdir -p ignored
cpuset-alloc run --cores 12 --tag li2-region-client -- \
  env -i HOME="$HOME" PATH="$LI2_TOOLCHAIN/bin:/usr/bin:/bin" LANG=C LC_ALL=C \
  python3 -I -B evaluation/owned-clock-region-client/reproduce.py \
  "$REGION_CLIENT_REV" ignored/owned-clock-region-client-new
```

The runner verifies the exact revision and clean source scope, records the
actual compiler versions and hashes, and checks source/tool/binary continuity
through the campaign. Detailed captures stay under `ignored/`. Public results
must retain the six literal JSON outcomes and a compact receipt with exact
revision, hardware and commands. No result, performance improvement, deadline,
asynchronous publication or executable reclamation is claimed before execution.
