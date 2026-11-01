# Bounded clock batch qualification

The single release cohort **passed** at revision
`b61a644e465100abdcff718af42aa3e4b92aede5`. Both the original and batch oracles
passed 192 architectural comparisons. The batch completed all 352 exact q64
handoffs, both wrong-reply controls and the fork-at-entry refusal. Focused
validation passed 33 library tests, 11 compile-fail controls and strict Clippy.
Full validation at the same revision passed formatting, strict workspace
Clippy, all-target checking, 4,414 top-level workspace tests (39 ignored, three
controlled child passes counted separately) and 1,039 serial launch tests.
See the [full-gate receipt](validation.json). No batch timing or speedup is claimed.

The [receipt](receipt.json) records the exact revision, release binary, hardware,
commands, bounds, owner closures, CPU reservation and load. Literal JSON and CSV
outcomes are retained for the [original oracle](region-oracle/summary.json) and
[batch oracle](region-batch-oracle/summary.json). The existing per-call API,
benchmarks and failed qualifications remain unchanged.

The new unsafe batch API admits a fixed number of invocations on one previously
unused clock lease. Each call is precharged against the acquired work bound;
explicit token completion and a final owner check are required. The caller
excludes fork, reentry and foreign entry throughout the interval and proves the
per-call work bound. The generated gate, counter layout and callback protocol
are unchanged.

The release cohort first ran the existing region oracle, then the
new `region-batch-oracle` command. Both use the existing exact architectural
comparator. The batch command includes 192 state comparisons, native/counter/stop
arms of 2,048 calls each, 30,720 encounters and 22,528 taken branches per
instrumented arm, and 352 exact q64 stops (288 inner, 64 outer). Every result and
full clock/canary must match. Two actual wrong-site/count replies must refuse
before refill. One child forked before batch admission must refuse the inherited
lease with no generated entry or clock mutation. Finish owner mismatches are
covered by unit controls; no live-batch fork is accepted.

Raw logs and binary witnesses stay under `ignored/`. The compact JSON/CSV
outcomes and receipt retain exact revision, hardware, commands, CPU reservation
and load. The ordinary oracle and new cohort each run once, with every failure
retained and no replacement attempts. This is correctness qualification only;
ptrace prefixes do not establish full state after callbacks or executable
reclamation.

Reproduce from a clean checkout at the measured revision using the tracked script, a direct
Rust toolchain and a new private output directory:

```sh
BATCH_REV=b61a644e465100abdcff718af42aa3e4b92aede5
BATCH_TAG=li2-owned-clock-batch-v1
mkdir -p "$PWD/ignored"
cpuset-alloc run --cores 12 --tag "$BATCH_TAG" -- \
  env -i HOME="$HOME" PATH="$LI2_TOOLCHAIN/bin:/usr/bin:/bin" LANG=C LC_ALL=C \
  python3 -I -B evaluation/owned-clock-batch/reproduce.py \
  "$BATCH_REV" ignored/owned-clock-batch-new "$BATCH_TAG"
```

Cargo jobs and harness threads are capped at 12. Both native commands use the
first two reserved CPUs. The build has a 600-second wall limit and 2 MiB capture
cap. Each native command has 60 CPU seconds, 90 wall seconds, 1 MiB file/capture
caps and no core files. CPU/file limits are inherited per process; the wall
bound covers the owned process tree. The process owner retains its separate
three-second cleanup budget. The existing oracle reserves a 4 GiB virtual
arena, so this recipe adds no address-space cap. The runner records the caller's
allocator tag and its observed affinity; it does not claim an independent live
reservation witness.

The full gate uses `evaluation/short-neighbor-parallel/validate.py` with the
exact environment, commands, bounds and revision recorded in `validation.json`.
All 21 short-neighbor cases and the earlier rapid, trampoline, prefixed-pun and
exec-map regressions passed. The five exec-map cases also passed serially.
