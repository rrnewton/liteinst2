# Bounded clock batch qualification

Status: **UNRUN**. This separate profile preserves the original per-call API,
its benchmarks and every existing failed qualification. No batch timing or
speedup is claimed.

The new unsafe batch API admits a fixed number of invocations on one previously
unused clock lease. Each call is precharged against the acquired work bound;
explicit token completion and a final owner check are required. The caller
excludes fork, reentry and foreign entry throughout the interval and proves the
per-call work bound. The generated gate, counter layout and callback protocol
are unchanged.

The prospective release cohort first runs the existing region oracle, then the
new `region-batch-oracle` command. Both use the existing exact architectural
comparator. The batch command includes 192 state comparisons, native/counter/stop
arms of 2,048 calls each, 30,720 encounters and 22,528 taken branches per
instrumented arm, and 352 exact q64 stops (288 inner, 64 outer). Every result and
full clock/canary must match. Two actual wrong-site/count replies must refuse
before refill. One child forked before batch admission must refuse the inherited
lease with no generated entry or clock mutation. Finish owner mismatches are
covered by unit controls; no live-batch fork is accepted.

Raw logs and binary witnesses stay under `ignored/`. After execution, compact
JSON/CSV outcomes will record exact revision, hardware, command, CPU reservation
and load. The ordinary oracle and new cohort each run once, with every failure
retained and no replacement attempts. This is correctness qualification only;
ptrace prefixes do not establish full state after callbacks or executable
reclamation.

Reproduce from a clean committed checkout using the tracked script, a direct
Rust toolchain and a new private output directory:

```sh
BATCH_REV=$(git rev-parse HEAD)
BATCH_TAG=li2-owned-clock-batch-v1
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
