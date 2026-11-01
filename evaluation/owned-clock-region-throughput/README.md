# Owned two-backedge clock throughput

The fixed 12-process release campaign passed at revision
`2f1637bcbffcb5886d5ccb27807972374def65d0`. Counting costs **29.24× native**
and stopping every 64 taken backedges costs **491.72× native** on this tiny
36-byte function. These measurements include per-call admission and full
callback/controller checks; they do not isolate the clock gate's cost.

| Arm | Mean ns/call (95% CI) | Paired time ratio (95% CI) |
| --- | ---: | ---: |
| Native | 6.656 (5.982–7.331) | 1× |
| Counter | 192.774 (186.415–199.133) | 29.240× (26.203–32.628) |
| Stop q64 | 3241.257 (3144.477–3338.036) | 491.718× (440.128–549.355) |

Absolute means use 12 process means. Time ratios are geometric means of the
12 paired process ratios, with Student-t intervals on their logarithms (df 11).
Batches are not independent process samples. Every timing and outlier remains
in the CSV files; there were no replacement runs or performance thresholds.
See [statistics.json](statistics.json) and [receipt.json](receipt.json).

The AMD EPYC Zen 5 dev host has 316 logical CPUs. A single external reservation
assigned CPU 136 to the producer, 173 to the controller and 226 to the worker.
Load averages were 90.41/75.81/68.78 before and 97.84/78.15/69.66 after the
campaign. All 12 owned processes exited normally with complete cleanup and
zero rescued descendants. All 2,448 rows passed: 36 untimed qualifications,
108 warmups and 2,304 measured batches. The 24 actual wrong-reply child controls
also passed. The unchanged prerequisite oracle passed 192 full-state comparisons,
six parked stop checks and two wrong-reply child controls at the same revision
and release-binary hash.

The 36-byte nested-loop function returns 12. Each call encounters 15 branches
and takes 11 backedges. Native makes ordinary indirect calls to the original
body. Counter and Stop use the same verified whole-region relocation with two
clock gates, one exclusive lease per batch and one call guard per call.
Each batch makes 2,048 calls: 30,720 encounters, 22,528 taken backedges and checksum
24,576. Stop performs exactly 352 handoffs: 288 at the inner site and 64 at the
outer site. Each handoff authenticates the site, count, managed control, PID and
TID, preserves the saved 18-word context and full clock canary, and refills only
the remaining quantum. There is no artificial parked delay.

Each process qualifies all three arms and exercises actual wrong-site and
wrong-count replies in fresh children before timing. Each arm then has three
warmup and 64 measured batches. All six arm orders occur twice, shuffled once
with seed `20261101`. Each process retains its 204 rows in `cohort-NN/`, including
qualification and warmup. Raw logs and binary witnesses stay private; their
hashes and the decoded rejection CSVs are retained.

The worker timer starts after a bounded Ready/Go exchange, once affinity,
lease acquisition/reset, TLS setup and controller thread creation are complete.
Timing includes indirect calls, per-call guards, checksum bookkeeping, callback
checks and real controller handoffs/scheduling. Mapping, startup, lease
acquisition, final verification, thread join and CSV writes are outside timing.
The existing two-second handoff deadline remains enforced. Each cohort has
60 CPU seconds, 90 wall seconds, 1 MiB per-file/capture limits and core files
disabled. The process owner has a separate three-second cleanup budget.

To reproduce, check out the measured revision, select the recorded direct
Rust toolchain binaries on `PATH`, and run from the checkout with fresh output
directories. Python must support `-I -B`; the recorded version is in the receipt.
The allocator must reserve disjoint CPUs and retain the reservation for the
whole command. The first command is correctness validation; the second builds
with `--release --locked --offline -j 3` and executes the fixed campaign.

```sh
REGION_REV=2f1637bcbffcb5886d5ccb27807972374def65d0
REGION_ORACLE="$PWD/ignored/region-throughput-oracle-new"
REGION_OUTPUT="$PWD/ignored/region-throughput-new"
mkdir -p "$PWD/ignored"
cpuset-alloc run --cores 12 --tag region-throughput-oracle -- \
  python3 -I -B evaluation/owned-clock-region/reproduce.py \
  "$REGION_REV" "$REGION_ORACLE"
sha256sum "$REGION_ORACLE/closed.json"
# Use that actual SHA as ORACLE_CLOSED_SHA below.
cpuset-alloc run --cores 3 --tag region-throughput -- \
  python3 -I -B evaluation/owned-clock-region-throughput/run.py \
  "$REGION_REV" "$REGION_OUTPUT" "$REGION_ORACLE/closed.json" ORACLE_CLOSED_SHA
```

The runner checks the exact revision, source, scripts, tools, prerequisite and
release binary before and after owned work. It retains every failed or incomplete
cohort without replacement. The standalone [summarizer](summarize.py) accepts only
a SHA-pinned closed campaign and revalidates every row and witness before
calculating statistics. [Full validation](validation.json) of merged revision
`7cb04528f15bffcfce51d19a97b29cdd96b47493` passed 4,393 workspace tests (39 ignored),
three controlled child tests and 1,039 serial launch tests, plus formatting,
strict Clippy and all-target/all-feature compilation. The initial focused
Clippy failure and zero-dispatch revision typo remain recorded in
[the first validation receipt](validation-first.json). The [earlier merged gate](validation-merged-first.json)
is also retained. The merge preserves all
Rust/Cargo/benchmark inputs from the measured revision; the performance campaign
was not rerun or relabeled.

This fixture cannot establish general application throughput, production
publisher performance, a deadline guarantee or full machine state after a
callback. It exposes the cost of this explicit call-guard and handoff protocol.
