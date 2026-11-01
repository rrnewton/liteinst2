# Clock admission throughput

This separately named comparison is **UNRUN**. It compares `native`,
`counter-per-call` and `counter-batch` using the same release binary, the same
36-byte body and one shared Counter image. It predicts no speedup. Existing
native/counter/stop results and failed deadline qualifications remain unchanged.

Each process qualifies all three arms, then runs three warmup and 64 measured
batches per arm. Each batch makes exactly 2,048 calls: checksum 24,576,
30,720 branch encounters and 22,528 taken backedges. Counter arms must finish
with remaining quantum 64, zero callbacks and the full clock canary intact.
Native must leave the clock unchanged. All six arm orders occur twice,
shuffled with seed `20261101`: 12 independent processes and 2,448 retained rows.
There are no replacement attempts, outlier exclusions or performance cutoffs.

The unchanged worker timer starts after its bounded Ready/Go exchange.
It includes the calls, loop/checksum bookkeeping and ordinary admission/drop
or batch admission, precharged tokens, return acknowledgements and finish.
Affinity, clock acquisition/reset and TLS setup precede timing; final checks,
join and output follow it. Both Counter arms use the same generated image.
The batch caller additionally promises no fork, foreign or recursive entry
throughout the entire batch, including host gaps. The measurement compares
these different admission contracts; it does not establish equivalent runtime
enforcement or isolate syscall or gate cost.

The complete old and batch oracles at the same revision and binary are required
before timing: each has 192 full-state comparisons; their exact stops, real
wrong-reply controls and the batch fork-entry refusal remain mandatory. This
Counter-only campaign adds no new Stop, callback or rejection observations.

From a clean checkout at the eventual measured revision, select direct Rust
toolchain binaries and fresh output paths. The external allocator retains
disjoint CPU reservations for each complete command; run them sequentially.

```sh
mkdir -p "$PWD/ignored"
cpuset-alloc run --cores 12 --tag admission-oracle -- \
  env -i HOME="$HOME" PATH="$LI2_TOOLCHAIN/bin:/usr/bin:/bin" LANG=C LC_ALL=C \
  python3 -I -B evaluation/owned-clock-batch/reproduce.py \
  "$ADMISSION_REV" "$PWD/ignored/admission-oracle-new" admission-oracle
sha256sum "$PWD/ignored/admission-oracle-new/closed.json"
# Use that actual hash as ADMISSION_ORACLE_SHA below.
cpuset-alloc run --cores 3 --tag admission-throughput -- \
  env -i HOME="$HOME" PATH="$LI2_TOOLCHAIN/bin:/usr/bin:/bin" LANG=C LC_ALL=C \
  python3 -I -B evaluation/owned-clock-admission-throughput/run.py \
  "$ADMISSION_REV" "$PWD/ignored/admission-throughput-new" \
  "$PWD/ignored/admission-oracle-new/closed.json" "$ADMISSION_ORACLE_SHA"
```

The build uses release optimization, offline locked dependencies, three Cargo
jobs, a 600-second wall bound and 1 MiB capture. Each cohort has 60 CPU seconds,
90 wall seconds, 1 MiB file/capture bounds and no core dumps; the owner retains
a separate three-second cleanup budget. Raw captures remain private and are
read only after owner closure. The receipt records observed affinity and load,
without claiming an independent live allocator witness.

Statistics use 12 process means, each containing all 64 measured batches.
Absolute 95% intervals use Student-t with 11 degrees of freedom. Paired
geometric ratios use the same intervals on log ratios; the primary comparison
is `counter-batch/counter-per-call`. Every row remains available. The scope is
this tiny finite fixture, with no application-throughput, deadline, production
publication or full-state-after-callback claim.
