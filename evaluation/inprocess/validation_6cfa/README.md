# Validation at 6cfa572f2ba8

The accompanying seven-row CSV and JSON report actual outcomes at
`6cfa572f2ba8d2cad10077f3674e0cca5de4a084`. The original required invocation
failed: the recorder exceeded its unchanged 180-second wall limit. A separate
invocation passed the four original Cargo checks and the serial launch suite.
An instrumented recorder run passed all 366 cases in 157.135 seconds. That
diagnostic result does not replace the failed required check. These are
validation durations, with no runtime qualification or performance credit.

The two scripts here are byte-identical copies of the executed private
wrappers. `cargo_serial.py` has SHA256
`b97f3171a601c1553ea00ad7cbe69de66aff1bdfeebabb40d5e415c90ca8c1d3`;
`recorder_timing.py` has SHA256
`62e9991183297baa89f986de2f3fd075eb906aaadd5d73bfafa153ebb36bcfa2`.
Their published locations have not been executed. They invoke the existing
command owners and comparators; neither supplies a replacement test corpus.

Use a dedicated, clean checkout of the exact revision above, Linux x86-64,
Python 3.12 with assertions enabled, and the recorded stable Rust/Cargo 1.97.1
toolchain. Make `python3` on `PATH` resolve to the same executable as
`python3.12`. The diagnostic checks that identity explicitly. The JSON records
the CPU model, microcode, kernel version, ISA digest, affinity and tool versions.
The recorded processor numbers identify the actual reservations; reproduction
requires four reserved CPUs and does not require those same processor numbers.

Before checking out the measured revision, save the two published scripts in
these ignored locations, preserving their bytes:

```sh
mkdir -p target/page-region-next/recorder-current-timing-r1
cp evaluation/inprocess/validation_6cfa/cargo_serial.py \
  target/page-region-next/cargo-checks-6cfa-attempt1.py
cp evaluation/inprocess/validation_6cfa/recorder_timing.py \
  target/page-region-next/recorder-current-timing-r1/run.py
git checkout --detach 6cfa572f2ba8d2cad10077f3674e0cca5de4a084
```

Run each invocation from the checkout root under a separate four-CPU
reservation. For example, with the externally installed `cpuset-alloc`:

```sh
cpuset-alloc run --cores 4 --tag validation-required -- \
  python3.12 -B evaluation/inprocess/checks.py \
  --expect-revision 6cfa572f2ba8d2cad10077f3674e0cca5de4a084
cpuset-alloc run --cores 4 --tag validation-cargo-serial -- \
  python3.12 -B target/page-region-next/cargo-checks-6cfa-attempt1.py
cpuset-alloc run --cores 4 --tag validation-recorder-diagnostic -- \
  python3.12 -B target/page-region-next/recorder-current-timing-r1/run.py \
  --expect-revision 6cfa572f2ba8d2cad10077f3674e0cca5de4a084
```

The wrappers require fresh output directories:
`target/evaluation/inprocess/cargo-checks-6cfa-attempt-1` and
`target/evaluation/inprocess/recorder-current-timing-attempt-1` must not exist.
Preserve earlier results separately rather than overwriting them. The original
required driver creates its own fresh timestamped directory. Its failure stops
that invocation; it does not prevent the two separately labelled invocations.

The unchanged controlled environment fixes Cargo jobs and ordinary harness
threads at four, disables incremental compilation, uses one `target` directory,
and runs the launch suite with one harness thread. The workspace wall limit is
900 seconds; every other command retains 180 seconds and an 8 MiB log bound.
The diagnostic adds per-case timing around the existing recorder's four-worker
execution without changing its discovery or assertions. Complete private
receipt and log hashes are retained in the summary; raw logs are not published.
