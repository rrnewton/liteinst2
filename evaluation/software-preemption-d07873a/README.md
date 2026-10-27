# Taken-backedge software preemption

At revision `d07873afaef7c0adafc31dff2adc8172ff4db0b0`, a real managed observing trampoline stopped four authored loops at exact taken-backedge quanta and resumed them without changing the saved context. All 96 stop/resume cases passed: 256 parked checks, 48 repeated ordered stop projections, 16 native cells, 16 counter cells and 512 independent hardware SETcc checks. This supports claim 3 for the finite corpus.

The clock stops **before** the counted taken branch executes. Conditional branches that are not taken consume no quantum. This increment handles one selected near back edge in each private call-free function; it does not instrument arbitrary executables or promise progress through calls or indirect transfers.

Release results on the AMD EPYC Zen 5 dev host, median of seven repetitions after two warmups:

| Loop | Native ns/iteration | Counter ns/iteration | Stop/resume ns/iteration | Counter/native | Stop/native |
|---|---:|---:|---:|---:|---:|
| Countdown/JNZ | 0.579 | 355.921 | 428.131 | 614.9× | 739.6× |
| Signed/JG | 0.578 | 361.239 | 434.730 | 625.0× | 752.2× |
| Unsigned/JB | 0.599 | 356.978 | 431.086 | 595.9× | 719.6× |
| Direct/JMP | 0.613 | 361.663 | 459.988 | 589.6× | 749.9× |

Each repetition performs 128 calls of 256 iterations. Stop/resume uses a quantum of 64 taken back edges, giving 510 stops per repetition. Timing includes the work, full-state callbacks and controller scheduling; it excludes publication and thread creation. The benchmark has no deliberate parked delay or ptrace. These tiny loops expose the callback cost; the numbers establish a baseline for a future generated counter fast path, not production performance.

[measurements.csv](measurements.csv) retains all 108 raw timing rows, including warmups. [qualification.csv](qualification.csv) and [stops.csv](stops.csv) retain all qualification rows. [receipt.json](receipt.json) records exact revision, binary digest, build flags, commands, hardware, limits of the state checks and data hashes. Rust release optimization is level 3, with assertions and overflow checks enabled. The repeated-run state comparison is the stated register/flag projection; the separate check across each parked wait compares all 18 saved context words. This fixture does not add an independent XSAVE/full-application-stack oracle.

Use the [reproduction recipe](../../tools/software-preemption/README.md#build-and-run) from a checkout containing `evaluate.py`. It builds and runs the same fixed experiment and keeps detailed host-specific records under `ignored/`. The wrapper was added after this measured revision and was source-reviewed; it was not used for this historical run. The recorded run used the same `run.py` five-command driver after an independently checked release build. No compiler or native failure was retried in this cohort.
