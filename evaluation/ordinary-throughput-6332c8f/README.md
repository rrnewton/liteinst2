# Ordinary-module elapsed-time comparison

At source `6332c8f229833e7f6b9a7c99c9101c410e6cb0cb`, all ten fresh measured
processes completed the same 3,072 calls through 1,536 helper invocations
(614,400 specified target instructions). All five fixed pairs passed their
functional, source, clock, CPU, process-identity and owner checks. The one
qualification completed 34 prerequisite stages plus 8 Rust, 6 checker,
10 runner and 5 timer controls. No measured process was retried or excluded.

Always-on segmented call time was **19.8–21.6 times native**. These spans include
helper checks, loops/stores and installed next-entry confirmations. They do not
isolate hook cost. Whole-process time was lower for always-on in all five pairs,
but the configurations perform different validation work: native invokes
`verify_original()` after every block and at final validation, including file
and mapping provenance checks; installed instead validates checkpoints and
Reports. The measured whole-process ratios therefore **do not establish an
application speedup or pure observer overhead**. No causal cost breakdown was
measured, and no subtraction or correction was applied.

| Pair | Native call path (ms) | Always-on call path (ms) | Call-path A/N | Service A/N | Whole-process A/N |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 0.193 | 4.16 | 21.6 | 0.565 | 0.608 |
| 2 | 0.196 | 4.23 | 21.5 | 0.527 | 0.581 |
| 3 | 0.21 | 4.16 | 19.8 | 0.549 | 0.598 |
| 4 | 0.198 | 4.16 | 21 | 0.493 | 0.535 |
| 5 | 0.194 | 4.18 | 21.5 | 0.565 | 0.606 |

Each ratio is always-on elapsed time divided by native elapsed time for its
fixed pair; the exact body/service numerator and denominator are retained in
[pairs.json](pairs.json). The reciprocal gives the same fixed-work throughput
ratio when both durations are positive. These are observations of the complete
validated configurations, not a production application-throughput score.
Native/always-on order alternated N/A, A/N, N/A, A/N, N/A. There were no warmup
calls in measured processes, adaptive repetitions or performance threshold.
Five pairs do not establish statistical confidence, interval accuracy or full A5.

The AMD EPYC Zen 5 dev host had a 9D85 processor, family 26/model 17/stepping 0,
microcode `0xb101066`, kernel 7.1.3 and 316 available logical CPUs. Rust 1.97.1
built the release collector with opt level 3, debug info 0, debug assertions and
overflow checks enabled, four compiler jobs and incremental compilation off.
`cpuset-alloc` reserved logical CPUs **215, 224, 251, 297** with hard
`AllowedCPUs`; producer/application/timer used 215/224/251. The one-minute load
average at trial boundaries ranged from **107 to 119**. This is not a claim of
quiet or exclusive hardware. All load observations are in
[driver-receipt.json](driver-receipt.json).

[trials.csv](trials.csv) contains every outcome and raw setup, call-path,
service, whole-process and child-CPU total. [timing.csv](timing.csv) retains all
1,300 setup/body/service endpoint rows. Collector timestamps use
CLOCK_MONOTONIC_RAW; the external before-fork/after-wait4 timer uses
CLOCK_MONOTONIC. Their absolute timestamps must not be compared. Wall time
includes descheduling. The full process includes inner taskset, initialization,
output and teardown; service ends before timing metadata validation, encoding
and later owner teardown. Definitions are in
[the collector contract](../../tools/rapid-profiler/NORMAL_THROUGHPUT.md).

The original workspace validation hit its 360-second resource guard and remains
a recorded **timeout**. One separately declared completion pass had a
600-second workspace allowance; it completed in 348 seconds with **3,101 passed,
0 failed, 36 ignored**, plus two custom harnesses. Serial launch passed 1,039;
staged allocation passed 3; prefixed-pun oracle passed 36. Formatting, strict
Clippy and all-target/all-feature compilation also passed. Default workspace
libtest parallelism was unchanged. [checks.csv](checks.csv) retains both
attempts, including the timeout and its two cleanup reaps. The completion
process also carried five recorded Python-startup environment additions; all
explicit Rust profile settings remained exact, with no test-thread override.
The strict 2 ms profiler gate and its earlier outcomes are unchanged.

[development-controls.csv](development-controls.csv) preserves a draft-test
failure: its reordered spans violated Service before the intended Order check.
Only that fixture's service start was corrected; the production validator and
exact Order assertion stayed unchanged. Those draft observations identify a
base plus working-source digest. The committed controls above ran afresh in
the release qualification.

[receipt.json](receipt.json) binds the hardware, exact source, commands, retained
private receipts, review hashes and limitations. [protocol.json](protocol.json)
was frozen before implementation qualification. Raw logs and functional
transcripts remain ignored; the public records total about 100 KiB.

To reproduce, save this script outside the source checkout, use a clean checkout
at the source revision above, and provide an absolute executable
`cpuset-alloc` entry plus absolute toolchain/home paths. The destination must be
new beneath that checkout's `ignored/`. Existing XDG/DBUS session coordinates
may be supplied explicitly for the allocator. The wrapper runs one comparison
with a 1,200-second/8-MiB outer bound and returns normal exit 0 or 1 unchanged.
It was source-reviewed, not launched for a second experiment.

```sh
python3 -B "$REPRODUCE" --repo "$REPO" \
  --raw "$REPO/ignored/throughput-reproduction" \
  --allocator "$CPUSET_ALLOC" --toolchain "$TOOLCHAIN" \
  --user-home "$HOME" --cargo-home "$CARGO_HOME"
```

`REPRODUCE` names [reproduce.py](reproduce.py). Authenticate the actual allocator
and its hard reservation transcript; a tag or successful outer exit alone is
not qualification. The driver retains every failed or unrun outcome and
withholds ratios after shared source or ownership failure. This evidence
supports claim 4's validation and cost accounting; ordinary application
throughput, back-off comparison and the A5 accuracy/release gates remain open.
