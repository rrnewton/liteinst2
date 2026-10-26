# Finite original-signal admission validation

The complete recorded protocol passed on source
`e4d13229b57b265ded61364d6c4f7bd25629aa77`. This qualifies the finite signal
profile described in [the protocol](b3-signals.md), not the complete B3
lifecycle and real-application milestone.

The [machine-readable result](results/20261026T100231.311828Z-e4d13229b57b.json)
has SHA-256
`097a31a60a003f13a52fd52b4382c4b63eba4026de0c164004993268982b477d`.
It records all six commands, 458 source identities, hardware/toolchain,
configuration observations, capture hashes and cleanup. Source and configuration
were unchanged throughout. Every command exited zero, completed cleanup and
reported zero adopted descendants. Raw captures remain private.

## Reproduction and environment

From a clean checkout of the exact source revision:

```sh
python3 evaluation/admission/run.py --expect-revision e4d13229b57b265ded61364d6c4f7bd25629aa77
```

The runner uses four build jobs, four workspace test threads, serial libtest
execution, disabled incremental compilation and the original command/output/cleanup
bounds. Hardware was AMD EPYC 9D85, family 26, model 17, stepping 0, microcode
`0xb101066`, x86-64, with 316 visible logical CPUs. Linux upstream version was
7.1.3; the receipt records the complete release hash. Execution was non-root
with effective capabilities zero. Rust and Cargo were 1.97.1. These results
cover this hardware/ABI; they do not establish Intel or CET coverage.

| Required command | Result | Seconds |
| --- | --- | ---: |
| Recorder calibration | 208 passed | 7.903 |
| `cargo fmt --check` | passed | 1.665 |
| Workspace/all-target/all-feature Clippy, warnings denied | passed | 0.320 |
| `cargo test --workspace` | 1,318 passed, 0 failed, 4 unchanged ignored; 77 harnesses | 296.810 |
| Workspace/all-target/all-feature `cargo check` | passed | 6.240 |
| Serial launch integration/unit oracles | 484 passed, 0 failed; 25 harnesses | 75.716 |

These elapsed times describe validation commands, not benchmark performance.
Workspace outer totals exclude five completed nested tests and two child starts
without completion summaries. The exact parser keeps these observations separate.

## Signal observations and controls

All five named signal fixtures passed in both workspace and serial runs:
ordinary stack, application-configured alternate stack, edited return to an
untouched NX page, inherited nonzero exception metadata, and comparator
corruption calibration. The four trajectories compare complete GPRs, flags,
XSTATE, masks, initialized data and stack ranges, signal information and frames
against independently launched pristine executions. Comparator calibration is
not an additional instruction sample.

The inherited-history fixture requires a real predecessor page fault and an
exact typed inner completion after assertions and both physical cleanups;
child exit zero alone is insufficient. Production retains the actual kernel
frame separately from the application-visible projection of exactly the three
trap/error/CR2 words. Saved alternate-stack flags are checked against the
original authenticated frame; the reference independently establishes its own
pre-exec flags. No stack-field normalization is used.

The real `rt_sigreturn` ENTRY and EXIT retain full state. The historical EXIT
identity remains unchanged; current rearmed state must have exactly one later
generation and otherwise match completely. The edited trajectory preserves
an errno-looking RAX as register state and requires a new fetch fault before
executing its declared untouched landing page.

Eight separate native reset/ownership failure controls passed in both runs.
They cover failed packet transfer, helper death before/after clone, absent PID
handoff, reaper discovery before its first stop, the original deadline, injected
pin allocation refusal and cancellation before START. They do not count as
application signal trajectories. The additions also include 56 pure Rust
controls and eight recorder calibrations. All original cases remain required.

The serial receipt retains the previous 50 static instruction cases, 15 dynamic
admission fixtures and 388 dynamic instruction-matrix cases. Its 36 separately
named validation outcomes comprise 17 kernel-journal, six B2 reference, eight
reset and five signal outcomes. These overlapping cohorts are not added into
a new aggregate instruction count.

## Preserved failures and scope

Seven earlier failed attempts remain unchanged in tracked JSON:

| Source | Receipt | Observed failure |
| --- | --- | --- |
| `57a9e013474a` | [attempt 1](results/20261026T092553.845869Z-57a9e013474a.json) | Compile/Clippy gate before native qualification |
| `6fa5eab7c201` | [attempt 2](results/20261026T092716.981591Z-6fa5eab7c201.json) | Compile/Clippy gate before native qualification |
| `0d1bfb4cd483` | [attempt 3](results/20261026T093056.623561Z-0d1bfb4cd483.json) | Compile/Clippy gate before native qualification |
| `22a87c171f80` | [attempt 4](results/20261026T093239.470712Z-22a87c171f80.json) | Original signal setup journal refused |
| `c355f6693cd1` | [attempt 5](results/20261026T093929.244584Z-c355f6693cd1.json) | Full-stack request exceeded the per-request memory bound |
| `7525d23cb324` | [attempt 6](results/20261026T094208.421346Z-7525d23cb324.json) | Saved stack flags and historical/current generation mismatches |
| `319efef9c94a` | [attempt 7](results/20261026T095721.067788Z-319efef9c94a.json) | Checkpoint exec returned ETXTBSY after the signal cohort passed |

No failed attempt qualifies through partial results. Corrections retained
assertions, fixture identities, complete comparisons, resource limits and
deadlines. The checkpoint correction excludes executable-file writers from
fork windows while retaining concurrent launches; the failed capture did not
identify the specific inherited descriptor holder. It adds no error retry.

This cohort supports finite evidence for page admission (claim 1), selected
instruction interception at signal entry (claim 2), and systematic validation
(claim 4). It measures no preemption clock (claim 3) or signal throughput.
Nested/general signals, syscall restart, synchronous exceptions, arbitrary
thread/fork/exec combinations, mapping churn, dlopen, JIT/alias paths and real
application/browser coverage remain outside this signal profile. Full B3 and
B4 remain open.
