# Software-clock SPSC experiment

At merged revision `73d1830bb83bb8ecca813d9f55e1fc8a6a254f6e` on the AMD EPYC
Zen 5 dev host, both channel and SPSC profiles passed the fixed six-command
release population. Each completed 28 gate pairs / 56 children, 96 stop cells,
256 parked checks, 48 repeated sequences and 108 timing rows. All three separate
fatal controls passed with exact actual-cause witnesses and exit 123. Focused
checks passed 32 Rust tests, 394 Python controls and Rust 1.85 compilation.

The repair retains the exact main-only publication guard. After each successful
join, it waits under one two-second cleanup deadline for that worker's actual
returned TID to disappear. Unknown tasks, malformed observations and late
completion refuse. This observation is outside the unchanged measured work loop.
The earlier failed channel qualification below remains FAILED; its extra TID
was not recorded, so the historical task's identity remains unknown.

Median wall nanoseconds per work unit (seven measurements after two warmups):

| Function | Native (SPSC cohort) | Counter (SPSC cohort) | Channel stop | SPSC stop | Channel / SPSC stop |
|---|---:|---:|---:|---:|---:|
| countdown-jnz | 0.569 | 2.731 | 206.469 | 83.997 | 2.458 |
| signed-jg | 0.561 | 2.707 | 217.628 | 95.140 | 2.287 |
| unsigned-jb | 0.581 | 1.865 | 240.407 | 88.107 | 2.729 |
| direct-jmp | 0.609 | 1.797 | 225.620 | 79.226 | 2.848 |

This one fixed ordered pair used the same release binary and reserved CPUs
159, 193, 230, 267. The stop medians were 2.287–2.848 times faster with SPSC.
These observations are not a general speedup bound: native channel/SPSC ratios
ranged 0.987–1.413, and counter ratios 0.688–1.580. CPU consumption was not measured;
spinning may use more CPU. There was no endpoint-specific CPU pinning. The
strict 2 ms consumer campaign remains **one PASS / four FAIL**.

[All 216 raw timing rows](measurements-73d1830.csv) and
[compact release/focused receipts](results-73d1830.json) retain both complete
cohorts, every command, build/source/product hash, reservation and load average.
Reproduce with the command below at revision 73d1830, first the fatal profile,
then channels, then SPSC, each once in a fresh directory under one four-CPU
reservation. No command/resource bound, work denominator or comparator changed.
The failed b4 attempt is separate and is never substituted into this pair.

[Merged-tree validation](validation-73d1830.json) passed fmt, strict Clippy,
all-feature/all-target check, parallel workspace (**3,824 passed, 0 failed,
37 ignored**) and serial launch (**1,039 passed, 0 failed**). The workspace used
16 disjoint reserved CPUs and 316 test threads, completing in 805.818 seconds
within its unchanged 900-second limit. All 117 named prior regression cases and
six additional exec-admission/deadline cases passed; three filtered child
summaries receive no credit in the workspace total. All closures record complete
cleanup and zero rescued descendants. These checks ran at the exact source
revision above; later evidence-only commits do not change that tested source.

## Earlier b4 attempt, retained
Revision `b4bb411157c66f10733285d66d2141f3a9d0eb7e`, AMD EPYC Zen 5 dev host.
The new single-producer/single-consumer handoff passed all six release commands:
28 gate pairs / 56 children, 96 stop cells, 256 parked-state comparisons,
48 repeated stop sequences and all 108 timing rows. Three separate rejection
controls passed with actual exit 123 and exact callback cause witnesses.
Focused validation passed 25 Rust tests, seven Python witness controls and the
Rust 1.85 compatibility check.

The fixed channel-then-SPSC comparison used the same four reserved CPUs. The
channel cohort FAILED qualification: the unchanged publication guard observed
two `/proc/self/task` entries after worker join. The extra TID was not recorded,
so its ownership is unknown. Its four benchmarks remain UNRUN. This run provides
no matched transport speedup result; no failed result was replaced by a retry.

SPSC median wall nanoseconds per work unit, seven measurements after two warmups:

| Function | Native | Counter only | Stop/resume, quantum 64 |
|---|---:|---:|---:|
| countdown-jnz | 0.581 | 1.818 | 80.465 |
| signed-jg | 0.582 | 1.828 | 79.405 |
| unsigned-jb | 0.560 | 1.847 | 78.757 |
| direct-jmp | 0.617 | 1.750 | 91.676 |

Every timing row runs 128 calls of 256 iterations, 32,768 work units and exactly
510 stop/resume handoffs in stop mode. Timing includes callback/controller work
and scheduling, excludes thread creation/join and publication, and contains no
intentional parked delay. The four CPUs are a reserved process affinity set;
individual endpoints are not pinned separately. Busy spinning may consume more
CPU. These wall measurements establish no CPU-cost reduction or general latency
bound. The earlier strict 2 ms consumer campaign remains one PASS / four FAIL.

[Raw timing rows](b4bb411-spsc-measurements.csv), [exact compact receipts](b4bb411-results.json)
and [focused checks](b4bb411-controls.json) retain every outcome, revision,
commands, build flags, binary/source hashes, CPU reservations, load averages and
limits. Logs and captures stay ignored. Public paths use `$ROOT`, `$TOOLCHAIN`,
`$MSRV_TOOLCHAIN`, `$USER_HOME` and `$CARGO_HOME` substitutions.

Reproduce from the clean stated revision using
[`evaluate.py`](../../tools/software-preemption/evaluate.py), first with
`--profile inline-clock-spsc-fatal-v1`, then the fixed ordered pair
`--profile inline-clock-v1` and `--profile inline-clock-spsc-v1`, each once with
fresh ignored output. Supply the exact path arguments recorded in the receipts:

```sh
python3 -B tools/software-preemption/evaluate.py --repo "$PWD" \
  --raw "$PWD/ignored/clock-new" --toolchain "$LI2_TOOLCHAIN" \
  --user-home "$HOME" --cargo-home "$CARGO_HOME" \
  --profile inline-clock-spsc-v1
```

Use a disjoint four-CPU reservation for the complete fixed pair. The evaluator
builds release opt-level 3 with assertions and overflow checks, then retains the
unchanged 60 CPU / 90 wall second / 1 MiB command limits and strict ECHILD cleanup.
Fatal controls have their distinct 5 CPU / 8 wall second limits. A failure leaves
remaining commands UNRUN. Full workspace validation is recorded separately.
This remains four authored call-free functions, not arbitrary ELF coverage or
full-stack qualification after callback entry.
