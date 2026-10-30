# Software-clock SPSC experiment

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
