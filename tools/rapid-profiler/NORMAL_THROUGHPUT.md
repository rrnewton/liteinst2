# Ordinary-module elapsed-time comparison

`normal-work/throughput_probe.py` compares native and always-on observation of
the same ordinary module. Each fresh process makes 3,072 target calls through
1,536 helper invocations, in 128 blocks of 24 calls. The target executes 614,400
specified instructions. Those instruction counts exclude the helper, observer,
validation and timing code.

The fixed experiment has five pairs, ordered native/always-on, always-on/native,
native/always-on, always-on/native, native/always-on. It has no warmup calls in
the measured processes, retries, adaptive repetitions or performance threshold.
A fresh release qualification precedes the experiment; this does not establish
cold host caches. All scheduled outcomes are retained, including failed and
unrun trials. This does not replace or qualify prior strict 2 ms deadline results.

The collector preserves the existing per-call functional transcript and all
source, input, result, journal, checkpoint, report and history checks. An
independent Python checker validates that transcript and the timing appendix.
Successful transcript parsing alone does not establish physical execution or
process ownership; the runner joins the source, executable, selection, process,
CPU and bounded-owner records.

| Observation | What it includes |
| --- | --- |
| Setup | Module loading and preparation after argument checks and CPU pinning, through initial custody checks and preallocation. |
| Segmented call path | Sum of all 128 block spans. Includes the unchanged helper wrapper, loop and stores, and its PID, target and sum checks. Installed blocks also include 23 next-entry confirmations. |
| Validated service | First block start through final workload and custody checks; also includes all checkpoints, transfers, detach, disarm and report/history validation for always-on. Includes gaps between blocks. |
| Whole process | Separate timer observation from immediately before `fork` through immediately after `wait4`, including inner `taskset`, initialization, encoding, output and teardown; also reports child user/system CPU time from `wait4`. |

The first three observations use `CLOCK_MONOTONIC_RAW`; whole-process wall time
uses `CLOCK_MONOTONIC`. Their absolute timestamps must not be compared. All wall
times include descheduling. No overhead is subtracted, and zero durations remain
unresolved denominators. Segmented time is not uninterrupted application
throughput or the complete cost of the observer. Service excludes setup, timing
metadata validation, encoding and subsequent owner teardown. These observations
do not establish interval accuracy, statistical confidence or full A5 coverage.

Run from a clean committed checkout with the Rust toolchain and dependencies
already available. `RUST_TOOLCHAIN` and `CARGO_HOME` must name absolute directories.
Reserve four CPUs for the complete command with
`cpuset-alloc`; the producer uses the first sorted CPU, the application the
second and the external timer the third after qualification. Builds and
prerequisites use the four reserved CPUs. Neither the cooperative reservation
nor the recorded load average proves a scheduler-quiet host.

```sh
cpuset-alloc run --cores 4 --sample-s 1 --tag li2-throughput -- \
  python3 -B tools/rapid-profiler/normal-work/throughput_probe.py \
  --revision "$(git rev-parse HEAD)" \
  --raw "$PWD/ignored/throughput-run" \
  --toolchain "$RUST_TOOLCHAIN" --user-home "$HOME" \
  --cargo-home "$CARGO_HOME" --reservation-tag li2-throughput
```

The raw destination must be new. Bind the exact outer command and allocator
transcript to the result; `--reservation-tag` is an identity label, not proof of
reservation. Keep raw logs, paths and functional transcripts private. Publish
the exact revision, hardware description, command with portable path variables,
reservation CPUs, loads, every trial outcome, every available timing endpoint
and pair ratios. The pair ratio is always-on elapsed time divided by native
elapsed time. For identical fixed work, the always-on/native throughput ratio is the reciprocal
when both times are positive. Only pairs with two valid members and positive
native denominators receive elapsed-time ratios. A shared-source or ownership failure stops later
trials explicitly; a fully closed independent functional failure is retained
while the remaining fixed trials continue.
