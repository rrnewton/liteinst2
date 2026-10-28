# External requests through ordinary instrumented calls

Revision `d62d332eaa1b9cc95c02021345c7765f13a41715` adds a finite external-input
session around the admitted, unchanged FreeBSD `strnlen` body. A calling thread
attaches once, makes ordinary C ABI calls, and checkpoints returned work. The
controller independently rearms sampling, drains absolute history beyond 512
actions, and handles CALL, FLUSH and STOP with bounded queues and output.
No per-call SDK invocation is required.

The release qualification passed on an **AMD EPYC Zen 5 dev host** (family 26,
model 17, stepping 0), Rust 1.97.1 and GCC 11.5.0. Four CPUs were cooperatively
reserved with hard AllowedCPUs enforcement; this does not establish exclusive
host access. The controller actively waits during the timed phase and can
occupy one CPU. Every original 10 ms arm, 2 ms lateness check and strict shutdown
deadline remains enforced. This is functional validation, with no throughput,
low-overhead, scheduling-accuracy or real-time guarantee.

| Case | Calls | Arms / actions | Sampled / unsampled | Result |
| --- | ---: | ---: | ---: | --- |
| Full K10 | 40 | 520 / 521 | 18 / 22 | Complete, five flushes |
| Full K1000 | 40 | 520 / 521 | 40 / 0 | Complete, five flushes |
| Requested stop | 64 | 1 / 2 | 10 / 54 | Complete, explicit stop |
| Output backpressure | 1,024 | 520 / 521 | 20 / 1,004 | Complete, one flush |
| Duplicate ID | — | — | — | Required refusal, child exit 1 |
| Partial line at EOF | — | — | — | Required refusal, child exit 1 |

Both full cases include zero bound, early/final/absent NUL, 4,096-byte input and
calls after history prefix 512. Backpressure withholds stdout reads for 250 ms
while continuing request writes; 72,118 actual EAGAIN writes were observed
before finalization. This count depends on polling and is not a performance
score. All four positive cases detach and actually join the worker. All six
producer children and nine stage helpers were normally reaped with zero rescues.
The complete intended request population, scalar results, guarded inputs,
512-word journals, history, acknowledgement ownership and Reports are checked.
Raw ticks retain unavailability and are not calibrated application durations.

Eleven producer controls, ten session controls and seven Schedule controls pass.
The fresh native prerequisite repeats 17 original/instrumented pairs, 34
children, 4,044 full-state comparisons with zero mismatches, 696 input-byte reads,
68 target CALLs, 68 target RETs and 34 outer returns. Its separate consumer keeps
8 original and 8 installed calls and both pending-owner abandonment cases.
The native oracle retains its original 15-second / 20,000-step bounds and covers
its fixed calls; it does not trace every external session request. Existing
named, selected and gated whole-function prerequisites also run unchanged.

Three preceding full qualification attempts failed at a poll deadline, after
130, 62 and 327 arms. Reserving CPUs and then introducing a pre-due guard did
not eliminate sleep overruns. A prospectively fixed five-run diagnostic cohort
failed in all five cases: requested waits of at most 1 ms lasted 2.8–15.9 ms.
The guarded attempt later observed 32.25 ms for a requested 1 ms sleep. These
observations identify the wait interval, not an OS cause. All failures and the
one preceding successful diagnostic run remain in the receipt. The final source
uses fixed-target active waits instead of timed-phase sleeps; it still refuses
excessive preemption or work latency. Shutdown keeps the original sleep policy.
No failed attempt was reclassified or substituted into the successful run.

This supports **claim 4: systematic validation** of the finite session. It keeps
one calling thread, depth one, an explicitly trusted complete read-only scalar
leaf, ordinary matching CALL/RET and continuous source/input custody. It does
not establish general application, multithreaded, unwind, unload, browser,
independent accuracy or full A5 coverage. Code owners remain process-lived.

Reproduce at the recorded revision, with a new absolute output under `ignored/`:

```sh
$PYTHON -B tools/rapid-profiler/verify_normal_session.py \
  --revision d62d332eaa1b9cc95c02021345c7765f13a41715 \
  --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

The receipt records the exact optional `cpuset-alloc` prefix and tool revision,
all compiler/source/artifact identities, commands, hardware and failure lineage.
The recipe accepts the caller's permitted CPU set and uses four CPUs. Resource
selection cannot guarantee deadlines on a shared host. `sessions.csv` retains
all six case outcomes; `normal-pairs.csv` and `normal-rows.csv` retain the fresh
native prerequisite's scalar summaries. `wait-diagnostics.csv` retains every
fixed-cohort failure. Raw captures, source manifests, private paths and logs
remain ignored.

The diagnostic runs used `tools/rapid-profiler/normal-work/session_driver.py --mode full --k 10`
at revision `8e7144c8a63a00638061956bdb5ef92c628c0323`, five sequential invocations
with separate output directories, against the authenticated 41-byte subject
(ELF VA 4096, full ELF SHA256 recorded in the receipt). Each invocation used
`tools/unwind-oracle/bounded_command.py` with 20 CPU seconds, 30 wall seconds
and a 4 MiB file limit. Their numbers are observations, not a promised future
failure rate; the normal native prerequisite builds the subject reproducibly.

All seven checks pass on merged revision `d61bd7c62db4229f61e3891682e699ee5bd94871`, which includes
coordinator main `63642aee94979d2f2b0ac9e84572d7e6fdf70acc`. The 464 qualification
inputs match their measured Git blobs exactly; this is source inheritance,
not a second native run. With 316 available CPUs and default libtest parallelism,
workspace testing passed **2,982 tests, 0 failed, 33 ignored**
in 355.7 seconds. Serial launch passed 1,039; staged allocation
and prefixed pun passed 3 and 36. Formatting, strict workspace Clippy and
all-target/all-feature compilation passed. The seven historical exec-admission
and allocation regressions are present and pass. No thread-count reduction or
new skip was used. `workspace-checks.json` records commands, totals and hashes.

```sh
$PYTHON -B evaluation/admission/check_exec_identity.py \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/NEW_GATES" --checks-only
```
