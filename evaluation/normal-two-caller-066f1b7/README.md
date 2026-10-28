# Two ordinary calling threads share one installed function

Revision `066f1b76bb5ba9ac54514907ebce5661ad74b754` adds a distinct two-caller
normal profile and `ordinary-interval normal-session-two`. Both application
threads attach before either starts ordinary C ABI calls. They share the
installed function and epochs while retaining separate pending-return custody,
checkpoints, journals and registrations. External CALL IDs are assigned round
robin; FLUSH acknowledges both workers, and STOP drains and joins both.

Release qualification passed on an **AMD EPYC Zen 5 dev host**, family 26,
model 17, stepping 0, with Rust 1.97.1/GCC 11.5.0. The build uses opt3/debug0
with assertions and overflow checks. Four CPUs were cooperatively reserved
with hard AllowedCPUs enforcement; this is not exclusive host access.

| Case | Calls | Admitted / retained / dropped | Unsampled | Arms / actions |
| --- | ---: | ---: | ---: | ---: |
| Full K10 | 40 | 18 / 18 / 0 | 22 | 520 / 521 |
| Full K1000 | 40 | 40 / 40 / 0 | 0 | 520 / 521 |
| Requested stop | 64 | 10 / 10 / 0 | 54 | 1 / 2 |
| Output backpressure | 1,024 | 22 / 20 / 2 | 1,002 | 520 / 521 |

All 1,168 positive calls are accounted for: 90 admitted, 88 retained, two
dropped and 1,078 unsampled. Both full cases reach history prefix 513 on both
workers and complete five flushes each. Backpressure withholds stdout reads
for 250 ms and observes 72,078 EAGAIN writes; this polling counter is not a
performance score. Every positive case detaches and actually joins both workers.
Duplicate-ID and partial-EOF cases produce their required exit-1 refusals.
All six producer children and twelve stage helpers close normally with ECHILD
and zero rescues. The CSV preserves every case, including refusal outcomes.

Three fresh native processes additionally pass K1 completion with each worker
first, and E4 storage exhaustion/recovery while actual worker-local closed
receipts retain their owners. These check retained and dropped payloads,
foreign receipt refusal, local confirmation and actual worker joins. All four
SDK, six consumer and fifteen parser controls pass. Report closure and local
admission/completion order are checked without imposing cross-worker output
order. Complete guarded inputs, all 512 journal words, absolute history and
Reports remain checked; the external projection independently joins every
intended request and both dispositions.

The fresh single-caller prerequisite passes all six cases. Its separate native
oracle repeats 17 pairs/34 children, 4,044 full-state comparisons with zero
mismatches, 696 input-byte checks, 68 target CALLs/RETs and 34 outer returns.
Its functional and abandonment cases, plus named/selected/gated prerequisites,
remain mandatory. These state comparisons cover those fixed calls, not every
two-thread interleaving or external request. Compact prerequisite CSVs are
included; raw captures and source manifests remain ignored.

Two earlier complete attempts remain FAILED: `5d541db` stopped at an inherited
admission namespace census; `7378cd3` passed its first native control but the
wrapper rejected libtest's singular header. The corrections preserve all old
method names and exact counts, and require the new namespace separately.
Development Clippy and fixture-header failures are also recorded. No deadline,
comparator or population was relaxed, and no failed attempt supplies a missing
case in this successful qualification.

All seven checks pass at the same revision with four compiler jobs and full
316-CPU affinity/default libtest parallelism: workspace **2,992 passed, zero
failed, 36 ignored** in 335.7 seconds; serial launch 1,039 passed; staged
allocation three and prefixed pun 36. Formatting, strict workspace Clippy and
all-target/all-feature compilation pass. All seven historical exec-admission
and allocation regressions are present and pass. The three new native tests
are ignored by ordinary libtest and are mandatory separate processes above.

This supports **claim 4: systematic validation** of the explicit E4/T2/D1
normal profile for one trusted complete 5–80-byte read-only scalar leaf.
The subject is unchanged FreeBSD strnlen (41 bytes, both RETs). Code owners
remain process-lived. The controller's timed phase can occupy one CPU; its
original 10 ms period, 2 ms lateness and strict shutdown checks remain.
Raw ticks are uncalibrated. This establishes no throughput, timing accuracy,
real-time, arbitrary thread/unwind/unload/application or complete-A5 claim.

Reproduce at the exact revision with a new absolute output under `ignored/`:

```sh
$PYTHON -B tools/rapid-profiler/verify_normal_session_two.py \
  --revision 066f1b76bb5ba9ac54514907ebce5661ad74b754 \
  --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
$PYTHON -B evaluation/admission/check_exec_identity.py \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/NEW_GATES" --checks-only
```

The receipt records the exact reservation prefix, compiler/source/artifact
identities, stage commands, hardware, bounds and failed attempts. The workspace
receipt keeps exact commands, aggregate terminal counts and private log hashes.
Public files contain summarized results, with no raw logs or host paths.
