# Two-function module native-state reproduction

This recipe builds one release oracle, the CSV and length functions in one
localized DSO, and the distinct 123-byte four-call helper. It runs K16 then K1
once each: two seeds × sixteen CSV cases per cohort, with length case i mod 8.
The complete matrix is 64 original/candidate pairs, 128 normal child reaps,
512 target calls/returns and 128 actual outer returns. There are no retries,
warmups or extra priming calls. Each child calls CSV → length → CSV → length.

After source review and the separate workspace checks, use a clean checkout at
the exact reviewed revision inside an externally supplied single-CPU reservation.
The toolchain and home arguments must be canonical absolute directories. OUTPUT
must be fresh beneath an existing directory in this checkout's ignored/ tree;
its basename must also be unused beneath target/evaluation/.

```sh
python3 -B evaluation/ordinary-module-native/reproduce.py \
  --revision "$REVISION" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" --output "$OUTPUT"
```

The runner pins complete tracked source against Git before project imports, then
retains source, tool, compiler-subtool, command, receipt, stream, closure and
artifact hashes. Cargo remains offline and locked, opt3/debug0 with assertions
and overflow checks, four jobs and no incremental build. Exact Cargo JSON joins
the target, manifest, source, executable and profile. No artifact is borrowed
from a different revision or qualification.

Twelve fabricated Python controls precede all native work. The exact complete
calibration inventory retains all 149 prior methods and requires ten additional
module methods. The one existing hardware-stop control remains explicitly
ignored, with its original reason; this recipe does not claim to execute it.
The four existing CallerOwner controls remain mandatory. No older recipe or
control is removed or modified.

The mixed module uses the same explicit flags and source hashes as the functional
module recipe. Complete LOCAL symbol extents and disassembly establish the two
selections without truncation, in either canonical address order on one shared
source page. The helper's complete GLOBAL symbol and disassembly must match all
123 normative bytes and all 40 heads. Trusted complete files are pinned before
separate-inode candidate copies and before either native invocation. The source
revision also pins the native owner, loader, runtime and full comparator.

Each K cohort retains its unchanged 510-second owner bound and CPU480 seconds
per process, 1 MiB FSIZE and CORE0. The limit/redirect branch checks inherited
limits, creates exclusive separate streams, and execs in the same PID. Every
pair still has its continuous 15-second deadline and each child's 20,000-step
ceiling. These limits are not measurements. A separate root owner may bound the
whole recipe at 1,200 seconds; that does not extend any inner bound.

Both cohort rows exist as UNRUN in the initial plan. Each only launch records
FAILED with attempts=1 before invoking the owner. Failure stops later cohorts;
partial bytes remain private. Completed files acquire one original pin, which
cannot be refreshed during finalization. Uncertain cleanup prevents output
reads. A complete table or printed terminal cannot override an actual nonzero
exit, failed deadline, source drift or incomplete cleanup. A host failure may
prevent final receipt publication, so external ownership remains necessary.

For each cohort the strict parser retains the exact 39-column/32-row pair table,
12-column/two-row coverage table and complete terminal. It joins all input/scalar,
canonical-index, four-call, comparison, step, repeated-read and RET counts. CSV
head/edge coverage is descriptive; length coverage must equal its complete
reachable CFG. Full state/XSAVE, source/input/stack, function-aware journal/Report
and actual call/return/reap checks remain authenticated native-source authority;
the exported tables do not replay those checks or independently record child
PIDs. This qualifies only the selected bodies under this helper. It supplies no
Rust application-caller state, opposite first-direction, timing, accuracy,
performance, arbitrary-module or full-A5 qualification. All proposal controls
and native execution remain UNRUN until the root performs them.
