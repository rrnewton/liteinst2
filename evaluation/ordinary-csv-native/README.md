# CSV native-state reproduction

This recipe builds one release oracle and the CSV target plus the existing
67-byte ordinary C caller. It runs one fixed CSV qualification: two seeds ×
sixteen records, 32 original/candidate pairs, 64 normal child reaps, 128 target
calls/returns, and 64 actual outer returns. There are no retries or warmups.

After source review, run from a clean checkout at the exact reviewed revision
inside an externally supplied single-CPU reservation. `TOOLCHAIN`, `USER_HOME`
and `CARGO_HOME` must be canonical absolute directories. `OUTPUT` must name a
new directory directly beneath an existing directory under this checkout's
`ignored/`; its basename must also be unused under `target/evaluation/`.

```sh
python3 -B evaluation/ordinary-csv-native/reproduce.py \
  --revision "$REVISION" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" --output "$OUTPUT"
```

The runner authenticates source against Git before project imports. It uses
offline, locked Cargo, release opt3/debug0, assertions and overflow checks,
four build jobs, and incremental compilation disabled. Cargo JSON must join
the exact executable, target, source, manifest and profile. Trusted complete
ELFs are retained before separate candidate copies. The CSV symbol's complete
extent is derived from the trusted ELF; it is never shortened to fit admission.
The fixed compiler commands include `-z now`; compiler drift that changes the
caller's accepted bytes is a failure.

Nine fabricated Python controls run first. The full source-bound native
calibration census is 149 passed methods plus the one unchanged explicitly
ignored hardware-stop control; four existing CallerOwner controls also run.
These prerequisite validator controls are separate from the single CSV cohort.
No earlier native/reference population or prior result is replaced.

Every pair keeps its original absolute 15-second deadline and each child's
continuous 20,000-step ceiling. The standalone native owner permits 510 seconds
for all 32 sequential pairs, plus the unchanged owner's separate three-second
cleanup budget. The child-exec branch sets and checks CPU480 seconds per process,
FSIZE1 MiB and CORE0, then redirects separate streams and execs in the same PID.
An inherited lower limit refuses. CPU limits are not aggregate CPU measurements.
The historical bounded-command helper remains unchanged; short builds use its
CPU120/wall180/file128 MiB limits and controls use CPU20/wall30/file1 MiB.

`plan.json` initially records the native stage as UNRUN. Before its only launch,
`native-attempt.json` durably records an attempted FAILED state; completion is
accepted only after normal owner closure, unchanged source/artifacts, empty
actual stderr and the complete strict tables. A complete printed terminal
followed by nonzero exit or failed final deadline remains FAILED. Uncertain
custody stops further work and output inspection. SIGKILL or host failure cannot
guarantee final receipt publication; the external root owner remains necessary.

Private commands, environment, build records, artifacts and logs remain under
the fresh output and owner-log directories. `result.json` joins their hashes;
stdout reports only status, attempt count and the result digest. The exact raw
`normal-csv-pairs.csv` and `normal-csv-coverage.csv` are retained, along with all
partial files on failure. No binary or log from an earlier attempt is accepted.
Immutable metadata and completed evidence are pinned once, including requests,
commands, receipts, streams, closure records and both owner-log copies. Those
original pins are checked before dependent stages and immediately before result
publication. Changed or missing pinned bytes make the result FAILED; finalization
does not replace an expected hash with a new observation. Partial failed output
is first pinned only after cleanup, and uncertain custody prevents file reads.

This qualifies the selected CSV body under the existing helper. It does not
qualify the separate functional Rust caller's emitted CALL/store. Complete
register/XSAVE, stack/data/source, journal, Report and reap predicates are
enforced by authenticated native source; the tables do not replay them.
Observed head/edge coverage is descriptive. There is no timing, performance,
arbitrary-module or full-A5 claim. All implementation-proposal controls and
native execution are UNRUN until the root performs them.
