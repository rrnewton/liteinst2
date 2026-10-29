# Copied native-oracle batching qualification

Source `cadf5e768eaf3cd898b7070c39b903fcdb22fab0` caches immutable caller
instruction metadata and batches each fresh memory snapshot into one exact
vector read. Every architectural comparison, complete stack/image read, case,
reap requirement and execution bound remains in force. Short reads refuse.
This receipt records the one fixed release qualification; there was no retry.

The qualification **FAILED** its unchanged 510-second cohort wall limit.
The 48-pair prerequisite completed 4,490 full-state comparisons. The larger
cohort retained 791 of 1,280 pair rows and 96,231 comparisons before timeout;
all of that prefix remains `OBSERVED_UNQUALIFIED`. The 489 slots without
accepted results include interrupted work. Cleanup reaped two descendants.
There is no speedup claim or full-cohort architectural qualification.
The [prior timeout](../ordinary-leaf-set-whole-7886d8b/README.md) remains failed.

All prerequisites passed: 199 Rust calibrations plus one unchanged hardware
ignore, one SDK control and 76 Python controls. Of 32 planned stages, 31
closed normally and the final native cohort timed out. The root owner then
closed normally with exit 1 and no additional rescue reap. All 285 retained
files (48,959,717 bytes, including the root records) were authenticated after
closure, including the original build products before later checks. The
summary collector rechecked archived evidence, not mutable build-cache files.

Hardware: AMD EPYC Zen 5 dev host, AuthenticAMD family 26/model 17/stepping 0,
kernel 7.1.3, Rust 1.97.1. Release optimization 3, assertions and overflow
checks enabled, incremental compilation disabled, four compiler jobs.
Hard reservation: CPUs 98/131/177; tracer and tracees on 131. Load moved from
35.14/38.92/37.12 to 40.43/36.42/36.16. Reservation evidence uses authenticated
normal allocator return; no independent ledger readback is claimed.

Reproduce from the exact clean source revision using
[the tracked recipe](../ordinary-leaf-set-native/README.md):

```sh
python3 -B evaluation/ordinary-leaf-set-native/reproduce.py \
  --revision "$REV" --reservation-tag "$TAG" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --raw "$REPO/ignored/NEW_LEAF_WHOLE_NATIVE_RUN"
```

Run inside a fresh hard three-CPU reservation and an external 1,200-second,
8 MiB process owner. `receipt.json` contains the complete command/environment
with named local-path placeholders, allocator revision, tool hashes, protocol
and closed-receipt hashes. The recipe preserves 480 CPU/510 wall seconds per
cohort and 15 seconds/20,000 steps per child pair. The strict 2 ms arm,
10 ms cadence and 2 s shutdown gates are unchanged; this native run does not
qualify those application timing gates. Raw logs and captures stay ignored.

All seven required checks passed at this exact source revision. The workspace
reported 3,289 passes/0 failures/36 ignores in 357.920 seconds under its existing
360-second bound. Serial launch reported 1,039 passes, staged allocation three,
and prefixed pun 36. Fmt, strict workspace/all-target/all-feature Clippy and
check passed. Checks used eight hard-reserved CPUs: 15/154/157/188/202/210/238/313.
Cargo totals can include nested summaries; this is not a 316-thread claim.
Command durations are validation costs, not performance measurements.

This supports claim 4 only within the completed prerequisite and calibration
scope. Original-address Rust ABI, nested-call execution, full selected-leaf
native coverage, performance and full A5 remain open.
