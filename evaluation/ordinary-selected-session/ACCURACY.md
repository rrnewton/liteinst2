# First Exact37 accuracy functional attempt

This is one fixed calibration trial, not an accuracy qualification: master
`16b3b34b02c2f1054381195ee3d0767b493b427ad041bbfd8924e630d0f369b1`,
trial 1, `late_expensive`, all 2,048 records, function 41 `exact_work_nonempty`,
whole-function policy, K10, 10 ms, E520, requested locked/0. The first 1,024
records contain one byte and the remaining 1,024 contain 64 bytes. Original-work
truth is 409,600 instructions, 66,560 conditional branches, 64,512 taken branches,
66,560 input bytes and 16,384 return-word bytes. These are semantic counts, not
PMU predictions. The source-bound `truth.py` and strict `output.py` are unchanged.

Use a clean committed checkout and the existing three-CPU reservation. Preserve
all failed earlier captures. Select a fresh tag and basename for every declared
new attempt; the shared process helper uses a global `target/evaluation` basename
namespace. There is one preparation and one functional invocation, no retry or
population selector. The full 100-seed × six-workload × 24-policy matrix in each
calibration/holdout/comparison population remains required. This attempt does not
complete a realized-phase matrix cell.

First run the public [build/test/whole-control recipe](BUILD.md) at the exact new
revision, with `--profile selected-session-whole-functional-v1` for controls.
The current required controls are all 103 Rust and 104 Python cases. The new
helpers are in that recipe's source inventory, so use fresh build/control
receipts after committing them. `accuracy_functional_controls.py -v` supplies
16 additional pure controls; they grant no native or hardware credit. The legacy
owner/producer APIs, byte limits, old comparators and historical receipts stay
unchanged.

The commands below require absolute canonical paths. `PYTHON` is the same pinned
Python used by the build, and the invocation must already have exactly the three
reserved CPUs as affinity. The public owner reserves no CPUs itself. Set `REV`,
`TAG`, `RAW`, `TOOLCHAIN`, `USER_HOME`, `CARGO_HOME`, `HARDWARE`, and the four build
and four controls receipt variables from the actual closed files. Compute each
SHA-256 from those files. The outer owner remains 1,200 seconds and 8 MiB of log.

```sh
"$PYTHON" -B "$ROOT/evaluation/ordinary-selected-session/accuracy_functional_owner.py" \
  --phase accuracy-prepare --revision "$REV" --reservation-tag "$TAG" \
  --owner "$RAW/prepare-owner.json" --raw "$RAW/$TAG-prepare" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" --hardware "$HARDWARE" \
  --build "$BUILD" --build-sha "$BUILD_SHA" --build-owner "$BUILD_OWNER" --build-owner-sha "$BUILD_OWNER_SHA" \
  --controls "$CONTROLS" --controls-sha "$CONTROLS_SHA" --controls-owner "$CONTROLS_OWNER" --controls-owner-sha "$CONTROLS_OWNER_SHA"
```

Preparation independently replays the closed release/control commands and source
pins, generates the four exact truth files, assembles the literal `exact_work.S`
with the established flags, and captures complete ELF/disassembly. It uses the
existing one-MiB Exact37 ELF parser, retains a separate-inode candidate copy,
and derives the actual 20-byte/nine-head Rust CALL/store/RET caller from the
accepted build capture. Assembly and each capture use 20 CPU seconds, 30 wall
seconds and 1 MiB. No candidate is executed by preparation.

Before functional dispatch, independently review the actual whole ELF/source
page, caller and ABI/lifetime assumptions. Supply a JSON acceptance with exactly:

- `kind`: `selected-accuracy-functional-geometry-acceptance-v1`;
- `status`: `INDEPENDENTLY_ACCEPTED_FOR_FIXED_SCALAR_EXECUTION`;
- `scope`: `selected-accuracy-functional-first-v1`, `revision`: `REV`;
- `preparation_sha256`: actual SHA-256 of the closed preparation `result.json`;
- `facts`: the complete, unchanged value of its `geometry-facts.json`;
- `premises`: all nine names in `accuracy_functional.PREMISES`, each `true`;
- `review`: the concrete independent review basis;
- `native_state`: `UNRUN_SEPARATE_REQUIRED`.

Those premises are explicit unsafe authority, not conclusions from a digest.
They cover the complete body/CFG/ELF/caller, SysV pointer/length→u64 with immutable
nonempty 1..64-byte readable inputs and no pointer wrap, ordinary CALL/RET,
no active CET or asynchronous signals/reentry/nonlocal exits, sole controlled
worker, and unchanged loader/object/path/input/code lifetime through shutdown.
Body-byte equality alone cannot authorize these conditions. Existing two-leaf
copied-caller accuracy-state evidence does not qualify this Exact37 combination.

```sh
"$PYTHON" -B "$ROOT/evaluation/ordinary-selected-session/accuracy_functional_owner.py" \
  --phase accuracy-functional --revision "$REV" --reservation-tag "$TAG" \
  --owner "$RAW/functional-owner.json" --raw "$RAW/$TAG-functional" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" --hardware "$HARDWARE" \
  --build "$BUILD" --build-sha "$BUILD_SHA" --build-owner "$BUILD_OWNER" --build-owner-sha "$BUILD_OWNER_SHA" \
  --controls "$CONTROLS" --controls-sha "$CONTROLS_SHA" --controls-owner "$CONTROLS_OWNER" --controls-owner-sha "$CONTROLS_OWNER_SHA" \
  --preparation "$RAW/$TAG-prepare/result.json" --preparation-sha "$PREPARATION_SHA" \
  --preparation-owner "$RAW/prepare-owner.json" --preparation-owner-sha "$PREPARATION_OWNER_SHA" \
  --geometry "$GEOMETRY" --geometry-sha "$GEOMETRY_SHA"
```

The functional adapter authenticates PID/main TID, version, CPU roles and all
fixed READY fields before queueing the complete original input. It never sleeps
or paces records. It retains the monotonic READY receipt, every successful write's
before/after timestamps and cumulative bytes, and EOF close. READY precedes the
application's private controller clock origin; these timestamps cannot establish
locked/random phase realization. The reported phase remains `UNRESOLVED`.

The existing helper enforces 20 CPU/30 wall seconds, the adapter retains the
15-second absolute deadline, and the helper owner remains 55 seconds. This named
profile explicitly requests an 8 MiB per-file limit, including inherited
`RLIMIT_FSIZE`; old profiles remain 4 MiB. Accepted streams remain bounded to
8 MiB, 350 bytes per line and 11,820 lines. On overflow, the already consumed
prefix and the separately bounded offending read (at most 8,192 bytes) are kept
before refusal. No unread child bytes are claimed. The evidence reservation
covers both streams, result, offending chunk, helper logs and complete joined
records until final closure/identity checks finish.

Success requires normal child exit 0, one normal reap, no rescue, exact complete
input, complete strict wire and scalar equality, and unchanged source/tool/input
pins. The original inclusive 2 ms ARM deadline is unchanged. Raw failure bytes
and closures are kept; a failed reader is not forced through a success path.
`joined.json` retains every sampled and unsampled CALL, both raw counter endpoints,
requested/post-open 128-byte attributes, ID/enable/disable/close, every ARM and
all unavailable/error/short-read/ID/AUX/zero-running/multiplexing limitations.
Bytes use explicit `bytes_hex` fields; original streams remain separately pinned.
No scaling, body-only/per-call perf interpretation, hardware accuracy, calibrated
phase, performance, bank-exhaustion or executable-retirement claim is made.
Installed code owners remain process-lived; interval-bank reclamation is separate.
