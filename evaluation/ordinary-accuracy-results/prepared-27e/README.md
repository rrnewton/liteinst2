# Prepared first-call observations at 27e57a2

Two fixed, one-attempt runs prepared the first accepted row and its guarded result storage **before the shared Schedule origin**, then waited for the actual accepted ARM2 and the immutable target `10,000,000 ns + manifest delay`. Both runs completed all 2,048 calls. The locked and random target releases were late by **516,938 ns** and **268,174 ns**, respectively; both missed zero whole periods relative to their target. **Phase realization remains UNRESOLVED.** There is no epsilon or phase-success threshold.

The exact first observations (nanoseconds on the shared in-process clock, except the positive pre-origin lead) are:

| Observation | Locked | Random |
| --- | ---: | ---: |
| Original requested delay | 0 | 581334 |
| Immutable epoch-1 target | 10000000 | 10581334 |
| Prepared ready before origin | 5969 | 7981 |
| First gate poll | 2774 | 3666 |
| ARM2 start / completion | 10000944 / 10006272 | 10000774 / 10013683 |
| Gate opened = RELEASE enter = released | 10516938 | 10849508 |
| First CALLTIME before / after | 10517579 / 10539643 | 10849888 / 10868767 |

Both target publications and first NORMAL entries joined actual generation 2/history-prefix 2. The first gate polls preceded the targets; the eventual admission samples were late. `rows.csv` and `receipt.json` retain the original delay-relative error as well as target-relative lateness, whole-period misses and first/last CALLTIME endpoints. No modulo reduction hides a missed period. Each run also has two CALLTIME enclosures overlapping an ARM and one enclosing a due; these are enclosures, not exact leaf-entry events. Subsequent CSV polling paused through the first physical return; the CSV transport has no external Stop grammar and this does not promise EOF responsiveness while prepared. CALLTIME encloses the actual Rust CALL/store/RET, not exact leaf-entry/RET instants; preemption after admission can delay physical native entry.

All **4,096 calls** are retained: 3,090 sampled and 1,006 unsampled. All **313 recorded ARMs** (158 locked, 155 random) passed the unchanged inclusive 2 ms completion-minus-original-due gate; the maxima were 164,806 ns and 33,117 ns. E=520 remains a cap, not an invented count of executed ARMs. All 8,192 raw PMU reads returned 32 bytes without errno, and all 4,096 windows were `full_running`. This describes instrumented callback windows, not calibrated body-only instruction counts. Hardware/PMU accuracy, native full-state, performance and phase qualification remain unresolved; no throughput or matched speedup is reported.

The seven actions ran on exact committed revision `27e57a250104f0b0e55e9ac441e0b96217ec010d`, on an **AMD EPYC Zen 5 dev host**, using one hard disjoint reservation: controller 13, worker 157, producer 284. Every owner exited 0 with complete cleanup and zero rescued descendants; the reservation parent then exited 0, the reservation was released and its scope disappeared. The receipt records all seven elapsed times and load averages; these are action bookkeeping, not performance benchmarks. Rust app/test products used Cargo opt-level 3, debug 0, assertions and overflow checks enabled, incremental off and four build jobs. C fixtures/reference used `-O2`.

The fresh native prerequisite roster passed 130 ordinary Rust and 104 Python tests. The separate [focused evidence](../prepared-focused-27e/README.md) covers 22 added Python controls; its historical overlay attribution remains explicit. The 45 SDK prerequisites came from separately bound [fresh full-workspace validation at 27e](../workspace-27e/README.md), not these seven commands. The original strict-clock campaign's **one PASS/four FAIL** and [phase-071's already-due releases](../phase-071/README.md) remain unchanged; this new profile does not relabel them. Both new runs use the same body/full input population, but phase positions are not established and the full matrix denominator remains 43,200 cells.

## Reproduction with the existing owners

Use a clean checkout of the exact revision, cached offline dependencies and the recorded toolchain. Before native work, require freshly closed full-workspace validation at that revision including all 45 SDK prerequisites, plus the focused controls including all 18 added Rust and 22 added Python controls. The seven actions below do not execute the SDK roster or those 22 Python controls. Set `PREPARED_RAW` to a fresh canonical absolute directory under that checkout's `ignored/`; create only the parent. Choose fresh `PREPARED_TAG` and `PREPARED_NAME` (a single basename; each action raw directory must be new). Set `PREPARED_TOOLCHAIN`, `PREPARED_USER_HOME`, `PREPARED_CARGO_HOME` and `PREPARED_HARDWARE` to actual values. Raw logs stay private. No new runner is added.

The actual reservation used an allocator-held interactive Bash parent. To reproduce that mechanism, set `PREPARED_ALLOCATOR` to the installed cpuset allocator source, `PREPARED_RUNTIME_DIR` and `PREPARED_DBUS_ADDRESS` to the actual user-systemd endpoint, then launch:

```sh
/usr/bin/env -i HOME="$PREPARED_USER_HOME" PATH=/usr/bin:/bin \
  XDG_RUNTIME_DIR="$PREPARED_RUNTIME_DIR" DBUS_SESSION_BUS_ADDRESS="$PREPARED_DBUS_ADDRESS" \
  PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 LC_ALL=C HISTFILE=/dev/null \
  /usr/local/bin/python3 -B "$PREPARED_ALLOCATOR" run --cores 3 --sample-s 1 \
  --tag "$PREPARED_TAG" -- /bin/bash --noprofile --norc -i
```

Inside that retained shell, set the same variables and `PREPARED_CPUS` to the three sorted IDs actually reserved. Record allocator PID/start time, hard cpuset evidence and load; verify parent/lease/affinity before every owner and after each closure. Keep the parent alive through all seven actions and both geometry reviews. `taskset` only applies affinity. The shell supplies no aggregate timeout or automatic custody check; session loss, expired geometry window or unknown cleanup stops remaining actions as UNRUN/0, never a replacement attempt.

Run each command below once in order. Authenticate each normally CLOSED outer owner **before** any child/log read: exact revision/argv/profile/CPUs/attempt/bounds, matching exit 0 or 1, no termination, cleanup true, zero rescues, unchanged sources/empty overlay, archived log and hash. Then require complete child custody, equal source snapshots, all retained pins and unexceeded/released evidence reservations. First five prerequisites require exit 0 and their exact PASS status. Each functional PASS requires exit 0, `PREPARED_PHASE_FUNCTIONAL_STRUCTURAL_PASS`, producer PASS, full 2,048 identities and functional PASS/attempt 1. A safely closed locked exit 1 may precede the one random attempt only with exact FAILED producer/functional status, planned 2,048 identity and all custody/source/retention proofs; preserve the locked failure and aggregate FAILED. Any uncertain closure or join stops untouched actions. Do not retry, extend limits, discard partial populations or borrow old receipts.

Compute each `*_SHA` only from its indicated newly closed file. After both preparations pass and before either functional command, start **one nonrenewable 1,200 s geometry-review window**. Independently review both complete actual ELF/body/CFG/RET/caller/source-page objects and all nine premises in `accuracy_functional.py:PREMISES`. Obtain two new `selected-accuracy-prepared-phase-functional-geometry-acceptance-v1` acceptances; set `PREPARED_LOCKED_GEOMETRY`, `PREPARED_RANDOM_GEOMETRY` and their SHA variables. Each must bind its own complete facts/result SHA, this exact revision, the prepared profile and `native_state=UNRUN_SEPARATE_REQUIRED`. Preparation success or equal hashes alone are not execution authority; this recipe generates no acceptance.

Retain all original bounds: owner 1,200 s/8 MiB; builds 120 CPU/180 wall seconds/128 MiB per stream; ELF 20 CPU/30 wall seconds/4 MiB; controls/preparations 20 CPU/30 wall seconds/1 MiB; functional producer 15 s absolute, 20 CPU/30 wall seconds, 55 s helper, 8 MiB streams, 350-byte lines, 13,873 strict-success rows and 13,874 failure-envelope rows. Preserve the inclusive 2 ms ARM gate, first admission before original 5.2 s end and returns before 7.2 s fence. Cancellation cannot count as exit 0/DONE success. All exact limits are in the receipt.

### 1. products

```sh
/usr/bin/taskset --cpu-list "$PREPARED_CPUS" /usr/bin/python3.9 -B evaluation/ordinary-selected-session/owner.py \
  --phase products \
  --revision 27e57a250104f0b0e55e9ac441e0b96217ec010d \
  --reservation-tag "$PREPARED_TAG" \
  --owner "$PREPARED_RAW/products-owner.json" \
  --raw "$PREPARED_RAW/${PREPARED_NAME}-products" \
  --toolchain "$PREPARED_TOOLCHAIN" \
  --user-home "$PREPARED_USER_HOME" \
  --cargo-home "$PREPARED_CARGO_HOME" \
  --hardware "$PREPARED_HARDWARE"
```

Set `PREPARED_BUILD_SHA` from `${PREPARED_NAME}-products/result.json` and `PREPARED_BUILD_OWNER_SHA` from `products-owner.json` beneath `PREPARED_RAW`.

### 2. tests

```sh
/usr/bin/taskset --cpu-list "$PREPARED_CPUS" /usr/bin/python3.9 -B evaluation/ordinary-selected-session/owner.py \
  --phase tests \
  --revision 27e57a250104f0b0e55e9ac441e0b96217ec010d \
  --reservation-tag "$PREPARED_TAG" \
  --owner "$PREPARED_RAW/tests-owner.json" \
  --raw "$PREPARED_RAW/${PREPARED_NAME}-tests" \
  --toolchain "$PREPARED_TOOLCHAIN" \
  --user-home "$PREPARED_USER_HOME" \
  --cargo-home "$PREPARED_CARGO_HOME" \
  --hardware "$PREPARED_HARDWARE" \
  --build "$PREPARED_RAW/${PREPARED_NAME}-products/result.json" \
  --build-sha "$PREPARED_BUILD_SHA" \
  --build-owner "$PREPARED_RAW/products-owner.json" \
  --build-owner-sha "$PREPARED_BUILD_OWNER_SHA"
```

Set `PREPARED_TEST_SHA` from `${PREPARED_NAME}-tests/result.json` and `PREPARED_TEST_OWNER_SHA` from `tests-owner.json`.

### 3. controls

```sh
/usr/bin/taskset --cpu-list "$PREPARED_CPUS" /usr/bin/python3.9 -B evaluation/ordinary-selected-session/owner.py \
  --phase controls \
  --revision 27e57a250104f0b0e55e9ac441e0b96217ec010d \
  --reservation-tag "$PREPARED_TAG" \
  --owner "$PREPARED_RAW/controls-owner.json" \
  --raw "$PREPARED_RAW/${PREPARED_NAME}-controls" \
  --toolchain "$PREPARED_TOOLCHAIN" \
  --user-home "$PREPARED_USER_HOME" \
  --cargo-home "$PREPARED_CARGO_HOME" \
  --hardware "$PREPARED_HARDWARE" \
  --build "$PREPARED_RAW/${PREPARED_NAME}-products/result.json" \
  --build-sha "$PREPARED_BUILD_SHA" \
  --build-owner "$PREPARED_RAW/products-owner.json" \
  --build-owner-sha "$PREPARED_BUILD_OWNER_SHA" \
  --test-product "$PREPARED_RAW/${PREPARED_NAME}-tests/result.json" \
  --test-product-sha "$PREPARED_TEST_SHA" \
  --test-owner "$PREPARED_RAW/tests-owner.json" \
  --test-owner-sha "$PREPARED_TEST_OWNER_SHA" \
  --profile selected-session-whole-functional-v1
```

Set `PREPARED_CONTROLS_SHA` from `${PREPARED_NAME}-controls/result.json` and `PREPARED_CONTROLS_OWNER_SHA` from `controls-owner.json`; require the complete 130 Rust/104 Python census.

### 4. locked-prepare

```sh
/usr/bin/taskset --cpu-list "$PREPARED_CPUS" /usr/bin/python3.9 -B evaluation/ordinary-selected-session/accuracy_functional_owner.py \
  --phase prepared-phase-prepare \
  --revision 27e57a250104f0b0e55e9ac441e0b96217ec010d \
  --reservation-tag "$PREPARED_TAG" \
  --owner "$PREPARED_RAW/locked-prepare-owner.json" \
  --raw "$PREPARED_RAW/${PREPARED_NAME}-locked-prepare" \
  --toolchain "$PREPARED_TOOLCHAIN" \
  --user-home "$PREPARED_USER_HOME" \
  --cargo-home "$PREPARED_CARGO_HOME" \
  --hardware "$PREPARED_HARDWARE" \
  --build "$PREPARED_RAW/${PREPARED_NAME}-products/result.json" \
  --build-sha "$PREPARED_BUILD_SHA" \
  --build-owner "$PREPARED_RAW/products-owner.json" \
  --build-owner-sha "$PREPARED_BUILD_OWNER_SHA" \
  --controls "$PREPARED_RAW/${PREPARED_NAME}-controls/result.json" \
  --controls-sha "$PREPARED_CONTROLS_SHA" \
  --controls-owner "$PREPARED_RAW/controls-owner.json" \
  --controls-owner-sha "$PREPARED_CONTROLS_OWNER_SHA" \
  --epoch-phase locked
```

Set `PREPARED_LOCKED_PREPARE_SHA` from `${PREPARED_NAME}-locked-prepare/result.json` and `PREPARED_LOCKED_PREPARE_OWNER_SHA` from `locked-prepare-owner.json`.

### 5. random-prepare

```sh
/usr/bin/taskset --cpu-list "$PREPARED_CPUS" /usr/bin/python3.9 -B evaluation/ordinary-selected-session/accuracy_functional_owner.py \
  --phase prepared-phase-prepare \
  --revision 27e57a250104f0b0e55e9ac441e0b96217ec010d \
  --reservation-tag "$PREPARED_TAG" \
  --owner "$PREPARED_RAW/random-prepare-owner.json" \
  --raw "$PREPARED_RAW/${PREPARED_NAME}-random-prepare" \
  --toolchain "$PREPARED_TOOLCHAIN" \
  --user-home "$PREPARED_USER_HOME" \
  --cargo-home "$PREPARED_CARGO_HOME" \
  --hardware "$PREPARED_HARDWARE" \
  --build "$PREPARED_RAW/${PREPARED_NAME}-products/result.json" \
  --build-sha "$PREPARED_BUILD_SHA" \
  --build-owner "$PREPARED_RAW/products-owner.json" \
  --build-owner-sha "$PREPARED_BUILD_OWNER_SHA" \
  --controls "$PREPARED_RAW/${PREPARED_NAME}-controls/result.json" \
  --controls-sha "$PREPARED_CONTROLS_SHA" \
  --controls-owner "$PREPARED_RAW/controls-owner.json" \
  --controls-owner-sha "$PREPARED_CONTROLS_OWNER_SHA" \
  --epoch-phase random
```

Set `PREPARED_RANDOM_PREPARE_SHA` from `${PREPARED_NAME}-random-prepare/result.json` and `PREPARED_RANDOM_PREPARE_OWNER_SHA` from `random-prepare-owner.json`. Complete both new geometry reviews within the original window before continuing.

### 6. locked-functional

```sh
/usr/bin/taskset --cpu-list "$PREPARED_CPUS" /usr/bin/python3.9 -B evaluation/ordinary-selected-session/accuracy_functional_owner.py \
  --phase prepared-phase-functional \
  --revision 27e57a250104f0b0e55e9ac441e0b96217ec010d \
  --reservation-tag "$PREPARED_TAG" \
  --owner "$PREPARED_RAW/locked-functional-owner.json" \
  --raw "$PREPARED_RAW/${PREPARED_NAME}-locked-functional" \
  --toolchain "$PREPARED_TOOLCHAIN" \
  --user-home "$PREPARED_USER_HOME" \
  --cargo-home "$PREPARED_CARGO_HOME" \
  --hardware "$PREPARED_HARDWARE" \
  --build "$PREPARED_RAW/${PREPARED_NAME}-products/result.json" \
  --build-sha "$PREPARED_BUILD_SHA" \
  --build-owner "$PREPARED_RAW/products-owner.json" \
  --build-owner-sha "$PREPARED_BUILD_OWNER_SHA" \
  --controls "$PREPARED_RAW/${PREPARED_NAME}-controls/result.json" \
  --controls-sha "$PREPARED_CONTROLS_SHA" \
  --controls-owner "$PREPARED_RAW/controls-owner.json" \
  --controls-owner-sha "$PREPARED_CONTROLS_OWNER_SHA" \
  --preparation "$PREPARED_RAW/${PREPARED_NAME}-locked-prepare/result.json" \
  --preparation-sha "$PREPARED_LOCKED_PREPARE_SHA" \
  --preparation-owner "$PREPARED_RAW/locked-prepare-owner.json" \
  --preparation-owner-sha "$PREPARED_LOCKED_PREPARE_OWNER_SHA" \
  --geometry "$PREPARED_LOCKED_GEOMETRY" \
  --geometry-sha "$PREPARED_LOCKED_GEOMETRY_SHA" \
  --epoch-phase locked
```

Retain this outcome, all 2,048 identities and every raw counter/timing outcome before considering the separate random attempt.

### 7. random-functional

```sh
/usr/bin/taskset --cpu-list "$PREPARED_CPUS" /usr/bin/python3.9 -B evaluation/ordinary-selected-session/accuracy_functional_owner.py \
  --phase prepared-phase-functional \
  --revision 27e57a250104f0b0e55e9ac441e0b96217ec010d \
  --reservation-tag "$PREPARED_TAG" \
  --owner "$PREPARED_RAW/random-functional-owner.json" \
  --raw "$PREPARED_RAW/${PREPARED_NAME}-random-functional" \
  --toolchain "$PREPARED_TOOLCHAIN" \
  --user-home "$PREPARED_USER_HOME" \
  --cargo-home "$PREPARED_CARGO_HOME" \
  --hardware "$PREPARED_HARDWARE" \
  --build "$PREPARED_RAW/${PREPARED_NAME}-products/result.json" \
  --build-sha "$PREPARED_BUILD_SHA" \
  --build-owner "$PREPARED_RAW/products-owner.json" \
  --build-owner-sha "$PREPARED_BUILD_OWNER_SHA" \
  --controls "$PREPARED_RAW/${PREPARED_NAME}-controls/result.json" \
  --controls-sha "$PREPARED_CONTROLS_SHA" \
  --controls-owner "$PREPARED_RAW/controls-owner.json" \
  --controls-owner-sha "$PREPARED_CONTROLS_OWNER_SHA" \
  --preparation "$PREPARED_RAW/${PREPARED_NAME}-random-prepare/result.json" \
  --preparation-sha "$PREPARED_RANDOM_PREPARE_SHA" \
  --preparation-owner "$PREPARED_RAW/random-prepare-owner.json" \
  --preparation-owner-sha "$PREPARED_RANDOM_PREPARE_OWNER_SHA" \
  --geometry "$PREPARED_RANDOM_GEOMETRY" \
  --geometry-sha "$PREPARED_RANDOM_GEOMETRY_SHA" \
  --epoch-phase random
```

Retain this outcome and all prior outcomes. After closed custody verification, exit the parent once and verify reservation/scope removal. Publish compact summaries only; structural PASS is not phase realization.

The closed-data audit pin is recorded in `receipt.json`. Raw logs and per-call audit rows remain private. The public command templates normalize only documented path/run/reservation inputs; hashes of those normalized argv arrays use sorted compact JSON with no final newline.
