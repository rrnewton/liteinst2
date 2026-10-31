# Phase observations at 071783b9

Two complete 2,048-call runs recorded the locked and random requests, first-call release, every invocation enclosure and every ARM using one shared in-process `Instant` origin. Both runs used the same function body and full input population; the requested phase positions were not established. Both gates were already due when entered. The locked request was 0 ns and released at 1,293,742 ns. The random request was 581,334 ns and released at 1,329,035 ns, 747,701 ns late. These are observed late releases; **phase realization remains UNRESOLVED**. No epsilon or phase-success threshold is introduced.

The complete 4,096-call population is retained: 2,947 sampled and 1,149 unsampled calls, including all 4,096 timing and raw counter windows. The 147 locked and 155 random ARMs passed the unchanged <=2 ms recorded-deadline gate; maximum completion-minus-due values were 28,283 and 76,038 ns. E=520 is the requested schedule cap, not a claim that 520 ARMs occurred in either run. These observations do not repair or relabel the earlier strict-clock campaign's one PASS/four FAIL outcomes.

All seven public actions closed normally on committed revision `071783b9a3c27ae26c439c7c5b7ac599cfeb7245`, on an AMD EPYC Zen 5 dev host. The reservation assigned controller=121, worker=177 and producer=183. The Rust application and test products used Cargo optimization 3, assertions/overflow checks enabled, incremental off and four build jobs; receipt.json's `build_profile` describes this Rust/Cargo profile. The C fixture and reference builds used `-O2`. The required control roster was 112 Rust and 104 Python tests, all passing. The earlier [focused validation](../focused-071/README.md) separately covers the 22 additive Python controls and exact nine Rust phase controls.

`observations.csv` contains the two unfiltered run summaries. `receipt.json` records exact artifact, tool, source and private-capture hashes, the seven action closures, CPU roles, loads, actual bounds and raw PMU outcomes. An independent closed-data audit reconstructed all record joins and raw wire outcomes with no campaign findings; its binding is recorded in the receipt. All 8,192 counter reads returned 32 bytes with no errno; every counter window was `full_running`. This describes raw instrumented callback windows, not calibrated or body-only instruction counts. Timing encloses `csv::invoke`, including CALL/store/RET; it does not identify exact leaf entry or RET instants. No clock transform to producer monotonic time, TSC or PMU time is inferred.

This is a structural observation result, not native full-state, PMU-accuracy, performance, executable-retirement or strict-2-ms design qualification. The full matrix remains 43,200 cells; these two observations confer no realized-phase matrix credit. No throughput number is reported.

## Reproduction using existing public owners

Run from a clean checkout of the exact revision above with cached offline dependencies and the recorded toolchain. Set `PHASE_RAW` to a fresh absolute directory under that checkout's `ignored/`; create only that parent. Set `PHASE_TAG` to a fresh reservation/run tag, `PHASE_CPUS` to exactly three sorted IDs held by one disjoint reservation, and `PHASE_TOOLCHAIN`, `PHASE_USER_HOME`, `PHASE_CARGO_HOME` to actual canonical paths. Set `PHASE_HARDWARE` to the actual host description. Keep the reservation and original products throughout all seven actions. `taskset` applies affinity; it does not reserve CPUs. Every phase basename must be fresh because the existing helper also retains captures under `target/evaluation`.

Execute each command once, in the order below. Before reading any child result, authenticate a normally closed owner with exit 0 or 1 matching the command exit, no termination, complete cleanup, zero rescued descendants, `log_archived=true`, unchanged sources and an empty source overlay. Require the exact revision, command, profile, reserved CPUs, one attempt, fixed bounds and archived-log hash. Then authenticate child custody, equal before/after source snapshots, retained evidence, an unexceeded evidence budget and its released per-action evidence reservation. Compute every `*_SHA` from the newly closed file indicated below; historical hashes are not substitutes for new receipts.

All first five prerequisites require exit 0 and their corresponding PASS status before dependent work. Each functional success requires exit 0, `PHASE_FUNCTIONAL_STRUCTURAL_PASS` and functional status/attempts `PASS`/1. A locked exit 1 permits the single random attempt only after all the same custody/source/retention checks and exact phase/profile/unqualified flags are proven, with producer status `FAILED`, functional status/attempts `FAILED`/1 and the planned 2,048-record functional identity. Preserve that locked failure and keep the aggregate result `FAILED` even if random passes. Apply the same outcome checks to random; accept no other nonzero exit. If closure, custody or any exact join is missing or uncertain, stop before remaining actions and retain their untouched `UNRUN`/0 state. Keep every failure or partial population; do not retry, extend limits or promote absent outcomes.

The original owner limits are 1,200 s and 8 MiB logs. Build commands retain 120 CPU/180 wall seconds and 128 MiB per stream; ELF captures retain 20 CPU/30 wall seconds and 4 MiB. Controls/preparation retain 20 CPU/30 wall seconds and 1 MiB. Functional execution retains a 15 s absolute producer deadline, 20 CPU/30 wall seconds, 55 s helper, 8 MiB streams, 350-byte lines and the strict 2 ms ARM gate. The existing owners and scripts implement these limits; no new wrapper or arbitrary-command interface is added here.

### 1. Release products

```sh
taskset --cpu-list "$PHASE_CPUS" /usr/bin/python3.9 -B evaluation/ordinary-selected-session/owner.py \
  --phase products \
  --revision 071783b9a3c27ae26c439c7c5b7ac599cfeb7245 \
  --reservation-tag "$PHASE_TAG" \
  --owner "$PHASE_RAW/products-owner.json" \
  --raw "$PHASE_RAW/${PHASE_TAG}-products" \
  --toolchain "$PHASE_TOOLCHAIN" \
  --user-home "$PHASE_USER_HOME" \
  --cargo-home "$PHASE_CARGO_HOME" \
  --hardware "$PHASE_HARDWARE"
```

After closure, set `PHASE_BUILD_SHA` from `${PHASE_TAG}-products/result.json` and `PHASE_BUILD_OWNER_SHA` from `products-owner.json`, both beneath `PHASE_RAW`.

### 2. Release test product

```sh
taskset --cpu-list "$PHASE_CPUS" /usr/bin/python3.9 -B evaluation/ordinary-selected-session/owner.py \
  --phase tests \
  --revision 071783b9a3c27ae26c439c7c5b7ac599cfeb7245 \
  --reservation-tag "$PHASE_TAG" \
  --owner "$PHASE_RAW/tests-owner.json" \
  --raw "$PHASE_RAW/${PHASE_TAG}-tests" \
  --toolchain "$PHASE_TOOLCHAIN" \
  --user-home "$PHASE_USER_HOME" \
  --cargo-home "$PHASE_CARGO_HOME" \
  --hardware "$PHASE_HARDWARE" \
  --build "$PHASE_RAW/${PHASE_TAG}-products/result.json" \
  --build-sha "$PHASE_BUILD_SHA" \
  --build-owner "$PHASE_RAW/products-owner.json" \
  --build-owner-sha "$PHASE_BUILD_OWNER_SHA"
```

After closure, set `PHASE_TEST_SHA` from `${PHASE_TAG}-tests/result.json` and `PHASE_TEST_OWNER_SHA` from `tests-owner.json`.

### 3. Complete whole-function controls

```sh
taskset --cpu-list "$PHASE_CPUS" /usr/bin/python3.9 -B evaluation/ordinary-selected-session/owner.py \
  --phase controls \
  --revision 071783b9a3c27ae26c439c7c5b7ac599cfeb7245 \
  --reservation-tag "$PHASE_TAG" \
  --owner "$PHASE_RAW/controls-owner.json" \
  --raw "$PHASE_RAW/${PHASE_TAG}-controls" \
  --toolchain "$PHASE_TOOLCHAIN" \
  --user-home "$PHASE_USER_HOME" \
  --cargo-home "$PHASE_CARGO_HOME" \
  --hardware "$PHASE_HARDWARE" \
  --build "$PHASE_RAW/${PHASE_TAG}-products/result.json" \
  --build-sha "$PHASE_BUILD_SHA" \
  --build-owner "$PHASE_RAW/products-owner.json" \
  --build-owner-sha "$PHASE_BUILD_OWNER_SHA" \
  --test-product "$PHASE_RAW/${PHASE_TAG}-tests/result.json" \
  --test-product-sha "$PHASE_TEST_SHA" \
  --test-owner "$PHASE_RAW/tests-owner.json" \
  --test-owner-sha "$PHASE_TEST_OWNER_SHA" \
  --profile selected-session-whole-functional-v1
```

After closure, set `PHASE_CONTROLS_SHA` from `${PHASE_TAG}-controls/result.json` and `PHASE_CONTROLS_OWNER_SHA` from `controls-owner.json`. This exact whole-function profile requires 112 Rust and 104 Python executions.

### 4. Locked preparation

```sh
taskset --cpu-list "$PHASE_CPUS" /usr/bin/python3.9 -B evaluation/ordinary-selected-session/accuracy_functional_owner.py \
  --phase phase-prepare \
  --revision 071783b9a3c27ae26c439c7c5b7ac599cfeb7245 \
  --reservation-tag "$PHASE_TAG" \
  --owner "$PHASE_RAW/locked-prepare-owner.json" \
  --raw "$PHASE_RAW/${PHASE_TAG}-locked-prepare" \
  --toolchain "$PHASE_TOOLCHAIN" \
  --user-home "$PHASE_USER_HOME" \
  --cargo-home "$PHASE_CARGO_HOME" \
  --hardware "$PHASE_HARDWARE" \
  --build "$PHASE_RAW/${PHASE_TAG}-products/result.json" \
  --build-sha "$PHASE_BUILD_SHA" \
  --build-owner "$PHASE_RAW/products-owner.json" \
  --build-owner-sha "$PHASE_BUILD_OWNER_SHA" \
  --controls "$PHASE_RAW/${PHASE_TAG}-controls/result.json" \
  --controls-sha "$PHASE_CONTROLS_SHA" \
  --controls-owner "$PHASE_RAW/controls-owner.json" \
  --controls-owner-sha "$PHASE_CONTROLS_OWNER_SHA" \
  --epoch-phase locked
```

After closure, set `PHASE_LOCKED_PREPARE_SHA` from `${PHASE_TAG}-locked-prepare/result.json` and `PHASE_LOCKED_PREPARE_OWNER_SHA` from `locked-prepare-owner.json`.

### 5. Random preparation

```sh
taskset --cpu-list "$PHASE_CPUS" /usr/bin/python3.9 -B evaluation/ordinary-selected-session/accuracy_functional_owner.py \
  --phase phase-prepare \
  --revision 071783b9a3c27ae26c439c7c5b7ac599cfeb7245 \
  --reservation-tag "$PHASE_TAG" \
  --owner "$PHASE_RAW/random-prepare-owner.json" \
  --raw "$PHASE_RAW/${PHASE_TAG}-random-prepare" \
  --toolchain "$PHASE_TOOLCHAIN" \
  --user-home "$PHASE_USER_HOME" \
  --cargo-home "$PHASE_CARGO_HOME" \
  --hardware "$PHASE_HARDWARE" \
  --build "$PHASE_RAW/${PHASE_TAG}-products/result.json" \
  --build-sha "$PHASE_BUILD_SHA" \
  --build-owner "$PHASE_RAW/products-owner.json" \
  --build-owner-sha "$PHASE_BUILD_OWNER_SHA" \
  --controls "$PHASE_RAW/${PHASE_TAG}-controls/result.json" \
  --controls-sha "$PHASE_CONTROLS_SHA" \
  --controls-owner "$PHASE_RAW/controls-owner.json" \
  --controls-owner-sha "$PHASE_CONTROLS_OWNER_SHA" \
  --epoch-phase random
```

After closure, set `PHASE_RANDOM_PREPARE_SHA` from `${PHASE_TAG}-random-prepare/result.json` and `PHASE_RANDOM_PREPARE_OWNER_SHA` from `random-prepare-owner.json`. Before the next two actions, independently review each new preparation, complete actual ELF/body/CFG/RET/caller/source-page facts and all nine invocation premises. Obtain separate phase-profile acceptances as required by [ACCURACY.md](../../ordinary-selected-session/ACCURACY.md). Set `PHASE_LOCKED_GEOMETRY`/`PHASE_RANDOM_GEOMETRY` and their `*_SHA` values from those new acceptances. Preparation success alone supplies no native execution authority; no acceptance is generated by this recipe.

### 6. One complete locked run

```sh
taskset --cpu-list "$PHASE_CPUS" /usr/bin/python3.9 -B evaluation/ordinary-selected-session/accuracy_functional_owner.py \
  --phase phase-functional \
  --revision 071783b9a3c27ae26c439c7c5b7ac599cfeb7245 \
  --reservation-tag "$PHASE_TAG" \
  --owner "$PHASE_RAW/locked-functional-owner.json" \
  --raw "$PHASE_RAW/${PHASE_TAG}-locked-functional" \
  --toolchain "$PHASE_TOOLCHAIN" \
  --user-home "$PHASE_USER_HOME" \
  --cargo-home "$PHASE_CARGO_HOME" \
  --hardware "$PHASE_HARDWARE" \
  --build "$PHASE_RAW/${PHASE_TAG}-products/result.json" \
  --build-sha "$PHASE_BUILD_SHA" \
  --build-owner "$PHASE_RAW/products-owner.json" \
  --build-owner-sha "$PHASE_BUILD_OWNER_SHA" \
  --controls "$PHASE_RAW/${PHASE_TAG}-controls/result.json" \
  --controls-sha "$PHASE_CONTROLS_SHA" \
  --controls-owner "$PHASE_RAW/controls-owner.json" \
  --controls-owner-sha "$PHASE_CONTROLS_OWNER_SHA" \
  --preparation "$PHASE_RAW/${PHASE_TAG}-locked-prepare/result.json" \
  --preparation-sha "$PHASE_LOCKED_PREPARE_SHA" \
  --preparation-owner "$PHASE_RAW/locked-prepare-owner.json" \
  --preparation-owner-sha "$PHASE_LOCKED_PREPARE_OWNER_SHA" \
  --geometry "$PHASE_LOCKED_GEOMETRY" \
  --geometry-sha "$PHASE_LOCKED_GEOMETRY_SHA" \
  --epoch-phase locked
```

Retain all 2,048 records, including every unsampled call, all raw failures and closure. `PHASE_FUNCTIONAL_STRUCTURAL_PASS` is not phase realization.

### 7. One complete random run

```sh
taskset --cpu-list "$PHASE_CPUS" /usr/bin/python3.9 -B evaluation/ordinary-selected-session/accuracy_functional_owner.py \
  --phase phase-functional \
  --revision 071783b9a3c27ae26c439c7c5b7ac599cfeb7245 \
  --reservation-tag "$PHASE_TAG" \
  --owner "$PHASE_RAW/random-functional-owner.json" \
  --raw "$PHASE_RAW/${PHASE_TAG}-random-functional" \
  --toolchain "$PHASE_TOOLCHAIN" \
  --user-home "$PHASE_USER_HOME" \
  --cargo-home "$PHASE_CARGO_HOME" \
  --hardware "$PHASE_HARDWARE" \
  --build "$PHASE_RAW/${PHASE_TAG}-products/result.json" \
  --build-sha "$PHASE_BUILD_SHA" \
  --build-owner "$PHASE_RAW/products-owner.json" \
  --build-owner-sha "$PHASE_BUILD_OWNER_SHA" \
  --controls "$PHASE_RAW/${PHASE_TAG}-controls/result.json" \
  --controls-sha "$PHASE_CONTROLS_SHA" \
  --controls-owner "$PHASE_RAW/controls-owner.json" \
  --controls-owner-sha "$PHASE_CONTROLS_OWNER_SHA" \
  --preparation "$PHASE_RAW/${PHASE_TAG}-random-prepare/result.json" \
  --preparation-sha "$PHASE_RANDOM_PREPARE_SHA" \
  --preparation-owner "$PHASE_RAW/random-prepare-owner.json" \
  --preparation-owner-sha "$PHASE_RANDOM_PREPARE_OWNER_SHA" \
  --geometry "$PHASE_RANDOM_GEOMETRY" \
  --geometry-sha "$PHASE_RANDOM_GEOMETRY_SHA" \
  --epoch-phase random
```

Apply the same full-population checks. Compare observed requests/releases without inventing a phase tolerance or discarding late outcomes. Retain all seven owners and raw child captures privately; publish only compact sanitized summaries.
