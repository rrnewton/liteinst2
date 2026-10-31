# Exact37 accuracy SDK copied-caller state

This is a separate, prospective native-state profile. Its source and controls
must be reviewed and executed before any result can be reported. The previous
two-leaf 192-pair campaign does not cover this body. No result is supplied here.

The complete `exact_work_nonempty` symbol is 37 bytes with eleven instruction
heads and RET at offset 36. The fixed population is K10, function ID41, the two
SDK seeds `0x1234567887654320` and `0xfedcba9801234567`, and every length 1..64.
Each seed chooses the complete 64-byte pattern `(37*j + 11 + seed_index) mod 256`.
These are 128 pairs, divided into four fixed 32-pair cohorts. The prospective
totals are 25,600 original body visits, 26,880 original/candidate boundary
comparisons and 256 normal child reaps. Counts become evidence only after the
complete collector checks all actual rows.

The Rust command is:

```
frontend-native-oracle exact37-accuracy-copied-state-v1 DSO_CANDIDATE DSO_TRUSTED APP_CANDIDATE APP_TRUSTED OUTPUT SEED LENGTH ELF_VA EXTENT
```

It has eleven arguments including the executable. Numbers are canonical unsigned
decimal; extent is 37. The actual accuracy SDK uses WholeFunction publication,
one manually armed bank, nominal 10 ms, K10 and a 4096-call cap. The existing
original-instruction interpreter checks all loop visits and the actual return.
The full-state comparator also covers the complete copied 20-byte CALL/store/RET
caller and its 152-byte stack window, retaining the existing TF/RF and canonical
xstate scope. The candidate checks real acquisition, counter sidecars, normal
records, acknowledgments, journal, history, report, detach and bank reclaim.
PMU unavailability remains explicit under those checks.

The public entrypoint is `exact_state_owner.py`. It calls the existing public
owner and bounded helper; it implements no process supervisor. Each native pair
gets one attempt, 20 CPU seconds, 30 wall seconds, the unchanged internal
15-second deadline and 20,000-step ceiling. Each outer phase keeps the existing
1200-second/8-MiB limits and three reserved CPUs. No failure triggers a retry.

First, use [BUILD.md](BUILD.md) at one committed, clean revision to produce the
fresh `products`, `tests`, whole-profile `controls`, `sdk-build` and `sdk-controls`
receipts. Retain one disjoint three-CPU reservation through the sequence. Those
phases remain mandatory and use their existing exact rosters and assertions.
The SDK build must contain the actual release `frontend-native-oracle` and the
release test artifact `frontend-native-calibrations`. The new preparation phase
requires all eight additional literal Rust names in `exact_state.RUST_CONTROLS`
and all twelve new Python controls; listing alone is not execution credit.

Define `ROOT`, `RAW`, `REV`, `TOOLCHAIN`, `TASK_USER_HOME`, `TASK_CARGO_HOME`,
`RESERVATION` and `HARDWARE` for that reservation. `RAW` is an existing canonical
directory below `${ROOT}/ignored`; every phase basename and owner output must be
fresh. `PYTHON` is the same canonical interpreter used in the earlier phases.
`BUILD`, `BUILD_OWNER`, `SDK_BUILD`, `SDK_BUILD_OWNER`, `SDK_CONTROLS` and
`SDK_CONTROLS_OWNER` point to the closed prerequisite JSON files.

```bash
sha_file() { sha256sum "$1" | cut -d ' ' -f 1; }
prerequisites=(
  --build "$BUILD" --build-sha "$(sha_file "$BUILD")"
  --build-owner "$BUILD_OWNER" --build-owner-sha "$(sha_file "$BUILD_OWNER")"
  --sdk-build "$SDK_BUILD" --sdk-build-sha "$(sha_file "$SDK_BUILD")"
  --sdk-build-owner "$SDK_BUILD_OWNER" --sdk-build-owner-sha "$(sha_file "$SDK_BUILD_OWNER")"
  --sdk-controls "$SDK_CONTROLS" --sdk-controls-sha "$(sha_file "$SDK_CONTROLS")"
  --sdk-controls-owner "$SDK_CONTROLS_OWNER" --sdk-controls-owner-sha "$(sha_file "$SDK_CONTROLS_OWNER")"
)
exact_owner() {
  local exact_phase="$1" exact_name="$2"
  shift 2
  "$PYTHON" -B "$ROOT/evaluation/ordinary-selected-session/exact_state_owner.py" \
    --phase "$exact_phase" --revision "$REV" --reservation-tag "$RESERVATION" \
    --owner "$RAW/$exact_name-owner.json" --raw "$RAW/$exact_name" \
    --toolchain "$TOOLCHAIN" --user-home "$TASK_USER_HOME" --cargo-home "$TASK_CARGO_HOME" \
    --hardware "$HARDWARE" "${prerequisites[@]}" "$@"
}
exact_owner exact-prepare exact-preparation
```

Preparation runs the exact reviewed GCC assembly command followed by bounded
readelf and objdump captures. It authenticates the original and a distinct copy,
the full ELF metadata, all 37 bytes/eleven heads/RET, and the complete 4096-byte
source page. It joins the existing application's actual ELF and complete caller
captures and pins both release SDK artifacts. All raw files, requests, closures,
source snapshots, tool digests, CPU reservation and load averages remain private.

After preparation closes successfully, an independent reviewer must inspect the
actual bytes and provide a geometry acceptance. The producer never creates this
acceptance. Its exact fields are checked by `exact_state_geometry.acceptance`:

- `kind`: `exact37-accuracy-copied-geometry-acceptance-v1`;
- `status`: `INDEPENDENTLY_ACCEPTED_FOR_FIXED_EXACT37_COPIED_ACCURACY_STATE`;
- `scope`: `exact37-accuracy-copied-state-v1`, and the exact `revision`;
- exact `{path, sha256}` references named `preparation`, `build`, `sdk_build`;
- `facts`: the complete actual `geometry-facts.json` object, unchanged;
- `premises`: every named `PREMISES` entry explicitly `true`;
- `review`: the independent acceptance explanation;
- `supporting_pins`: 1..64 absolute paths with exact `{bytes, sha256}` pins for
  the accepted platform/ABI/lifetime basis;
- `native_state`: `UNRUN_SEPARATE_REQUIRED`;
- `qualification`: `pmu_metric`, `cadence`, `performance`, all explicitly `false`.

The premises include the full symbol/CFG/source page, complete copied machine
caller, scalar ABI and readable inputs, immutable pathname/object lifetime,
termination, sole-worker ownership, and signal/CET conditions. Equal hashes or
control success do not prove these unsafe premises.

After explicit acceptance, let `GEOMETRY` be its canonical path. Freeze four
cohorts before running any of them. Execute each command once under the same
reservation; retain failures and do not repeat a command to seek a pass.

```bash
prepared=(
  --preparation "$RAW/exact-preparation/result.json"
  --preparation-sha "$(sha_file "$RAW/exact-preparation/result.json")"
  --preparation-owner "$RAW/exact-preparation-owner.json"
  --preparation-owner-sha "$(sha_file "$RAW/exact-preparation-owner.json")"
  --geometry "$GEOMETRY" --geometry-sha "$(sha_file "$GEOMETRY")"
)
exact_owner exact-cohort seed0-lengths01-32 "${prepared[@]}" --cohort seed0-lengths01-32
exact_owner exact-cohort seed0-lengths33-64 "${prepared[@]}" --cohort seed0-lengths33-64
exact_owner exact-cohort seed1-lengths01-32 "${prepared[@]}" --cohort seed1-lengths01-32
exact_owner exact-cohort seed1-lengths33-64 "${prepared[@]}" --cohort seed1-lengths33-64
```

Proceed between owners only after normal process closure and source custody are
established. A safely closed pair failure remains FAILED. Uncertain custody
stops dispatch; later keys remain UNRUN. The existing bounded reader accepts only
its original finite child-exit domain; a panic or other unsupported terminal
status remains a conservative custody failure, never a successful row.

Create `COHORTS_JSON` as a JSON array in the four orders above. Each entry has
exactly `cohort`, `result: {path, sha256}`, and `owner: {path, sha256}` for its
closed receipts. No execution result may be fabricated to fill a missing phase.
Then run the collector once:

```bash
exact_owner exact-collect exact-collection "${prepared[@]}" \
  --cohorts "$COHORTS_JSON" --cohorts-sha "$(sha_file "$COHORTS_JSON")"
```

The collector verifies every planned request, all four independent file copies,
helper closure and source pins, one-attempt coordinates, exact 32-column output
and terminal marker. Every column has a fixed meaning; step counts remain
bounded observations. It requires all 128 unique ordered rows for PASS and keeps
closed FAILED/UNRUN rows. Missing or untrusted receipts fail the collection and
remain retained inputs; they never grant state credit.

This profile supplies no PMU accuracy or performance number. Raw PMU endpoints
and per-boundary register snapshots are not exported by its CSV; its state
evidence is the actual source-bound assertions plus closed per-pair receipts.
Reclaim is interval-bank reclaim; executable owners remain process-lived. One
call per key does not test unsampled transfer batches, exhaustion, rotation,
concurrent preemption, requested producer phase, cadence or the strict 2 ms gate.
The full 100-seed accuracy matrix and all earlier failures remain separate.
