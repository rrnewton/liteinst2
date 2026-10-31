The public `owner.py` and `build.py` entrypoints prepare and run the fixed selected-scalar experiment using the existing process owner and bounded helper. They need a clean committed checkout, local offline Cargo dependencies, a stable Rust toolchain, GCC/binutils/Clang in `/usr/bin`, and exactly three externally reserved disjoint CPUs. `taskset` applies affinity; it does not reserve CPUs. Record the allocator's reservation tag and the actual hardware description. Keep the same revision and reservation for the sequence below, and retain all original Cargo product paths and private outputs through final verification.

The new public build schema is separate from the historical private receipts. Both historical build-script digest checks remain intact. Fresh receipts bind the tracked public producer's exact Git blob, literal argv, complete source snapshots, compiler/subtool hashes, all actual requests, bounded receipts and outer closures. No private script is required for the fresh path. The public owner accepts the four original scalar phases and four separate SDK phases described below, and delegates process supervision to `evaluation/admission/processes.py`; it neither supplies unsafe permission nor implements another process supervisor. Its active capture log is created in a fresh directory under `target/evaluation`, as that existing API requires. Only after confirmed cleanup does the adapter read the bounded log, require the exact closed digest, copy it exclusively beside the ignored owner JSON, and reread the copy. Unknown closure retains its original target capture and failure header without any additional wrapper log read or copy; the existing process owner itself remains unchanged. Failed archival remains failure; neither the capture nor prior evidence is deleted.

Set these variables to actual values before running any command: `SELECTED_REV` (full current commit), `SELECTED_CPUS` (the three reserved IDs), `SELECTED_TAG`, `SELECTED_HARDWARE`, `SELECTED_TOOLCHAIN`, `SELECTED_USER_HOME`, `SELECTED_CARGO_HOME`, and `SELECTED_RAW` (a new directory under this checkout's `ignored/`). All path values must be absolute canonical paths. Create only `SELECTED_RAW` itself; the phase output directories and owner files below must not exist. Use a fresh `SELECTED_TAG` for each sequence: the existing shared run helper also reserves `target/evaluation/<phase-directory-basename>`, so a new parent alone does not make a reused phase basename fresh. Keep old captures intact. Run from the checkout root using the same resolved Python executable throughout. The option order shown is intentional: the owner validates its complete literal invocation before dispatch.

```
taskset --cpu-list "$SELECTED_CPUS" python3 -B evaluation/ordinary-selected-session/owner.py \
  --phase products --revision "$SELECTED_REV" --reservation-tag "$SELECTED_TAG" \
  --owner "$SELECTED_RAW/products-owner.json" --raw "$SELECTED_RAW/${SELECTED_TAG}-products" \
  --toolchain "$SELECTED_TOOLCHAIN" --user-home "$SELECTED_USER_HOME" \
  --cargo-home "$SELECTED_CARGO_HOME" --hardware "$SELECTED_HARDWARE"
```

This performs exactly four builds and eight read-only ELF/disassembly captures, once each. The existing GCC/strip flags are unchanged; Cargo uses `--release --locked --offline --jobs 4 --message-format=json-render-diagnostics`, optimization 3, debug information 0, and enabled assertions/overflow checks. Each build has the original 120 CPU-second/180 wall-second/128 MiB per-stream cap. Each capture has the original 20 CPU-second/30 wall-second/4 MiB per-stream cap. Each existing helper owner has the original child wall bound plus 25 seconds. No product or test binary is executed. The product phase has an internal 1200-second deadline.

Require successful outer exit, `source_unchanged: true`, exit-zero/complete cleanup/no rescued descendants in the recorded owner, and `BUILD_AND_ELF_CAPTURE_PASS` in `${SELECTED_TAG}-products/result.json`. Record SHA256 of that result and `products-owner.json` as `SELECTED_BUILD_SHA` and `SELECTED_BUILD_OWNER_SHA`. Keep all failures and stop on failed or unknown ownership; do not retry until a separately reviewed new source/experiment is declared.

```
taskset --cpu-list "$SELECTED_CPUS" python3 -B evaluation/ordinary-selected-session/owner.py \
  --phase tests --revision "$SELECTED_REV" --reservation-tag "$SELECTED_TAG" \
  --owner "$SELECTED_RAW/tests-owner.json" --raw "$SELECTED_RAW/${SELECTED_TAG}-tests" \
  --toolchain "$SELECTED_TOOLCHAIN" --user-home "$SELECTED_USER_HOME" \
  --cargo-home "$SELECTED_CARGO_HOME" --hardware "$SELECTED_HARDWARE" \
  --build "$SELECTED_RAW/${SELECTED_TAG}-products/result.json" --build-sha "$SELECTED_BUILD_SHA" \
  --build-owner "$SELECTED_RAW/products-owner.json" --build-owner-sha "$SELECTED_BUILD_OWNER_SHA"
```

This runs only the existing `cargo test --release -p rapid-profiler --bin ordinary-interval --no-run --locked --offline --jobs 4 --message-format=json-render-diagnostics` build under the same build caps. It consumes the closed fresh product build and exact original inputs. Its internal deadline is 600 seconds. Both new build phases use three reserved CPUs; the earlier four-CPU historical test receipt remains distinct and unchanged. Require `RELEASE_TEST_BUILD_PASS` plus the complete outer closure. Record the result and owner SHA256 as `SELECTED_TEST_SHA` and `SELECTED_TEST_OWNER_SHA`.

```
taskset --cpu-list "$SELECTED_CPUS" python3 -B evaluation/ordinary-selected-session/owner.py \
  --phase controls --revision "$SELECTED_REV" --reservation-tag "$SELECTED_TAG" \
  --owner "$SELECTED_RAW/controls-owner.json" --raw "$SELECTED_RAW/${SELECTED_TAG}-controls" \
  --toolchain "$SELECTED_TOOLCHAIN" --user-home "$SELECTED_USER_HOME" \
  --cargo-home "$SELECTED_CARGO_HOME" --hardware "$SELECTED_HARDWARE" \
  --build "$SELECTED_RAW/${SELECTED_TAG}-products/result.json" --build-sha "$SELECTED_BUILD_SHA" \
  --build-owner "$SELECTED_RAW/products-owner.json" --build-owner-sha "$SELECTED_BUILD_OWNER_SHA" \
  --test-product "$SELECTED_RAW/${SELECTED_TAG}-tests/result.json" --test-product-sha "$SELECTED_TEST_SHA" \
  --test-owner "$SELECTED_RAW/tests-owner.json" --test-owner-sha "$SELECTED_TEST_OWNER_SHA"
```

This requires all 112 Rust controls (the unchanged 68 legacy controls, 24 selected controls, 11 accuracy controls and nine phase-observation controls) and 94 Python controls across 12 stages, including the release test inventory. The shared LeafSet census requires all eleven exact accuracy names in addition to its old 68, giving 79, then adds all nine exact phase-observation names for 88; this selected recipe then adds the unchanged 24 selected controls. Missing, duplicate or unknown names refuse. Each stage retains the original 20 CPU-second/30 wall-second/1 MiB per-stream cap and 55-second helper-owner backstop. It does not dispatch the selected application campaign. The 21 additive fabricated public-builder controls are separately reproducible with `python3 -B evaluation/ordinary-selected-session/build_controls.py -v`; these fabricated controls do not validate an actual compiler, process owner or native candidate. Their result belongs in its own bounded execution receipt.

Require `SELECTED_CONTROLS_PASS` and complete outer closure; record result/owner digests as `SELECTED_CONTROLS_SHA` and `SELECTED_CONTROLS_OWNER_SHA`. Before proceeding, obtain independent review of the actual newly built files, complete ELF metadata and every selected function body/CFG/RET, both ordinary callers, stripping preservation and complete source pages. Review all unsafe ABI/input, no-concurrency/termination, CET/signal, immutable-object and pathname lifetime premises from README.md. Neither build success, a source decoder nor the scalar oracle grants those premises. A changed compiler shape must be reviewed or refused; do not truncate extents, change flags, reorder selections to fit a favorable subset, or copy the old accepted geometry onto new bytes.

Freeze a separate acceptance JSON and its exact SHA256 as `SELECTED_GEOMETRY` and `SELECTED_GEOMETRY_SHA`. Its required schema is `selected-session-geometry-acceptance-v1`, with status `INDEPENDENTLY_ACCEPTED_FOR_FIXED_SCALAR_EXECUTION`, scope `selected-session-functional-v1`, and native_state `UNRUN_SEPARATE_REQUIRED`. It binds the actual build result digest/revision/products, complete ordered table rows `(function_id,operation,policy,elf_va,extent,returns)`, caller extent/continuation, complete source-page list, nonempty independent-review reference and exact review-fact pins. The fixed IDs/labels are `(101,first_equal)` and `(202,uppercase_count)`, both certified. All nine explicit premises must be independently accepted: complete_symbol_extents, complete_cfg_and_all_returns, complete_elf_and_source_pages, strip_preserves_selected_bytes_and_pages, ordinary_rust_and_reference_callers, immutable_path_and_object_lifetime, scalar_sysv_abi_and_readable_inputs, termination_no_hidden_calls_exits_or_concurrency, and cet_and_signal_preconditions. There is deliberately no automatic acceptance generator.

```
taskset --cpu-list "$SELECTED_CPUS" python3 -B evaluation/ordinary-selected-session/owner.py \
  --phase campaign --revision "$SELECTED_REV" --reservation-tag "$SELECTED_TAG" \
  --owner "$SELECTED_RAW/campaign-owner.json" --raw "$SELECTED_RAW/${SELECTED_TAG}-campaign" \
  --toolchain "$SELECTED_TOOLCHAIN" --user-home "$SELECTED_USER_HOME" \
  --cargo-home "$SELECTED_CARGO_HOME" --hardware "$SELECTED_HARDWARE" \
  --build "$SELECTED_RAW/${SELECTED_TAG}-products/result.json" --build-sha "$SELECTED_BUILD_SHA" \
  --build-owner "$SELECTED_RAW/products-owner.json" --build-owner-sha "$SELECTED_BUILD_OWNER_SHA" \
  --controls "$SELECTED_RAW/${SELECTED_TAG}-controls/result.json" --controls-sha "$SELECTED_CONTROLS_SHA" \
  --controls-owner "$SELECTED_RAW/controls-owner.json" --controls-owner-sha "$SELECTED_CONTROLS_OWNER_SHA" \
  --geometry "$SELECTED_GEOMETRY" --geometry-sha "$SELECTED_GEOMETRY_SHA"
```

All four public phases have the same explicit outer 1200-second/8 MiB limit. The wrapper does not increase the existing inner campaign deadline. The campaign performs four independent reference calls followed by four installed cells: unstripped/stripped × K10/K1000, both functions, n=2 and 520 epochs. K10 uses every one of 12 records/24 calls; K1000 uses all 1001 records/2002 calls. Each cell has one attempt and unchanged 20 CPU-second/30 wall-second bounds, 15-second producer deadline, stdin/READY handshake, full numeric history and scalar oracle, and exact child/outer closure. Reference failure leaves installed cells UNRUN; uncertain custody stops subsequent work. Expected populations are not observed success counts. Keep every failure; do not turn a stopped cell into a pass.

Only complete successful owner closure plus `SELECTED_SCALAR_FUNCTIONAL_PASS` supports this finite scalar result. Retain exact revision, hardware, reservation, load, commands, artifact and raw-output digests; publish compact sanitized summaries. Architecture-state qualification, performance, the strict 2 ms design claim, arbitrary DSOs/ABIs, and the full prior application campaign remain separate. This recipe does not retroactively rerun or relabel the earlier fixed campaign. Until this new public producer is actually validated, it is source-only and UNRUN.

The optional whole-function experiment is named `selected-session-whole-functional-v1`. It uses the same public products and tests phases. Append `--profile selected-session-whole-functional-v1` **at the end** of both the controls and campaign commands above; no profile option is accepted for products or tests. The default and explicit `selected-session-functional-v1` retain both certified-block policies. The whole-function profile requires both table rows to use `whole`, with the existing 5–80-byte extent limits; mixed policies and implicit fallback are refused. This is a separate planner capability experiment, not a reinterpretation of the retained certified-profile failures.

For the whole-function experiment, the independently reviewed geometry acceptance must have scope `selected-session-whole-functional-v1` and both policies `whole`. All nine original premises, the complete two-function bodies/returns/source pages, ordinary callers, stripping checks and independent scalar expectations remain required. Control and campaign receipts must use the same chosen profile; an otherwise valid certified-profile receipt cannot supply a whole-profile control or child result. The controls phase retains all 112 Rust and 94 Python checks and appends the ten `profile_controls.py` cases as a thirteenth bounded stage (104 Python checks total). The default profile retains its original twelve-stage, 94-Python-check replay shape. The new cases also run directly with `python3 -B evaluation/ordinary-selected-session/profile_controls.py -v` and provide only fabricated source/control evidence.

Both profiles keep all eight cells, the same unstripped/stripped inputs, K10/K1000 populations, 520 epochs, attempt limit one, full numeric wire/guard checks and unchanged process/evidence limits. No compiler flag, function extent, old assertion, deadline or failed result is changed by choosing this named profile. Native execution, architectural-state qualification and performance outcomes require separate revision-pinned receipts.

The separate architectural-state producer is `sdk_state.py`, with profile `selected-leaf-set-copied-state-v1`. It uses four named owner phases: `sdk-build`, `sdk-controls`, `sdk-cohort`, and `sdk-collect`. The original four phases and their historical receipts remain unchanged. Start from fresh products/tests and the **whole-functional** controls above at the same clean combined revision, three-CPU reservation, canonical tools and hardware description. Do not reuse products whose complete source snapshot predates the SDK helpers. Keep all original build paths and copies stable through collection.

The fixed population is 192 pairs: two forms × K10/K1000 × two SDK seeds (`1311768467139281696`, `18364758542526924135`) × IDs101/202 × all12 `oracle.py` literals. Each pair loads/publishes both complete WholeFunction selections. Four prospective cohorts each contain48 keys; all four are required. There are16 coverage groups, each with all12 inputs. Successful collection requires 27,560 ordered caller/leaf boundary comparisons and both return paths in every group. Python independently derives literal values, visit/read counts and complete head/edge/return sets, then joins every source-bound Rust row and exact terminal. It does not construct architecture-state equality from a PASS flag.

`sdk-build` makes exactly two additional release artifacts, once each: `cargo build --release -p rapid-profiler --bin frontend-native-oracle ...` and `cargo test --release -p rapid-profiler --test frontend-native-calibrations --no-run ...`. Both use `--locked --offline --jobs 4 --message-format=json-render-diagnostics` and the unchanged120CPU/180wall/128MiB build caps. The executable target has `test=false`; calibration is an integration-test target, not a nonexistent binary-test harness. Both original Cargo products and exclusive copied artifacts are retained and checked. No native pair runs in this phase.

For compact shell examples, use the previously defined actual variables and these fixed argument arrays. Run each command once, recording its actual result/owner hashes before supplying them to a later command. The helper below only abbreviates the public owner's exact canonical argument order; it adds no dispatch mode.

```bash
sdk_owner() {
  local phase="$1" label="$2"
  shift 2
  taskset --cpu-list "$SELECTED_CPUS" python3 -B evaluation/ordinary-selected-session/owner.py \
    --phase "$phase" --revision "$SELECTED_REV" --reservation-tag "$SELECTED_TAG" \
    --owner "$SELECTED_RAW/$label-owner.json" --raw "$SELECTED_RAW/${SELECTED_TAG}-$label" \
    --toolchain "$SELECTED_TOOLCHAIN" --user-home "$SELECTED_USER_HOME" \
    --cargo-home "$SELECTED_CARGO_HOME" --hardware "$SELECTED_HARDWARE" "$@"
}
PRODUCT_REFS=(--build "$SELECTED_RAW/${SELECTED_TAG}-products/result.json" --build-sha "$SELECTED_BUILD_SHA"
  --build-owner "$SELECTED_RAW/products-owner.json" --build-owner-sha "$SELECTED_BUILD_OWNER_SHA")
sdk_owner sdk-build sdk-build "${PRODUCT_REFS[@]}"
```

Require `SDK_BUILD_PASS` and complete owner closure; set `SDK_BUILD_SHA` and `SDK_BUILD_OWNER_SHA` from those closed files. The next phase replays the complete whole-functional112Rust/104Python controls and runs the exact eight additional SDK calibration names plus thirteen new Python producer controls. The shared compiled-fixture registration is `...selected_leaf_set::compiled::literal_answers_and_complete_reachable_population_are_frozen` at module root. Listing the complete calibration binary does not claim all inherited tests ran; only the eight explicit new selections receive new control credit here. All other existing ignored/control inventories remain separate.

```bash
SDK_BUILD_REFS=(--sdk-build "$SELECTED_RAW/${SELECTED_TAG}-sdk-build/result.json" --sdk-build-sha "$SDK_BUILD_SHA"
  --sdk-build-owner "$SELECTED_RAW/sdk-build-owner.json" --sdk-build-owner-sha "$SDK_BUILD_OWNER_SHA")
sdk_owner sdk-controls sdk-controls "${PRODUCT_REFS[@]}" "${SDK_BUILD_REFS[@]}" \
  --controls "$SELECTED_RAW/${SELECTED_TAG}-controls/result.json" --controls-sha "$SELECTED_CONTROLS_SHA" \
  --controls-owner "$SELECTED_RAW/controls-owner.json" --controls-owner-sha "$SELECTED_CONTROLS_OWNER_SHA"
```

Require `SDK_CONTROLS_PASS` and closed ownership; record `SDK_CONTROLS_SHA` and `SDK_CONTROLS_OWNER_SHA`. The independent geometry acceptance is a **new** JSON with kind `selected-sdk-copied-geometry-acceptance-v1`, status `INDEPENDENTLY_ACCEPTED_FOR_FIXED_COPIED_SDK_STATE`, scope `selected-leaf-set-copied-state-v1`, and native_state `UNRUN_SEPARATE_REQUIRED`. It binds `build_result_sha256`, `build_revision`, exact `products`, and `sdk_build={path,sha256}` for the actual SDK build result. Retain all nine named premises, nonempty review/fact pins, complete table and source-page facts from the scalar geometry schema. Both table policies must be `whole`; extents/returns must be41/[34,40] and55/[40,54], first VA nonzero/page-aligned and upper VA=first+48. `caller={extent:20,continuation:15}` remains exact. Add `caller_state` with heads `[0,1,4,7,10,13,15,18,19]`, call13, outer_ret19, subject_rsp_delta16, stack_bytes152, and body_sha256 `732eb5cbc05ef8024c072c75ca3df69d08214cec8dc92beec456b1a5a3ff3046`. These are reviewed actual-byte requirements, not permission to copy old acceptance onto new files. A scalar acceptance or mixed policy cannot authorize this phase. Bind the independent new acceptance as `SDK_GEOMETRY`/`SDK_GEOMETRY_SHA`; no command here creates it automatically.

```bash
SDK_CONTROL_REFS=(--sdk-controls "$SELECTED_RAW/${SELECTED_TAG}-sdk-controls/result.json" --sdk-controls-sha "$SDK_CONTROLS_SHA"
  --sdk-controls-owner "$SELECTED_RAW/sdk-controls-owner.json" --sdk-controls-owner-sha "$SDK_CONTROLS_OWNER_SHA")
SDK_GEOMETRY_REFS=(--geometry "$SDK_GEOMETRY" --geometry-sha "$SDK_GEOMETRY_SHA")
for cohort in unstripped-k10 unstripped-k1000 stripped-k10 stripped-k1000; do
  sdk_owner sdk-cohort "$cohort" "${PRODUCT_REFS[@]}" "${SDK_BUILD_REFS[@]}" \
    "${SDK_CONTROL_REFS[@]}" "${SDK_GEOMETRY_REFS[@]}" --cohort "$cohort" || break
done
```

Each cohort freezes all192 keys and its exact48 requests before the first candidate, with four distinct owned DSO/app copies. Each key has one attempt. Every pair retains20CPU/30wall, the15-second internal deadline/20,000 steps per child,4MiB streams,1MiB generated CSV and the55-second helper backstop. Each public phase retains1200seconds/8MiB outer bounds. Four cohorts do not guarantee48 worst-case pairs fit1200seconds; deadline/custody failure retains all FAILED/UNRUN rows and never adaptively subdivides or retries. A normal functional failure may allow later fixed keys only after the unchanged custody/pin checks. The evidence reservation remains active through generated-file and semantic joins. Preserve all unsuccessful phases; a successful subset cannot establish the full population.

The final `SDK_COHORTS` input is a four-element JSON array in the exact cohort order. Each element has exactly `cohort`, `result={path,sha256}` and `owner={path,sha256}` referring to the actual closed cohort outputs. Set `SDK_COHORTS_SHA` to the whole JSON digest. Collection dispatches no candidates. It reconstructs raw helper requests/closures, full stdout/stderr and all39 CSV fields, exact producer/source/tool/product/geometry identities, one attempt per key and all16 group coverage joins. Fully closed failed outcomes retain their labels and prevent aggregate success; missing or uncertain custody refuses collection. Prior failure files are never rewritten.

```bash
sdk_owner sdk-collect sdk-collect "${PRODUCT_REFS[@]}" "${SDK_BUILD_REFS[@]}" \
  "${SDK_CONTROL_REFS[@]}" "${SDK_GEOMETRY_REFS[@]}" \
  --cohorts "$SDK_COHORTS" --cohorts-sha "$SDK_COHORTS_SHA"
```

Only the complete `SDK_192_STATE_PASS` result with successful final owner closure supports this finite scope. The actual SDK path reclaims epoch banks but retains installed executable owners until process exit; it does not retire/unpatch code. The copied complete machine caller includes CALL/store/outerRET and the owned stack/red-zone comparator before harness restoration, with the existing TF/RF mask and canonical kernel-exposed xstate comparison. This is not original-address Rust ABI, concurrent scheduling, K-exhaustion/rotation, every SDK instruction, arbitraryDSO/ABI, performance or strict2ms qualification. The old1280-pair profile and all scalar/core results/failures remain distinct. These new producer paths and fabricated controls require their own revision-pinned execution results; source alone provides no native credit.
