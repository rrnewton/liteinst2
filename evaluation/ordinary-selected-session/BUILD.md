The public `owner.py` and `build.py` entrypoints prepare and run the fixed selected-scalar experiment using the existing process owner and bounded helper. They need a clean committed checkout, local offline Cargo dependencies, a stable Rust toolchain, GCC/binutils/Clang in `/usr/bin`, and exactly three externally reserved disjoint CPUs. `taskset` applies affinity; it does not reserve CPUs. Record the allocator's reservation tag and the actual hardware description. Keep the same revision and reservation for the sequence below, and retain all original Cargo product paths and private outputs through final verification.

The new public build schema is separate from the historical private receipts. Both historical build-script digest checks remain intact. Fresh receipts bind the tracked public producer's exact Git blob, literal argv, complete source snapshots, compiler/subtool hashes, all actual requests, bounded receipts and outer closures. No private script is required for the fresh path. The public owner accepts only the four named phases and delegates process supervision to `evaluation/admission/processes.py`; it neither supplies unsafe permission nor implements another process supervisor. Its active capture log is created in a fresh directory under `target/evaluation`, as that existing API requires. Only after confirmed cleanup does the adapter read the bounded log, require the exact closed digest, copy it exclusively beside the ignored owner JSON, and reread the copy. Unknown closure retains its original target capture and failure header without any additional wrapper log read or copy; the existing process owner itself remains unchanged. Failed archival remains failure; neither the capture nor prior evidence is deleted.

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

This requires the complete existing 92 Rust controls and 94 Python controls across 12 stages, including the release test inventory. Each stage retains the original 20 CPU-second/30 wall-second/1 MiB per-stream cap and 55-second helper-owner backstop. It does not dispatch the selected application campaign. The 21 additive fabricated public-builder controls are separately reproducible with `python3 -B evaluation/ordinary-selected-session/build_controls.py -v`; these fabricated controls do not validate an actual compiler, process owner or native candidate. Their result belongs in its own bounded execution receipt.

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

For the whole-function experiment, the independently reviewed geometry acceptance must have scope `selected-session-whole-functional-v1` and both policies `whole`. All nine original premises, the complete two-function bodies/returns/source pages, ordinary callers, stripping checks and independent scalar expectations remain required. Control and campaign receipts must use the same chosen profile; an otherwise valid certified-profile receipt cannot supply a whole-profile control or child result. The controls phase retains all 92 Rust and 94 Python checks and appends the ten `profile_controls.py` cases as a thirteenth bounded stage (104 Python checks total). The default profile retains its original twelve-stage, 94-Python-check replay shape. The new cases also run directly with `python3 -B evaluation/ordinary-selected-session/profile_controls.py -v` and provide only fabricated source/control evidence.

Both profiles keep all eight cells, the same unstripped/stripped inputs, K10/K1000 populations, 520 epochs, attempt limit one, full numeric wire/guard checks and unchanged process/evidence limits. No compiler flag, function extent, old assertion, deadline or failed result is changed by choosing this named profile. Native execution, architectural-state qualification and performance outcomes require separate revision-pinned receipts.
