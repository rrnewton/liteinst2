This opt-in qualification extracts the complete `liteinst_csv_call_and_store` FUNC from the release Rust application, admits its bounded instruction/dataflow grammar, and copies its unchanged bytes into a guarded RX page. It compares execution through that body for exactly two fixed seeds × (16 CSV cases + eight bounded-length cases): 48 pairs, 96 children, 96 target CALL/RETs and 96 copied outer RETs. The outer RET executes and receives a full architectural-state comparison before restoring the harness. This qualifies the copied body under explicit machine entry conditions; the original application address, application call-site Rust ABI, complete worker and Schedule remain separate.

Run once from a clean exact revision under the [same external process owner and hard three-CPU reservation](../ordinary-module-session/README.md) used by the isolated ownership recipe. Use a fresh output directory, a 1,200-second outer wall and 8 MiB outer log cap. The script records reservation tag, affinity and load; the external allocator's actual hard reservation receipt must be retained separately. Affinity or a descriptive tag alone supplies no reservation authority.

```sh
python3 -B evaluation/ordinary-rust-invoke-native/reproduce.py \
  --revision "$REV" --reservation-tag "$TAG" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --raw "$REPO/ignored/NEW_COPIED_BODY_RUN"
```

The driver authenticates clean Git inputs before helper imports, pins all source/tools/build products, builds release artifacts with assertions and overflow checks, and retains complete application and DSO copies. Its middle reserved CPU runs the native parent and tracees. The fixed cohort executes once with the existing 480-CPU-second/510-wall-second bounds. Each native pair retains its continuous 15-second deadline and 20,000-step child limit. CSV and coverage tables each retain a 65,536-byte cap; successful stdout is at most 1,024 bytes and stderr must be empty. Any failure remains FAILED and any unstarted work remains UNRUN. There is no fallback, changed body, alternate population, retry or timing campaign.

All original 163 calibration controls remain required alongside ten admission and six adapter controls, with the same one explicit hardware-stop ignore. The existing 18 native and 26 Session Python controls also run, followed by ten copied-wire and four runner controls. The independently parsed whole-symbol disassembly supplies caller geometry to the transcript checker; the Rust parent retains the sealed Plan, exact page snapshot and original ELF owner through both normal reaps. Numeric rows do not independently prove instruction effects, full-state comparison or opaque ownership.

Only exit-zero, normal closure, unchanged source/artifacts, complete output and verified final retention can produce `COPIED_RUST_INVOKE_QUALIFICATION_PASS`. Raw logs and executables stay under `ignored/`; publish compact exact-revision receipts and pair/coverage numbers separately. Functional command durations are not performance measurements, and this qualification supplies no full A5 result.
