# Eight-call native batch state qualification

The source-provenance batch API amortizes the file and mapping checks across
eight ordinary calls. Its unsafe contract requires the source, input and stack
to remain valid and immutable, on the same actual thread, throughout the batch.
The owner refuses abandonment, incomplete finish and a ninth call. The separate
[owner qualification](BATCH-OWNERS.md) exercises these lifecycle failures.

```sh
python3 -B tools/rapid-profiler/tree-work/verify_hardware_stop.py \
  --batch-state --revision "$REVISION" --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

This requires a clean tracked checkout at the exact revision. The runner first
passes the actual [hardware-stop prerequisite](HARDWARE-STOP.md), then runs ten
batch parser controls, four Rust protocol controls and four native pairs:
two fixed cache cases with two seeds. Each pair runs an original child and an
installed child, each making eight calls and consuming a successful batch
finish before normal exit. All code is built in release mode with optimization
level 3, debug information off, assertions and overflow checks on.

Calls 1 and 8 each compare 343 ordered states: 332 application visits and
11 gate boundaries. They compare registers, flags, segments, TLS bases,
canonical XSAVE, input, source, installed images and the unmasked application
stack. The parent reconstructs the operand trace from
the original execution for those calls. Calls 2–7 check the scalar result,
frame protocol and actual outer CALL/RET and application CALL/RET transfers;
they receive no full-state or operand-trace credit. Each child uses one
continuous explicit-step counter capped at 20,000 and its pair has one absolute
15-second deadline established before allocation or fork. CONT instructions
are not counted as explicit steps. Neither counter nor deadline is reset.

The fixed population is 64 root invocations, 2,744 full-state comparisons,
304 authenticated hardware stops, 192 application transfers, 64 outer CALLs
and 64 outer RETs. The installed children also verify 64 rows, 128 journal
events and 64 report records against their actual invocation identities and
cursor state. These checks and eight batch finishes are source-attested before
normal child exit; the CSV does not independently reconstruct those objects.
Every middle CALL/RET step requires hardware RF clear in the actual registers.

The runner requires normal exit, ECHILD and zero cleanup rescues at every stage.
A failure remains a failed attempt. The CSV parser requires all four rows in
order, every field, exact scalar results, continuous step joins, the complete
terminal record and empty stderr. Mutation controls reject omissions,
duplicates, changed values, numeric grammar violations and malformed output.

The public receipt records the exact revision, commands, hardware, artifact
hashes, source-manifest digest and measured counts. Keep private requests,
logs and full manifests under `ignored/`; copy only the summarized JSON and
four-row CSV to `evaluation/`. This route provides correctness evidence for
the fixed batch population, with no performance or clock-accuracy result.
