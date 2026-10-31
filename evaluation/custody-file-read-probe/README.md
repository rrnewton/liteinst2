# Fresh-file read split probe

This standalone Rust probe measures wall intervals around a fresh `File::open`, `Take(1_048_577).read_to_end` and ordinary `drop` on two distinct 13,360-byte fixture files. Both files and the compile-time expected bytes must have SHA256 **`ec282b162def940f84a37e8945adfb745a96991bd0c1458a3f782d6308d57b20`**. It neither loads nor calls the fixture. Compilation, controls and measurements are currently **UNRUN**.

The fixed campaign is five once-only processes. Each performs 64 warmup pairs followed by 256 measured pairs, candidate then trusted: **640 rows per process, 3,200 rows total**. Every row is retained, including warmup and failures. There is no calibration, retry, outlier filtering or performance threshold.

Each file keeps the original order: fresh pathname stamp, equality to an independently frozen stamp, buffer clear, fresh open, unchanged bounded std read, drop, complete-byte comparison, second fresh stamp equality. Only empty buffer capacity is reused. Four clock samples split open/read/drop and their total; do not add that total a second time. The read interval includes the open-result branch, Take construction and remaining-limit query. Stamps, reserve, comparison and output formatting are outside the component timers. Read allocation, clock overhead and preemption can be included; cache state is uncontrolled. Rust File drop does not report close errors. These are not syscall counts or exclusive CPU costs. Installed std source was not inspected, so extra reads are not asserted or ruled out.

The first failed row stops that process; subsequent planned rows are explicitly UNRUN. Unreached numeric fields are `-1`, not zero. A killed process or failed output remains incomplete. Stop the campaign on the first failed compilation, control, owner or repetition; later repetitions stay UNRUN. No replacement attempt is allowed.

## Reproduction payloads

An operator must first own the immutable input paths and source, hash the complete regular files and expected bytes, and freeze each input's eight-field stamp independently of the timed reads. Preserve before/after metadata stability and distinct `(dev, ino)` identities. The comma-separated stamp order is **dev, ino, mode, length, mtime_seconds, mtime_nanoseconds, ctime_seconds, ctime_nanoseconds**, all decimal; mode includes the regular-file type bits. Input and expected-byte paths must be absolute. Recheck these pins around compilation and execution; no live read may supply a replacement expected stamp.

Set `PROBE_RUSTC` to the authenticated stable compiler, `PROBE_EXPECTED` to the pinned expected-byte file, `PROBE_CANDIDATE`/`PROBE_TRUSTED` to the two pinned inputs, and `PROBE_CANDIDATE_STAMP`/`PROBE_TRUSTED_STAMP` to the frozen stamp strings. The private campaign companion records their exact token values and environment. It retains the original private source/plan history separately from this reviewed path-interface correction.

Use a fresh `target/evaluation/custody-file-read-probe-v1/` directory and one retained, disjoint HARD CPU. Run each payload through the existing [process owner](../admission/processes.py) around [bounded_command.py](../../tools/unwind-oracle/bounded_command.py), with authenticated tools, clean environment and fixed affinity. Compilation gets 60 CPU seconds/90 wall seconds/128 MiB file limits; controls and each repetition get 20 CPU seconds/30 wall seconds/1 MiB output. The operator supplies and records containment; the commands below are payloads, not an unbounded dispatcher. No shared target cleanup is needed.

```sh
probe_out=target/evaluation/custody-file-read-probe-v1
CUSTODY_PROBE_EXPECTED="$PROBE_EXPECTED" "$PROBE_RUSTC" --edition=2024 --crate-name custody_file_read_probe -C opt-level=3 -C debuginfo=0 -C codegen-units=1 evaluation/custody-file-read-probe/probe.rs --emit=link,dep-info -o "$probe_out/probe"
CUSTODY_PROBE_EXPECTED="$PROBE_EXPECTED" "$PROBE_RUSTC" --edition=2024 --crate-name custody_file_read_probe -C opt-level=3 -C debuginfo=0 -C codegen-units=1 --test evaluation/custody-file-read-probe/probe.rs --emit=link,dep-info -o "$probe_out/controls"
"$probe_out/controls" --test-threads=1 --nocapture
"$probe_out/probe" 1 "$PROBE_CANDIDATE" "$PROBE_TRUSTED" "$PROBE_CANDIDATE_STAMP" "$PROBE_TRUSTED_STAMP"
"$probe_out/probe" 2 "$PROBE_CANDIDATE" "$PROBE_TRUSTED" "$PROBE_CANDIDATE_STAMP" "$PROBE_TRUSTED_STAMP"
"$probe_out/probe" 3 "$PROBE_CANDIDATE" "$PROBE_TRUSTED" "$PROBE_CANDIDATE_STAMP" "$PROBE_TRUSTED_STAMP"
"$probe_out/probe" 4 "$PROBE_CANDIDATE" "$PROBE_TRUSTED" "$PROBE_CANDIDATE_STAMP" "$PROBE_TRUSTED_STAMP"
"$probe_out/probe" 5 "$PROBE_CANDIDATE" "$PROBE_TRUSTED" "$PROBE_CANDIDATE_STAMP" "$PROBE_TRUSTED_STAMP"
```

All eight original read controls remain mandatory: exact, empty, truncated, changed, appended, 1 MiB+1, beyond-cap and pre-open stamp mismatch. A ninth control checks argument refusals. They create only exclusive test files beside the target binary and use the same reader. No custom read loop or injected-I/O claim is introduced.

Authenticate normal owner closure before inspecting output. Retain commands, compiler/sysroot/linker and source identities, dep-info, binary hashes, CPU/load, all exits and raw numeric CSV. Preserve the stderr status separately; if the owner combines streams, retain the complete original log and extract the unchanged CSV lines only after closure. CSV phase 0 is warmup and phase 1 measured; file 0 is candidate and file 1 trusted. Status codes and missing-value semantics are defined beside `Row` in [probe.rs](probe.rs). Report all outcomes and per-repetition/per-file measured count, sum, min, median and max; keep warmup separate. Normal lease release is required.

This diagnostic cannot qualify profiler completion, accuracy, native state or performance. The [closed 01ca campaign](../ordinary-accuracy-results/coordinate-01ca/README.md) remains failed at 1,342/2,048 short rows, with long structural-only completion. The original 2 ms ARM, 520 ms/2,048-row short requirement, 43,200 denominator, fresh custody observations and all prior failures remain unchanged. No whole-profiler improvement follows from these isolated split costs.
