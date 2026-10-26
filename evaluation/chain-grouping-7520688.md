# Grouped successor-chain result at 7520688

At `752068868f78279d2953082ceb4d54efe510d0d4`, all four unchanged required workspace gates passed on the **AMD EPYC Zen 5 dev host**. The fixed depth-two B2 chain retained four virtual pages while sharing one sealed 4 KiB backing page. Its observed selected image was 300 bytes; the virtual address span was 1,835,634,688 bytes, with only 16,384 mapped bytes.

The cohort completed 12 original, 12 installed and 12 retired traces over six entry heads and two existing state seeds. The unchanged `NativeOracle` passed 108 full-state comparisons covering registers, defined flags, extended state, application memory and stack. These are successful source assertions; individual machine-state snapshots were not serialized. The cohort also passed exact shared RX page/owner and PC-ownership assertions, one late collision rollback before source writes, and four refused writable permission upgrades. The [observed case](results/chain-grouping-7520688/case.json) preserves the actual counters.

The workspace log has 63 outer groups with 1,056 passes, zero failures, four unchanged ignores and zero filtered tests. Five completed one-test nested summaries are counted separately; two guard-child starts receive no separate terminal credit. [Summary](results/chain-grouping-7520688/summary.json), [four command rows](results/chain-grouping-7520688/commands.csv) and [file hashes](results/chain-grouping-7520688/files.json) retain the source, hardware, request/environment and log identities. Elapsed times are operational diagnostics, not performance measurements.

Use the checked-in [recipe](chain-grouping/reproduce.py) and its [instructions](chain-grouping/README.md) from a clean checkout of that exact revision. With Python 3.9, Rust 1.97.1, GCC, locked offline Cargo dependencies and Linux x86-64 ptrace permission for owned children:

```sh
"$PYTHON" -B "$REPO/evaluation/chain-grouping/reproduce.py" \
  --raw "$RAW" --toolchain "$RUST_TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

`RAW` must be a fresh absent absolute directory strictly beneath `REPO/ignored`, with an existing canonical parent. The toolchain and home directories must be canonical existing directories. The summary defines all coordinate tokens and the complete recorded dispatcher environment; each gate inherits it with the exact listed overrides, including `TMPDIR=$RAW/gates` and four test threads. This recipe command is derived from the checked-in recipe; the captured dispatcher invocation is separately preserved in the summary. Raw logs, process maps and isolation records remain private under `ignored/`.

The original gate wall limits remain 180/180/360/180 seconds, with four build jobs and no incremental compilation. The native cohort retains 20 CPU seconds, 30 wall seconds, a two-second owned-cleanup deadline and a 16 MiB per-file limit; each existing native trace retains 15 seconds and 20,000 steps. No placement failure becomes a skip.

This supports one bounded chain-grouping slice of claim 4. It does not establish exhaustive grouping, full A2, CET, Intel-host behavior, claims 1–3 or performance. Earlier results remain separate. The packet author authored the grouped native fixture; the summary identifies the independent actual-campaign review.
