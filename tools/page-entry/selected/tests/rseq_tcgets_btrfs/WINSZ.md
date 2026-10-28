# Finite TIOCGWINSZ extension

The explicit `LI2_RSEQ_TIOCGWINSZ_BTRFS` profile adds only request `0x5413` to the existing trusted-parent btrfs FD1 contract. Both commands must actually return `-ENOTTY`. Source review and supplied-data controls do not qualify native execution, general ioctls, application completion or performance.

Run the unchanged exact-revision prerequisite producers for positive6, failure49 and inactive-rseq17, then use their full private receipts with one reserved CPU:

```
python3 evaluation/inprocess/page_selected_rseq_native_boundary_run.py \
  --expect-revision "$REVISION" --tiocgwinsz-btrfs \
  --positive-receipt "$POSITIVE_PRIVATE_RECEIPT" \
  --negative-receipt "$FULL49_PRIVATE_RECEIPT" \
  --rseq-receipt "$FULL17_FAST_RSEQ_PRIVATE_RECEIPT"
```

The driver first runs all original sixteen registered-native cases, four boundary pairs, twenty macro-off TCGETS pairs and sixteen supplied TCGETS refusals. Their original readers, outcomes, command bounds and completion checks remain required. The additional cohort has seventeen same-ELF native/gated pairs and one gated result-injection control, specified by `WINSZ-CASES.json`. It adds156 commands and35 subject processes:25 exit0 and10 required exit125. No historical subject is counted again.

Seven TIOCGWINSZ positives use the original normal buffer, null, actually unmapped page, zero publication word, actual startup vDSO, proven subvolume and same-open-description duplicate. Nine refusals retain prior close, close/restore, adjacent requests `0x5412`/`0x5414`, high-bit request `0x100005413`, FD3/-1/high-bit FD, and FIONREAD at the publication word. The FIONREAD native lane is still a genuine before-operation prefix, not a forwarded call. One additional TCGETS case0 pair runs on the new bridge to qualify its separate command counter. The result-injection control retains the real raw `-ENOTTY` separately before supplying zero; the operation must fail125 with neither counter nor frame commit.

All native/gated frame, FP, source, application data/stack, registration page, signal-envelope ownership and trusted-parent FD/subvolume joins use the original complete readers. The existing subvolume proof must succeed on an actual capture FD; there is no path-based assumption, setup fallback or skipped case. The additional observer state consists only of the production's two appended64-bit command counters. Actual new DWARF must preserve every field and offset from the freshly built macro-off bridge, with exactly16 extra bytes. Every earlier stage has zero counters; successful result validation and terminal stages have exactly `[1,0]` for TCGETS or `[0,1]` for TIOCGWINSZ. Refusals and the injected result retain `[0,0]`. The complete report joins those actual bytes and original retained request. A genuine second frame remains necessary for architectural commit.

Subject limits remain5 CPU seconds/15 wall seconds/512MiB/16MiB capture, and links remain30 CPU/60 wall with the same memory/capture limits. The added recipe `build-winsz.sh` changes only the fixed request-selection macro; it does not change the original recipe. The helper uses the same Build/invoke/source/tool/header/ELF/DWARF/namespace/capture closure. Qualification failures remain failures, including partial builds, missed frames, unexpected errno or incomplete cleanup.
