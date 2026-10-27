# Complete common-corpus comparison at e8a8b6d

At `e8a8b6d447673aa7b98e00ff18df2eedf5e07d82`, all **357 stages and 192 ordinary executions passed**, followed by all **16 additional E9-null stages**. The combined controlled replay covers **24 cells, 4,224 pairs, 8,448 children and 12,672 live state comparisons**, with zero mismatches. Cells cover stripped/unstripped images, jump-site/heap-write selection, null/recording hooks, and LiteInst/stock-E9/bootstrap-patched-E9 lanes. Each cell retains all 87 original heads, 174 normal pairs and two fault pairs.

The NOP correction preserves exact scanner bytes, including segment/operand prefix ordering. Address and length now identify each source NOP independently of iced's semantic equality. The original exact-byte witness remains unchanged. This run completes the previously outstanding 704 core-null, 2,112 recording and separate 1,408 E9-null pair populations. It does not complete every A3 requirement or establish arbitrary-program, ABI or unwind support.

[full](full/) and [e9-null](e9-null/) contain the actual normalized invocations, compact receipts and complete numeric CSV rows. [validation.json](validation.json) records all required gates: 2,468 outer named workspace tests passed, zero failed, four ignored; strict Clippy, fmt, check, serial launch and historical allocation regressions passed. Five nested child summaries are not counted again. Development builds use opt-level 0/debug-info 0 with assertions and overflow checks. Hardware is the **AMD EPYC Zen 5 dev host**, with the observed CPU/kernel/libc and four-CPU affinity recorded in each receipt. Durations are operational, not performance measurements.

Comparisons use the existing live Rust GPR/flags/XSAVE/stack/data/generated-code/journal checks. Saved schema/hash corroboration and lossless capture retention are separate from an independent saved-state replay, which is not claimed. All 24 capture trees were verified and compressed privately; raw logs, captures and path-bearing metadata remain ignored. Two denied configuration lookups remain content-unknown; classified observations stayed equal. [failed-attempts.json](failed-attempts.json) preserves all three earlier failed attempts and their partial populations.

## Reproduce

Use a clean source checkout at the exact revision, the pinned six E9 products, an offline Rust 1.97.1 cache, and the target layout accepted by the script. Keep this report directory outside that source checkout. Populate [tools.example.json](tools.example.json) with canonical absolute tool paths; its `toolchain` value names the toolchain's **bin directory**. Then run:

```sh
python3 -B "$REPORT/run_all.py" \
  --repo "$SOURCE" --tools "$TOOLS_JSON" \
  --raw "$SOURCE/ignored/common-new"
```

`run_all.py` supplies the same 7,200-second full-run and 4,500-second continuation parent bounds, four CPUs and 16-MiB parent logs. It saves the actual successful full closure and pins it, the receipt and the result list before continuing. The recorded executions used these exact child scripts under separate parents; the convenience launcher is source-reviewed and was not itself used for this recorded run. Its optimization refusal and help checks passed, recorded in [preflight-checks.json](preflight-checks.json). Child limits and all cases remain fixed. Synthetic controls are `test_reproduce.py` (13 methods) and `test_continue.py --reproducer reproduce.py` (four methods), both passed for these script bytes.

The fresh release comparison on two additional programs is in [offline-corpus-e8a8b6d](../offline-corpus-e8a8b6d/). Functional caller-owned preemption evidence is in [owned-loop-5eca3cb](../owned-loop-5eca3cb/).
