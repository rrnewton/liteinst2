# Common-corpus production with original-derived placement

The full campaign at `29be7f8424e75ae16ed92a5d9df7459d821474d0` completed all **74 stages: 62 passed, 12 failed, none unrun**. Its enclosing process returned 1 after 186.541016 seconds. This is a failed structural campaign; the duration is an operational observation, not a benchmark. Hardware: **AMD EPYC Zen 5 dev host**; four-CPU affinity.

All eight cells retain the complete 87-head corpus and nine jump sites or one heap-store site. Each selection is compared with both the stock-algorithm and bootstrap-patched-reference E9 lanes. Both retain the pinned PLDI'20 revision and their documented build/transport adaptations.

| Selection across both hooks and strip forms | Core production | E9 production/adapters | Site comparisons |
| --- | --- | --- | --- |
| Four heap-store cells | 4 passed, B1 candidates emitted | 8 producer and 8 adapter passes | 8 passed; the selected E9 trampoline site is retained in every comparison |
| Four jump cells | 4 failed; no partial candidate | 8 producer and 8 adapter passes | 8 failed; all nine E9 trampoline sites are lost in every comparison |

Every jump report retains the same per-site failures: IDs 14, 24, 32, 36, 49 and 64 have composition `ExpectedBytesChanged` (10001); ID 15 has core `NoPatchWindow` (9); IDs 41 and 81 are withheld by the atomic-selection rule (10003). The placement refusal does not explain away the composition failures. No selected site is dropped, and no trap fallback is relabelled as a trampoline.

Reproduce with [produce.py](e9-common-app/produce.py) and its complete [input/command contract](e9-common-app/PRODUCTION.md), using this exact clean revision and fresh output coordinates. Build the inputs using [build_inventory.py](e9-common-app/build_inventory.py) with `--allocation-profile original-derived-v1`; the [build results](e9-common-placement-29be7f8.md) record all four workspace gates and 1,694 passing tests. All original stage budgets, source/owner checks, slot sizes, search bounds and the 1 GiB span cap remain unchanged. E9 does not consume the core's placement permits, so this is not an identical-allocation-policy comparison.

[CSV/JSON results](results/e9-common-production-29be7f8/summary.json) preserve all stages, cells, per-site comparisons, exact commands, revisions, hardware and artifact identities. Raw logs and binaries remain private. Historical fixed-arena failures remain separate records.

This adds partial evidence for claim 4 (systematic tactic validation). No original or rewritten application, native oracle, paired architectural-state, ABI/unwind/CET or performance campaign ran here. Successful heap-store production is not execution equivalence. The jump losses fail the E9Patch subsumption gate; full A3 remains open.
