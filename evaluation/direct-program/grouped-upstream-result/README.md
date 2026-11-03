# Bounded upstream jump and register-stack corpus

**All three declared attempts failed at revision `319d363a0094ca8fcb0d1bf768a35799733d5700`.** The separate `jumps-gpr-stack64-block-upstream-v1` profile retains the complete jump/register-stack selection and the original limits. All 27 native rows remain: 18 original/E9 PASS and nine LiteInst UNOBSERVED.

| Program | Selected sites (jump/push/pop) | LiteInst | E9 structural coverage |
| --- | --- | --- | --- |
| cat | 1,008 (751/111/146) | 88 core refusals; 920 atomically withheld; 0 emitted | 936/1,008; 72 misses |
| head | 1,214 (870/143/201) | 80 core refusals; 1,134 atomically withheld; 0 emitted | 1,130/1,214; 84 misses |
| wc | 1,645 (1,228/177/240) | FAILED_UNVERIFIED; counts unknown | 1,544/1,645; 101 misses |

WC's LiteInst process exited with signal 25 (SIGXFSZ) under the unchanged 64 MiB file limit. Postclosure `lstat` recorded a 67,108,864-byte partial ledger; no authenticated COMPLETE or report existed. Planning, refusal and emission quantities remain unknown. There was no retry, higher cap or compact-ledger substitution.

[results.csv](results.csv) retains every program/arm/case and catalog input/expected-output identity. PASS requires exact stdout, exit zero and empty stderr. Blank observed fields are unrecorded; LiteInst rows are UNOBSERVED because no candidate was produced. E9's three native matches per program do not satisfy its separate full structural N/N gate. Across the corpus E9 covered 3,610/3,867 sites, leaving 257 misses.

Cat and head locally accepted 40 and 124 more members than the [prior exact grouped attempts](../grouped-program-result/README.md). All those members were withheld atomically, with no LiteInst native execution. This is a planner observation, not a successful candidate or a performance result.

[receipt.json](receipt.json) records exact source/tree, scripts, tested original/E9 and release-product hashes, tool versions, actual normalized argv, CPU/load, bounds, capacity, class/group counts, refusals and closure. All 66 inner owners and three functional outer owners completed cleanup with zero rescues; inner exits were 63 zero, two exit 2 and one signal exit -25. Durations are observations only. Hardware was the AMD EPYC Zen 5 dev host; CPU reservations were root-attested, with recorded affinity rather than an independent reservation-ledger witness.

To reproduce, use a clean checkout of the exact revision above, the [corpus protocol](../CORPUS.md), pinned GNU coreutils 9.5 originals and E9 tools, and [reproduce.py](../reproduce.py). The receipt contains the literal release argv and three functional argv arrays, with directory placeholders documented there. Supply your directory paths, unused work/unit names and newly computed release/build receipt hashes; keep each invocation under a separate external one-CPU reservation. Make one release, then one explicitly selected invocation each for cat, head and wc using `--rewrite-profile jumps-gpr-stack64-block-upstream-v1`. Unit names must start with `li2core-direct-cat-`. Keep inline storage, all resource limits, the 160 MiB functional reserve and whole-slot ceilings unchanged. Release settings are opt-level 3, debug off, assertions and overflow checks on.

The prior grouped and [ungrouped failures](../jump-stack-result/README.md), separate jump-only success and [correctness history](../grouped-upstream-validation/README.md) retain their outcomes. Caller complete-code/ownership, helper-stack and zero-bias loader premises remain unproved. These finite trials grant no complete CFG, runtime page exemption, broad stack/fault semantics or throughput qualification.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
