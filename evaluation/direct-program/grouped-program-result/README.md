# Grouped jump and register-stack corpus

**All three declared attempts FAILED** at `52ec3184b994cf10eb6cdfcbd8c8a361d7e14961`. The separately named `jumps-gpr-stack64-block-observation-v1` planner retains the complete `jumps-gpr-stack64-v1` selection. All **27 planned native rows** remain: 18 original/E9 PASS and nine LiteInst UNOBSERVED.

| Program | Selected | LiteInst outcome | E9 coverage |
| --- | ---: | --- | --- |
| cat | 1,008 | 128 core refusals; 880 accepted members withheld atomically; 0 emitted | 936/1,008; 72 misses |
| head | 1,214 | 204 core refusals; 1,010 accepted members withheld atomically; 0 emitted | 1,130/1,214; 84 misses |
| wc | 1,645 | FAILED_UNVERIFIED: SIGXFSZ at the unchanged 64 MiB ledger limit; no authenticated COMPLETE/report; planning and emission counts unknown | 1,544/1,645; 101 misses |

Cat has 817 policy units, including 74 groups; 777 units were locally accepted. Head has 951 units, including 93 groups; 896 were locally accepted. Complete member accounting preserves selected jumps, register PUSH/POP, RSP and refused sites. Local acceptance does not produce a partial executable. Neither backend established full structural coverage in these attempts.

[results.csv](results.csv) contains each planned case, its input/expected-output identity and observed outcome. Blank observed fields mean unobserved. Native PASS requires exact stdout, exit zero and empty stderr. [receipt.json](receipt.json) records exact source/tree, release products/tools, commands, CPU reservations/load, limits, capacity, owner outcomes and refusal counts. Durations are individual validation observations, not a performance comparison. All 66 functional child owners closed with complete cleanup and zero rescues, including the failed generators.

Reproduce from a clean checkout of the exact revision using the [corpus protocol](../CORPUS.md), its pinned GNU coreutils 9.5 inputs and external E9 tools, and [reproduce.py](../reproduce.py). Reserve one CPU per sequential invocation, use fresh work/unit names and new receipt hashes, and replace the protocol's rewrite selector with:

```text
--rewrite-profile jumps-gpr-stack64-block-observation-v1
```

Run exactly one invocation each for `--program cat`, `--program head` and `--program wc`; preserve failed exit statuses and all nine rows per invocation. Use the recorded release settings: optimization level 3, debug information off, assertions and overflow checks on. The receipt's normalized argv records the actual commands; its placeholders identify local directories, not shell expressions. Raw captures remain private.

Hardware: **AMD EPYC Zen 5 dev host**. The [correctness campaign](../grouped-program-validation/README.md) passed; the [earlier ungrouped failures](../jump-stack-result/README.md) and separate jump-only successes remain unchanged. Caller complete-code/ownership, helper-stack and zero-bias loader obligations remain unproved. These finite results do not qualify full-program coverage, complete CFG recovery, runtime page exemption or performance.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
