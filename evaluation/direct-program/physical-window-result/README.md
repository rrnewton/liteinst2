Full correctness validation passed; all three full-program rewrites FAILED. There were 18 original/E9 native passes and 9 LI2 cases UNOBSERVED. No LI2 executable was produced.

| Program | Selected | Local/withheld | Δ alphabet | Refused | LI2 emitted | E9 coverage |
|---|---:|---:|---:|---:|---:|---:|
| cat | 1,008 | 979 | +10 | 29 | 0 | 936/1,008 |
| head | 1,214 | 1,184 | +18 | 30 | 0 | 1,130/1,214 |
| wc | 1,645 | 1,569 | +14 | 76 | 0 | 1,544/1,645 |

Local acceptance rose by 42; atomic selection withheld every accepted member. Window refusals fell 65→15, ownership refusals rose 96→104, and 16 unsupported-semantics refusals remain. E9 misses 257 of 3,867 sites despite its native passes.

The workspace passed 4,758 raw tests (4,747 top-level + 11 nested), with 43 unchanged ignores; serial passed 1,039. All 215 focused controls passed, including three new router native controls. The earlier focused FAILED attempt and reviewed test-only correction remain in the receipt; production was unchanged.

[receipt.json](receipt.json) gives source, commands, bounds, loads and walltimes; [cases.csv](cases.csv) retains all 27 rows. The receipt documents named tables, pinned JSON references, normalized `${NAME}` paths and shared CSV fields. Blank seconds mean unobserved.

Reproduce with a clean exact revision, fresh namespaces, 12 reserved CPUs for validation, one CPU per release/corpus attempt, and the original GNU build. All fixed capacity gates apply.

Per-physical min5 seals retain the full jump/PUSH/POP union; complete code/ownership is caller supplied. No arbitrary-stack, complete-CFG, page-exemption, full-corpus or performance qualification follows. Prior failures/unknowns, including the older 16 MiB profile, remain historical; freestanding was not rerun.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
