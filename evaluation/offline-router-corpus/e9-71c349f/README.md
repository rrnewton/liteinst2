# Complete-program E9 structural comparison

At `71c349f3c83ca61b0f8d8a0f6d1961d9478b5d23` on the AMD EPYC Zen 5 dev host,
all eight fixed E9 commands and all four structural comparisons passed.
Checksum and RLE include their complete startup streams: 187 original
instruction heads and 42 selected jumps. Both the pinned PLDI2020 algorithm
and the separately disclosed bootstrap-patched reference emit trampolines for
all 42 sites; LiteInst retains every one. There are zero lost E9 trampoline
sites and zero E9 trap sites in this cohort.

`sites.csv` records every one of the 84 site/lane observations, including both
tactic choices. `results.json` records the exact commands, tool/input/product
hashes, all stage results, CPU reservations, load averages and unchanged limits.
Six common preparation/build/verification stages also passed. Raw artifacts and
logs stay in ignored storage. These durations describe command completion;
they are not performance measurements.

The directory-enumeration repair keeps the exact eight-file closure check.
It opens a fresh description relative to the retained directory owner, avoiding
the reproduced stale two-file enumeration. The two preceding attempts remain
FAILED in [their records](../absolute-c712f70/README.md); this result uses the
repaired source and a new fixed campaign.

All **80 application-output rows remain UNRUN**. This structural result supplies
no native full-state, ABI, unwind, CET, route-coverage or performance qualification,
and does not complete A3. The programs form a finite authored corpus, not a
general compiled-program corpus.

To reproduce, use `../reproduce_preparation.py` for the six recorded common
stages, then `../../offline-corpus/full_startup_e9.py` and the explicitly selected
`produce` phase of `full_startup_e9_execute.py`. The exact argv, revision, external
hashes and one-attempt bounds appear in `results.json`. Generate fresh actual
source/build/platform records in new ignored directories; `$ROOT`, `$TOOLCHAIN`,
`$CARGO_HOME` and `$USER_HOME` are local path substitutions. The separate `outputs`
phase requires a completed independently admitted ordinary execution result and
was not invoked here.
