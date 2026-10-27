# Normal ELF debug0 corpus at f454ba1

All 27 B1 stages and 93 tactic stages passed at
`f454ba175197c47f15e73bc5027a2506980dc413` on an AMD EPYC Zen 5 dev host:
19 entry heads, 20 candidates, 76 original and 152 rewritten traces,
748 live state comparisons and 30 ordinary executions. This cohort has no failed or unrun stage.

The CSVs preserve observed family counts, all 120 stage exits and original
duration values. All 119 strict helpers reported ECHILD. Both recipe
supervisors completed cleanup with zero rescued descendants, and B1 closed
before tactics received its prerequisite flag.

The explicit debug0 profile keeps optimization level 0, debug assertions and
overflow checks enabled. Durations are validation observations, not performance
measurements. Review checked all stage/receipt/source/profile joins and 12,362
capture hashes. The native driver performed the live register, flag, XSAVE,
data and stack comparisons; this review is not architectural replay.

Repeat using [the tracked recipes](../elf-exec/README.md) at the exact revision
with `--build-profile dev-debug0-v1` for both, fresh ignored output paths,
cached dependencies and one target directory. Run tactics only after B1 passes
and its parent and descendants are reaped. Retain all original supervisors and
bounds; do not add another timeout process. The receipt contains normalized
commands, environments and source/tool hashes. Raw logs, captures and path
inverses remain private. READ_DENIED configuration observations establish no
contents or absence; tool pins do not establish complete library closure.

Earlier profile controls separately passed at 2b18607: two accepted records
and 28 refusals, with no native credit. This finite authored ET_EXEC result
covers stripped/unstripped files and null/recording hooks. It does not qualify
general binaries, PIE/DSO, unwind, CET, SIGILL routing, E9 comparison or other
vendors, or complete the separate 704 core and 2,112 recording pairs.
`qualification_complete` remains false.
