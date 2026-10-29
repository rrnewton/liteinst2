The two selected normal functions preserve architectural state across four
continuous calls at 28290e363bf2d3f269bb023a8e0c021636b93422. Each child calls
CSV → bounded length → CSV → bounded length using one seed and one final
restore, with actual CALL/result-store and RET checks between functions.

One fixed release qualification ran K16 then K1, once each, without retries:
64/64 original/candidate pairs passed, with 24,568 full-state comparisons and
zero mismatches, 512 target calls/returns, 128 actual outer returns and 128
normal child reaps. K16 covers four sampled slots; K1 covers two sampled slots
and two FunctionClosed calls. Function identity, global slots/sequences,
function-local ranks, all 512 journal words, three next-entry acknowledgements,
final caller checkpoint, Report/history and process closure remain mandatory.

Both RETs of each function were observed for each seed and K. CSV coverage is
38/42 heads and 45/49 edges, explicitly partial path coverage. Bounded length
covers all 13 reachable heads and 14 edges. Complete independent final ELFs
retain the 126-byte CSV and 41-byte length functions on one source page, plus
the distinct 123-byte/40-head helper. Root rechecked their executable ELF
extents, all 64 pair rows, four coverage rows, 540 source files, 12 tools and
208 original retained evidence pins. The four CSV files retain every pair and
coverage result. Full state and actual reap checks remain source-authenticated
native assertions; the tables do not reconstruct them or record child PIDs.

Hard reserved CPU 35; one-minute load 36.04 to 39.96. K16 and K1 owners closed
normally in 71.896 and 66.629 seconds; whole qualification took 292.740 seconds,
with zero rescues. These are operational durations, not performance numbers.
Release uses opt3/debug0, assertions and overflow checks, four build jobs and no
incremental build. All original limits remain: absolute 15 seconds per pair,
20,000 cumulative steps per child, 510-second cohort owner and 480 CPU seconds
per process. All 19 prerequisites passed, including 159 active calibrations,
one existing ignored hardware control, four caller controls and twelve Python
controls. The receipt records the exact revision, recipe, commands, hardware,
reservation, load, artifacts, review hashes and development corrections.

All seven exact-source checks passed: default-parallel workspace reported
3,169 passes, zero failures and 36 ignores in 349.799 seconds; serial launch
1,039 passes; staged allocation three; prefixed-pun 36; fmt, strict workspace
Clippy and all-feature/all-target check. Workspace totals are the checker's
reported terminal observations and can include nested child summaries.

This qualifies the two bodies under the four-call C helper. It does not qualify
full state for the separate Rust application caller, the opposite first-call
direction, arbitrary/nested modules, accuracy, performance or full A5. Earlier
fixed five strict 2 ms outcomes remain FAILED, PASS, PASS, FAILED, PASS; no sixth
attempt. Raw logs and ELF captures remain ignored.
