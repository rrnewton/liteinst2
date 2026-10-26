# Retained source history validation

The complete six-command protocol passed on source
`a9d7f66a31e9ebe11e9bfcebaa95acdb7efcce40`. Historical plans, guards and
routes now authenticate against a separately retained source census, with live
source checks still required. This qualifies the foundation described in
[the protocol](source-history.md); full B3 and B4 remain open.

The [typed result](results/20261026T104603.280543Z-a9d7f66a31e9.json) has
SHA-256 `c575472598413be92d340abdc51880cebbdda8ace4641bd784bad706afc7cafd`.
It records 464 source identities, exact commands, toolchain and hardware,
capture hashes and cleanup. Source and configuration remained unchanged.
All six commands exited zero, completed cleanup and reported zero adopted
descendants. Raw captures remain private.

## Reproduction

From a clean checkout of the exact source revision:

```sh
python3 evaluation/admission/run.py --expect-revision a9d7f66a31e9ebe11e9bfcebaa95acdb7efcce40
```

Hardware was AMD EPYC 9D85, family 26, model 17, stepping 0, microcode
`0xb101066`, x86-64, with 316 visible logical CPUs. Linux upstream version was
7.1.3; the receipt includes the complete release hash. Execution was non-root
with effective capabilities zero. Rust and Cargo were 1.97.1. The protocol kept
four build jobs, four workspace test threads, serial launch execution, disabled
incremental compilation and the original deadlines, capture and cleanup bounds.

| Required command | Result | Seconds |
| --- | --- | ---: |
| Recorder calibration | 213 passed | 7.896 |
| `cargo fmt --check` | passed | 1.630 |
| Workspace/all-target/all-feature Clippy, warnings denied | passed | 0.101 |
| `cargo test --workspace` | 1,337 passed, 0 failed, 4 unchanged ignored; 77 harnesses | 301.842 |
| Workspace/all-target/all-feature `cargo check` | passed | 3.327 |
| Serial launch integration/unit oracles | 503 passed, 0 failed; 25 harnesses | 75.428 |

These durations describe validation commands, not application or hook
performance. Outer workspace totals exclude five completed nested tests and two
child starts without completion summaries, as required by the unchanged parser.

## Added controls and retained coverage

Eighteen pure tests exercise immutable source and mapping identity, foreign
bindings, retained-plan corruption, live/history independence, epoch continuity,
guard versus declared-head decoding, full page inventory and resource accounting.
They do not supply native stop, publication or source-replacement authority.

One native test has three mutation subcases: a missing reserved executable
mapping, changed file offset and changed pathname. Each reaches actual exec
EXIT and requires the exact refusal before bootstrap changes application code
or permissions. It compares all original image bytes and mappings, full GPRs,
XSTATE and signal mask, allowing only the actual exec EXIT result in RAX, then
requires physical application and helper cleanup. Both workspace and serial
runs passed this test. Three subcases remain one named fixture outcome.

Five added parser calibrations require that exact native identity, truthful
partial results and complete command/run success. They pin the previous 36
native identities and add exactly one. The serial result contains all 37 named
outcomes: 17 journal/capacity/dispatch, six B2 reference, eight reset, five
signal and one source-census control. It also retains the separate 50 static
instruction cases, 15 dynamic admission fixtures and 388 dynamic matrix cases.
These overlapping collections are not combined into an instruction sample count.

## Preserved failure and scope

The [first attempt](results/20261026T103540.768128Z-7113048e1b96.json) at source
`7113048e1b96616f12724dfa75e1a63ea143d982` remains failed, with SHA-256
`6d94b35cb3ef828f2345f2e00654af651fa02305bc6e7f82e820b382c53d66aa`.
Cargo exited zero, but the strict evidence parser rejected the old catalog's
202 launcher-unit count after 19 tests had been added. The two later commands
did not run. That receipt was committed unchanged before correction.

The correction raises the fixed source-derived counts to 221 launcher unit
tests, 1,341 total workspace cases including the four existing ignores, and 503
serial cases. It also requires the new native outcome explicitly. Rust code and
assertions were unchanged between attempts; no case, comparator, capacity,
deadline, cleanup or source/configuration check was relaxed.

This supplies systematic validation evidence for claim 4 and preserves the
existing finite page-admission and selected-interception evidence for claims 1
and 2. The catalog cannot replace a live source set, authorize a writer or alias,
or retire a saved continuation/CALL obligation. Actual admitted mapping changes,
fork/exec, dlopen, JIT invalidation and real-application coverage remain required
for B3. Persisted metadata and sparse-overlay agreement/fallback remain required
for B4. No preemption-clock, performance, Intel or CET qualification is added.
