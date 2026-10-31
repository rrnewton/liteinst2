# Accuracy roster controls

The first attempt remains FAILED: 99 tests passed, one AST guard failed, and an owner invocation missing `-I` ran none of its four tests. Correcting that invocation produced four passes. A source repair then produced 17 CallPair passes under each Python interpreter. Only empty `type_params` metadata is normalized; the exact historical semantic digest, nonempty-field refusal and all old assertions remain.

[receipt.json](receipt.json) records all commands, outcomes, source hashes, CPU reservations, load and closure. The first two attempts ran at `0ac5765e` plus source later committed as `fd3364d8`; the third ran at `fd3364d8` plus the pinned AST repair. Full revisions and overlay maps are recorded. Interpreter binary hashes were not captured.

Reproduce the tracked script argv in the receipt from `${ROOT}` with its parameterized environment. The private roster driver runs its eight rows in order with `PYTHON39 -B script -v`, each with a 60-second timeout; the AST driver runs the two listed interpreter commands with that same timeout. Corrected owner argv requires `-I -B`. Existing process supervision supplies the recorded 1,200-second/8-MiB outer bound. Private driver hashes describe the historical run; the tracked entrypoints reproduce the assertions.

The accuracy suite repeats the 13 legacy SDK tests; executions are not summed as new coverage. The [earlier preparation](../preparation-0ac/README.md) remains failed. These Python controls grant no executed Rust-roster, native, PMU, cadence, strict 2 ms or performance qualification. See [BUILD](../../ordinary-selected-session/BUILD.md) and [STATE](../../ordinary-selected-session/STATE.md) for separate prerequisites. Raw logs remain private.
