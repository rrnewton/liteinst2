This record covers six closed validation phases at `dd94a43b7986509f70635896ab759659fbd81ba4` on the **AMD EPYC Zen 5 dev host**. All six phases passed. The workspace run contains 95 libtest groups and 2,256 named cases: 2,252 passed and four remained ignored. Every case identity and status from the earlier `50c0715e` workspace inventory remains unchanged, including the three allocation regressions. There are no doctest identity relocations in this comparison.

The serial launch run passed 995 cases; the default parallel library run passed 218 with one ignored; the prefixed and neighbor runs passed 30 and 74. These overlap the workspace run. `cases.csv` therefore contains 3,574 repeated observations, not 3,574 distinct tests. Child summaries, unsummarized child starts, bare terminals, and the custom backing-cleanup harness stay separate in `summary.json`; they add no libtest pass credit. All existing ignored reasons are retained.

`commands.csv` has nine validation commands and one required-gates dispatch. `contexts.json` preserves all 16 complete command/parent contexts, including each phase result and actual parent closure. Absolute paths use injective role placeholders; the inverse remains private. The four inner gate environments are derived from the saved outer environment and the exact pinned `required-gates.py` assignment, including `RUST_TEST_THREADS=4` and each gate output directory as `TMPDIR`; they were not independently saved by that script. This origin is explicit in every inner context. Each phase reports complete cleanup with zero reaped descendants under `run_command`'s recorded `pidfd_authenticated_proc_candidates` strategy. This is that helper's cleanup record, not a separate ECHILD receipt. Elapsed times are operational observations, not performance measurements.

The native build is count-free. Its Cargo record uses opt-level 0, debug information 0, debug assertions enabled, and overflow checks enabled. It does not execute the new native-point campaign. The implementation agent separately reported that the first campaign at this revision failed its initial mapping-permission check (one failed case and 12 unrun); that failure is outside this validation inventory and remains failed. This validation report does not review that campaign, establish readiness for landing, supply a new common-corpus result, or establish full A3 or A4 qualification. Earlier failed cohorts remain historical failures.

To repeat validation, copy this recipe directory outside the checkout, then use a fresh checkout at the exact revision above. The saved run used Python 3.9 and Rust 1.97.1; `tool-versions.json` records the full observed rustc version and exact cargo/rustc/rustdoc hashes. Dependencies must already be available for offline Cargo. CPUs 0–7 must be available. The caller retains four build jobs, 8 MiB logs, the existing process cleanup, four CPUs for serial/required/build and eight for the parallel commands. Debug assertions remain enabled when debug information is disabled.

Install the byte-identical `validate.py` at `ignored/a4/code-point-native-validation-source-v1/validate.py` in that fresh checkout. Materialize `launch.py.template` outside the checkout by replacing its three *quoted string literals* `${TOOLCHAIN}`, `${USER_HOME}`, and `${CARGO_HOME}` with Python `repr()` values for the local paths. No other source edit is needed. The three substitutions reverse exactly to the actual parent, whose SHA-256 is recorded in `summary.json`; the materialized parent's own hash will reflect its local paths. The driver SHA-256 must remain `b5d7f6652746fc0cf2c987997ce28d6122943c5cc2fbd5604fa8954726865c40`.

From the fresh checkout, invoke the materialized parent once per phase, in this order:

```sh
python3 -B /absolute/path/to/launch.py native-build
python3 -B /absolute/path/to/launch.py required
python3 -B /absolute/path/to/launch.py serial
python3 -B /absolute/path/to/launch.py parallel-library
python3 -B /absolute/path/to/launch.py parallel-prefixed
python3 -B /absolute/path/to/launch.py parallel-neighbor
```

The parent refuses an existing phase output directory, records complete argv/env/source pins, and retains bounded waits of 240, 1060, or 420 seconds with the original 10-second cleanup wait. The underlying phase bounds are unchanged: 180 seconds for build/serial, 1000 for required dispatch, and 360 for each parallel command; required gates retain 180/180/360/180 seconds. Fresh execution and its source/tool/config checks are required for new results; copying this report confers none.

`collect.py` only projects the authenticated saved logs, metadata, and complete independent inventories for this exact cohort. With the private input envelope and saved records it runs as:

```sh
python3 -B collect.py --inputs /absolute/path/to/inputs.json \
  --inputs-sha256 EXACT_INPUT_SHA256 --new-output /absolute/path/to/new-ignored-output
```

It does not run validation or read built products. The envelope and raw logs remain private. The public files contain summarized results, individual case identities/statuses, source hashes, tool facts, and normalized contexts; no raw stdout/stderr or memory captures are published. Repeating validation uses the driver and parent above. Regenerating the report uses the saved-evidence projector and is a separate operation.
