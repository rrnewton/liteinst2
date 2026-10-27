Six ordinary validation phases passed at `16212e9ab00a18ce003a305f7265bce8633e1c0e` on the **AMD EPYC Zen 5 dev host**. The complete workspace contains 95 libtest groups and 2,279 named cases: 2,275 passed and four remain ignored. All 2,256 identities and raw statuses from the earlier `dd94a43b` workspace inventory are retained, with no doctest identity relocation. Exactly 23 added interval-entry model tests passed and were joined by name to their committed source. All three allocation regressions passed.

Targeted-profiler passed 225 observations across six groups. It includes three separate 26-case executions of the same calibration names: the calibration target and the two native-binary unit-test harnesses. These are calibration tests, not native campaign executions. Serial passed 995 cases; default-parallel library passed 218 with one ignored; prefixed and neighbor passed 30 and 74. These commands overlap the workspace. The 3,822 rows in `cases.csv` are repeated observations, not distinct tests. Nested child summaries, bare terminals and the custom backing-cleanup protocol are retained separately in `summary.json` and add no libtest credit.

`commands.csv` contains nine validation commands and one required-gates dispatch. `contexts.json` retains all 16 complete command/parent contexts using injective path roles; the exact inverse stays private. The four inner gate environments are derived from the saved outer environment and the exact pinned `required-gates.py` assignment, including `RUST_TEST_THREADS=4` and the gates directory as `TMPDIR`. That script did not save each environment independently, and each derived context says so. Recorded process cleanup is complete with zero reaped descendants under `pidfd_authenticated_proc_candidates`; this is the `run_command` record, not a separate bounded-command ECHILD receipt. Durations are operational observations, not performance measurements.

The interval-entry seam is enabled for tests only. Its model cases do not establish native callback pairing, interval exits, synchronization completion, normal-loader behavior, or full A3/A4 qualification. This cohort contains no native-build phase or native campaign review. Separate historical native failures remain failures. A pending or later native campaign cannot acquire authority from this report.

To repeat these six phases, copy this recipe directory outside the checkout and use a fresh checkout at the exact revision above. The saved run used Python 3.9 and Rust 1.97.1. `tool-versions.json` contains the full observed rustc version and exact cargo/rustc/rustdoc hashes. Offline dependencies and CPUs 0–7 must be available. The driver retains four build jobs, 8 MiB logs, four CPUs for targeted/required/serial, and eight CPUs for each parallel command. It disables debug information while retaining the normal development/test assertions and overflow behavior; no Rust flags override is supplied.

Install the byte-identical `validate.py` at `ignored/a4/interval-entry-validation-source-v1/validate.py`. Its SHA-256 must remain `a819f578148b1a0d8031b8add0b1dd6a0461b8d277fc7b75a9a6799d04a75ec4`. Materialize `launch.py.template` outside the checkout by replacing its three quoted string literals `${TOOLCHAIN}`, `${USER_HOME}` and `${CARGO_HOME}` with Python `repr()` values for the local paths. Those substitutions reverse to the actual recorded parent. The materialized parent's hash will reflect its local paths; no other source edit is needed.

From the fresh checkout, run the materialized parent once for each phase:

```sh
python3 -B /absolute/path/to/launch.py targeted-profiler
python3 -B /absolute/path/to/launch.py required
python3 -B /absolute/path/to/launch.py serial
python3 -B /absolute/path/to/launch.py parallel-library
python3 -B /absolute/path/to/launch.py parallel-prefixed
python3 -B /absolute/path/to/launch.py parallel-neighbor
```

The parent refuses existing phase output directories and records full commands, source pins and closure. Parent limits remain 240, 1060 or 420 seconds, with a bounded 10-second cleanup wait. Inner limits remain 180 seconds for targeted/serial, 1000 for the required dispatch and 360 for parallel commands. The four required gates retain 180/180/360/180 seconds. New results require fresh execution and source/tool/config observations.

`collect.py` performs saved-report projection only. With the private, exact input envelope and reviewed inventories:

```sh
python3 -B collect.py --inputs /absolute/path/to/inputs.json \
  --inputs-sha256 EXACT_INPUT_SHA256 --new-output /absolute/path/to/new-ignored-output
```

It executes no validation and reads no built products. The public results contain summaries, case identities/statuses, source hashes, tool facts and normalized contexts. Raw stdout/stderr, the input envelope, private paths and captures remain private. Reproducing validation uses the driver and parent; regenerating this report is a separate operation.
