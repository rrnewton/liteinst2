# Cross-function planner validation at be886cc

`validate.py` is a byte-identical export of the driver used at tested revision `be886cc1637630985bef497ad2d6376facdb883f` (SHA-256 `138dac66abdfe8cd41f1345c4e7faee468d54a6fd6302d0a673b9b9a64353aae`). It runs the targeted source/engine contracts, the four required workspace gates, a serial launch-crate run, and separate default-parallel library and prefixed-pun runs. These are five driver phases and eight actual validation commands: the required phase dispatches four inner commands. Its parent is reported separately, not as a ninth validation command.

Copy this directory outside the checkout before checking out the tested revision. With a clean exact tested checkout, the recorded Rust 1.97.1 toolchain, its dependencies available offline, CPUs 0–7 available, sufficient disk capacity, and fresh output/log paths, run the existing driver for each phase:

```sh
CF_REPO=/absolute/path/to/checkout
CF_DRIVER=/absolute/path/to/export/validate.py
CF_TOOLCHAIN=/absolute/path/to/the/recorded/toolchain
CF_USER_HOME=/absolute/path/to/user/home
CF_CARGO_HOME=/absolute/path/to/cargo/home
CF_RAW="$CF_REPO/ignored/cross-function-reproduction"
mkdir "$CF_RAW"
for CF_PHASE in targeted required serial parallel-library parallel-prefixed; do
  /usr/bin/python3.9 -B "$CF_DRIVER" --repo "$CF_REPO"     --output "$CF_RAW/$CF_PHASE" --toolchain "$CF_TOOLCHAIN"     --user-home "$CF_USER_HOME" --cargo-home "$CF_CARGO_HOME"     --phase "$CF_PHASE" || break
done
```

The driver refuses an existing phase output or `target/evaluation/<phase>.log`; use a fresh checkout/output context. It authenticates the exact revision and unchanged tracked sources before each phase. This example reruns validation; it does not recreate the historical recorded owners or timings. The report collector is a separate saved-record transformation.

The driver keeps `CARGO_INCREMENTAL=0`, four build jobs, offline Cargo, empty Rust flags/wrappers, and dev/test debug information disabled. It does not disable debug assertions. Required gates use four test threads and their unchanged 180/360-second limits. Serial uses `--test-threads=1 --nocapture`, four CPUs and a 180-second command bound. Library and prefixed runs use default test threading, eight CPUs and 360-second command bounds. The targeted four integration targets retain all 23 tests (9 + 9 + 1 + 4) under a 180-second bound. Complete argv, environment, affinity, limits, process cleanup, parent closure and operational timings are projected from each actual record.

`collect-cross-function.py` takes a private caller-pinned record index and authenticated closed-log inventories. It emits summary JSON, full command JSON/CSV, full outer case JSON/CSV, groups, literal terminal observations, public-parser results and source hashes. It never runs validation or opens target products. Missing unstarted phases remain UNRUN; closed failures remain FAILED. An existing but unclosed phase refuses collection. Successful test rows require the complete independent outer inventory joined to the whole saved log hash. The unchanged public parser is also applied; unsupported interleavings remain explicit parser results, while reviewed outer identities are a separate authority. Nested child terminals are never summed into outer counts or repeated command totals.

A private role map normalizes every complete command context injectively and retains an exact inverse. Public files omit raw logs, private owners, usernames and hostnames. The saved full rustc version is reported; cargo/rustdoc hashes are reported, and unsaved version strings remain null. Saved source/tool/configuration equality is a per-phase observation, not a claim that today's host is the same.

Example report regeneration after all selected phases are actually closed:

```text
python3 -B collect-cross-function.py --inputs PRIVATE_INPUTS.json --inputs-sha256 INPUT_SHA256 --new-output FRESH_IGNORED_DIRECTORY
```

The report documents planner/source-pipeline validation. It provides no new native cross-function T3 oracle result, common-corpus qualification, normal-loader equivalence or full A3 completion. Old common-production and audit failures are not replaced by these source-pipeline results. Timings are operational durations, not performance measurements.
