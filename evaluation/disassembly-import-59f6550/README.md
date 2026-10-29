# Trusted disassembly importer validation

The importer at `59f655011a8fdb9334cce74de380708d6a03925b` checks trusted complete instruction ledgers against original ELF bytes, retains every decoded jump and uses the existing planner/carrier. It adds eight controls without changing the existing common-sites frontend, limits or comparator. All **160 package tests** and strict package Clippy pass against the exact seven source images. Completeness/no-overlap/no-code-as-data remain explicit external premises.

The seven hand-back checks have six passes and one retained workspace timeout. Fmt, strict workspace Clippy and check pass. Workspace hits its original 360-second limit: 1,990 completed pass observations, zero reported assertion failures, one ignore; these are prefix/nested observations, not whole-suite success. Only initially UNRUN checks then execute: serial launch **1,039 passes**, staged allocation **3**, prefixed pun **36**. All three historical observing-control allocation tests pass in the workspace prefix. The checks use hard eight-CPU reservations; exact CPUs, loads, commands and closures are in [receipt.json](receipt.json). No 316-thread claim.

Admission inventory at `96bcbd6cf9560f6c28698a2ac1c32ce4cb7cc9d0` initially produces **349 passes/one failure**: a historical control hashes current lib.rs against its pre-importer epoch. Commit `5fdea886f9a110f4de3154e3e8509d660dcf55ea` checks the authenticated historical projection while retaining both expected hashes, live-source guards and every malformed-source case. All **350 controls pass** on that corrected source. Both outcomes remain recorded. The census is 103 harnesses/3,582 tests/37 existing ignores; declarations are not an execution total.

Main `c2e86f5eb147d9f1119d4f2611bf6a5570a6da00` is merged at `9d83067232e5bd3b1d1327bbfdf22675bed0a63e`. That merge changes ancestry only; its complete tree is byte-identical to 5fdea886. No result is relabelled to the merge and no failed same-source command is repeated.

Reproduce the actual commands from their recorded source revision. The existing [seven-check driver](../admission/check_exec_identity.py) preserves per-command limits and cleanup; the [tail materializer](../ordinary-call-pair-native-cfc8d76/reproduce_tail.py) recreates only the three initially UNRUN checks. Use fresh ignored output directories, a disjoint eight-CPU reservation, and record its load before/after:

```sh
python3 -B evaluation/admission/check_exec_identity.py --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" --output "$REPO/ignored/NEW_CHECKS" --checks-only
# After that owner closes, run the tail only if those three checks were UNRUN.
python3 -B evaluation/ordinary-call-pair-native-cfc8d76/reproduce_tail.py
python3 -B ignored/a5/cfc8d76-tail-checks-source-v1/successor-v2/tail_checks.py --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" --output "$REPO/ignored/NEW_TAIL" --checks-only
```

The final admission command is `python3 -B -m unittest discover -s evaluation/admission -p 'test_*.py'`, under the recorded 1,200-second/8-MiB process owner and a four-CPU reservation. The importer package commands are `cargo test --offline --locked -p liteinst-rewrite` and `cargo clippy --offline --locked -p liteinst-rewrite --all-targets --all-features -- -D warnings`. Exact environment/build settings are those of the existing seven-check driver: stable 1.97.1, four compiler jobs, one target, incremental disabled, development opt0/debug0 with assertions/overflow checks. Development commands used the bound dirty source images and their original base; the first development receipt omitted dirty elf-rewrite hashes and is explicitly not final-source coverage.

Hardware: **AMD EPYC Zen 5 dev host**. Durations are operational validation times, not performance measurements. Raw logs stay ignored. This supports claim 4's input/refusal validation only. Full A3/A5, actual corpus fit, native behavior, ABI/unwind, grouping and performance remain open. The prior fixed-five deadline campaign remains one pass/four failures; no new deadline campaign ran here.
