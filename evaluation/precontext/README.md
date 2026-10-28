# Optional observation before context capture

This qualification checks the constrained, unsafe pre-context core API. The entry gate reads a selector once and records Fast or Slow in caller-owned scratch; the return gate follows that same choice even when a helper changes the selector during the call. Fast bypasses context capture and the observer. Slow uses the existing preserving observer. Publication still requires quiescence; the selector is not a code-publication or epoch authority.

The fixed native population is two seeds, two branches and both initial selector values: eight original/candidate pairs with 148 full-state comparisons, plus two malformed-entry cases that must stop at the local UD2 before application execution. Each positive child physically returns and joins its real selector writer. The unchanged state comparator includes GPRs, defined flags, canonical XSAVE, application input and stack/red-zone bytes. Separate controls reject corrupt layouts, acknowledgement fields, trailing messages and missing return records.

Run from a clean checkout of the exact revision:

```sh
python3 -B evaluation/precontext/verify.py \
  --revision "$(git rev-parse HEAD)" \
  --raw "$PWD/ignored/NEW_RUN" \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME"
```

`TOOLCHAIN` names a Rust toolchain directory; `CARGO_HOME` contains the already fetched dependencies. The recipe uses an offline release build, four available CPUs and four compiler jobs. Native execution has a 20-second CPU limit and 30-second wall limit; each pair shares its original 15-second deadline from setup through reap and each executor has a 20,000-step limit. Failures remain failures. Logs and captures stay under `ignored/`; `NEW_RUN/public` holds compact result and receipt JSON suitable for publication. Python corruption controls, six core tests, two compile-fail contracts, eight planner tests and thirty-one inherited oracle calibrations are prerequisites.

This is functional qualification of a fixed core fixture. It does not establish frontend accounting, arbitrary function/ABI support, concurrent code publication, cheap-off latency, performance or a completed profiler. Command durations are operational metadata, not benchmark results. Recorded results identify their exact tested revision and hardware.

At revision `a3f593c2b05e61fcad9938ca6be3c234a4302bd4`, the release qualification passed on an AMD EPYC Zen 5 dev host: all eight pairs / 148 comparisons, two required local-UD2 faults, sixteen physical subject returns, sixteen outer returns and sixteen helper joins. All six Python controls, forty-seven Rust prerequisite tests and five native protocol controls passed. `receipt.json` binds the command, revision, hardware, executable and closed process metadata; `cases.json` contains the compact native rows.

`attempts.json` retains two earlier recipe failures before native execution: the complete inherited calibration population was 31 rather than 13, and Cargo marks a test target's artifact `profile.test=true` even when its custom harness disables libtest. Both checks now require the exact correct value. `development.csv` records source-development commands separately; it does not provide qualification credit.

`gates.json` records all seven required checks on the same revision: formatting, strict workspace Clippy, workspace check, default-parallel workspace tests (2,625 passed, zero failed, nine ignored), serial launch (1,039 passed), staged allocation (three passed), and prefixed pun (36 passed). The workspace used the full 316-CPU affinity and no test-thread override. The first gate attempt remains FAILED in `gates-failed.json`: its workspace command reached the unchanged 360-second limit after a 34.62-second test build; three descendants required cleanup and the remaining checks were unrun. With those build artifacts populated, the identical gate recipe passed in 329.43 seconds for the workspace and 124.41 seconds for serial launch. These durations describe validation, not performance.

Reproduce the seven gates with `python3 -B evaluation/admission/check_exec_identity.py --checks-only --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" --output "$PWD/ignored/NEW_GATE_RUN"`. Project the closed receipt using `evaluation/merged-af5a1ef/summarize.py`; it excludes nested libtest summaries from the workspace count. Raw logs stay in ignored storage.

After merging main `5cda729355cf45b9198b831a27845bbfcc46f320`, the identical release qualification passed at `21b5cab3477ddf602c8acecf1a538184411b9eba`. `receipt-merged.json` binds that rerun; its native JSON is byte-identical to `cases.json`. All seven gates also passed on the merged revision (`gates-merged.json`), with the same test populations: workspace 2,625/0/9 in 324.38 seconds and serial launch 1,039/0/0 in 126.58 seconds. All final native and gate closures exited normally with zero rescued descendants.
