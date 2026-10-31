# Prepared first-call focused checks

The corrected Rust checks passed fmt, check, strict Clippy and the complete ordinary-interval run: **506 passed, zero failed, one unchanged ignored** out of 507 listed tests. All 18 new prepared controls passed. Python ran **220 passing test executions** across 19 suites: the unchanged 17-suite census of 198 plus 14 new reader and eight new recipe controls. The 198 includes 13 deliberately repeated legacy SDK control bodies; these are not new coverage.

Execution used `f0ad44be8ad09d42780da3a4b5936dbed13416de` with frozen overlays. The final source was subsequently committed as `27e57a250104f0b0e55e9ac441e0b96217ec010d`. All 39 files guarded during the Python run exactly match that commit; the 14-file Rust-v2 overlay is an exact subset. These are precommit executions, not runs at the later commit. Hardware was an AMD EPYC Zen 5 dev host. Builds used opt level 0, debug information 0, assertions and overflow checks enabled, four build jobs and 316 Rust test threads. Durations below describe validation work, not performance.

| Attempt | Outcome retained | Owner wall seconds | Reserved CPUs |
|---|---|---:|---|
| Rust v1 | FAILED: missing imports; full test run UNRUN | 39.163989 | 8,33,35,43 |
| Rust v2 | Collector FAILED; all five project commands exited 0 | 45.136821 | 17,27,33,34 |
| Python v1 | PASS: 220 executions, no failures/skips/errors | 135.976288 | 3,6,13,15 |

Rust v1 emitted four E0433 diagnostics in each check/Clippy/list command: two missing `Arc` uses, plus `Instant` and `Duration`, in the new test module. Adding those imports was the only source repair before v2. The v2 collector then misparsed 22 existing `- should panic` annotations and the comma before the one existing ignored-test reason. A separate audit of the same closed logs verified all 507 names, 506 `ok` outcomes, that exact ignored identity/reason and the unique successful summary. The failed collector receipt remains unchanged. No project command was rerun to correct the census.

[receipt.json](receipt.json) records every command, outcome, wall duration, CPU/load observation, tool-file pin and raw receipt/log digest. Each Rust command had a 180-second wall bound, each Python suite 60 seconds; each of the three owners retained its 1,200-second/8-MiB bound. All closed normally with complete cleanup, zero rescued descendants and unchanged source. Raw logs remain private. Recorded tool-file hashes do not claim contemporary version captures or a complete shared-library/subtool inventory.

To repeat the corrected checks, use [reproduce.py](reproduce.py) from the publication checkout, with `ROOT` pointing to a separate clean checkout at the exact source commit above. The script is a source-only reproduction adapter; it did not produce these historical results. It reuses the unchanged tracked process owner and focused-071 Python census/closure helpers. It requires the recorded tool-file hashes, four externally reserved CPUs and fresh output names. Affinity alone is not a CPU reservation. Keep the reservation alive through both owner closures.

```sh
"$PYTHON" -B "$PUBLICATION/evaluation/ordinary-accuracy-results/prepared-focused-27e/reproduce.py" \
  --root "$ROOT" --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --cpus "$CPUS" --phase rust --name prepared-focused-rust-reproduction
"$PYTHON" -B "$PUBLICATION/evaluation/ordinary-accuracy-results/prepared-focused-27e/reproduce.py" \
  --root "$ROOT" --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --cpus "$CPUS" --phase python --name prepared-focused-python-reproduction
```

`PYTHON` is the pinned Python 3.9 executable; `TOOLCHAIN` is the real toolchain directory containing the pinned Cargo/Rust executables. The receipt's `$CARGO` expands to `$TOOLCHAIN/bin/cargo`; `$PYTHON` expands to that interpreter. The full five Rust commands and nineteen Python commands are explicit in the receipt. Reproduction logs and owner/child outcomes go under `$ROOT/target/evaluation/<name>`; failures remain failures, and a refused listing leaves the Rust test run UNRUN. Neither phase retries.

This evidence establishes focused source checks only. Prepared native execution, PMU accuracy, realized phase, cadence, executable reclamation and performance are not qualified. The unchanged 2 ms gate, historical strict-clock **1 PASS / 4 FAIL**, [phase-071 observations](../phase-071/README.md) and 43,200-cell full-matrix denominator remain in force. Native and full-workspace receipts are separate.
