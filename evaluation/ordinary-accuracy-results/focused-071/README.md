# Focused phase-observation controls

The closed run passed 24 stages: fmt, check, strict Clippy, two exact Rust listings, nine Rust tests and 198 Python test executions in 17 suites. There were no failures, skips or UNRUN cases. The 198 includes 13 repeated legacy SDK executions; new coverage is nine Rust and 22 Python controls.

Execution began on 2026-10-31 UTC on an AMD EPYC Zen 5 dev host, using four reserved CPUs. It ran on base `20cbe068487f10b47c08b02505ba0dcda7248f54` plus a 35-file overlay. That unchanged overlay was **subsequently** committed as `071783b9a3c27ae26c439c7c5b7ac599cfeb7245`. These commands were not run after that commit. `receipt.json` records source/tool hashes, loads, closure, fixed bounds and counts. Elapsed owner time is execution metadata, not a performance result.

The preceding v2 attempt remains FAILED: strict Clippy failed and Python had 197 passes/one failure. Two control-only repairs preserved the size predicate and fixture assertions. The first v3 auditor then refused because its regex consumed the next Rust result line. An independently approved line-local regex correction audited the same closed run once; no project rerun or weakened assertion was used.

## Reproduction

Use a clean checkout of the exact source commit above. Run this script from a separate checkout containing this receipt. Set `FOCUSED_SOURCE` to the source checkout, `FOCUSED_CARGO` to the real toolchain cargo binary, and `FOCUSED_CPUS` to four sorted CPU IDs held by a disjoint reservation for the entire run:

```sh
/usr/bin/python3.9 -B evaluation/ordinary-accuracy-results/focused-071/reproduce.py \
  --root "$FOCUSED_SOURCE" --cargo "$FOCUSED_CARGO" --cpus "$FOCUSED_CPUS"
```

The script is a new, UNRUN reproduction adapter. It checks the recorded tool hashes and exact source commit, then executes the same fixed 24 commands. Dependencies must already be cached for locked/offline Cargo. It uses the existing process owner with the original 1,200 s outer limit, 180 s command/Rust and 60 s Python limits, 8 MiB logs, four build jobs, incremental compilation off, and explicit `--test-threads=316`. Cold-build or other failures remain failures; there is no retry or limit extension. Raw output and compact results go only under `target/evaluation/focused-071-reproduction`; an existing directory refuses reuse.

Hashes of exact sorted identity sets replace copied inventories, while duplicate and count checks remain separate. All digest inputs use UTF-8 JSON with sorted keys, comma/colon separators and no newline. The source manifest maps the 35 Git-changed paths to `{bytes,sha256}`; command vectors and identity arrays are defined by the script and receipt. Historical private logs remain outside Git.

This validates focused controls only. It grants no native, performance, PMU-accuracy or phase-realization qualification. Phase realization remains UNRESOLVED, the ARM gate stays at 2 ms, and the full matrix still requires 43,200 cells.
