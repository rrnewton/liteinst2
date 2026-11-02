# Fixed-address ET_EXEC correctness

The corrected campaign at `0076fced9793c7b1b8459b76020616791dafafbf` **passed** `fixed-exec-correctness-1800-360-v1`: format, strict Clippy, check, seven focused targets, workspace and serial launcher.

Workspace: **4,605 top-level + 11 nested = 4,616 passed**, 43 unchanged ignores. The complete prior direct-input roster remains, with exactly twelve additions. All 539 should-panic rows, 27 critical cases and 21 short-neighbor cases are preserved. Serial: **1,039 passed**, zero failed or ignored, including all five critical cases. The 280 focused pass observations overlap each other and the workspace.

The first campaign at `cb8fcbfc9eb40dfd6fc7a826c0220869f781419c` remains **FAILED**: rewrite: 200 passed/4 failed; bridge, disassembly CLI, workspace and serial UNOBSERVED. The indexed route reported carrier `OutputInvariant`; the other failures stopped at candidate-completeness prerequisites.

The correction uses the carrier's original-to-output header map. Inserted/interleaved headers change table indices. Readback checks the complete ordered, bounded map and every original LOAD field after translating only its index. Controls compare all 56 header bytes and reject malformed maps and field mutations. All four candidate-completeness assertions remain; the earlier failure is retained.

This validates explicit fixed ET_EXEC/zero-bias binding, signed displacement fields, metadata binding and writer readback. It establishes no application success, complete CFG, page exemption, runtime admission or performance. The separate first cat comparison remains FAILED: original/E9 each passed three cases; LI2 produced no candidate and its three cases were UNOBSERVED.

[summary.json](summary.json) records source/authority hashes, exact commands/environment, affinity, storage and census. [results.csv](results.csv) retains all 24 planned command outcomes, times, bounds and loads; blank values mean unobserved or inapplicable. Hardware: **AMD EPYC Zen 5 dev host**. Rust/Cargo 1.97.1 is carried metadata, not freshly measured. Twelve-CPU reservation is root-attested without an independent ledger witness; actual affinities are recorded. Times and loads are operational observations.

From a clean checkout of the chosen exact revision, with an offline toolchain at `TOOLCHAIN` and fresh output:

```sh
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
REV=0076fced9793c7b1b8459b76020616791dafafbf
cpuset-alloc run --cores 12 --tag fixed-exec-reproduce -- \
  python3.9 -I -B evaluation/direct-program/validate_fixed.py \
  --revision "$REV" --output "$ROOT/ignored/fixed-exec-reproduce" \
  --toolchain "$TOOLCHAIN"
```

The runner enforces clean source, 12 jobs/12 harness threads (serial 1), ordinary180/workspace1800/serial360 seconds, 8 MiB captures and original cumulative storage ceilings. Owners close before capture reads; failures stop dispatch and incomplete cleanup forbids follow-up. Reproducing the first revision requires explicit selection. Earlier 180/900-second failures remain FAILED; scientific bounds are unchanged.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
