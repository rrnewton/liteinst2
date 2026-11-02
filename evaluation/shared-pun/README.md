# Shared generalized-pun geometry

The core planner and offline permit generator now use one implementation of
pun head/store/target geometry and rel32 byte constraints. At
`f8f2e709b3019ecb52d479b09d7590ba52407606`, the separately declared
**1800-second workspace / 360-second serial correctness profile passed**.
All seven planned commands completed; all 11 command/capacity owners exited
normally with complete cleanup and zero rescued descendants.

| Check | Observed result |
| --- | --- |
| Format, strict Clippy, workspace check | PASS |
| Core `quiescent::` controls | 66 passed, 0 failed or ignored |
| Offline `common_sites` controls | 25 passed, 0 failed or ignored |
| Workspace | 4,584 top-level + 11 nested = 4,595 passed; 43 unchanged ignores; 935.928s / 1800s |
| Serial launcher | 1,039 passed, 0 failed or ignored; 144.567s / 360s |

The workspace preserves the complete prior CFG roster and adds exactly four
controls: three core feasibility tests and one offline parity test. All 27
critical regressions and 21 short-neighbor cases pass. All 43 ignore reasons
and 539 should-panic registrations are unchanged. The serial contextual roster,
five required critical cases and eight harness-less backing records match the
previous complete serial run.

Earlier [shared-decoder](../shared-x86/README.md) and
[shared-CFG](../shared-cfg/README.md) failures remain FAILED, including both
180-second serial timeouts and the initial empty-filter failure. This new
profile does not retroactively satisfy those invocations. Elapsed times are
operational observations, not performance measurements. No page exemption,
complete-program CFG, application execution or strict A4 qualification follows.

[receipt.json](receipt.json) records exact revision/tree, commands, source and
review pins, environment, CPU/load and storage. [results.csv](results.csv)
contains all seven planned results; blank counts mean no libtest count.
Hardware is **AMD EPYC Zen 5 dev host**. Rust/Cargo **1.97.1** metadata is carried
from the reviewed shared-decoder toolchain, with the same configured environment.
Actual affinity is recorded; reservation tag `li2core-shared-pun-v1` is
root-attested, without an independent allocator-ledger witness. No quiet-host
claim is made. Storage uses the original cumulative count-links ceilings,
not a fresh allowance or a physical-free-space measurement.

Reproduce from a clean checkout of the exact revision, with an existing offline
toolchain at `TOOLCHAIN` and a fresh output under `ignored`:

```sh
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
REV=f8f2e709b3019ecb52d479b09d7590ba52407606
cpuset-alloc run --cores 12 --tag shared-pun-reproduce -- \
  python3.9 -I -B evaluation/shared-pun/validate.py \
  --revision "$REV" --output "$ROOT/ignored/shared-pun-reproduce" \
  --toolchain "$TOOLCHAIN"
```

The tracked runner enforces exact clean source, 12-CPU affinity, jobs12/harness12,
serial harness1, 8 MiB captures and owned pre/post capacity checks. It persists
owners before reading captures and contains no automatic retry. Read CLOSED
ownership before raw logs; retained authority records remain private.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
