# Shared offline CFG and explicit program inputs

At `643c9f357eb41fd5ea20506738dcd44cfd6b0cf2`, the declared
**1800-second workspace / 360-second serial correctness profile passed**.
All nine planned commands completed. All 13 command/capacity owners exited
normally with complete cleanup and zero rescued descendants.

| Check | Observed result |
| --- | --- |
| Format, strict Clippy, workspace check | PASS |
| Shared graph controls | 2 passed, 0 failed or ignored |
| Offline `common_sites` controls | 28 passed, 0 failed or ignored |
| Rewrite library | 199 passed, 0 failed or ignored |
| Full-program bridge controls | 13 passed, 0 failed or ignored |
| Workspace | 4,593 top-level + 11 nested = 4,604 passed; 43 unchanged ignores; 1017.108s / 1800s |
| Serial launcher | 1,039 passed, 0 failed or ignored; 147.230s / 360s |

The complete prior [shared-pun](../shared-pun/README.md) workspace roster is
preserved, with exactly nine additions: three shared-CFG parity controls,
three input-policy controls and three bridge controls. All 27 critical
regressions and 21 short-neighbor cases pass. The 43 ignore reasons and 539
should-panic registrations are unchanged. The serial contextual roster, five
critical cases and eight harness-less backing records match the prior complete
serial run.

This validates the shared graph adapter and explicit input/policy interfaces.
It does not establish GNU cat execution, a gap-free whole-program CFG, page
exemption eligibility or performance. Earlier [shared-decoder](../shared-x86/README.md)
and [shared-CFG](../shared-cfg/README.md) failures remain FAILED, including the
180-second serial timeouts and initial empty-filter attempt. The current
1800/360 profile does not retroactively pass those invocations.

[receipt.json](receipt.json) records exact source/tree and review pins, commands,
environment, per-command CPU load and cumulative storage. [results.csv](results.csv)
contains all nine planned results; blank counts mean no libtest count.
Hardware is **AMD EPYC Zen 5 dev host**. Rust/Cargo **1.97.1** metadata is carried
from the reviewed shared-decoder toolchain in the same configured environment.
Actual affinity is recorded; reservation tag `li2core-direct-input-v1` is
root-attested, without an independent allocator-ledger witness. Elapsed times
are operational observations, with no quiet-host or performance claim.
Storage retains the original count-links ceilings, not a fresh allowance or
physical-free-space measurement.

Reproduce from a clean checkout of the exact revision, with an existing offline
toolchain at `TOOLCHAIN` and a fresh output under `ignored`:

```sh
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
REV=643c9f357eb41fd5ea20506738dcd44cfd6b0cf2
cpuset-alloc run --cores 12 --tag direct-input-reproduce -- \
  python3.9 -I -B evaluation/direct-input/validate.py \
  --revision "$REV" --output "$ROOT/ignored/direct-input-reproduce" \
  --toolchain "$TOOLCHAIN"
```

The tracked runner enforces exact clean source, 12-CPU affinity, jobs12/harness12,
serial harness1, 8 MiB captures and owned pre/post capacity checks. It persists
owners before reading captures and has no automatic retry. Authenticate CLOSED
ownership before reading raw logs; retained authority records remain private.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
