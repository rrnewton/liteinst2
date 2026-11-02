# Shared CFG correctness

The shared graph core serves offline neighbor cataloguing, ordinary runtime
admission and whole-function admission while retaining each adapter's refusal
rules. The proposed [page exemption](../../A3-SHARED-ADMISSION.md) remains
unimplemented; this is not complete-program CFG or performance qualification.
Hardware: **AMD EPYC Zen 5 dev host**; Rust/Cargo **1.97.1**, the same reviewed
toolchain as the shared-decoder campaign.

Both original campaigns **FAILED**. All required functional checks are now
available across the corrected campaign and the separate companion profile:

| Attempt | Result |
| --- | --- |
| `f9bf24e` | Format/Clippy/check and focused 2/15/4 passed. A wrong ordinary-module filter selected zero tests; the mandatory nonempty guard failed. Workspace/serial UNOBSERVED. |
| `2eb75c6` | Only the missing `module::` filter component changed. Focused 2/15/4/56 passed with no failures or ignores. Workspace PASS at 1059.748s/1800; serial FAILED timeout at 180.162s/180. |
| Separate `e869d9b` | PASS: all 1,039 serial tests completed in 174.394s under the separately declared 360s functional-completion budget. Neither original 180s failure changes. |

Workspace: **4,580 top-level + 11 nested = 4,591 passes, 43 unchanged ignores**.
The prior roster survives plus five CFG controls; all 27 critical regressions
and 21 short-neighbor cases pass. The second campaign's serial run recorded
**817 observed passes, one pending,
221 not started** against the complete 1,039-test baseline. The pending case is
`matrix::scripted_random_all_widths_all_gprs_and_both_carry_results`.
Its five required critical cases passed. Timeout cleanup reaped two descendants;
cleanup and partial passes do not establish campaign success or a deadlock.
The earlier [shared-decoder campaign](../shared-x86/README.md) also stays FAILED.
The initial filter mistake and review miss remain recorded.

[receipt.json](receipt.json) binds exact source/tree, commands, CPU sets, loads,
storage, limits and CLOSED review hashes. [results.csv](results.csv) includes
all planned stages, failures and unobserved stages. Blank counts are not zero;
the timed-out serial counts are partial and the companion count is complete.
Raw captures remain private. The original campaigns remain failed; no deadline,
quiet-host or application-performance claim is made. The companion
adds only its runner script to `2eb75c6`; product source and the common owner
remain byte-identical. Its complete 1,039-test roster, all five serial critical
cases and eight harness-less backing records match the reviewed baseline.
Completion in less than 180 seconds on this later invocation does not
retroactively satisfy either failed 180-second invocation.

Reproduce from a clean checkout of the chosen exact revision, with an offline
Rust toolchain in `TOOLCHAIN`, a fresh output and 12 disjoint reserved CPUs:

```sh
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
REV=2eb75c66e7a30565f9ccd277333c198c447e6d55
cpuset-alloc run --cores 12 --tag shared-cfg-reproduce -- \
  python3.9 -I -B evaluation/shared-cfg/validate.py \
  --revision "$REV" --output "$ROOT/ignored/shared-cfg-reproduce" \
  --toolchain "$TOOLCHAIN"
```

For the initial failure, check out its full revision from the receipt and set
`REV` accordingly. The runner enforces source/affinity, jobs12/harness12 and
serial threads1, durable owners, 8 MiB captures and original cumulative storage
ceilings. Count-links accounting is not physical free-space assurance. Read
CLOSED ownership before captures. No automatic retry is included. The separate
[serial_completion.py](serial_completion.py) uses the same CLI flags, an
`e869d9bd1336c5c4f9967e1756cd80895f08e4b4` checkout/revision, a different fresh
output, and its declared 360-second profile. Reservations used `cpuset-alloc`;
second/companion tags are root-attested in the receipt. The first tag was not
recorded. Actual CPU sets and per-command workspace/serial loads are retained.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
