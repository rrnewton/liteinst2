# Complete artifact; startup/help parity failed

At `90ff38d89ddd178ef1ab29eb3a62d3dcb711437c`, this mode produced one complete
artifact for **2,053 selected sites and 13,143 verified heads**, with zero primary
refusals or withheld plans. The 8,769,843-byte candidate has SHA-256
`43c11c7a4322d245516ab52c1e0e0523a68620c1e2f9a525561e282dcc1a16d9`.
Tactics: B1=1,623, B2=355, T1=38, T2=13, T3=24.

The subsequent fixed startup/help comparison **failed**:

| Input | Outcome | stdout | stderr |
| --- | --- | ---: | ---: |
| Original PLDI2020 e9patch | exit 0; recognized help | 947 B | 0 B |
| LI2 candidate | fd-exec `ENOEXEC` (errno 8); wrapper exit 1 | 0 B | 552 B |
| E9 candidate | SIGSEGV; exit -11 | 0 B | 0 B |

Each arm ran once with canonical `e9patch --help` argv and identical subject
limits. Both exact stream/status comparisons failed. Clean closure does not make
them pass. The signal's cause and an address-space-limit explanation are not
established here. There is no whole-program native equivalence, all-sites-executed,
performance or A5 claim; `qualification_complete` remains false.

For short-T3 selected roles, the new layout keeps constrained entry E and places
its body at the same page's base B, with an explicit E9 from E to B. Direct fitting
remains preferred. The conservative bound must fit before E and the complete
body/gap/jump envelope must fit one page. One body encode, all field/PC/source-byte
and ownership checks, complete original 2-GiB policy, and one candidate/4-KiB
mapping per role remain unchanged.

[results.csv](results.csv) preserves all six historical rows. Relative to
[fitting](../full-program-fitting/), site 1888 is the one newly resolved refusal;
all 2,053 statuses change to emitted, not 2,053 new tactic successes. Against
[mixed neighbors](../full-program-mixed-neighbor/), refusals 1392/1888/2040/2041
are resolved, with no new refusal. Earlier
[current](../full-program-current-placement/),
[owned](../full-program-owned-placement-result-v1/) and original 16-MiB/2-GiB
failures remain failed. The independent comparison retains full ordered identities
and logical COMPLETE sets. Four historical ledgers use verified archival content;
original inode custody is not recreated. Conservative recovery: 817,464,512 B.

Build/corpus/startup were measured at 90ff. The 23 focused controls passed at 63488594
(17 core/2 library/2 CLI/2 native; 58 original/58 linked/58 restored traces, 14 entry
transitions); their byte-identical source carry is not another execution. Both
bb7c6f41 and90ff full gates failed strict Clippy 101 despite fmt/check/workspace/
serial 0. A later test-only equivalent predicate at 0e880aa failed standalone Clippy
because `is_multiple_of` exceeds unchanged Rust 1.85 MSRV; full v4 was not dispatched.
The source-reviewed b969fac2 correction uses an equivalent bitmask and compile-time
PAGE power-of-two assertion. The full correctness gate subsequently passed at **b969fac2**: workspace
**4,341 passed / 0 failed / 39 ignored**, plus serial **1,039 / 0 / 0**. The
independent census retains every prior identity, status, ignore reason and custom
record, the same three controlled nested exclusions (raw 4,344), and 23 added tests.
The finite oracle again observed 58 original/58 linked/58 restored traces and 14
entry transitions. All five commands exited 0; outer wall time was 908.083566s.
[validation.csv](validation.csv) records exact commands, times, loads and bounds.
Gate and census owners closed normally with zero rescues; the gate retains both
independent root and owner raw identity witnesses. The short census has no
independent live witness. This validation does not rerun or qualify the 90ff
artifact/startup experiment; both startup failures above remain unchanged.

The first release controller refused capacity with zero compiler attempts.
After recovery, one build took 39.957595s wall on CPU 1 and one planner 19.236483s on
CPU 3 (outer 28.833147s). Startup used CPU 174. Host: AMD EPYC Zen 5 dev host, x86_64.
These are diagnostic wall times, not throughput or CPU-cost measurements.
[receipt.json](receipt.json) gives exact values, loads, hashes and bounds. All these
owners closed normally with zero rescues. The short startup/comparison owners lack
an independent root live witness; none is inferred.

## Reproduce the measured revision

Retain [reproduce.py](reproduce.py) and
[run_help_comparison.py](run_help_comparison.py) outside the clean exact checkout.
The build reproducer is source-authored/unexecuted; the help script is byte-identical
to the executed script. Supply exact pinned original/ledger/inventory/policy via the
[original](../e9-upstream-corpus-c66ea06/README.md),
[provider](../full-program-provider/README.md),
[whole-input](../full-program-whole-result-v1/README.md) and
[policy](../offline-corpus/full_program_policy.py) recipes; no bit-exact rebuild of
the original is assumed. Reserve one external HARD CPU at 100% quota within 1200% lane.
All path variables are absolute; `OUT` is fresh directly under checkout/ignored.

```sh
/usr/bin/git switch --detach 90ff38d89ddd178ef1ab29eb3a62d3dcb711437c
/usr/bin/python3.9 -I -B "$REPRODUCER" "$ORIGINAL" "$LEDGER" "$SITES" "$POLICY" "$OUT" "$TOOLCHAIN_BIN"
```

Build: offline/locked, one job, opt3/debug0, assertions/overflow on, incremental off;
CPU 240s/AS4GiB/file128MiB/wall300s. Planner:CPU 180s/AS3GiB/file512MiB/wall240s;
both logs 8MiB. Before/after build and before planner, bounded system-du queries
(CPU 30s/AS256MiB/file64KiB/wall 60s each) count hard links conservatively and require
max(allocated,apparent) slot <= 17,785,407,488 B. This reserves 2GiB+64MiB below 20GB.
The 2-GiB post-stage output cap is not an instantaneous quota. No failed admission
or stage is retried; the build reproducer executes no generated program.

For help, supply fresh distinct mode 0500 copies of the exact LI2 and
[E9 candidate](../full-program-backend-result-v1/), preserving originals. The helper
checks exact hashes. `HELP_OUT` is fresh directly under target/evaluation. Pass this
argv to existing `evaluation/admission/processes.py::run_command` with wall 60s,
log 131072B and environment `PATH=/usr/bin:/bin, LANG=C, LC_ALL=C, TZ=UTC`, retaining
the one-CPU external reservation:

```sh
/usr/bin/prlimit --cpu=30 --as=2147483648 --fsize=1048576 --core=0 -- \
  /usr/bin/python3.9 -I -B "$HELP_SCRIPT" \
  --revision 90ff38d89ddd178ef1ab29eb3a62d3dcb711437c --cpu "$CPU" \
  --out "$HELP_OUT" --original "$ORIGINAL" --li2 "$LI2" --e9 "$E9"
```

Each subject: CPU 5s/AS1GiB/wall10s/file+log64KiB/core0/cleanup3s, empty private cwd,
separate stdout/stderr, one owned fd-exec. Pass requires exit0, recognized help and
exact stream/status parity; matching failures never pass. Input-read cap 8,769,843 B
admits the exact candidate without widening subject limits.

## Reproduce the correctness gate

Use a clean `b969fac23c8fe2aa8233577b407591caa2ae26aa` checkout and the existing
[validation recipe](../short-neighbor-parallel/validate.py), SHA-256
`968956df64edd3f5754a0adbd4b900ac68535d188be01af0628eff94d2ed6d10`.
Reserve 12 external CPUs under the 1200% lane cap. Apply the exact environment
overrides in receipt.json (`$ROOT`, `$TOOLCHAIN_BIN`, `$CARGO_BIN` are caller paths;
Git resolves to pinned `/usr/bin/git`). Set fresh `GATE_OUT` under checkout/ignored.
Pass the following argv through the existing owner with wall 1200s/log8MiB:

```sh
/usr/bin/python3.9 "$ROOT/evaluation/short-neighbor-parallel/validate.py" \
  --revision b969fac23c8fe2aa8233577b407591caa2ae26aa --output "$GATE_OUT"
```

The recipe runs the five CSV commands once, with wall bounds 180/180/180/900/180s,
8-MiB logs, jobs/harness 12 and serial harness 1. No command or failure is skipped.
