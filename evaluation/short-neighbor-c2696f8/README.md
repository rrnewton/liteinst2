# Native short-neighbor qualification

The opt-in same-function API now handles original victims 6–9 bytes long.
It installs the selected short jump and a ten-byte victim relay through the
existing quiescent transaction. It keeps every borrowed successor byte, full
fetch/entry/function obligations and source lease. This is not an atomic
ten-byte publication claim. The default engine still uses its old long-victim
path; whole-program rewriting has not gained this tactic yet.

Source revision: `c2696f85fe36d343bf66375bfbd7253a5134e172`.
Hardware: AMD EPYC Zen 5 dev host. This supports claim 4.

All 19 new native controls passed in 133.13 seconds. Eight rel8-endpoint
layouts contribute 1,019 original heads; successor overlap, RIP-relative read
and conditional-branch fixtures contribute 83 more. Every head runs with both
seeds while installed and after retirement: **2,204 installed + 2,204 retired
comparisons, zero mismatches**. Calibration and hostile controls are additional
and do not inflate those populations. [tests.csv](tests.csv) joins each actual
passing test to its fixed population; zero denotes a control outside the census.

The independent validator derives original length and first effect from literal
MOV/RIP/JNZ bytes and an actual raw step plus two full native snapshots. It
checks complete state, source publication, targets, image ownership and ordered
relay/hook visits. Old long-victim descriptors, validation and execution checks
remain. Per-comparison limits remain 15 seconds/20,000 steps, with two-second
cleanup. Exact-address fixture allocation gets one attempt; failure is a failure.

The core library passed 277 tests with one unchanged ignore, including seven
new planner controls. The existing neighbor contract passed. The five inventory
controls passed in 70.797 seconds. The earlier full recorder run timed out at
180.063 seconds after 309 completed result dots; it is not a 350-test pass.
A first native invocation accidentally selected zero tests; it remains UNRUN,
then the corrected module filter executed all 19 controls once. A separate
core wrapper initially rejected its log destination before launching Cargo.
[receipt.json](receipt.json) retains these outcomes, commands, CPU reservations,
load averages, source hashes and cleanup results. No performance result is claimed.

Runs preceded the source commit. Their recorded base revisions and working
source hashes identify the exact tested trees; the native hashes match the
source revision above. Raw logs stay ignored. Full-workspace qualification is
separate and is not established by these targeted results.

To reproduce the full bounded validation, use the tracked
[admission runner](../admission/run.py) at the chosen exact revision as described
in its [recipe](../admission/README.md). The targeted commands used here are:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 cargo test -p liteinst2 --lib
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 cargo test -p liteinst2 --test neighbor_eviction_contract
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 cargo test -p liteinst2 --test neighbor_eviction_oracle short_neighbor::
python3 -B -m unittest discover -s evaluation/admission -p test_main813_inventory.py -v
```

Reserve four disjoint CPUs for the complete process tree and retain every
outcome. The recorded commands use `evaluation/admission/processes.py` for
owned-child cleanup, 8 MiB log caps and 180-second command limits, except
360 seconds for the new native population. Do not interpret a zero-test summary,
a timeout or a passing subset as completion.
