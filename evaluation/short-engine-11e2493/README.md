# Explicit short-neighbor engine and importer

The engine and trusted-disassembly importer now have an explicit route for
6–9-byte neighbor victims. The legacy 10–15-byte route remains unchanged.
The new route keeps the same five tactic stages, original-byte/overlay checks,
search and allocation budgets, and complete-selection transaction.

Code revision: `11e2493f30def00efd271df8afcef44338a5e692`.
Inventory revision: `00859a54ce2d66b045131439599565859ce929ac`.
Hardware: AMD EPYC Zen 5 dev host. This supports claim 4; **A3 remains open**.

All 11 new Rust controls passed. Seven targeted commands reported 428 outer
test passes and one unchanged ignore, including the full core and importer
libraries, CLI example, native engine bridge, legacy engine/foreign-engine
checks, and the 36-test prefixed-pun oracle. The bridge published the actual
engine bundle and compared five original entry heads under both fixed seeds:
10 installed and 10 retired entry comparisons, zero mismatches, using 30 fresh
trace children. The original full-state comparator and 15-second / 20,000-step /
2-second-cleanup limits remain unchanged. This small bridge supplements the
[existing larger native campaign](../short-neighbor-c2696f8/README.md).

All 27 profile controls and five inventory-control methods passed. The profile
controls ran before the code commit; their recorded source hashes equal the
committed files. Independent source reviews approved the engine, profile and
inventory changes. All historical inventory values and 719 prior assertions
remain, with 11 new Rust declarations and one new example harness.

| Check | Result |
| --- | --- |
| Formatting | PASS, 10.83 s |
| Strict workspace Clippy, all targets/features | PASS, 40.46 s |
| Workspace compilation, all targets/features | PASS, 26.83 s |
| Seven targeted commands | PASS, 428 tests and one ignore |
| Inventory controls | PASS, 5 methods, 97.86 s |
| Serial launch | PASS, 1,039 tests in 27 harnesses, 149.85 s |
| Full workspace | TIMEOUT at unchanged 360 s limit |

Before the timeout, 70 completed harnesses reported 2,002 passes and one ignore.
The incomplete neighbor-oracle harness reported 16 additional passes and no
new short-neighbor tests. There were no reported failed tests. These partial
observations do not qualify the workspace. Cleanup completed and reaped four
descendants. The serial parser accepted all native, dynamic, matrix, validation
and cleanup records. The earlier full-recorder timeout remains unchanged.

## Complete-program attempt

The separately named `offline-whole-authored-short-only-2g-v1` profile uses the
exact existing broad-profile placement, permissions and budgets, changing only
the explicit T3 family. Each program received one release importer attempt.
Both rewrites **FAILED**; no candidate was emitted or executed.

| Program | Heads | Jumps | B1 | B2 | T1 | T2 | T3 | Composition refusals |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| checksum | 80 | 16 | 7 | 3 | 2 | 2 | 2 | 1 |
| RLE | 107 | 26 | 17 | 3 | 2 | 2 | 2 | 1 |

ShortOnly found local plans at sites 7 and 12 in both programs, where the
[previous broad profile](../whole-authored-broad-f2aa721/README.md) reported
`NoPatchWindow`. Site 7 then refused with `OwnershipConflict` during composition
in each program. The complete-selection rule discarded the other plans. All
187 heads and 42 selected jumps remain in the evidence; no subset was retried.
Local planning success is not successful rewriting. No new E9 comparison ran.

All 13 release build/capture phases passed. The build still exited 2 because
two configuration paths were unreadable: one read, thirteen absent and two
read-denied. Configuration and qualification therefore remain incomplete.
No exemption was added. The original instruction rosters and loaded code match
the earlier 16 MiB capture; the fresh ELF files differ in the loaded header's
section-table offset. Complete file hashes are recorded separately.

The [16 MiB results](../whole-authored-window-f59b215/README.md), broad-profile
refusals, prior clock failures and prior recorder timeout are retained. A5 also
remains open. The next capability gap is selecting a bundle compatible with
inherited ownership during the bounded search.

[receipt.json](receipt.json) records exact commands, revisions, tool hashes,
CPU reservations, load observations, cleanup and source review bindings.
[checks.csv](checks.csv) and [sites.csv](sites.csv) retain every check and selected
site. The importer reservation was recorded by cpuset-alloc, but no per-import
load snapshot was captured; the receipt marks that field unavailable. Raw logs
and captures remain ignored. Durations here are validation costs, not throughput.

Reproduce validation with the tracked [admission runner](../admission/run.py)
and its [bounded protocol](../admission/README.md), at the inventory revision.
The receipt gives the exact targeted commands. Reproduce the corpus using
[build_whole.py](../offline-corpus/build_whole.py) followed by
[reproduce_whole.py](../offline-corpus/reproduce_whole.py), following the
[placement recipe](../offline-corpus/WHOLE-PLACEMENT.md) and selecting
`offline-whole-authored-short-only-2g-v1`. Reserve four disjoint CPUs and use
fresh canonical absolute directories under `ignored/`; retain every outcome.
`${REPO}`, `${TOOLCHAIN}`, `${CARGO_CACHE}`, `${USER_HOME}` and `${PYTHON}` in
the receipt stand for local absolute paths. Release builds use opt-level 3,
debug-info 0, with assertions and overflow checks enabled.
