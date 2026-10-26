# Original anonymous mapping validation

The six-command protocol passed on source
`7022e1372ec6f6c96037e653c37ef594040d2827`. The finite singleton mapping
profile now connects original mapping syscalls, runtime source capture and
immutable source history. It qualifies the trajectory described in
[the protocol](mapping-lifecycle.md), with the limitations below. Full B3 and
B4 remain open.

The [typed result](results/20261026T120552.007190Z-7022e1372ec6.json) has
SHA-256 `8e592c9f088456eef6621cc3411112bdc2d8a27b4fdcb02f96107becd4a92218`.
It records 495 source hashes, a mode-bound Git tree, hardware, toolchain, exact commands,
complete harness outcomes, private capture digests and cleanup. Source and
configuration remained unchanged. Every command exited zero, completed cleanup
and reported zero adopted descendants. Raw output remains private.

## Reproduction and environment

From a clean checkout of the exact source revision:

```sh
python3 evaluation/admission/run.py --expect-revision 7022e1372ec6f6c96037e653c37ef594040d2827
```

Hardware was AMD EPYC 9D85, family 26, model 17, stepping 0, microcode
`0xb101066`, x86-64, with 316 visible logical CPUs. Linux upstream version was
7.1.3; the complete kernel release has SHA-256
`549727bb276577a43b738c4d3e8167ceb8d3d54f317035ae91560f869cf7f60d`.
Execution was non-root with effective capabilities zero. The ptrace-scope
interface was absent; this is not inferred policy zero. Actual child ptrace
and cleanup assertions passed. Rust and Cargo were 1.97.1.

The unchanged runner uses four build jobs, four workspace test threads, serial
launch tests, disabled incremental compilation and offline dependency
resolution. Workspace tests retain their 360-second deadline; the other
commands retain 180 seconds. Capture and cleanup bounds are unchanged.

| Command | Result | Seconds |
| --- | --- | ---: |
| Recorder calibration | 219 passed | 8.244 |
| `cargo fmt --check` | passed | 1.758 |
| Workspace/all-target/all-feature Clippy, warnings denied | passed | 0.426 |
| `cargo test --workspace` | 1,399 passed, 0 failed, 4 unchanged ignored; 78 harnesses | 320.978 |
| Workspace/all-target/all-feature `cargo check` | passed | 4.020 |
| Serial launch integration/unit oracles | 565 passed, 0 failed; 26 harnesses | 81.939 |

These are validation durations, not application or hook performance. Nested
child summaries remain separate from outer totals.

## Native trajectory and controls

The program itself creates one isolated anonymous RW page, copies source A,
changes it to RX, executes an original CPUID, changes it back to RW, copies
source B with a different selected PC, restores RX, executes another original
CPUID and unmaps it. Five original mapping calls and two CPUID invocations
form the complete trajectory. Production code obtains bytes from the held
process and asks a capture-identity-bound resolver for instruction heads;
it contains no fixture-byte whitelist.

All five named fixtures passed in both workspace and serial runs:

- Complete original RW/RX/rewrite/unmap trajectory against an independent raw tracer.
- A stale resolver capture reply after the actual second RX transition.
- Resolver panic after actual RX, retaining failure history and physical cleanup.
- Resolver blockage past the original absolute deadline, with cleanup observed before releasing the callback.
- Full-state and mapping comparator corruption controls after native cleanup.

The oracle compares all native GPRs, flags, kernel register bookkeeping,
complete exported XSTATE, signal masks, fixed stack/data, source/armed bytes,
and every mapping descriptor. Original syscall ENTRY and EXIT information,
actual wait statuses, return bridges and admission completion remain distinct.
Five persistent map-capture slots retain complete or explicitly failed prefixes
across owner teardown. The successful fixtures require every slot and its exact
initialized payload; the pure failure controls retain partial prefixes.

Every owned lane keeps its actual addresses. The vDSO has the exact
NX/RX/RX/RX/NX permission sequence across before-window, logical-window, ENTRY,
EXIT and quarantine. Its independent raw original descriptor establishes RX;
all other descriptor fields and raw-line bytes remain unchanged in the gated
lane. No row is omitted or cross-process address normalized. The existing 62
state/source/map corruptions remain, with 200 additional wrong-phase vDSO
permission and descriptor corruptions in the same fifth test.

The five-case source schedule contains 35 raw original selected instructions,
23 attempted gated invocations, 20 completed gated invocations and eight source
resolver callbacks per run. These are distinct source-derived trajectory
counts, not extra fixture outcomes or exported timing samples. Failure-path
invocations do not become completed admission. Physical cleanup is separately
checked through pidfd readiness and an actual no-child result.

The increment adds 57 pure Rust controls and six recorder calibrations. All
278 launch unit tests passed. Named native outcomes increase from 37 to 42:
17 journal, six B2 reference, eight reset, five signal, one source census and
five mapping cases. The separate 50 static cases, 15 dynamic fixtures and 388
matrix rows remain required. These overlapping collections are not pooled into
an instruction sample count.

## Preserved development failures

All five preceding receipts were committed unchanged before their corrections.
They remain failed, with unexecuted later commands recorded as such:

| Source | Receipt | Failure |
| --- | --- | --- |
| `67ceed7539ee` | [first](results/20261026T114958.150809Z-67ceed7539ee.json) | Four Rust integration errors after recorder/fmt passed. |
| `4a93030f6463` | [second](results/20261026T115208.249020Z-4a93030f6463.json) | Strict unused/style lint failures. |
| `38b79a1026d5` | [third](results/20261026T115324.254831Z-38b79a1026d5.json) | Unnecessary unsafe block around the safe CPUID intrinsic. |
| `b6ba1af3c30e` | [fourth](results/20261026T115626.408325Z-b6ba1af3c30e.json) | Four launch unit failures: ordinary journal contract and three fixture/accounting expectations. |
| `3e1539c52422` | [fifth](results/20261026T115942.979476Z-3e1539c52422.json) | All five native cases rejected the incorrect unchanged-vDSO expectation. |

The ordinary journal preparation contract now keeps its original finite syscall
set; mapping preparation has a separate path with the same exact binding
checks. The original signal negative test is unchanged. New controls require
both cross-profile refusal and unchanged archive state. Fixture corrections
bind the actual retained task identity and complete literal prefix, and account
for shared Arc control words and embedded headers from their allocation layout.
The vDSO correction requires the protocol's exact phase permissions and adds
corruption controls. It does not accept either permission. No case, state field,
resource cap, deadline, cleanup requirement or failure classification was relaxed.

## Scope of the evidence

This supports claim 1 within the singleton page-admission profile: application
pages are held while code and permissions change, and the original syscall
window closes before source resolution and further admitted execution. It
supports claim 2 for interception of CPUID in each newly admitted source version
and preserves the existing seven-class selected-instruction cohort. Claim 4
receives systematic positive, refusal, failure-prefix and comparator evidence.
No complete global claim, software preemption clock or performance result is
established.

The profile covers isolated whole private anonymous VMAs, bounded RW/RX
transitions and whole unmap. It restores old r/w/x inputs for the original
syscall; it does not certify hidden VMA flags or arbitrary security-module
history. Complete instruction heads remain an unsafe caller obligation.
Writable aliases, file-backed/partial mapping changes, concurrent mapping
writers, combined signal/thread profiles, later admitted exec, ordinary dynamic
loaders and real applications remain outside this result. Lifetime accounting
retains the 64 MiB cap and no refunds. Full B3 requires the remaining lifecycle
and application coverage; B4 still requires verified artifact/overlay agreement
and fallback. No Intel or CET qualification is added.
