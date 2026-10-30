# Adjacent two-byte pun planning

Claim 4 / A3 core increment: the explicit artifact API searches two adjacent
observing forward Jcc instructions together. It retains failed placements,
cumulative upper/lower image budgets, continuation budgets, original identities,
pending ownership and transactional composition. Existing engine paths are unchanged.

At merged revision `f02e6a06d9a220d02bfa7e32758f6f3fba3a5d14`, ten new control
groups pass, including all 16 condition opcodes at each role, real singleton and
pair images, inherited compositions, budget boundaries, and aggregate refusal
followed by success. The parallel workspace has **3,623 passed, 0 failed,
37 ignored**; serial launch has **1,039 passed, 0 failed**. All 21 short-neighbor
tests and the earlier trampoline/prefixed-pun allocation regressions pass.
Formatting, strict workspace Clippy and all-target checking also pass.

[receipt.json](results-f02e6a0/receipt.json), [checks.csv](results-f02e6a0/checks.csv)
and [controls.csv](results-f02e6a0/controls.csv) record the exact revisions,
commands, hardware, CPU reservations, load, source hashes and results. Both the
pre-merge and merged validation rounds are retained. Totals exclude five nested
single-child summaries already included in their outer tests. Two custom
workspace harnesses complete separately and are identified in the receipt.
Raw logs stay in ignored storage; their content hashes are recorded.

These are debug-build correctness results. Command elapsed times are operational
receipts, not performance measurements. These core-only results at that revision
do not establish native adjacent-pair equivalence, frontend use, full-program
coverage or completion of A3. Artifact qualification remains false.

To reproduce, use Rust 1.97.1 and Python 3.12, check out the tested revision, and
run the existing validation script inside a disjoint 16-CPU reservation. It
records affinity and load, retains 316 test threads, and uses the same bounded
commands. Choose a fresh ignored output directory for each invocation.

```sh
env CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  CARGO_PROFILE_DEV_OPT_LEVEL=0 CARGO_PROFILE_TEST_OPT_LEVEL=0 \
  CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true \
  CARGO_PROFILE_DEV_OVERFLOW_CHECKS=true CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true \
  LITEINST_EVALUATION=1 \
  python3 -B evaluation/short-neighbor-parallel/validate.py \
    --revision f02e6a06d9a220d02bfa7e32758f6f3fba3a5d14 \
    --output ignored/adjacent-b2-reproduction
```

The isolated control command in `checks.csv` is
`cargo test -j 4 -p liteinst2 --lib quiescent::adjacent_b2::tests:: -- --nocapture`.
The full workspace script executes those same ten groups as part of its suite.

The separate native-campaign runner has six passing unit tests covering eleven
fixed scenarios: one successful stub campaign and ten injected failures. They
check retained outcomes, dependent stages left unrun, source/binary guards and
mutually exclusive custody receipts. The tests use a stub command owner and
execute no native stage; they supply no native-equivalence or real-cleanup claim.
[The receipt](runner-controls-be41ea0/receipt.json) binds the exact added source
hashes atop `be41ea072a0b7168c6f8833894194ecf811b8b09`, with all
[control results](runner-controls-be41ea0/controls.csv). Reproduce them with
`python3 -B evaluation/adjacent-b2/test_native_runner.py`.

## Transactional frontend and native state comparison

At source revision `5f6299e945c31ab6fb445aaf5f865a5d7154751b`, the explicit
`elf-disassembly-null-jumps-adjacent-b2-short-t3-pending-v1` frontend tries each
legacy baseline once, then can try one bounded two-site transaction. It keeps
all selected instructions pending until accepted, checks resources for the full
composition, and publishes only a complete selection. Its version-5 policy
keeps upper/lower/continuation budgets separate from the old allocation caps.
The old 16 MiB and broader profiles remain available.

The native campaign passed **64 scenarios / 192 child traces**, with no state
mismatches. It uses two authored JNE layouts, null and recording hooks, two
seeds, both ZF values and all four original instruction heads. Each scenario
executes pristine, installed and source-restored ELF artifacts. The comparisons
cover general registers, flags with only the tracing TF/RF mask, standard XSAVE
state, data and stack/red-zone bytes, and immutable mapped pages. The run
observed 40 hook CALL/RET pairs and 20 recorded events. Its controls rejected
368 state, 24 immutable-page, 22 journal and 150 structural mutations; all 36
planner refusals and seven filesystem positives also passed.

Frontend validation passed 133 library tests and three publication tests. The
new controls require real complete candidates, inherited compositions, exact
rollback, cumulative budgets, full denominators and all final input rereads.
The Python material/capture/reproducer suites passed 25/6/12 methods, including
six new material methods covering 204 cases. Pure material controls use
synthetic inputs and do not establish native or importer correctness.

The first frontend run retained one fixture failure: its fourth branch crossed
a cache line. The corrected positive moves one byte earlier and retains every
assertion; the original geometry remains an exact exclusion control. Initial
build and Clippy failures are retained alongside their subsequent corrections.
The merged workspace exposed a shared-fixture parity lint. The final equivalent
bitwise predicate preserves Rust 1.85 compatibility; the rejected Rust 1.87-only
spelling and both lint failures remain in the receipt. All raw logs and captures
remain in ignored storage.

The merged pre-correction revision `5eca8ef` completes the parallel workspace:
**3,649 passed, 0 failed, 37 ignored**. At final source revision `5f6299e`,
formatting, strict workspace Clippy and all-target checking pass. The fixed
900-second workspace bound expires after **2,393 passed, 0 failed, 4 ignored**
in 89 complete harness summaries; later harnesses remain unrun. The completed
neighbor oracle takes 647.56 seconds, versus 576.86 seconds in the preceding
complete run. This timeout remains a timeout; there is no identical rerun or
widened deadline. The only intervening source change is the equivalent parity
predicate reviewed above.

Both rounds retain 316 test threads inside disjoint 16-CPU reservations. Serial
launch passes **1,039 tests, 0 failed** in each. All 21 short-neighbor tests and
the previous trampoline/prefixed-pun allocation regressions pass in each round.
Five nested child summaries are excluded; both custom workspace harnesses
complete separately. Timeout cleanup completes with two descendants reaped.

[The receipt](native-5f6299e/native.json), [commands](native-5f6299e/checks.csv),
[scenarios](native-5f6299e/native-scenarios.csv) and
[controls](native-5f6299e/native-controls.csv) record exact revisions, commands,
CPU reservations, load and raw-result hashes on an AMD EPYC Zen 5 dev host.
Both source-revision native runs are retained and cover the same 64 scenarios;
repetition adds no unique coverage. The target, producer, structural verifier
and control artifacts are byte-identical across the parity correction.

These results cover authored XSAVE64 fixtures and artifact construction.
Source-restored files do not establish live retirement. Whole-program adjacent
coverage, general ELF admission, CET and performance remain unqualified. Every
artifact retains `qualification_complete=false`. All elapsed times here are
debug-build correctness receipts.

Reproduce the native campaign at the source revision with the same debug
profile environment above, Rust 1.97.1 and a disjoint CPU reservation:

```sh
cargo build --locked --offline -j 4 -p liteinst-rewrite --example adjacent_b2_native
python3 -B evaluation/adjacent-b2/native.py \
  --revision 5f6299e945c31ab6fb445aaf5f865a5d7154751b \
  --profile debug --output ignored/adjacent-b2-native-reproduction
```

The runner freezes one attempt at each stage and retains every result. A failed
stage prevents its consumers from running. It checks source and binary identity
before each stage and after completion, and retains bounded custody receipts.
The frontend controls run with
`cargo test -j 4 -p liteinst-rewrite --lib --example adjacent_b2_disassembly_sites -- --nocapture`.
Run `disassembly_controls.py`, `head_capture_controls.py`, and
`reproduce_whole_controls.py` in `evaluation/offline-corpus/` with `python3 -B`.

The [full-roster corpus diagnostic at 21728d7](corpus-21728d7/README.md)
retains all 187 instruction heads and 42 selected branches across checksum and
RLE. Both producers refuse without a candidate; mixed backward-JBE/forward-JMP
support remains missing. Its compact records preserve the earlier driver
failure, configuration-incomplete capture, controls and full workspace pass.
No artifact, native, corpus or performance qualification is claimed.
