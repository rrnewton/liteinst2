# Ordinary-call reference reader qualification

Revision `d5caaf4a30451df08f8eaa5efd13310409748421` adds an independently
fenced reference enclosure around two actual ordinary ABI calls. The release
qualification passed all 23 top-level stages and its unchanged prerequisite
chain on the AMD EPYC Zen 5 dev host. This supports claim 4: architectural and
endpoint-provenance validation. It does not establish timing accuracy or
performance.

The four new original/installed pairs cover two seeds and lengths 1 and 64,
with two equal-length calls sharing immutable input in each child. They perform
1,736 architectural comparisons with zero mismatches. The native witness checks
all 640 helper instruction heads, including 368 reader-interior heads, all 32
actual RDTSCP results and their 96 low-word stores, whole guarded cell pages,
16 returned cells, 16 target CALL/RET pairs, eight actual outer RETs and eight
normal child reaps. Registers, defined flags, XSAVE, complete input, protected
stack and source/generated/helper bytes remain checked. Timestamp-changing
reader interiors use explicit same-child instruction-effect checks; restored
points and both complete original bodies retain cross-child comparisons.

The unchanged ordinary-call population adds 17 pairs and 4,044 comparisons;
the unchanged Exact37 caller adds four pairs and 1,696 comparisons. All 25
pairs therefore complete 7,476 comparisons with zero mismatches. The original
8+8 functional calls and both abandonment controls also pass. The separate
named, selected and strnlen prerequisites remain mandatory. The new suffix runs
57 Python/Rust controls with exact test inventories. Every one of the 69 stage
receipts in the full chain was independently rechecked against its request,
output and clean closure. No cleanup rescue was needed.

The new native stages keep 20 CPU seconds / 30 wall seconds each, an absolute
15-second deadline per pair and 20,000 continuous steps per child. Observed
reference candidate steps range from 7,137 to 7,920. The whole recipe took
101.415 seconds; this is an operational validation duration, not a throughput
measurement. Release compilation used optimization level 3, no debug info,
and enabled assertions and overflow checks. Exact tools, hardware, binary and
source-manifest hashes are in `receipt.json`.

The first attempt at `4e9825d963dbffb65525c8f940c3e24cebc65503` remains FAILED:
all four new owner controls rejected their valid labels. `object` 0.36.7's
`is_definition()` excludes zero-size NOTYPE labels. The correction validates
their exact concrete section and address, and checks every extra selected-section
symbol. Added controls cover undefined/unresolved section indices, an extra
unnamed label, and valid/invalid standard section symbols. No body, label
shape, comparator, workload or deadline was relaxed. Native reference stages
were UNRUN in that failed attempt.

Reproduce from the exact revision with Rust 1.97.1, GCC 11.5.0 and Python 3.12.15:

```sh
python3 -B tools/rapid-profiler/verify_normal_interval.py \
  --reference-exact --revision d5caaf4a30451df08f8eaa5efd13310409748421 \
  --raw "$PWD/ignored/NEW_REFERENCE_RUN" --toolchain "$TOOLCHAIN" \
  --user-home "$HOME" --cargo-home "$CARGO_HOME"
```

The recorded run inherited four cooperatively reserved CPUs with hard CPU
assignment. This does not exclude unrelated host work. The recipe authenticates
Git source before imports, fresh whole ELF artifacts before candidate copies,
Cargo release products, exact control censuses and every owned stage. Run the
seven workspace gates with the command recorded under `required_checks`.
`checks.csv` records their exact-revision outcomes and command durations.
All seven passed: default-parallel workspace 3,036 passed / 0 failed / 36 ignored
in 333.495 seconds; serial launch 1,039 passed in 126.855 seconds; staged
allocation 3 and prefixed-pun 36. All seven historical exec/allocation failure
names appeared exactly once as passes in the workspace log. No affinity or
libtest thread override was used for the workspace (316 permitted CPUs).

The CSV files retain all ordinary, Exact37 and reference rows, including every
raw reference endpoint. The endpoints were collected while single-stepping;
their differences are deliberately not interpreted as native duration or
observer overhead. Mixed lengths/distinct input buffers, timing calibration,
accuracy, concurrent reference callers and the broader A5 matrix remain open.

The four earlier whole timed Exact37 session attempts remain FAILED as recorded
in [the separate progress receipt](../ordinary-exact-progress-20261028/README.md).
This qualification neither repeats nor completes that temporal campaign.
Raw logs, complete source inventories and private captures stay under `ignored/`;
this directory contains compact measurements and exact receipts only.
