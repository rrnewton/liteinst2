Execution across two disjoint source pairs now passes an actual native comparison
at `057a09e1b34bb3b64c71d577527e858ba2adc033`. Two cold publications are followed
by a warm domain that holds both source pairs. Canonical register-JMP handoffs
reach the destination before its first instruction executes. The warm interval
models 512 generated instructions and 127 transfers between the two certificates;
it records zero interior signals. Both certificates' 34 generated pages close
before source and lifetime authority are released.

The maintained and fresh-maps differential lanes match the original 522-PC,
12-frame native reference: all 23 GREGs, 65,536 FP bytes per full frame, four
source pages, data, stack, permissions, TLS and lifetime. Both pass all 320
owner, 24 pair, 73 terminal, 33 TLS, 22 probe, 19 internal-entry and 12 effect
controls. The native reference passes 36 controls; the actual handoff component
passes 216 predicate and transition checks. The differential lane records
33,326 current-view comparisons with zero mismatches.

The [JSON](results/20261031T144543.379088Z-cross-pair-loop-057a09e1b34b.json)
and [CSV](results/20261031T144543.379088Z-cross-pair-loop-057a09e1b34b.csv)
record exact revision, hardware, commands and release artifacts. On one reserved
AMD EPYC 9D85 CPU, native took 0.177260532 s, maintained 1.688112599 s and
differential 2.902341827 s. These are qualification durations, including launch
machinery, without application performance credit. Reproduce at that revision
with `cpuset-alloc run --cores 1 -- python3 -B evaluation/inprocess/cross_pair_loop.py --expect-revision 057a09e1b34bb3b64c71d577527e858ba2adc033`.

The prior failed checks remain recorded at `678b8ff` and `70a2cf1`. Their
readers expected the wrong source-validation count and warm rseq footprint.
The final reader requires the extra peer-source validation and exact inheritance
of the complete 872-byte warm rseq state; it retains all earlier controls and
adds 28 causal refusals. No execution, output or resource bound changed.

This fixture uses a tiny interpreter. Whole-profile qualification remains false:
the original 392-instruction cohort remains a separate mandatory gate, and its
latest generated runs still fail at the unchanged 30 CPU-second limit. Its
failure and the failed real-startup prefix are documented in
[the earlier internal-entry report](internal-entry-qualification-2dcdd1f.md).
This result supports claims 1 and 4 within the finite fixture. It establishes
neither faster real loader startup nor the target within ten times DynamoRIO.

The [required-check receipt](results/20261031T150430.538811Z-checks-057a09e1b34b.json)
passes all four cargo checks, all 366 recorder tests and all 1,039 serial launch
tests. Workspace testing reports 4,218 passed, zero failed and 37 ignored across
all 112 expected harnesses. Source and configuration remain unchanged throughout
the six checks; all complete within their original bounds.
