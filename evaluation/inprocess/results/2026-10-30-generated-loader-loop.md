ADDS an opt-in immutable generated loop for the real dynamic loader hash routine, executed in process without a ptrace supervisor (claims 1 and 4). It passes the native state and actual-owner qualification. The release application cohort remains **FAILED** because the required `ls` maps differential run was killed near its original CPU limit. The 10×DynamoRIO target is not reached.

The runtime copies the loop body into a write-once private image with 64 unrolled iterations. Hardware performs the original data loads. Every exit returns to a held original NX instruction, and the runtime closes generated execution before releasing source ownership. One published image is reused across entries; each entry retains the existing source, backing, alias, rseq, full-frame and permission checks. This is one qualified loop, not a general translated-block engine.

Exact measured revision: `dbaf6a3d42a1514b4908909c0db5fc2b0530203e`. Hardware: AMD EPYC 9D85, family 26/model 17/stepping 0, microcode `0xb101066`, Linux 7.1.3. The unprivileged application cohort used reserved logical CPU 207. Bridges were release builds with `-O2`; the decoder archive, compiler, original binaries, dependencies and command identities are bound in the receipts. From a clean checkout of that exact revision, reproduce in order on separately reserved single CPUs:

```sh
python3 -B evaluation/inprocess/unrolled_hash_component.py --expect-revision dbaf6a3d42a1514b4908909c0db5fc2b0530203e
python3 -B evaluation/inprocess/unrolled_hash_owner.py --expect-revision dbaf6a3d42a1514b4908909c0db5fc2b0530203e
python3 -B evaluation/inprocess/unrolled_hash_performance.py --expect-revision dbaf6a3d42a1514b4908909c0db5fc2b0530203e --component-receipt evaluation/inprocess/results/20261030T081144.606394Z-unrolled-hash-component-dbaf6a3d42a1.json --owner-receipt evaluation/inprocess/results/20261030T080844.718163Z-unrolled-hash-owner-dbaf6a3d42a1.json
```

For a new reproduction, substitute the two newly produced receipt paths in the last command. Preserve the script's exact source and prerequisite checks, all fixed cases and original bounds. The program limits are 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB file size.

Qualification passed at that revision: nine component modes yield seven completed chunks, six completed loops, two required hardware read faults and 373 reader refusals. The 25 owner subjects comprise nine native, nine gated and seven required refusal controls: nine qualified pairs, 14 completed applications, two native and two gated read faults, 234 application-reader refusals, 472 owner-reader refusals and 542 terminal-reader refusals. The comparisons retain all GPRs, actual flags including AF, full 65,536-byte FP observations, mask/TLS, stack/data and exact generated fault-PC associations. A capture-only nested observer preserves actual live XSAVE state and the destination stack preimage; it does not initialize away differences. All historical failed qualification receipts remain failed. Independent closed-data reviews authenticated both complete results.

The fixed application cohort launched all 42 attempts exactly once: ten `ls -d .` and ten `true` runs per observe-only/active variant, followed by one differential run of each workload. All 40 ordinary runs passed, as did differential `true`. Differential `ls` exited -9 after 30.243134913 wall seconds, with 29.994675 CPU seconds and no wall timeout, consistent with the equal 30-second CPU soft/hard limit. Its output has no complete terminal counters. All 101 commands were reaped, descriptors closed, source unchanged and final cleanup complete. No failure is replaced or dropped.

The table contains ranges over **all ten ordinary attempts in each row**. These are retained observations, not an accepted performance cohort: no medians, IQRs or aggregate speedup are claimed. Exact nanoseconds and every attempt remain in the CSV.

| Workload / variant | Wall seconds, min–max | Handler events | SIGTRAP | Physical fresh maps acquisitions |
|---|---:|---:|---:|---:|
| ls / observe | 11.148507528–12.259250749 | 271562–271565 | 231315–231317 | 64873–64874 |
| ls / generated | 9.601856938–10.328292792 | 218016–218028 | 188106–188116 | 59472–59473 |
| true / observe | 4.072603498–9.889391804 | 103043 | 89769 | 23788 |
| true / generated | 3.599952601–4.399835872 | 84598 | 74904 | 21930 |

Every active `ls` attempt has one publication, 465 cache hits, 466 completed entries and 5,402 loop iterations. Every active `true` attempt has one publication, 137 hits, 138 completed entries and 1,859 iterations. All have zero head-cap exits, unexpected generated events and capacity misses. The actual signal classes are disjoint; the older route counters overlap and must not be summed. Counts begin after the existing nonreturning unsafe-rseq ingress guards and include bootstrap self-tests. Physical fresh requests equal miss refreshes plus differential comparisons.

Differential `true` completed in 12.033420307 seconds with 339,904 complete cached/fresh comparisons, zero mismatches, 21,934 miss refreshes and 361,838 physical fresh acquisitions. This qualifies cached/fresh equivalence for that run. Complete `ls` equivalence remains unproved. Differential time receives no performance credit.

The experiment removes tens of thousands of trap events, but still incurs approximately 188,000 SIGTRAP events and 59,000 fresh maps acquisitions per `ls`. The historical DynamoRIO median is 26.3060775 ms, making the requested 10× threshold 263.060775 ms. There is no contemporary DynamoRIO lane in this cohort. The observed multi-second active runs do not approach that threshold. The next architectural unit must retain a decoded graph and its source/exit ownership across internal edges; more one-block validation cannot close this gap. The read-only graph, stores, indirect control and longer-lived execution each require their own native qualification before performance credit.

Compact numerical records and reproduction identities:

- [Owner JSON](20261030T080844.718163Z-unrolled-hash-owner-dbaf6a3d42a1.json) and [CSV](20261030T080844.718163Z-unrolled-hash-owner-dbaf6a3d42a1.csv).
- [Component JSON](20261030T081144.606394Z-unrolled-hash-component-dbaf6a3d42a1.json) and [CSV](20261030T081144.606394Z-unrolled-hash-component-dbaf6a3d42a1.csv).
- [Failed application cohort JSON](20261030T081404.390248Z-unrolled-hash-performance-dbaf6a3d42a1.json) and [CSV](20261030T081404.390248Z-unrolled-hash-performance-dbaf6a3d42a1.csv).

The private application receipt digest is `1c50862bc80e8ea6cd5a126ca33f17221178d2353121c5c0b9bd75edc73bfac6`; raw logs and machine-state captures remain outside tracked evidence. Public files contain numerical summaries and hashes only.

The landing composition merges main `3155b2d3db716b167fae807eae5f9d2e2b835296` and is validated at `de4feb92422208e8c69cbdef6d14dfcf0f51618d`. All six required checks passed under unchanged bounds: 350 recorder tests, formatting, strict workspace Clippy, workspace 3,670 passed / 0 failed / 37 ignored across 105 harnesses, all-targets/all-features check, and serial launch 1,039 passed / 0 failed across 27 harnesses. The same nine component modes and 25 owner subjects passed again at this revision, with unchanged state/fault/refusal totals. These reruns do not add a new application performance cohort.

- [Merged-tree check receipt](20261030T085520.180869Z-checks-de4feb924222.json).
- [Merged-tree component JSON](20261030T091711.804672Z-unrolled-hash-component-de4feb924222.json) and [CSV](20261030T091711.804672Z-unrolled-hash-component-de4feb924222.csv).
- [Merged-tree owner JSON](20261030T091416.487497Z-unrolled-hash-owner-de4feb924222.json) and [CSV](20261030T091416.487497Z-unrolled-hash-owner-de4feb924222.csv).

The preceding workspace check at `47f36d7927c471a4f7a805c3ca1643b0abce40b7` exited 0 but had invalid evidence: child-test stdout interleaved with the parent harness summary. Three child stdout redirects fixed that output isolation; native assertions, parent status/control-pipe checks, stderr, deadlines, cleanup, parser and counts stayed unchanged. Its [failed receipt](20261030T083306.324136Z-checks-47f36d7927c4.json) remains failed. A separate [mistyped-revision attempt](20261030T085512.608604Z-checks-de4feb9f135e.json) refused before executing any check. Each new receipt records its exact hardware, command, revision and result.
