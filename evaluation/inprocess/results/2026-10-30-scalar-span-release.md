ADDS experimentally validated transfer from a genuine TRACE event into a broader scalar code cache. The whole-program comparison **failed qualification: 60 of 82 attempts passed**. Fewer traps and maps reads did not produce an acceptable whole-process cost. The 10×DynamoRIO target remains unmet.

The release source was `c7d02d8c4eac4be5759ca7d13c7c905791366811`, including core main `c712f7008af281191783f6478508ce4cad9d6bcb`. All ten native prerequisites and the fixed comparison used reserved CPU 16, unprivileged, on AMD EPYC 9D85 family 26/model 17/stepping 0, microcode `0xb101066`, Linux 7.1.3. Receipts bind exact tool versions, release archives, binaries, inputs and commands. Ordinary subjects retained 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB output; DynamoRIO alone retained its separate 16 GiB address-space bound.

All 82 attempts ran and all 174 commands closed. Twenty original-gate, twenty native and twenty DynamoRIO attempts qualified. All twenty ordinary TRACE-cache attempts and the true differential attempt exited zero but failed the unchanged original register-cache exhaustion check. LS used 30 old generations, 49 completions and 19 hits; true used 17/26/9. Neither retired an old register-cache generation. These are failed reader outcomes, not a demonstration that a different validator would accept the complete stream. The new span cache separately had positive retirement activity.

The LS differential attempt was killed at the original CPU limit: 10.157525 s user + 19.836036 s system, 30.221008841 s wall, exit -9, no wall timeout, and empty captures. True differential reported 647,343 fresh-versus-maintained comparisons and zero mismatches in 21.088716897 s, but remains failed qualification. No median, IQR, ratio or aggregate timing credit is granted. Only the twenty original-gate rows earned their reader controls: 2,780 original, 460 maps and 620 unrolled refusals; new span/current/chain controls earned no credit.

The following are **raw, unqualified observations from the first TRACE-cache attempt**, retained to explain the next design decision. They are not accepted equivalence or speedup results. Counts come from authenticated terminal records; no counts are inferred for the killed differential attempt.

| Observation | ls -d . | true |
|---|---:|---:|
| Whole-process wall, seconds | 14.071538490 | 5.651000495 |
| Handler events | 153,301 | 60,549 |
| TRACE traps | 95,012 | 37,380 |
| SEGV events | 58,141 | 23,074 |
| Completed translated spans | 43,034 | 17,441 |
| Publications / hits | 5,807 / 37,227 | 2,654 / 14,787 |
| Whole-plan validations | 134,845 | 54,913 |
| Per-plan rseq validations | 172,136 | 69,764 |
| Maps queries / fresh reads | 1,616,981 / 10,251 | 649,699 / 2,916 |
| Stack-frontier probes | 1,361,113 | 543,343 |
| Unsupported / graph / relocation refusals | 28,741 / 15,084 / 359 | 9,562 / 7,942 / 23 |

The first original-gate attempts took 9.652762668 / 3.679626040 s. The first native attempts took 5.622244 / 5.619602 ms, and the first DynamoRIO attempts 28.400449 / 21.370733 ms. These individual observations do not replace the withheld population statistics. Ordinary TRACE-cache wall ranges were 13.751820316–15.212122992 s for ls and 5.322503985–5.825004677 s for true; original-gate ranges were 9.640061486–9.955270025 and 3.623352781–3.724433203 s.

Relocation accounts for only 359 of 44,978 LS planning refusals. A drafted extra near arena therefore does not address the observed dominant population. The next architecture experiment needs one source-owned execution epoch spanning linked admitted blocks: authenticate and publish the immutable graph once, keep it RX across internal edges, and revoke the whole epoch before handing an unsupported frontier to a competing owner. Repeated full plan reconstruction, permission changes and queries must be replaced by an actual lifetime/exclusion contract, never omitted on a cached Boolean. Existing full-state, source, rseq, fault and retirement checks remain qualification requirements. Broader no-write cycle coverage is a separate contract; the graph-refusal count alone does not identify suitable loops or predict a speedup.

The ten prerequisites all passed and received independent raw-data review. They do not substitute for complete new-owner retirement/failure qualification:

| Prerequisite | Exact receipt |
|---|---|
| Span component 59 | [JSON](20261030T165456.414231Z-scalar-span-component-c7d02d8c4eac.json) |
| Genuine TRACE 9, four full-state pairs | [JSON](20261030T165606.963469Z-scalar-span-trace-c7d02d8c4eac.json) |
| Decoder 8 | [JSON](20261030T165756.818455Z-region-decoder-c7d02d8c4eac.json) |
| Scalar component 11 | [JSON](20261030T165834.797126Z-scalar-region-component-c7d02d8c4eac.json) |
| Certificate owner 43, transaction 8, mapping 8 | [JSON](20261030T165910.620073Z-scalar-region-reuse-certificate-owner-c7d02d8c4eac.json) |
| Original reuse owner 43, mapping 8 | [JSON](20261030T171536.949802Z-scalar-region-reuse-owner-c7d02d8c4eac.json) |
| Unrolled component 9 | [JSON](20261030T172820.680510Z-unrolled-hash-component-c7d02d8c4eac.json) |
| Original owner 25 | [JSON](20261030T172852.841188Z-unrolled-hash-owner-c7d02d8c4eac.json) |
| Current-view component 34 | [JSON](20261030T173229.912893Z-maps-current-component-c7d02d8c4eac.json) |
| Current-custody owner 27 | [JSON](20261030T173503.099554Z-current-custody-owner-c7d02d8c4eac.json) |

[Six required checks](20261030T163702.100200Z-checks-c7d02d8c4eac.json) also passed at c7d: recorder 356; fmt; strict Clippy; workspace 3,824 passed / 37 ignored across 106 harnesses; all-targets/all-features check; serial 1,039 passed across 27 harnesses. Original command and output limits remained unchanged.

A separate final-publication bug shadowed the CSV buffer with a capture-stream string after the failed private receipt had closed. Revision `172693fba938b0e729597d32e55630fdccb883ed` fixes only that publisher loop and adds a data-only recovery script. A retained data-only execution exited zero on reserved CPU 1 with 5 CPU seconds, 15 wall seconds, 512 MiB and 16 MiB limits and reproduced the public pair byte for byte; it did not rerun subjects or alter the original receipt. The recovered [JSON](20261030T173939.345604Z-scalar-span-trace-performance-c7d02d8c4eac.json) and [CSV](20261030T173939.345604Z-scalar-span-trace-performance-c7d02d8c4eac.csv) preserve all 82 outcomes and disabled timing credit. The JSON separately labels 21 unqualified terminal counter rows. Original private receipt SHA256: `ed4283f34475cc7d545f7134d1bc1a7f5a2c2d10e998ce621c7973099931e918`.

Reproduce native measurement using the ten prerequisite scripts and exact commands in their receipts, then [unrolled_hash_performance.py](../unrolled_hash_performance.py) with `--scalar-span-trace` and the complete `reproduce` argv in the result JSON. Supply the recorded DynamoRIO SDK and one reserved CPU; fresh receipts must share the new run's revision and CPU. To reproduce only publication from retained original artifacts, check out 172693f and run [scalar_span_publish_recovery.py](../scalar_span_publish_recovery.py) with the JSON's `publication_recovery.reproduce` arguments and a new output path. All previous failed cohorts remain failed. This is evidence for claims 1 and 4 in the stated finite scope, not B3 completion or the requested throughput target.
