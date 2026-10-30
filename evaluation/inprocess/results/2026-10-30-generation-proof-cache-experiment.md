# Generation-bound proof cache: native qualification passed, performance gate failed

Revision `1bf1874920384e517927f060cff926b2f43022d9` passed the six native qualification cohorts below. The mandatory performance cohort **failed: 81 of 82 attempts passed**. Observed certificate-profile intervals were slower than unrolled despite fewer traps. This is a qualified capability experiment, not a demonstrated performance improvement. The 10× DynamoRIO target remains unmet; no aggregate timing, speedup, median or IQR is credited.

The cache binds each scalar plan/no-write proof to its generated address, slot generation, source key, decoder archive and policy. Published certificate extents are read-only/non-executable. Replacement consumes the completed-generation permit and retires the old code/certificate authority before making storage writable. Cold construction/retirement retain full proofs; warm entries retain live source, permission, borrow, session, mask and rseq guards. Full-state comparisons remain mandatory. This changes repeated proof work, not the trap-count mechanism. This release does not select `LI2_MAPS_CURRENT_TF`.

All runs were unprivileged release builds on reserved CPU 6, AMD EPYC 9D85, microcode `0xb101066`, Linux 7.1.3. Receipts bind commands, tools, inputs, artifacts, captures and cleanup; adjacent CSVs retain outcomes.

| Cohort | Qualified population and supplied refusals | Commands | Evidence |
| --- | --- | ---: | --- |
| Decoder | 8 / 104 | 44 | [JSON](20261030T143637.618521Z-region-decoder-1bf187492038.json) |
| Scalar hardware component | 11, including 6 required read faults / 535 | 41 | [JSON](20261030T143716.698404Z-scalar-region-component-1bf187492038.json) |
| Certificate owner | 43; 13 native/gated pairs and 17 required owner refusals | 161 | [JSON](20261030T143752.634927Z-scalar-region-reuse-certificate-owner-1bf187492038.json) |
| Original reuse owner | 43 / 4,102 owner, 1,964 terminal, 348 application | 140 | [JSON](20261030T145431.597856Z-scalar-region-reuse-owner-1bf187492038.json) |
| Original unrolled component | 9, including 2 required read faults / 373 | 31 | [JSON](20261030T150759.871818Z-unrolled-hash-component-1bf187492038.json) |
| Original unrolled owner | 25 / 472 owner, 542 terminal, 234 application | 75 | [JSON](20261030T150828.036720Z-unrolled-hash-owner-1bf187492038.json) |

The certificate owner retains all original 4,102/1,964/348 refusal controls and adds 999 certificate-record and 450 certificate-terminal refusals. All eight mapping refusals passed 152 original and 184 certificate controls; all 754 protection-predicate cases passed. Eight transaction modes passed 256 controls with supplied caller/completion boundaries, limited to component evidence. There were 38 bounded metadata children. Audits checked actual generations/permissions/payloads, all 65,536 FP bytes, GREGs/AF, 224 stack and 8,192 data bytes, and real fault/nested prefixes. Refusals receive no completion credit.

The [performance JSON](20261030T151137.323919Z-scalar-reuse-certificate-performance-1bf187492038.json) and [CSV](20261030T151137.323919Z-scalar-reuse-certificate-performance-1bf187492038.csv) retain all 82 attempts and 166 commands. LS differential exited -9 after 30.209020459 seconds wall time and 29.996222 seconds of recorded user+system CPU. The wall-timeout flag is false; this occurred near the unchanged 30-second CPU limit, below the 60-second wall limit. It emitted no complete terminal counter row. The other 81 attempts passed, including all 40 fresh native/DynamoRIO processes. Source/artifact closure and cleanup passed with no final errors; the comparison gate remains failed.

Observed pre-launch-to-reap intervals include startup/reporting: ten ordinary samples per cell, seconds, without qualified timing estimates or ratios:

| Workload | Unrolled | Certificate reuse | Native | DynamoRIO |
| --- | --- | --- | --- | --- |
| LS | 9.710324789–11.518178246 | 15.624018343–16.719198851 | 0.005361911–0.005940186 | 0.027718630–0.064941401 |
| true | 3.607088082–4.737329551 | 5.680896932–6.622899791 | 0.004811182–0.006368553 | 0.021258708–0.036921589 |

Ordinary observed counts:

| Workload/profile | Handler events | TRAP signals | Physical refreshes |
| --- | ---: | ---: | ---: |
| LS/unrolled | 218,094–218,095 | 188,185 | 59,484 |
| LS/certificate reuse | 198,990–199,000 | 169,119–169,127 | 56,196–56,197 |
| true/unrolled | 84,661 | 74,963 | 21,938 |
| true/certificate reuse | 78,631–78,641 | 68,959–68,967 | 20,944–20,945 |

Each ordinary certificate LS run retained 9,023 entries, 1,976 static plan checks, 1,020 static rseq proofs, 18,046 certificate comparisons and 27,069 live rseq checks; true retained 3,026/1,126/595/6,052/9,078 respectively. The original scalar-reuse performance lane was not measured here, so this cannot isolate the certificate’s effect. The successful true differential run made 375,754 maps queries: 20,940 refreshes plus 354,814 comparisons, zero mismatches. The LS differential requirement remains failed.

Program limits remain 30 CPU/60 wall seconds, 512 MiB address space and 16 MiB output; DynamoRIO retains its original 16 GiB address-space allowance and SDK 11.91.0. Hardware components retain 5 CPU/15 wall seconds; decoder, transaction and boundary subjects retain 3 CPU/10 wall. No limit was increased. Reproduce from that clean revision on one reserved CPU: run the receipts' commands in table order, then the performance command with fresh same-revision/same-CPU prerequisite receipts and the pinned SDK.

The [earlier 1fa325 failure](2026-10-30-certificate-qualification-attempt.md) remains failed. Reader corrections added strict controls and required fresh native observations; diagnostic replays earned no qualification.

**Repository checks failed in preflight.** The [receipt](20261030T152554.678318Z-checks-1bf187492038.json) records `ac0963_source_inventory_differs`; all six commands were not run. The merged startup sources require a strict inventory successor and fresh checks. No repository-wide pass or landing readiness is claimed.
