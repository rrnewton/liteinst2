# Current-view custody: component success, native qualification failure

Claims 1 and 4 only. This experiment has no whole-program performance credit.
The native subjects used release builds on reserved CPU 15, AMD EPYC 9D85,
Linux 7.1.3, revision `e578e91ed484a918079d8185038b23b2548bc78a`.
Each linked JSON records the exact command, hardware, bounds and capture hashes;
its adjacent CSV preserves the numerical case outcomes.

| Cohort | Result | Evidence |
| --- | --- | --- |
| Original unrolled component | 9 passed, including 2 required read faults; 373 reader refusals | [JSON](20261030T121317.220187Z-unrolled-hash-component-e578e91ed484.json) |
| Current-view lifecycle component | 28 passed: 6 completed, 22 required API refusals; 700 reader refusals and 88 compiled-storage controls | [JSON](20261030T121346.698633Z-maps-current-component-e578e91ed484.json) |
| Current-view native owner | **Failed**; all 27 subjects launched, only 9 native references qualified; no gated/native pair qualified | [JSON](20261030T121516.229186Z-current-custody-owner-e578e91ed484.json) |

Seventeen gated records encountered an incorrect reader requirement that every
protected range be page-aligned. The runtime registers ten metadata objects by
their exact byte extents. The correction joins each registration to the actual
ELF symbol, DWARF type and complete RW/NX load, while preserving the nine current
objects' exact rounded load registrations. A second reader correction joins the
new terminal row to its protected snapshot before reading the unchanged older
report suffix. Neither correction requalifies these failed records.

The physical-fallback subject exposed a separate runtime defect: a real stack
`mprotect` retires maps reuse; the subsequent physical commit refresh discards
its staged custody. It exits 125 with chain error 903/detail 302, instead of the
required successful exit. Its terminal maps counters include 2,854 physical
refreshes and zero mismatches, but the subject did not reach its focal prefix.
These counters are not a completed workload or equivalence claim.

Independent closed-data audits verified all commands, captures and source
closure for these three cohorts. The failed owner run closed all 78 commands
with complete cleanup and no final closure errors. Fresh native qualification
is required after repair; the 10-times-DynamoRIO target remains unmet.

The separate [recorder diagnostic](20261030T122438.667498Z-recorder-shards-df119a0b9025.json)
at `df119a0b9025f905109646d06ddbee5a05493ee4` exited 1 after 124.775107 seconds
on reserved CPUs 23, 53, 62 and 72, within the unchanged 180-second limit.
It failed the synthetic partition API test and a strict historical error-code
test. This remains a failed validation result, with no credit for the other
five required checks. Reproduce with the receipt's tracked recorder command;
the process owner retains its 8 MiB output limit and complete cleanup.

After correcting those two defects, the [fresh recorder diagnostic](20261030T123121.738863Z-recorder-shards-38736fcdda54.json)
at `38736fcdda54f04b1cca5fd41b51327c3680524a` passed all 354 tests in
166.383721 seconds on reserved CPUs 35, 50, 121 and 147. Source and configuration
were unchanged and cleanup completed. The 180-second deadline, four-worker
limit and 8 MiB output cap remain unchanged. This qualifies the recorder only;
the other five required checks remain pending.

At revision `a60c96fcc007d039a2ba83a4878e6c96ecb41009`, fresh release
qualification ran unprivileged on reserved CPU 74, AMD EPYC 9D85, Linux 7.1.3
(microcode `0xb101066`). The component and original owner prerequisites passed;
the new current-custody owner **failed**.

| Cohort | Actual outcome | Evidence |
| --- | --- | --- |
| Original unrolled component | 9 qualified; 2 required read faults; 373 reader refusals | [JSON](20261030T123804.577436Z-unrolled-hash-component-a60c96fcc007.json), [CSV](20261030T123804.577436Z-unrolled-hash-component-a60c96fcc007.csv) |
| Current-view component and fallback companion | Original 28 plus 6 companion cases qualified; 700 + 192 reader refusals; 88 compiled-storage controls | [JSON](20261030T123847.340940Z-maps-current-component-a60c96fcc007.json), [CSV](20261030T123847.340940Z-maps-current-component-a60c96fcc007.csv) |
| Original unrolled owner | 25 qualified; 9 native/gated pairs and 7 required owner refusals; 234 application, 472 owner and 542 terminal reader refusals | [JSON](20261030T124100.792208Z-unrolled-hash-owner-a60c96fcc007.json), [CSV](20261030T124100.792208Z-unrolled-hash-owner-a60c96fcc007.csv) |
| Current-view native owner | All 27 launched with expected process exits; 9 native references qualified, all 18 gated records rejected | [JSON](20261030T124442.273065Z-current-custody-owner-a60c96fcc007.json), [CSV](20261030T124442.273065Z-current-custody-owner-a60c96fcc007.csv) |

The current-owner reader incorrectly required positive `initial_extent` on the
fixed main-image source. All 18 records instead contain allocation 1,
generation 7 and `initial_extent=0`. The lifecycle constructor and unchanged
original main-image reader require that exact zero annotation. A correction
must retain positive allocation/generation and require exactly zero here;
it cannot accept an arbitrary extent or retroactively qualify this cohort.

The physical-fallback process now exits 0. Its retained bytes show the real
stack protection request, a fresh physical query at commit without losing the
staged epoch, and subsequent retained continuation without new physical I/O.
The stale subject exits 125 as required. These are descriptive observations:
none of the 18 gated records reached the mandatory reader/control completion.
The original 25 cases and the separate stale/fallback cases remain required.

Independent closed-data audits authenticated source, artifacts, captures and
cleanup; all 78 current-owner commands closed without final closure errors.
The original component 5 CPU/15 wall-second and owner 30 CPU/60 wall-second
limits, 512 MiB address-space and 16 MiB file limits remain unchanged. No
performance cohort launched from this failed prerequisite, no diagnostic replay
can supply qualification credit, and the whole current-custody qualification
and 10-times-DynamoRIO target remain unmet. The component CSV retains its
original 28-case scope; the six added companion outcomes are in its JSON.
