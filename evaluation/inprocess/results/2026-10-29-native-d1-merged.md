# D1 admission after the call-pair merge

Native page admission now removes false HLE refusals for nontransactional D1 Group2 encodings. The all-offset selected-opcode and transactional barriers remain intact; there is no address or workload whitelist. This supports claims 2 and 4. The [original capability note](2026-10-29-native-d1.md) links the vendor rationale and component reproduction.

Source `d8c1917dfbb8148483fb849cc5892ff049e37a57` contains main `b66ce1fea7c48af00fca719574d19ed7e666cf4d`. Its [exact qualification](qualification-d8c1917dfbb8.json) records all six passing checks:

| Check | Result | Seconds |
|---|---:|---:|
| Recorder | 350 passed | 58.493 |
| Formatting | Passed | 8.178 |
| Clippy, all features/targets | Passed | 0.131 |
| Workspace | 3,521 passed, 0 failed, 37 ignored; 103 harnesses | 375.987 |
| Check, all features/targets | Passed | 27.835 |
| Serial launch | 1,039 passed, 0 failed; 27 harnesses | 172.973 |

The same revision passes the original 750,794 byte-policy checks plus 63,779 D1 cases, 3,584 canonical/14,336 strict-invalid LOCK decoder checks and 3,102,930 all-offset decoder observations, 102 BMI1 state pairs, six one-shot owners, all 49 failure/refusal controls, all 17 rseq application cases, and the original 16 registered/four boundary pairs. Required failed operations remain distinct from completed operations. Decoder mode checks do not claim 16/32-bit hardware execution.

[History at 690a5e5](history-690a5e5999cc.json) retains the earlier failed check run. Cargo exited zero, but the recorder rejected the new 271-test core harness because its exact historical summaryless-child tuple still named 262. That run remains `failed/invalid_evidence`, with two later checks not run. The correction adds only the exact `(unit/liteinst2/lib, 271, 1)` tuple and negative controls; it preserves the older tuples, stack/count/filtered checks and every existing assertion. The later complete run above supplies qualification.

The unchanged release workload remains **failed**: 12 of 20 subjects attempted, 11 completed. All five real `/bin/ls` pairs completed; process medians were 4.263784 ms native and 21.343949492 s gated. These are complete launch intervals, including namespace/exec/report costs, not steady throughput. The first gated hot process exited −9 after 30.265488721 s with the 30 CPU second limit in force and no wall timeout; its exact kernel kill origin was not separately observed. There is no completed gated hot-throughput, full first-touch or aggregate timing claim. [JSON](20261029T193417.491344Z-page-release-workload-performance-d8c1917dfbb8.json) and [CSV](20261029T193417.491344Z-page-release-workload-performance-d8c1917dfbb8.csv) retain every attempted process and completed timing row, exact commands, revision and hardware. The earlier 690 performance JSON/CSV also remain failed.

Shared metadata and lossless numeric tables keep both qualification histories compact. The separate two-page owner remains a private source candidate; these results provide no two-page execution or speedup claim.
