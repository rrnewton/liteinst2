# Linked native-hint finite qualification passes

The complete 26-subject finite profile **passes** at revision `92fb7d268751cba077fd763903daba0b76168a94` on reserved CPU 62. Metadata and all 25 hardware subjects qualify, including seven full-state native/gated pairs and the actual 65-entry replacement case. All 113 commands exit as expected; source remains unchanged, cleanup completes and no finalization error is reported.

Mode 5 retains two separate real witnesses: relocation retry and positive-advisory GRAPH retry, each from genuine TRACE through the next hardware NX, native admission and complete native close. Three corruption probes observe actual advisory invalidation and zero selection; they are not native-policy refusals. The replacement case retains 65 distinct source heads and generations, complete 64 KiB proof payloads, and an actual closed-generation replacement transaction.

This is finite graph, lifecycle, retry and replacement qualification. The fixed 62-launch performance cohort has no result credited here. No whole-program, preedge, MOV-store, performance ratio or aggregate claim follows from this pass. The ten-times-DynamoRIO target remains unmet.

| Attempt | Reserved CPU | Qualified | Commands | Outcome |
|---|---:|---:|---:|---|
| `1537ee5aef03` | 13 | 1/26 | 46 | **FAILED:** capture compilation stops under `-Werror`; metadata passes, no hardware subject starts. |
| `8b5b98949cbd` | 66 | 21/26 | 113 | **FAILED:** five record readers reject completed outputs; all 26 subjects were attempted. |
| `91d2a0dd575f` | 1 | 24/26 | 84 | **FAILED:** stale collector total stops before either reuse65 subject launches. |
| `92fb7d268751` | 62 | 26/26 | 113 | **PASSED:** all required subjects, pairs, raw records and control groups complete. |

| Control group | `8b5` completed / required | `91d2` completed / required | `92fb` completed / required |
|---|---:|---:|---:|
| Application | 234 / 234 | 198 / 234 | 234 / 234 |
| Owner | 385 / 477 | 430 / 477 | 477 / 477 |
| Terminal | 3,934 / 5,464 | 5,146 / 5,464 | 5,464 / 5,464 |
| Relocation retry | 149 / 187 | 178 / 187 | 187 / 187 |
| CR2 pair | 4 / 4 | 4 / 4 | 4 / 4 |
| Hint owner | 208 / 346 | 342 / 366 | 366 / 366 |
| Hint terminal | 533 / 738 | 697 / 738 | 738 / 738 |

All attempts used an unprivileged AMD EPYC 9D85 158-Core Processor, microcode `0xb101066`, Linux `7.1.3`, and recorded release recipes. Program limits remain 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB per output. No hardware subject in these attempts hit a limit. The actual original and reuse record sizes are 16,659,520 and 16,691,072 bytes including footers, both below the unchanged limit. The full GREG, actual AF, 65,536-byte FP, mask, lane-local TLS, source, data, stack, fault-PC, protection and generation comparisons remain mandatory.

The `8b5` failures were mode 5, three advisory probes, and gated reuse65. Two reader premises were incorrect: page publications were equated with closed epochs, and an unregistered rseq state was required to be held. The repairs require exact owner identity, lifecycle page counts, completed epochs and entries; reuse requires held, phase, calls and epoch all zero. All old controls remain, with 20 added causal hint controls. A separate retained-reader diagnostic completed 25 hardware readers and seven pairs, preserving its initial namespace-path failure and the original native failure.

The `91d2` collector still expected 326 original hint refusals and 20 reuse refusals after the reviewed additions required 342 and 24. Its exact gate now requires those new totals; no alternative count is accepted. That failed attempt received no credit for the absent reuse pair. Only the fresh `92fb` run supplies the complete native result. The earlier [relocation-only baseline failure](2026-10-30-linked-epoch-baseline.md) also remains unchanged.

Compact evidence preserves each attempt:

- `1537`: [JSON](20261030T203143.736564Z-linked-epoch-native-hint-1537ee5aef03.json), [CSV](20261030T203143.736564Z-linked-epoch-native-hint-1537ee5aef03.csv).
- `8b5`: [JSON](20261030T203801.819918Z-linked-epoch-native-hint-8b5b98949cbd.json), [CSV](20261030T203801.819918Z-linked-epoch-native-hint-8b5b98949cbd.csv).
- `91d2`: [JSON](20261030T205423.044845Z-linked-epoch-native-hint-91d2a0dd575f.json), [CSV](20261030T205423.044845Z-linked-epoch-native-hint-91d2a0dd575f.csv).
- `92fb`: [JSON](20261030T210413.960396Z-linked-epoch-native-hint-92fb7d268751.json), [CSV](20261030T210413.960396Z-linked-epoch-native-hint-92fb7d268751.csv).

The latest receipt's portable reproduction command, on one reserved CPU, is:

```sh
python3 -B evaluation/inprocess/linked_epoch.py --expect-revision 92fb7d268751cba077fd763903daba0b76168a94 --native-hint
```
