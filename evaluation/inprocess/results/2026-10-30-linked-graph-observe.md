# Linked GRAPH first-refusal observation

In one `/bin/ls -d .` run, the linked planner's 28,331 GRAPH refusals were most often triggered by a discovered edge outside the source page: 22,776. The observer recorded 4,534 actual Kahn stalls, 1,013 unsupported-frontier capacity refusals and 8 queue-capacity refusals. This points first toward a distinct page-boundary experiment. It does not show that all GRAPH refusals are cycles.

This is a completed, **unqualified diagnostic**, not a performance comparison or native-owner qualification. It leaves the planner's supported instructions, return codes, first-refusal ordering, 64-head / 8-frontier / 128-map limits and 40,704-byte plan unchanged. The release build adds only `LI2_LINK_GRAPH_OBSERVE=1` to the native-hint recipe.

| First GRAPH refusal | Count |
|---|---:|
| Initial enqueue invariant | 0 |
| Enqueue outside source page | 22,776 |
| Queue capacity | 8 |
| Source-byte overlap | 0 |
| Unsupported-frontier capacity | 1,013 |
| Supported-head capacity | 0 |
| Empty supported heads | 0 |
| No unsupported frontier | 0 |
| Unresolved primary successor | 0 |
| Unresolved conditional fallthrough | 0 |
| Kahn stall | 4,534 |
| Zero distance | 0 |
| Incoming-edge underflow | 0 |
| **Exact GRAPH total** | **28,331** |

The counters include every planner call, including reconstruction. This execution exited zero with no linked/native/hint error and no counter overflow; the reason sum equals the actual cold GRAPH refusal count exactly. These are planner decisions about reachable edges, not counts of actual guest page crossings. A first refusal hides any later property of that candidate. In particular, page-crossing candidates may have other problems, and “no unsupported frontier” is a separate category, not cycle evidence. No exit kind or source-PC distribution was collected.

The actual process recorded 132,298 events, including 90,609 TRAP events; 31,114 linked entries; 1,016 graph retries followed by native admissions; and 295 relocation retries. Maps counters were 1,637,438 queries, 1,625,771 hits, 11,667 refreshes and zero comparisons, so physical fresh observations were 11,667. The complete JSON also retains updates, invalidations and unexplained counts. The exact stdout was `.\n`. Popen-to-reap elapsed time was 12.343909774 seconds; the complete capture window was 12.344586360 seconds. These are observations from one instrumented execution, with no speedup, saved-event or timing-comparison claim.

Source revision: `52f9b7b81a80e698b556e980301b8b01b61978e7`. The runner reserved CPU 16 on an AMD EPYC 9D85 158-Core Processor, x86-64, microcode `0xb101066`; the receipt records one-CPU affinity and the complete hardware fingerprint. Subject limits remained 30 CPU seconds / 60 wall seconds / 512 MiB / 16 MiB. The fresh decoder build, source/policy/header binding, actual ELF checks and mandatory byte oracle all completed under their original separate bounds. All 33 commands exited zero; all 66 captures, 1,798 inputs and 88 artifacts authenticated. Source and cleanup closure passed. The actual observer object was 112 bytes in a compiled RW/NX load, with its getter in RX; this is compiled evidence, not runtime protected-wire credit. The 21 supplied report corruptions are separate from the single native subject.

Reproduce from that revision using one externally reserved CPU:

```sh
python3 -B evaluation/inprocess/linked_graph_observe.py \
  --revision 52f9b7b81a80e698b556e980301b8b01b61978e7 \
  --output "${PRIVATE_OUTPUT}"
```

`PRIVATE_OUTPUT` must be a fresh directory under the repository's `target/page-region-next`. The committed driver enforces the CPU affinity, exact source bytes, child bounds and final closure. [JSON](2026-10-30-linked-graph-observe-52f9b7b81a80.json) and [CSV](2026-10-30-linked-graph-observe-52f9b7b81a80.csv) are byte-exact copies of its sanitized outputs. They bind the private receipt (`1,064,985` bytes, SHA256 `615c434086cfe5a87b956937997cd6f501b7e1a01540004935c77c72d9b5f84b`) and the driver/source/archive facts. All previous failed and successful experiments retain their original status. Full native-owner qualification and the performance target remain separate obligations.
