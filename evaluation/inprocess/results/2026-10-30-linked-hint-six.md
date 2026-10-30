# Native-page hint feasibility — claims 1 and 4

The separate one-use native-page hint completes this six-subject release experiment at revision `56ed1e18cc97ab7919ffbd8f865dd692bdccf8ea`. It removes some repeated traps, but the observed whole-process cost remains far above the target of at most ten times DynamoRIO. These are individual **unqualified observations**, without medians, speedup estimates or complete owner/retirement qualification.

The [JSON](2026-10-30-linked-hint-six-56ed1e1.json) and [CSV](2026-10-30-linked-hint-six-56ed1e1.csv) retain every case. Both bridges were freshly built with release `-O2`, sharing one freshly built decoder archive. The baseline source is `a005a22fb174768f5822c57789a21a830efbcf1c`; the candidate adds only the reviewed hint and its build binding. All six subjects ran sequentially on reserved CPU 1, an unprivileged AMD EPYC 9D85, microcode `0xb101066`, Linux `7.1.3`. All 63 commands closed, source remained unchanged, and finalization reported no errors.

| Subject | Wall seconds | Events | SIGTRAP | Fresh maps | Native admissions | Hint admissions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline `ls -d .` | 14.454594199 | 160495 | 115533 | 10308 | 4185 | — |
| Hint `ls -d .` | 12.742205699 | 132299 | 90609 | 11667 | 4705 | 1016 |
| Baseline `true` | 5.616455120 | 62350 | 46078 | 2949 | 942 | — |
| Hint `true` | 4.905472980 | 54291 | 38927 | 3339 | 1100 | 293 |
| Native 65-entry fixture | 0.146705588 | — | — | — | — | — |
| Hint 65-entry fixture | 7.194649899 | 85137 | 60931 | 1333 | 2090 | 632 |

Fresh maps means actual refreshes plus differential acquisitions (zero differential acquisitions in these release runs). The hint uses a prior actual positive native-policy receipt only to select the existing real NX retry path. Every original native admission check still executes. All observed hint outcomes are admissions; zero clean refusals supplies no refusal-branch coverage. Fresh maps acquisitions rose alongside native admissions; these counters do not establish time attribution.

The unchanged fixture completed all 65 application-visible state comparisons against a fresh native reference. This release experiment has no protected owner record and supplies no epoch, permit, replacement or retirement qualification. The earlier [22/23 qualification result](2026-10-30-linked-epoch-baseline.md) remains failed at its original revision and bounds.

Reproduce on one reserved CPU:

```sh
python3 -B evaluation/inprocess/linked_hint_experiment.py \
  --baseline-revision a005a22fb174768f5822c57789a21a830efbcf1c \
  --candidate-revision 56ed1e18cc97ab7919ffbd8f865dd692bdccf8ea \
  --output target/page-region-next/new-hint-experiment
```

All subjects retain 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB per output. The script retains every failure and enforces the separate original build/oracle limits. The candidate's `ls` run still reports 28,331 graph refusals and 24,033 unsupported-form refusals. The next measurement must distinguish the actual graph-refusal reasons before choosing a broader translated-loop experiment; these counts alone do not identify cycles or attribute all remaining traps.
