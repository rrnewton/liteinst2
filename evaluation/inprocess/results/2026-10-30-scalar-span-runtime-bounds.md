The finite TRACE experiment at `4443d9e4dd1326e450e6b5d967f91106a5d8d697` **failed qualification**. All nine subjects launched and all returned their required exit status within the original limits. Four native references qualified; none of the five gated records completed the full validation chain.

| Subject | Exit | Wall seconds | Qualification |
| --- | ---: | ---: | --- |
| Gated mode 0 | 0 | 15.510269605 | Failed cache coverage assertion |
| Gated mode 1 | 0 | 15.688218370 | Failed cache coverage assertion |
| Gated mode 2 | 0 | 15.642146405 | Failed cache coverage assertion |
| Required generated read fault | 125 | 9.193927164 | Failed full native terminal-row comparison |
| Required nested refusal | 125 | 8.895973276 | Failed full native terminal-row comparison |

This release-build fixture ran on reserved CPU 6 of an AMD EPYC 9D85 158-Core Processor, Linux 7.1.3, microcode `0xb101066`, without root privileges. All 63 commands retained input/source identity and complete process/descriptor cleanup, with no final closure errors. The subject limits remained 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB file/output. The byte-operation oracle passed under its separate 5-CPU-second, 15-wall-second limits. It tests the actual header's copy, clear and comparison operations, including overlap, unmapped guards and FP preservation.

Retained-data diagnosis found that the three normal runs used 19 slots of the older register cache, with 19 publications, nine hits and 28 completed runs. The existing LS validator requires cache exhaustion and retirement beyond 64 slots. That older coverage requirement was not exercised by this broader translated-span fixture. Separately, the new protected terminal projection contains only 17 of the native report's 20 fields: it omits `version`, `main_admissions` and `main_refaults`. All 17 projected values match the actual reports in all five retained records, but whole-row equality correctly rejects the incomplete projection. New raw observations and a separately scoped finite closure check are under review; these failed results are not requalified by diagnosis.

The prior [runtime failure](2026-10-30-scalar-span-experiment.md) remains unchanged. This result earns no full native/owner pair, application/owner/terminal mutation-control, whole-program or throughput qualification. In particular, successful process exits alone do not establish state equivalence or a speedup. The target of at most ten times DynamoRIO remains unmet.

Exact [JSON](20261030T155737.729481Z-scalar-span-trace-4443d9e4dd13.json) and [CSV](20261030T155737.729481Z-scalar-span-trace-4443d9e4dd13.csv) retain revision, hardware, original limits, per-subject results and artifact hashes. Reproduce on one reserved CPU:

```sh
python3 -B evaluation/inprocess/scalar_span_trace.py --expect-revision 4443d9e4dd1326e450e6b5d967f91106a5d8d697
```
