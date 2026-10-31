# Complete-program long-T3 ownership follow-up

At `701c4c87e80efcb287a37c57c5b1d7ce5aecee0c`, both profiles still refused all-or-nothing emission. Neither produced a candidate.

| Span | Requested sites | Withheld local plans | Primary refusals | Exit | Wall seconds |
|---|---:|---:|---:|---:|---:|
| 16 MiB | 2,053 | 1,749 | 304 | 2 | 20.115030 |
| 2 GiB | 2,053 | 2,013 | 40 | 2 | 17.495505 |

Compared with the [GNU follow-up](../full-program-gnu-result-v1/), the 2 GiB search found alternate long victims for sites 238 and 1259 under unchanged budgets and ownership checks. Their local plans remain withheld by atomic selection. The other ownership conflicts remain refusals, now detected inside search. All other report rows retain their outcomes; no successful subset is emitted.

Focused validation remains **FAILED**: fmt, strict Clippy, three new core tests and 173 rewrite tests passed, but the separate 101-test neighbor oracle hit its 180-second deadline: exit -9, six rescued descendants, 76 passes and 25 incomplete tests. A previous complete context took 414.38 seconds. That is duration context, not proof this interrupted run would finish or lacked a new hang.

[receipt.json](receipt.json) records the exact source, products, counts, CPUs/load, closures and bounds. Retain it and the linked GNU receipt outside the checkout; use their recorded build/command protocol, current pins and fresh output paths. The tracked [runner](../offline-corpus/run_full_program_attempt.py) still uses `--li2-only`. No backend or candidate ran here.

All earlier failures remain unchanged. Full-gate validation is separate. These are artifact-planning observations, with no all-site execution, E9 help result, performance or A5 qualification.
