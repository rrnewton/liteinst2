ADDS authoritative event counts that survive a killed page-mode process. A protected shared page holds the runtime's actual ingress, maps, group and native-admission cells; the parent reads its sealed backing only after reaping the target. This is diagnostic evidence for claim4. It is not a completed execution or performance improvement.

At `b21243245d5895fc7ba347e2d61049bc96f10104`, one release `/bin/ls -d .` attempt on reserved CPU3 was killed at the unchanged30-CPU-second limit after30.174959992 seconds process wall. The [result](results/20261031-group-counters-b2124324.json) and [counter CSV](results/20261031-group-counter-prefix-b2124324.csv) retain usable final per-cell values:

| Counter | Observed partial execution |
| --- | ---: |
| Ingress events | 88,974 |
| Trace traps / SEGV / ILL | 72,648 / 16,211 / 115 |
| Physical maps acquisitions | 98,684 |
| Maintained-view hits | 1,313,193 |
| Cold group attempts | 47,359 |
| Cold publications / warm hits | 13 / 197 |
| Entered / completed group epochs | 210 / 210 |
| Cancelled attempts | 47,345 |
| Single-member graph refusals | 39,810 |
| Unsupported-root refusals | 6,147 |
| Link-limit / outside-pair refusals | 704 / 682 |
| Selected-root refusals | 2 |
| Native admissions / closed | 1,129 / 1,129 |
| Native attempts / blocked | 4,495 / 3,366 |

The single-member refusals are the clearest observed capacity-domain problem: this experimental two-image profile declines every graph with at most64 heads. The next resident-dispatch experiment admits1–128 proved heads and attempts register-indirect hits within that held source/rseq lifetime. These counts justify testing that change; they do not predict a whole-program speedup. Fresh maps reads also remain substantial. The maintained view reports29 unexplained refresh triggers,189088 updates and288227 invalidations; those counts alone do not attribute physical-read time or prove every refresh necessary.

The target remains FAILED/-9, with empty stdout/stderr and all terminal count columns unavailable. Final per-cell prefixes can split a transaction: offers47556 versus entries210 plus cancelled47345 is retained literally. No arithmetic normalization, completed-program time, saved-event count or comparison against DynamoRIO is inferred. This nondifferential run has zero comparisons, so it adds no cached-versus-fresh equivalence claim. The10x target remains open.

The [first attempt](results/20261031-group-counters-df27a828.json) at `df27a8280e3e5f851671e12a75e327da3f7de99e` failed before launching a guest. Its34 protocol controls and release build passed, but the build reader retained the earlier552-byte record expectation after the native fields expanded it to752 bytes. Actual retained nm output has bootstrap size0x2f0 and pointer size8. The correction changes only the exact expected extent and record-schema metadata to version2/752; the first failure remains failed. The successful build in the fresh b212 attempt independently checks the corrected extent.

Both attempts keep one4096-byte backing, original seals6→23, genuine parent read-only descriptor, child-only existing shared writer, exact nonce/PID/backing identity, runtime RW/NX protection and actual reap/cleanup before reading. All34 parser/kernel refusal controls pass, including existing-writer survival, rejection of new writers, zero padding/tail and exact split-prefix preservation. These controls qualify the observation protocol only. They do not qualify arbitrary group faults or whole-process coverage.

The actual optimized bridge and release decoder build are bound in each result, alongside exact commands and source/artifact hashes. Hardware: unprivileged AMD EPYC9D85, family26/model17, microcode0xb101066, Linux7.1.3. Each subject retains30CPU/60wall/512MiB/16MiB; source, sealed namespace and cleanup checks closed true. Reproduce on one externally reserved CPU from the exact recorded clean revision:

```sh
python3 -B evaluation/inprocess/persistent_group_experiment.py \
  --revision b21243245d5895fc7ba347e2d61049bc96f10104 \
  --output target/page-region-next/fresh-counter-diagnostic --final-counters
```

The earlier six-check receipt at1b081e validates the preceding merged runtime. It is not presented as validation of this new diagnostic source; fresh repository checks remain required before its hand-back.
