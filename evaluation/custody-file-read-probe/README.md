# Fresh-file read split probe: closed results

At `e42f503f6243accc268cc8780824845f87b7655f`, the first campaign **failed its controls** with SIGXFSZ. The separate corrected campaign passed all nine controls and completed five once-only probe processes. The probe source and both compiled binaries were unchanged between campaigns. It never loads or calls the fixture, and these results do not qualify profiler completion or performance.

[results.csv](results.csv) retains **all 3,200 numeric rows**, including 640 warmup rows and 2,560 measured rows, in original order. [summary.csv](summary.csv) has 80 per-repetition/file/phase/component summaries: count, sum, min, median and max. No outliers or warmup rows were dropped. [receipt.json](receipt.json) records all nine actual payload actions: two compilations and failed controls in v1, then controls and five measurements in v2.

Measured medians across both files, in nanoseconds:

| Repetition | Open | Read | Drop | Total |
|---|---:|---:|---:|---:|
| 1 | 25939 | 632 | 460 | 27031 |
| 2 | 25258 | 631 | 451 | 26349 |
| 3 | 25814 | 641 | 451 | 26950.5 |
| 4 | 25934 | 631 | 451 | 27030 |
| 5 | 26254 | 631 | 451 | 27336 |

Across all 2,560 measured rows, medians were **25,839 ns open, 632 ns read and 451 ns drop**; median total was 26,945.5 ns. The largest total span was **3,741,961 ns** and remains in both data files. Open occupies the largest component in these isolated observations. It is not proof of pure path-lookup cost or a causal explanation of the profiler's timing. The read interval includes open-result handling, Take construction and its remaining-limit query. Read allocation, clock overhead and preemption can be included; cache state is uncontrolled. File drop does not expose close errors. Stamps, reserve, byte comparison and reporting lie outside these component timers. Do not add total to its component times or subtract these isolated costs from a profiler result.

V1 ran on HARD CPU 19. Both compilations exited 0 with the exact standard filename-adaptation warning caused by `--emit=link,dep-info` plus `-o`. A fresh result reader initially required empty stderr, although the frozen plan did not; that refusal and warning remain retained. The exact warning was accepted without recompilation. Controls then produced two passed terminals and one interrupted test before signal 25; no suite pass was reported, and all five planned v1 measurements remain UNRUN. The root had translated a 1 MiB combined output budget into a 512 KiB `RLIMIT_FSIZE`, which also prevented the mandatory 1,048,578-byte beyond-cap fixture from being written.

V2 is a distinct corrected campaign on HARD CPU 37. Existing `processes.run_command` captures a combined stdout/stderr pipe capped at **1 MiB**, while `/usr/bin/prlimit --core=0 --cpu=20 --fsize=2097152 -- ...` sets an independent **2 MiB regular-file ceiling**. All six v2 payloads have a **30 s wall** bound and **20 CPU-second** limit. This explicitly changes v1's mistaken file ceiling; the output limit and all nine assertions/cases remain. The abandoned failed fixture was preserved and removed only by its authenticated owned identity. Both parent releases were recorded normally, with their original processes, scope and reservation tag absent. [receipt.json](receipt.json) retains every start/load, closure and binary/log/input pin; the hardware label is **AMD EPYC Zen 5 dev host**.

## Reproduction

The checked-in [probe.rs](probe.rs) is the exact executed source. Its initial “Unexecuted” comment records its pre-execution proposal state; the closed outcomes are above. The fixed schedule remains five processes, each with 64 warmup and 256 measured pairs, candidate then trusted: 640 rows per process. Stop on the first failed compilation, control, owner or repetition; no retry or replacement attempt. Preserve all statuses and raw rows.

The input is reproducible from tracked [exact_work.S](../../tools/rapid-profiler/exact-work/exact_work.S), using the existing [assembly recipe](../ordinary-selected-session/accuracy_functional.py). Under the authenticated bounded owner, with the pinned GCC/subtools and fresh absolute output paths, its payload is:

```sh
"$PROBE_GCC" -O2 -fPIC -shared -nostdlib -fno-builtin -fno-stack-protector -fomit-frame-pointer -fno-tree-vectorize -fno-tree-slp-vectorize -fno-asynchronous-unwind-tables -fno-unwind-tables -fcf-protection=none -Wl,-z,now -Wl,-z,noexecstack "$REPOSITORY_ROOT/tools/rapid-profiler/exact-work/exact_work.S" -o "$PROBE_TRUSTED"
```

Create `PROBE_CANDIDATE` as a fresh exclusive byte copy with a different `(dev, ino)`. Both whole files must be 13,360 bytes with SHA256 **`ec282b162def940f84a37e8945adfb745a96991bd0c1458a3f782d6308d57b20`**; refuse a different output. `PROBE_EXPECTED` can point to the same verified trusted bytes. Independently freeze each file's eight-field pathname stamp before timed reads: decimal **dev, ino, mode, length, mtime_seconds, mtime_nanoseconds, ctime_seconds, ctime_nanoseconds**. Mode includes the regular-file type. Recheck full bytes/stamps around compilation/execution; no measured lookup may create replacement expectations. Continuous immutable ownership remains necessary.

Set `PROBE_RUSTC` to the pinned compiler and use the receipt's exact source/tool/command contracts. Use a fresh `target/evaluation/custody-file-read-probe-v1/` output directory; do not overwrite old evidence. Compilation retains 60 CPU seconds/90 wall seconds/128 MiB file limits. Controls and measurements use the separate v2 output/file limits above. Run payloads through the existing [process owner](../admission/processes.py) with fixed affinity and clean environment. The owner enforces output/wall/cleanup; `prlimit` enforces the child limits. This block supplies payloads, not an unbounded dispatcher:

```sh
probe_out=target/evaluation/custody-file-read-probe-v1
CUSTODY_PROBE_EXPECTED="$PROBE_EXPECTED" "$PROBE_RUSTC" --edition=2024 --crate-name custody_file_read_probe -C opt-level=3 -C debuginfo=0 -C codegen-units=1 evaluation/custody-file-read-probe/probe.rs --emit=link,dep-info -o "$probe_out/probe"
CUSTODY_PROBE_EXPECTED="$PROBE_EXPECTED" "$PROBE_RUSTC" --edition=2024 --crate-name custody_file_read_probe -C opt-level=3 -C debuginfo=0 -C codegen-units=1 --test evaluation/custody-file-read-probe/probe.rs --emit=link,dep-info -o "$probe_out/controls"
/usr/bin/prlimit --core=0 --cpu=20 --fsize=2097152 -- "$probe_out/controls" --test-threads=1 --nocapture
/usr/bin/prlimit --core=0 --cpu=20 --fsize=2097152 -- "$probe_out/probe" 1 "$PROBE_CANDIDATE" "$PROBE_TRUSTED" "$PROBE_CANDIDATE_STAMP" "$PROBE_TRUSTED_STAMP"
/usr/bin/prlimit --core=0 --cpu=20 --fsize=2097152 -- "$probe_out/probe" 2 "$PROBE_CANDIDATE" "$PROBE_TRUSTED" "$PROBE_CANDIDATE_STAMP" "$PROBE_TRUSTED_STAMP"
/usr/bin/prlimit --core=0 --cpu=20 --fsize=2097152 -- "$probe_out/probe" 3 "$PROBE_CANDIDATE" "$PROBE_TRUSTED" "$PROBE_CANDIDATE_STAMP" "$PROBE_TRUSTED_STAMP"
/usr/bin/prlimit --core=0 --cpu=20 --fsize=2097152 -- "$probe_out/probe" 4 "$PROBE_CANDIDATE" "$PROBE_TRUSTED" "$PROBE_CANDIDATE_STAMP" "$PROBE_TRUSTED_STAMP"
/usr/bin/prlimit --core=0 --cpu=20 --fsize=2097152 -- "$probe_out/probe" 5 "$PROBE_CANDIDATE" "$PROBE_TRUSTED" "$PROBE_CANDIDATE_STAMP" "$PROBE_TRUSTED_STAMP"
```

Retain every compiler warning, normal/signal/timeout outcome, actual argv/env, dep-info/binary hash, CPU/load and owner closure. Authenticate closure before reading outputs. CSV phase 0 is warmup and phase 1 measured; file 0 is candidate and file 1 trusted. Status 1 means only the row's byte/stamp/time checks completed. `-1` denotes unavailable data or absent errno, never a zero-duration observation. A failed row stops its process and retains later rows as UNRUN; incomplete output stays incomplete. Keep warmup separate in summaries and require normal lease release.

The [01ca profiler campaign](../ordinary-accuracy-results/coordinate-01ca/README.md) remains **FAILED at 1,342/2,048 short rows**, with long structural-only completion. The original 2 ms ARM, 520 ms/2,048-row short requirement, 43,200-cell denominator and every prior failure remain. This isolated probe omits maps/tasks/live-code custody work; no whole-profiler speedup, CPU-time, accuracy, native-state or performance qualification follows.
