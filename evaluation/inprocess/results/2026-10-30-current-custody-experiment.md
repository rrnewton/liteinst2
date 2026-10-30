# Current-custody experiment, 2026-10-30

The fixed 82-attempt performance cohort **failed**: 81 attempts passed and differential `ls` was killed at the unchanged 30-second CPU limit. No attempt was replaced. The whole-cohort gate withholds medians, IQRs, ratios and performance qualification, including comparisons with native execution or DynamoRIO. The 10× DynamoRIO target remains unmet.

The [performance JSON](20261030T130807.757963Z-current-custody-performance-ea757fc6462b.json) and [CSV](20261030T130807.757963Z-current-custody-performance-ea757fc6462b.csv) retain all 82 outcomes. Differential `ls` exited −9 after 8.257522 seconds of user CPU plus 21.738009 seconds of system CPU; elapsed time was 30.188027332 seconds. It did not hit the wall timeout and emitted no terminal counter row. Differential `true` completed in 17.487952819 seconds with 377,006 fresh comparisons, 3,402 cache-miss refreshes and zero mismatches. Its physical fresh-request count is 380,408; comparison reads are separate from cache-miss refreshes.

Every ordinary lane completed its ten samples per workload. These are observed minimum–maximum elapsed times, including startup and reporting, not aggregate qualification or speedup estimates:

| Lane | `ls -d .` seconds | `true` seconds |
|---|---:|---:|
| Existing unrolled profile | 10.014672650–12.012520292 | 3.735844042–4.708897308 |
| Current-custody profile | 8.457099394–9.697303148 | 3.233974776–3.640210025 |
| Native | 0.005856532–0.006855313 | 0.005369831–0.009893913 |
| DynamoRIO, empty Release client | 0.028401566–0.042102975 | 0.021511991–0.034481373 |

The ordinary current profile performed fewer physical map refreshes. It still delivered nearly the same number of signals:

| Workload/profile | Actual signal events | SIGTRAP | Physical fresh requests |
|---|---:|---:|---:|
| `ls`, unrolled | 217,855–217,858 | 187,896–187,898 | 59,440–59,441 |
| `ls`, current | 217,850–217,851 | 187,891 | 12,020 |
| `true`, unrolled | 84,612 | 74,918 | 21,932 |
| `true`, current | 84,605 | 74,911 | 3,402 |

Every ordinary current `ls` sample recorded 47,420 attempts, 30,977 current seeds, 93,129 retained stages and commits, 155,281 retained checks, 47,420 cancellations and zero physical fallbacks. The corresponding `true` counts were 18,529 attempts, 12,316 seeds, 37,702 retained stages and commits, 63,088 checks, 18,529 cancellations and zero physical fallbacks. These producer counters have distinct scopes; overlapping route counts are not summed. Native and DynamoRIO rows have no invented map or signal counts. Current `ls` still recorded 983,765–983,782 map queries and 906,342–906,356 stack-frontier probes alongside 187,891 SIGTRAP events. These counts overlap and are not summed or assigned portions of elapsed time.

Four prerequisites passed on the same revision and CPU before this experiment:

| Qualification | Result and scope |
|---|---|
| [Unrolled component](20261030T125733.777165Z-unrolled-hash-component-ea757fc6462b.json) | 9/9; full hardware comparison including two required read faults, 373 supplied-record refusals. |
| [Current component and fallback companion](20261030T125806.557257Z-maps-current-component-ea757fc6462b.json) | 28/28 plus 6/6; 700 plus 192 supplied-record refusals. Supplied owner boundaries and compiled storage observations remain component scope. |
| [Original unrolled owner](20261030T130001.803898Z-unrolled-hash-owner-ea757fc6462b.json) | 25/25, nine native/gated pairs; all original application, owner and terminal checks retained. |
| [Genuine current-custody owner](20261030T130314.869969Z-current-custody-owner-ea757fc6462b.json) | 27/27: original 25 plus actual stale-ticket refusal and physical fallback. Full prefix GPR/flags, actual AF, FP, stack/data and cleanup joins; actual runtime protected-storage registrations; 1,091 appendix and 468 current-terminal refusals. |

The performance run also passed all six original finite maps modes, all three separate DynamoRIO exec/target/client/exit diagnostics, and all retained controls on its 41 completed gated streams: 5,778 original, 943 maps, 1,271 unrolled and 546 current-row refusals. All 149 commands were reaped with descriptors closed; final source, artifact and cleanup closure passed. This does not turn the failed 82-attempt cohort into a pass. Earlier failed cohorts retain their original results, and these qualifications do not qualify the separate scalar-reuse or certificate profiles.

The source revision was `ea757fc6462b2dffcd58e790c3eabd2715dfc053`, tree `d457bed04f3595b340f71430fc53a184a4b56804`, with a clean tracked source snapshot. Runs were pinned to CPU 103 on an AMD EPYC 9D85 158-Core Processor, family 26/model 17/stepping 0, microcode `0xb101066`, Linux 7.1.3. The exact DynamoRIO 11.91.0 SDK inventory and empty-client build are bound in the receipt. Program bounds remained 30 CPU seconds, 60 wall seconds, 512 MiB and 16 MiB output; DynamoRIO retained its original 16 GiB virtual-address allowance. The independent repository checks below do not qualify the failed performance cohort.

The receipt’s portable reproduction command, run with CPU affinity 103, was:

```sh
python3 evaluation/inprocess/unrolled_hash_performance.py \
  --expect-revision ea757fc6462b2dffcd58e790c3eabd2715dfc053 \
  --component-receipt evaluation/inprocess/results/20261030T125733.777165Z-unrolled-hash-component-ea757fc6462b.json \
  --owner-receipt evaluation/inprocess/results/20261030T130001.803898Z-unrolled-hash-owner-ea757fc6462b.json \
  --current-custody \
  --current-component-receipt evaluation/inprocess/results/20261030T125806.557257Z-maps-current-component-ea757fc6462b.json \
  --current-owner-receipt evaluation/inprocess/results/20261030T130314.869969Z-current-custody-owner-ea757fc6462b.json \
  --sdk "${SDK}"
```

The [six required checks](20261030T131802.440629Z-checks-ea757fc6462b.json)
passed on the same source revision with stable Rust 1.97.1 and reserved CPUs
8, 16, 31 and 36. Recorder: 354 passed in 122.992178 seconds. Workspace:
3,785 passed, zero failed and 37 ignored across all 106 harnesses in
785.943393 seconds. Serial launch: all 1,039 passed across 27 harnesses in
141.483659 seconds. Formatting, strict all-target/all-feature Clippy and
all-target/all-feature workspace checking passed. The original 180-second
recorder/serial limits, 900-second workspace limit, four-worker maximum and
8 MiB per-command log bound remained unchanged; all process and source checks
closed successfully. Exact commands and toolchain identities are in that JSON.
