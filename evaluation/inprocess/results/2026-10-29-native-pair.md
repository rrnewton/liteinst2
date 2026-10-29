# Two-page in-process native execution

ADDS: an opt-in page gate that retains two admitted source pages across native calls and returns, completes a real dynamically linked `/bin/ls`, and completes the unchanged sustained `strrchr` workload without a ptrace supervisor.

The measured source is `6c287c62bf47e4e7ce49132585b10bd4fcca56cf`, containing main `8f62276b9341c9eaccc6f8af1fa913691c7ad9a2`. The owner closes occupied pages on selected effects, incompatible policy, a third page, or failure. Cross-page fetches require a genuine first-byte refault before instruction ownership continues. Existing temporary patches cover CPUID, SYSCALL and RDTSC. This is an opt-in finite profile; it does not establish general B2/B3 completeness or arbitrary application coverage.

All six checks passed: fmt, Clippy, all-feature/all-target check, 3,521 workspace tests (37 ignored), 350 recorder tests, and 1,039 serial tests. Native qualification retained the 6 positive, 49 refusal/failure, 17 rseq, 16 registered and 4 boundary prerequisite cases. All 22 new profiles and 44 actual subjects qualified: 11 completed gated operations and 11 required failure/refusal prefixes, with 675 supplied-reader rejections. Actual nested signals and actual permission/synchronization denials remain distinct from supplied controls. This supports claims 1 and 4 within that finite scope.

## Release measurements

AMD EPYC 9D85, family 26/model 17/stepping 0, microcode `0xb101066`; x86-64 Linux 7.1.3; reserved CPU 17. The runner was unprivileged. Rust/Cargo 1.97.1, GCC 11.5.0 and Python 3.12.15 are recorded with binary/source hashes. All 20 planned subjects completed under unchanged limits: five alternating native/gated pairs for each workload. Outputs and checksums matched; all children and descriptors closed.

| Measurement | Native | Gated |
| --- | ---: | ---: |
| `/bin/ls -d .` whole-process time, median | 4.075 ms | 22.302 s |
| Hot workload whole-process time, median | 6.893 ms | 10.173 s |
| Post-warmup `strrchr`, median calls/s | 21,684,751 | 1,424,028 |

The hot rate is the median of five per-process rates, each measuring eight batches of 8,192 calls after 1,024 warmup calls. Gated throughput is 6.567% of native (15.228 times as much elapsed batch time by the ratio of median rates). These intervals include dispatch, loop and timing boundaries; they do not establish continuous native execution or route attribution for each batch. Whole-process overhead remains substantial. The earlier one-page hot workload exceeded its unchanged limit; it remains failed rather than receiving a completed speedup comparison.

Median initial admission **work** was 93.720 microseconds across ten gated processes; the pooled 160 same-page revisit work intervals had median 91.813 microseconds. These are handler work intervals and exclude fault ingress, application execution and closure. They are not full first-touch latency or a cache-cold measurement.

## Reproduction and retained results

At the measured revision, run `python3 evaluation/inprocess/checks.py --expect-revision 6c287c62bf47e4e7ce49132585b10bd4fcca56cf`. Use the [two-page recipe](../../../tools/page-entry/selected/README.md) for the finite native qualification and its same-revision prerequisite receipts. On one reserved CPU, run `python3 evaluation/inprocess/page_native_pair_performance.py --expect-revision 6c287c62bf47e4e7ce49132585b10bd4fcca56cf`. The performance evaluator uses release builds; the receipts record exact commands, inputs, hardware, limits and cleanup.

- [Correctness receipt](qualification-6c287c62bf47.json): all check results, complete cohort outcomes and reproduction commands.
- [Release JSON](20261029T205746.959581Z-page-native-pair-performance-6c287c62bf47.json) and [CSV](20261029T205746.959581Z-page-native-pair-performance-6c287c62bf47.csv): all process observations, 90 hot timing rows, admission work and terminal counters.
- [Historical failures](native-pair-history-0331-3558-203d.json): lossless shared-baseline representation with documented reconstruction rules and hashes for all three prior receipts. The initial native mask mismatch, nested FP-model error, configured-stack-flags error and 203d serial timeout remain failures. The last timeout stopped after 804 observed passes in eight completed harnesses; it is not a qualified serial pass.

Public files contain numeric results and summaries, without host paths or raw logs. Private captures support the receipt hashes. No performance result substitutes for the separate full-state native oracle.
