# Exact RX alias-query reuse

Adds reuse of a successful RX alias check within one authenticated maps acquisition, plus a bounded diagnostic for default-rseq application costs. This supports claims 2 and 4. It establishes fewer repeated alias scans in the oracle; it does not establish application speedup or default-rseq `/bin/ls` completion.

Diagnostic revision: `16cfebcd8f2afca6422b312336e926f8b01c6c6c`. Runtime and regression revision: `04dd95d5dd2080127d393796e330e84d0bf8d845`, which includes main `63642aee94979d2f2b0ac9e84572d7e6fdf70acc`.

The memo requires exact acquisition, handler, epoch, object/device/inode, offset, length, protection, exception interval and row-count identity. It caches only successful RX checks, invalidates before replacement and publishes validity last. Other queries retain the original implementation. Direct backing I/O and source, permission, lifecycle and rseq checks are unchanged; there is no cross-handler authority or new raw-syscall exemption.

All seven native suites pass: alias reuse, current lookup, selected maps, chain, generic full-state, the finite inactive-rseq profile and write footprint. Independent saved-data review authenticated 301 commands, 780 captures and 91 native processes. All 50 required failed/refused operations retain those outcomes. The new oracle checks 120 queries with 15 refusals, 38 memo hits and 80 direct calls; two overflow refusals occur before those counters. Its same-page scenario has two scans and six hits across two acquisitions. The existing lookup suite retains 3,716 comparisons, and the footprint suite retains 38 cases. No application instruction runs from the oracle's supplied test mappings.

The diagnostic first requires a fresh same-revision native footprint run. At `16cfebc`, the actual legacy and CPUID-NX default-rseq ls operations both fail with reportless exit -9, after 30.802240380 and 30.453943507 seconds. Their observed prefixes contain 107 and 106 paired samples, covering 327,250 and 324,148 chain steps. In 71 and 63 samples respectively, one registered plain step has two fresh maps acquisitions, six reused queries and one rseq instruction check. Observer clock/write invalidations remain included. These are counter observations, not component-time estimates. The initial invocation passed the public prerequisite projection instead of its private receipt and failed before launching a child; that failure is retained.

Both unchanged five-case release application matrices at `04dd95d` remain **FAILED, 4/5**. Default-rseq ls exits -9 without a terminal report after 31.666625150 seconds (legacy) and 30.278461596 seconds (CPUID-NX). Neither the kill cause nor last executed instruction is established. The 30 CPU/60 wall second, 512 MiB memory and 16 MiB file limits are unchanged.

| Disabled-rseq ls profile | Gated process, s | Native process, s | First admission service, ns | Median of 16 revisits, ns |
|---|---:|---:|---:|---:|
| Legacy | 20.636530545 | 0.003937437 | 83295 | 86154.5 |
| CPUID-NX | 20.728225191 | 0.003581441 | 90015 | 84772.0 |

Both disabled-rseq ls runs complete with matching output and all 5,732 admissions closed. These use optimized C and the release Rust decoder on one reserved AMD EPYC 9D85 CPU, Linux 7.1.3, GCC 11.5 and Rust 1.97.1. Whole-process times include namespace preparation. Admission service excludes signal delivery, execution and closing; these revisits are not application steady-state throughput. Observations are unpaired on a shared machine; no causal speedup is claimed.

All six required checks pass at `04dd95d5dd2080127d393796e330e84d0bf8d845`: 350 recorder tests; formatting; strict workspace/all-targets/all-features Clippy; workspace tests (2,957 passed, 0 failed, 33 ignored across 103 harnesses); workspace all-features/all-targets check; and serial launch tests (1,039 passed, 0 failed across 27 harnesses). Workspace took 346.422061843 seconds and serial took 130.367274242 seconds, within their unchanged 900/180-second bounds. The [check receipt](results/20261028T173856.851628Z-checks-04dd95d5dd20.json) records all outcomes.

Reproduce each native suite under `evaluation/inprocess/` with `--expect-revision FULL_SHA`: `page_current_lookup.py --maps-query-reuse`, `page_current_lookup.py`, `page_selected_maps.py`, `page_selected_chain_oracle.py`, `page_selected_generic_oracle.py`, `page_selected_rseq_application.py --fast-memset` and `page_selected_write_footprint.py`. Run `native_pages.py --expect-revision FULL_SHA --output NEW_RELATIVE_JSON --library-root /usr/lib64`, with and without `--cpuid-nx`. For the diagnostic, first run the footprint evaluator, then `page_default_ls_cost.py --expect-revision FULL_SHA --archive-receipt target/evaluation/inprocess/FRESH_RUN/receipt.json --output target/NEW_RUN`, with and without `--cpuid-nx`. Reserve one CPU per native evaluator and four for `checks.py --expect-revision FULL_SHA`.

Numeric receipts below record exact revisions, commands, hardware, bounds and source identities. Logs and binary records remain private. The singleton/private-entry/reserved-signal envelope, default-rseq application completion, broader lifecycle support and hybrid/offline parity remain open.

- [20261028T171412.001142Z-page-selected-write-footprint-16cfebcd8f2a.json](results/20261028T171412.001142Z-page-selected-write-footprint-16cfebcd8f2a.json)
- [default-ls-cost-16cfebc-legacy-private.json](results/default-ls-cost-16cfebc-legacy-private.json)
- [default-ls-cost-16cfebc-legacy.json](results/default-ls-cost-16cfebc-legacy.json)
- [default-ls-cost-16cfebc-nx.json](results/default-ls-cost-16cfebc-nx.json)
- [20261028T173248.454377Z-page-maps-query-reuse-04dd95d5dd20.json](results/20261028T173248.454377Z-page-maps-query-reuse-04dd95d5dd20.json)
- [20261028T173254.913963Z-page-current-lookup-04dd95d5dd20.json](results/20261028T173254.913963Z-page-current-lookup-04dd95d5dd20.json)
- [20261028T173301.433452Z-page-selected-maps-04dd95d5dd20.json](results/20261028T173301.433452Z-page-selected-maps-04dd95d5dd20.json)
- [20261028T173354.588878Z-page-selected-chain-oracle-04dd95d5dd20.json](results/20261028T173354.588878Z-page-selected-chain-oracle-04dd95d5dd20.json)
- [20261028T173428.826955Z-page-selected-generic-oracle-04dd95d5dd20.json](results/20261028T173428.826955Z-page-selected-generic-oracle-04dd95d5dd20.json)
- [20261028T173448.855813Z-page-selected-rseq-application-fast-memset-04dd95d5dd20.json](results/20261028T173448.855813Z-page-selected-rseq-application-fast-memset-04dd95d5dd20.json)
- [20261028T173529.898804Z-page-selected-write-footprint-04dd95d5dd20.json](results/20261028T173529.898804Z-page-selected-write-footprint-04dd95d5dd20.json)
- [native-pages-04dd95d.json](results/native-pages-04dd95d.json)
- [native-pages-nx-04dd95d.json](results/native-pages-nx-04dd95d.json)
