# Qualified BZHI and selected-hook measurements

Adds original-PC page stepping for the exact libc BZHI RBX,RDX,R11 form (`c4e2a0f5da`) and a reproducible measurement of the instrumented in-process callback, handler and next-NX costs for all seven selected classes. This advances claims 2 and 4; default-rseq `/bin/ls` completion and full B2/B3/B4 remain open.

Implementation `2896078bf8ed464b37b36140220a5d5abf115260`; merged native regression revision `358f7a808cfdb03553b09e0f0785695d4941ab9c`; timing/check revision `33eeaedd7e3dbec4ab33439ff312d9939b4b34b5`. The latter includes main `63642aee94979d2f2b0ac9e84572d7e6fdf70acc`. That final ancestry merge changed no tree content.

Both five-oracle runs pass: 190 commands and 474 captures each, including 18 required nonzero fault/refusal operations. BZHI has 25 new native/TF pairs plus two startups, every five-byte fetch split, 50 actual-before write-footprint queries and 374 refusal observations. Every compared flag bit, including AF/PF, remains checked alongside GPRs, FP/XSAVE, vectors/masks and memory. Original footprint, generic, VPXORQ128 and 17-subject rseq suites retain their cases and comparators. The exact form is a no-memory-write footprint; other BZHI forms still refuse.

Native timing uses optimized C and a release Rust decoder on one reserved AMD EPYC 9D85 CPU (Linux 7.1.3, GCC 11.5, Rust 1.97.1). Public receipts record hardware, source identities, bounds and reproducers; complete command/tool evidence is retained privately. The 249-command run requires all five original raw/model/explicit-trap/C reference trajectories, then five full-state qualifications of the exact timing ELFs. Three warmup and ten measurement children per fixture yield 51 warmup and 170 measured callbacks. All 65 children complete; no retries, outlier removal or overhead subtraction.

| Class | Samples | Callback median, ns | Handler median, ns | Return/refault median, ns | Cycle median, ns |
|---|---:|---:|---:|---:|---:|
| CPUID | 20 | 189.5 | 47185.5 | 1472.5 | 48793.5 |
| RDRAND | 20 | 180 | 47531 | 1472.5 | 49063.5 |
| RDSEED | 40 | 161 | 46690 | 1382 | 48092 |
| RDPID | 30 | 161 | 47616.5 | 1397 | 49264 |
| RDTSC | 40 | 170.5 | 47931.5 | 1452 | 49419 |
| RDTSCP | 10 | 285.5 | 46850 | 1432 | 48297 |
| SYSCALL | 10 | 210 | 72659 | 1472 | 74141 |

These are instrumented fixture-policy costs. The trusted raw clock probes also invalidate map-cache reuse, so their interference is included. They are not bare-instruction latency, an uninstrumented production estimate, one-shot cost or whole-program throughput. The return endpoint is the first genuine NX fault at the original successor PC, authenticated through the unchanged source/decode/owner checks. Each raw sample satisfies service + return/refault = cycle; separate class medians need not add.

The initial timing run at `21081093969ecb41347047796080906f704e8c80` remains failed: its first timing subject stopped with code 1768 before any callback. A bootstrap NOP trace had the same PC as the following CPUID. The corrected observer requires a genuine NX frame and consumption by the selected handler within that same event; the record format, reader, timer-count equation and incomplete-row failure checks remain unchanged.

Both original five-case real-program matrices at `a8b67511b2104aacdc7a46474eef227d3fd936c1` remain FAILED, four of five cases passed. Default-rseq `/bin/ls` exited -9 without a terminal report in 30.419370362 s (legacy) and 30.372617176 s (CPUID-NX); neither kill cause nor the next reached instruction is established. The 30 CPU/60 wall second bounds are unchanged.

| Disabled-rseq ls profile | Whole process, s | Native process, s | First admission service, ns | Median of 16 revisits, ns |
|---|---:|---:|---:|---:|
| Legacy | 20.123398070 | 0.003423501 | 79219 | 84266.5 |
| CPUID-NX | 21.236220425 | 0.003416322 | 92649 | 81367 |

Whole-process times include namespace preparation. Admission service excludes signal delivery, execution and closing; these revisits are not application steady-state throughput. No speedup is claimed.

All six required checks pass on `33eeaedd7e3dbec4ab33439ff312d9939b4b34b5`: 350 recorder tests; formatting; strict workspace/all-targets/all-features Clippy; workspace tests (2,957 passed, 0 failed, 33 ignored across 103 harnesses); workspace all-features/all-targets check; and serial launch tests (1,039 passed, 0 failed across 27 harnesses). Workspace took 371.623379143 s and serial took 150.142032366 s, within their unchanged 900/180-second bounds. The [check receipt](results/20261028T165824.262360Z-checks-33eeaedd7e3d.json) records all command outcomes and source identities.

Reproduce on the recorded revision, with one CPU for each native command: `page_selected_bzhi.py`, `page_selected_write_footprint.py`, `page_selected_generic_oracle.py`, `page_selected_vpxorq128.py`, `page_selected_rseq_application.py --fast-memset`, and `page_selected_hook_cost.py`, all under `evaluation/inprocess/` with `--expect-revision FULL_SHA`. Run `native_pages.py --expect-revision FULL_SHA --output RELATIVE_JSON` with and without `--cpuid-nx`; reserve four CPUs for `checks.py --expect-revision FULL_SHA`. Each numeric receipt below records its exact reproducer, source identities and resource bounds. Raw logs and binary records remain private.

Current constraints remain the cooperative singleton/private-entry/reserved-signal profile. Seven stack-pointer random/ID forms remain pre-effect refusals. CPUID-NX and restored one-shot are separate profiles; broader lifecycle, default-rseq completion and hybrid/offline parity remain future work.

Numeric receipts:

- [20261028T163618.975629Z-page-selected-bzhi-2896078bf8ed.json](results/20261028T163618.975629Z-page-selected-bzhi-2896078bf8ed.json)
- [20261028T163634.595958Z-page-selected-write-footprint-2896078bf8ed.json](results/20261028T163634.595958Z-page-selected-write-footprint-2896078bf8ed.json)
- [20261028T163643.735895Z-page-selected-generic-oracle-2896078bf8ed.json](results/20261028T163643.735895Z-page-selected-generic-oracle-2896078bf8ed.json)
- [20261028T163654.350634Z-page-selected-vpxorq128-2896078bf8ed.json](results/20261028T163654.350634Z-page-selected-vpxorq128-2896078bf8ed.json)
- [20261028T163723.708195Z-page-selected-rseq-application-fast-memset-2896078bf8ed.json](results/20261028T163723.708195Z-page-selected-rseq-application-fast-memset-2896078bf8ed.json)
- [20261028T164707.331728Z-page-selected-bzhi-358f7a808cfd.json](results/20261028T164707.331728Z-page-selected-bzhi-358f7a808cfd.json)
- [20261028T164722.581318Z-page-selected-write-footprint-358f7a808cfd.json](results/20261028T164722.581318Z-page-selected-write-footprint-358f7a808cfd.json)
- [20261028T164732.248518Z-page-selected-generic-oracle-358f7a808cfd.json](results/20261028T164732.248518Z-page-selected-generic-oracle-358f7a808cfd.json)
- [20261028T164744.280748Z-page-selected-vpxorq128-358f7a808cfd.json](results/20261028T164744.280748Z-page-selected-vpxorq128-358f7a808cfd.json)
- [20261028T164811.293997Z-page-selected-rseq-application-fast-memset-358f7a808cfd.json](results/20261028T164811.293997Z-page-selected-rseq-application-fast-memset-358f7a808cfd.json)
- [native-pages-a8b6751.json](results/native-pages-a8b6751.json)
- [native-pages-nx-a8b6751.json](results/native-pages-nx-a8b6751.json)
- [20261028T164125.906917Z-page-selected-hook-cost-21081093969e.json](results/20261028T164125.906917Z-page-selected-hook-cost-21081093969e.json)
- [20261028T165257.710080Z-page-selected-hook-cost-33eeaedd7e3d.json](results/20261028T165257.710080Z-page-selected-hook-cost-33eeaedd7e3d.json)
