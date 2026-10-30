# Kernel costs in the page-runtime startup benchmark

The new profiles locate most of the previously broad kernel remainder on file-open, file-close and proc-maps read paths. They also show substantial `perf_event_mmap` notification work. These are measured sampled-CPU paths, not proof that every notification belongs to our profiler or that every open/close names `/proc/self/maps`.

The unprofiled baseline is revision `f7dd159db74f7ca1181a89bd48c11a329d7a49a5`; the two separate profiles and six checks are revision `0847974d17b9f2b0e9c681c3c326e8e818af92ff`. All 932 pinned native-source inputs agree between baseline and profiles. The host is AMD EPYC 9D85, microcode `0xb101066`, Linux 7.1.3; the baseline used reserved CPU 3, ls profile CPU 10, and true profile CPU 13. Compiler versions and full hardware/tool hashes are retained in the linked evidence.

[Compact arithmetic](2026-10-30-page-kernel-cost.json) has SHA256 `c20da014ed3b46f9fb2aff8b03f0127b31a415a8512d5bfbedebd5302099a475` (20,734 bytes). The [projector](../page_cost_kernel_evidence.py) pins all original receipt/data bytes and recorded revision/tree/source manifests. It imports no evaluator and launches no process. It reproduces every original disjoint and overlapping inclusive callchain count before making a separate subdivision; original classifications remain unchanged.

## Unprofiled whole-process measurements

All 60 fixed attempts passed: ten runs for each workload and native/gated/DR-null lane, with rotating/reversed lane order. These intervals run from before Popen through reap; gated intervals include Python launch and namespace preparation, while offline builds are excluded. There is no cold-cache claim. Values below are **median / IQR in milliseconds**, with inclusive linear-interpolated quartiles.

| Workload | Native | Gated | DynamoRIO empty client |
|---|---:|---:|---:|
| `ls -d .` | 4.168 / 0.329 | 19,382.276 / 1,689.700 | 26.306 / 0.976 |
| `true` | 3.729 / 0.133 | 6,769.542 / 315.643 | 20.089 / 3.982 |

The gated user/system CPU medians are **9.1773655 / 10.068937 seconds** for ls and **3.2568545 / 3.4446065 seconds** for true. This establishes substantial system CPU without sampling instrumentation. Medians of separate columns do not necessarily sum to the median combined CPU time. [Original baseline JSON](20261030T030044.789458Z-page-cost-compare-f7dd159db74f.json) and [all 60 CSV rows](20261030T030044.789458Z-page-cost-compare-f7dd159db74f.csv) retain exact values, bounds, SDK/client identities, and untimed client-load/target-exec checks. The timed null client has no callbacks.

The [earlier cost report](2026-10-29-page-cost.md) retains admission counts/intervals, TF/NX/step routes, and fresh/reused maps diagnostics. Its comparator/route data are revisions `c97096fad229` and `c14f3078a1b5`, and its counter diagnostic is `3675540b8ada`; those historical observations are not new 0847 profile measurements.

## Recorded CPU paths

The ls/true diagnostics contain **2,114 / 785 samples**, covering **21.353535140 / 7.929292850 sampled CPU seconds**. Their whole-process durations are 21.718317437 / 8.268605037 seconds. There is one profile per workload, not a paired overhead experiment. Both profiles passed their original terminal/source/cleanup checks with no loss, throttle, or depth-limit hit; no such result proves complete unwinding.

The following syscall-root partition is disjoint. Percentages use **all sampled CPU**, including userspace; roots identify recorded operations, not filenames or userspace callers.

| Recorded kernel root | ls count / share | true count / share |
|---|---:|---:|
| openat | 432 / 20.44% | 155 / 19.75% |
| read | 275 / 13.01% | 92 / 11.72% |
| mprotect | 223 / 10.55% | 101 / 12.87% |
| close | 115 / 5.44% | 46 / 5.86% |
| membarrier | 76 / 3.60% | 33 / 4.20% |
| No recorded syscall root | 98 / 4.64% | 36 / 4.59% |
| Other recorded roots | 16 / 0.76% | 7 / 0.89% |

The original `other_known_kernel_path` category remains 540 / 189 samples. Its new subdivision is openat 298 / 96, close 115 / 46, read 41 / 18, no recorded syscall root 76 / 23, and other roots 10 / 6. The largest unresolved leaf paths reach `security_file_open → vfs_open → … → openat` (219 / 55 samples) or `fput_close_sync → close` (84 / 36). Thus 303 of 304 / all 91 unresolved kernel leaf samples have recorded file-open/close ancestry. Their non-core function/program identities remain unresolved. Known BPF helper paths separately account for 134 / 59 samples, 6.34% / 7.52%; unknown frames are not assigned guessed BPF program names or ranges.

Actual proc-maps anchors (`show_map[_vma]` or `proc_get_vma`) account for 11.07% / 9.43%. Authenticated userspace maps-parser symbols add 6.91% / 5.35%. Source [lifecycle_loader.c](../../../tools/page-entry/selected/lifecycle_loader.c) opens, fully reads and closes `/proc/self/maps` on each fresh acquisition. This supports investigating maps I/O, but the complete 25.88% / 25.61% open-plus-close share remains a candidate envelope. Inclusive suffixes overlap and are never added as CPU time.

**194 of 223 / 94 of 101** mprotect samples contain a recorded perf notification path through `perf_event_mmap` and `mprotect_fixup`; the full original perf-anchor category is 9.22% / 11.97%. Other host observers may contribute: the stack does not prove ownership by this profiling session. Mprotect samples without a perf anchor are 1.37% / 0.89%, not a bound on unprofiled mprotect cost. Signal/exception anchors are 1.23% / 1.78%; runtime-side work remains charged to userspace. The REP closed/quiet symbols cost 11.35% / 12.61%; maps parsing 6.91% / 5.35%; named frame/source copy/compare symbols another 5.58% / 5.99%. Complete state comparisons remain mandatory.

The current [ls leaf CSV](20261030T031508.195312Z-page-cost-kernel-callchains-ls-0847974d17b9.csv) and [true leaf CSV](20261030T031602.015156Z-page-cost-kernel-callchains-true-0847974d17b9.csv) also retain individual all-offset policy, decoder/classifier/footprint and scan symbols. Leaf samples do not measure total decoder time.

Core labels use retained boot-bound, next-distinct-symbol intervals within core text; these can include padding. Raw unwind PCs are not adjusted. Unknown frames occur in 522 / 188 chains and remain unknown even when a caller/root is resolved.

## Conditional next changes

1. **Investigate a separately qualified owned maps-FD acquisition mode.** Physical open/read/close is current source and fixture behavior, not an express requirement that every future acquisition repeat an open. A mode with truthful FD lifetime, rewind and complete-read observations could be legitimate while retaining the original mode and fixtures. No safe equivalent implementation has been demonstrated: opening-mm identity, guard/permission lifetime, credentials, FD aliases/cursor isolation and retirement before effects/returns remain unresolved. This investigation is deferred while the selected REP conjunction optimization proceeds; no old close flag may be synthesized and no stale permission cache is allowed. `maps.handler_id` is a phase token that may restart within one actual handler, so no reuse estimate is inferred from its ratio to fresh reads.
2. **Join adjacent REP closed/quiet observations while retaining both predicate sets.** The current cold branches scan the same full owner. Any joined query must preserve actual binding/hook behavior, every byte/padding check and independent old APIs; no persistent clean flag, forged permit or changed refusal.
3. **Optimize strict maps text parsing.** A bounded parser can reduce repeated line/digit traversal while retaining every overflow, delimiter, row-order, permission, capacity and EOF check over the same complete fresh bytes.

If each respective component cost were halved with no new cost, the sampled-CPU Amdahl models are **1.149× / 1.147×**, **1.060× / 1.067×**, and **1.036× / 1.027×** for ls/true. The first is especially conditional because not every open/close is identified as maps. Formula: `1 / (1 − f + f/s)`. These are design comparisons, not achieved improvements or predictions for baseline wall time; even halving all three disjoint envelopes gives only about 1.283× / 1.279× sampled CPU.

## Limits and reproduction

Exact ptrace request/stop counts remain **unavailable**. Seven retained tracefs/audit reads failed with EACCES. TF signals, context switches, no sampled ptrace stack, or an endpoint `TracerPid` value cannot supply that count. The initial capability probe's parser failed its predicted attribute layout; it remains failed. A separately pinned data-only observer subsequently parsed its 197 retained samples (189 kernel), without another workload or retrospective qualification.

The [40 supplied parser/graph controls](2026-10-30-page-kernel-controls.json) passed (5 parser positives, 29 parser refusals, 2 graph positives and 4 graph refusals), executed on the byte-identical private candidate before the 0847 source commit, not as a fresh post-commit run; the published reader SHA256 is `ef6cfe33985a58596063822cb9b40df2ec301cdf5d51d6dd3ea6e05c12f9ccd2` and control-script SHA256 is `f43da1c329086c5b899202b1a5a8fb81877ae6855cb82d7b2df73a4b44e685c2`, with no workload, mapping or timing credit. To reproduce these supplied controls at 0847:

```sh
python3 evaluation/inprocess/page_cost_kernel_controls.py --reader evaluation/inprocess/page_cost_profile_read.py --sha256 ef6cfe33985a58596063822cb9b40df2ec301cdf5d51d6dd3ea6e05c12f9ccd2
```

The [six closed checks](20261030T031648.378097Z-checks-0847974d17b9.json) passed: recorder 350; workspace 3,545 passed/37 ignored across 103 harnesses; serial 1,039 across 27 harnesses. Workspace/serial wall caps remained 900/180 seconds. The baseline and targets retain 30 CPU seconds, 512 MiB address space, 16 MiB file size and 60 seconds wall; DR alone retains its separate 16 GiB address-space allowance. The profiler retains 30 CPU seconds, 1 GiB address space, 128 MiB file size and 80 seconds wall. No qualification workload or limit was reduced for this analysis.

From the indicated exact source revisions, with `CPU` already reserved, `SDK` set to the pinned SDK, and a **new** output path:

```sh
# At f7dd159db74f7ca1181a89bd48c11a329d7a49a5:
taskset -c "$CPU" python3 evaluation/inprocess/page_cost_compare.py --expect-revision f7dd159db74f7ca1181a89bd48c11a329d7a49a5 --sdk "$SDK"
# At 0847974d17b9f2b0e9c681c3c326e8e818af92ff, using that closed receipt:
taskset -c "$CPU" python3 evaluation/inprocess/page_cost_profile_run.py --baseline "$CLOSED_BASELINE_RECEIPT" --expect-revision 0847974d17b9f2b0e9c681c3c326e8e818af92ff --workload ls --kernel-callchains
taskset -c "$CPU" python3 evaluation/inprocess/page_cost_profile_run.py --baseline "$CLOSED_BASELINE_RECEIPT" --expect-revision 0847974d17b9f2b0e9c681c3c326e8e818af92ff --workload true --kernel-callchains
# Reproduce this arithmetic only, from the retained pinned artifact tree:
python3 evaluation/inprocess/page_cost_kernel_evidence.py --root "$ARTIFACT_ROOT" --output "$OUTPUT_JSON"
```

The projector expects the same relative layout under a repository or exported artifact root and refuses mismatched inputs before writing. Fresh runs have their own identities; this fixed projector never substitutes them for these receipts. Original [ls JSON](20261030T031508.195312Z-page-cost-kernel-callchains-ls-0847974d17b9.json), [ls CSV](20261030T031508.195312Z-page-cost-kernel-callchains-ls-0847974d17b9.csv), [ls kernel drill-down](20261030T031508.195312Z-page-cost-kernel-callchains-ls-0847974d17b9-kernel.csv), [true JSON](20261030T031602.015156Z-page-cost-kernel-callchains-true-0847974d17b9.json), [true CSV](20261030T031602.015156Z-page-cost-kernel-callchains-true-0847974d17b9.csv) and [true kernel drill-down](20261030T031602.015156Z-page-cost-kernel-callchains-true-0847974d17b9-kernel.csv) are unchanged. Kernel drill-down rows are already included in the main CSV and must not be added again. Raw samples, addresses and logs stay private. This is neither B2/B3 completion nor a causal optimization result.
