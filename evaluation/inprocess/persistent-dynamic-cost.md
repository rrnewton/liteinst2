# Dynamic execution CPU costs

A release `/bin/ls -d .` run with the dynamic two-page owner still fails at the unchanged 30 CPU-second limit. This slice adds actual user-PC and bounded caller observations for that failure. It supports validation methodology for claims 1 and 4; it establishes neither completed-program coverage nor the ten-times-DynamoRIO target.

The [capture](results/20261031T032316-dynamic-cost-profile-8baf01b.json) uses profiler revision `8baf01be366bc262d106bd211b83fa0fbc3b0060` and the exact retained release built at `adb63e09a06f8560c00a93f06e5d0c0710c61af7`; compiled sources are unchanged. On one reserved AMD EPYC 9D85 CPU, target exit is -9 after 30.452783929 seconds, with wait4 user/system usage of 25.513086/4.489479 seconds. Output is empty and terminal admission/trap counters are unavailable. These are costs of a failed prefix, not completion latency.

Perf records user CPU at 99 Hz with a 4096-byte DWARF stack request. The [offline replay](results/20261031-dynamic-cost-replay-6de8c623.json) ([CSV](results/20261031-dynamic-cost-replay-6de8c623.csv)) at `6de8c62320a7a04884e1fbbdf9d2fcd082bcba3e` conserves all 2,547 samples and 25,727,272,470 sampled-period units. Five samples (0.1963%) remain unknown. No lost or throttle records were observed. The window includes carrier startup from the first same-PID exec through exit. Percentages below describe sampled user CPU, not wall or kernel time.

| Exclusive function | Samples | Sampled-period share | Design response |
| --- | ---: | ---: | --- |
| `project` (compact-plan projection) | 367 | 14.4091% | Retain an immutable compiled-group certificate across linked execution. |
| `pe_bytes` | 330 | 12.9564% | Keep code/proof authority for a group lifetime; avoid re-entering the owner at each internal edge. |
| `li2_pe_plan_pages_dynamic` | 304 | 11.9356% | Reuse authenticated admitted heads instead of rebuilding on every new root. |

All 367 `project` samples are leaf-only: the capture does not identify their callers. Across the full capture, 2,134 observations have multiple displayed frames, 408 are leaf-only and five are empty; no complete-stack claim is made. The recorded `pe_bytes` paths include entry, replacement claim and drain. Actual planner stacks include both compact-validation rebuild paths. Source inspection independently shows that a successful cold attempt plans three times and projects twice. The current resident-generation lookup also requires the original entry PC. Both facts motivate a longer cache lifetime; speeding one byte loop cannot establish the whole-process target.

The next experiment is two immutable generated images over one held two-page source/rseq lifetime, with explicitly supported capacity edges through protected data slots. Both images and links must be built and sealed before execution. Repeated A-to-B-to-A transitions must require no internal signal, fetch acquisition, decoding or publication. Unsupported instructions still drain into the existing path. Complete native/generated state, recovery, invalidation and revocation checks remain required. This is a proposed experiment, with no measured speedup yet.

## Reproduction and retained failures

Use an externally reserved one-CPU shell and fresh private output directories. First obtain the closed release receipt using the exact native revision and commands in [the dynamic experiment report](persistent-dynamic-adb63e.md). Then, at the indicated profiler and reader revisions:

```sh
# Checkout: 8baf01be366bc262d106bd211b83fa0fbc3b0060
python3 -B evaluation/inprocess/persistent_dynamic_profile.py \
  --expect-revision 8baf01be366bc262d106bd211b83fa0fbc3b0060 \
  --receipt "$closed_dynamic_ls_receipt" \
  --output target/page-region-next/fresh-dynamic-profile
# Checkout: 6de8c62320a7a04884e1fbbdf9d2fcd082bcba3e
python3 -B evaluation/inprocess/persistent_dynamic_profile_replay.py \
  --expect-revision 6de8c62320a7a04884e1fbbdf9d2fcd082bcba3e \
  --receipt target/page-region-next/fresh-dynamic-profile/receipt.json \
  --output target/page-region-next/fresh-dynamic-replay
```

The producer revision intentionally retains its observed metadata-layout failure; replay reads the capture without rerunning the target. Exact command, hardware, tool, release and receipt facts are in the linked JSON. Raw perf data, stacks, paths and logs stay private.

The earlier [setup failure](results/20261031T031951-dynamic-cost-setup-744a4d7.json) occurred before target/perf launch: the host observer dependency exceeded the guest namespace file cap. Separate observer dependency recording fixes that mismatch without changing the guest limit. The [first replay](results/20261031-dynamic-cost-replay-5b545523.json) also remains failed: its reader hit the existing CPU limit while searching historical mappings. An active interval index preserves the complete mapping history and original offsets; its eight-case oracle checks 5,586 queries against the original lookup semantics. The final replay completes under the same bounds and resolves distinct same-named functions by exact ELF interval.

Target bounds remain 30 CPU seconds, 60 wall seconds, 512 MiB and 16 MiB output. Separate observer and reader bounds remain 30 CPU seconds, 80 wall seconds, 1 GiB and 128 MiB files, with 16 MiB ordinary captures. The failed target remains failed after successful observation.

## Required checks

At source revision `6de8c62320a7a04884e1fbbdf9d2fcd082bcba3e`, the [second checks receipt](results/20261031T034728.268765Z-checks-6de8c62320a7.json) records fmt, clippy, workspace tests and the all-features check passing. Workspace tests completed 4,071 passed, 0 failed and 37 ignored across 109 harnesses; recorder tests completed 362. The serial launch check timed out at its unchanged 180-second limit, with eight complete harnesses and 804 passing tests observed; its receipt remains failed and incomplete. This is not a landing-ready validation set.

The [first checks receipt](results/20261031T033936.657272Z-checks-6de8c62320a7.json) retains a recorder timeout under the same 180-second bound and an untracked-input failure caused by this report draft. The report was moved out of the source tree before the second run. Neither failure was converted to a pass or used to relax a bound.
