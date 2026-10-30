The reproducible TRACE diagnostic collected 453 CPU-clock samples with zero reported lost samples from the retained pre-repair bridge at `e376443d5c35ab2d63fd05e3f4eb3b4b9ac9e93e`. This is a sampled, interrupted fixture run, not whole-program timing or qualification.

Collector revision: `60c09b1b5f235f7a2192cb79a9090595c797619b`. Hardware: AMD EPYC 9D85 158-Core Processor, Linux 7.1.3, microcode `0xb101066`, reserved CPU 80. The collector authenticated the historical application's original bridge, carrier, libraries and 29-file launch closure. All three commands were reaped with unchanged inputs and no final closure errors.

| Sampled bridge symbol | Samples | Share of 453 samples |
| --- | ---: | ---: |
| `equal` | 71 | 15.7% |
| `selected_generic_trace` | 69 | 15.2% |
| `copy` | 46 | 10.2% |
| `li2_span_plan_page` | 44 | 9.7% |
| `li2_tf_chain_span_close` | 38 | 8.4% |
| `selected_fetch` | 32 | 7.1% |
| `li2_span_plan_validate.part.0` | 27 | 6.0% |
| `memcpy` | 17 | 3.8% |

The three direct byte-operation symbols account for 134/453 samples (29.6%). Other listed functions also contain byte operations, but this symbol-level summary does not assign their entire cost to those operations. The full sample population, top 32 symbol groups and remainder are recorded in the JSON. These observations support investigating complete-state copy/clear/compare cost; they do not establish a speedup for the later bulk-operation repair.

The original diagnostic at collector `248b31370084` failed before a complete attachment: perf exited 255 with an mmap allocation failure. That failed result is retained. The successor explicitly requests 16 perf data pages and preserves the original 256 MiB tool limit, 99 Hz sampling and five-second requested attachment. It completed the diagnostic with no lost samples. This does not prove the original allocation's exact cause.

The subject retained its 10-CPU-second, 20-wall-second, 512-MiB address-space and 16-MiB file/output limits. It exited -9 after 11.262230799 wall seconds, with 9.162379 CPU seconds in user space and 0.822698 in the kernel; its application captures were empty. Perf exited -2 after the requested SIGINT. Observer overhead and interruption prevent any completion or performance claim. The original nine-subject qualification remains failed under its separate unchanged bounds.

Exact [successful diagnostic JSON](20261030T160919.686338Z-span-trace-diagnostic-60c09b1b5f23.json), [CSV](20261030T160919.686338Z-span-trace-diagnostic-60c09b1b5f23.csv), [failed diagnostic JSON](20261030T160409.692605Z-span-trace-diagnostic-248b31370084.json) and [CSV](20261030T160409.692605Z-span-trace-diagnostic-248b31370084.csv) include source, hardware, command, bounds, samples and artifact hashes. After reproducing the original e376 fixture and retaining its private artifacts, run on one reserved CPU at the collector revision:

```sh
python3 -B evaluation/inprocess/span_trace_diagnostic.py --receipt evaluation/inprocess/results/20261030T153625.131280Z-scalar-span-trace-e376443d5c35.json --expect-artifact-revision e376443d5c35ab2d63fd05e3f4eb3b4b9ac9e93e --kind perf
```
