ADDS an opt-in maintained address-space view and a fresh-view differential observer for the in-process page runtime (claims 1 and 4). This slice does not qualify the complete application cohort or reach the 10×DynamoRIO target.

Exact source: `2db2ae642d5bf54eb63f1870c1e874e19b211ebb`. Reproduce with one reserved CPU and `python3 evaluation/inprocess/maps_view.py --expect-revision 2db2ae642d5bf54eb63f1870c1e874e19b211ebb`. The release bridges use `-O2`; the receipt records compiler, binary, kernel and input identities. Hardware: AMD EPYC 9D85, family 26/model 17, microcode 0xb101066, kernel 7.1.3; unprivileged, reserved logical CPU 160.

Successful intercepted mprotect operations project permission intervals; other mapping operations invalidate before execution. Unsupported guest operations remain refused. Detected stack growth and unexplained faults force fresh observations. Existing source, alias, backing, custody and physical-fresh owner checks remain required. Differential mode compares every canonical interval and field on every hit and permanently poisons a mismatch. Its exact private maps I/O preserves existing source custody.

All six finite actual-TU cases passed. The current fixed application cohort is FAILED: 39/42 passed. Baseline ls ordinal 0, maintained ls ordinal 1 and differential ls ordinal 40 were killed at the original 30 CPU-second limit; none reached the 60-second wall limit. Their outputs were empty, so no terminal counters or completion are inferred. All subjects were reaped, descriptors closed and source/artifacts unchanged. No retry, replacement, dropped sample, aggregate timing credit or speedup is claimed.

All ordinary release wall times below are seconds, rounded to six decimals. A killed process remains a failure, not a latency sample. Exact nanoseconds and event counts are in the CSV.

| Repeat | ls baseline | ls maintained | true baseline | true maintained |
|---:|---:|---:|---:|---:|
| 0 | 30.247929 (killed) | 30.220851 (killed) | 16.163904 | 5.811199 |
| 1 | 22.017559 | 14.404386 | 7.569737 | 6.186625 |
| 2 | 18.896185 | 11.587472 | 6.593378 | 4.064859 |
| 3 | 18.369640 | 11.294308 | 6.473954 | 4.078439 |
| 4 | 18.580191 | 11.729829 | 7.536946 | 4.545944 |
| 5 | 19.501432 | 12.227415 | 6.830621 | 4.346954 |
| 6 | 19.570137 | 11.572243 | 6.894102 | 4.820711 |
| 7 | 20.331351 | 11.980783 | 7.362985 | 4.633280 |
| 8 | 20.993039 | 12.583679 | 7.523901 | 4.422369 |
| 9 | 19.308774 | 12.633184 | 7.508062 | 4.626749 |

The nine completed maintained ls runs report 1,082,369–1,082,404 queries, 1,017,532–1,017,566 hits, 64,837–64,838 physical fresh acquisitions, 233,907–233,911 mprotect projections and 1,001,440–1,001,471 stack probes. These are count ranges across every completed run; the killed run has no terminal counts. The existing route counters overlap and are not a total trap count. The baseline has no corresponding maps counter; the earlier 379,086 count belongs to a separate historical measurement.

The differential true run passed in 13.744558688 s: 388,305 full-view comparisons, zero mismatches or poison, 23,775 miss refreshes and 412,080 physical fresh acquisitions including comparisons. This establishes that run's cached/fresh equivalence. Differential ls did not complete; its equivalence remains unproved. Differential timing has no performance credit.

The preceding source `63f258813c46f55f3c4e1c5fc7a06d6d65946781` passed the six finite cases and all 40 ordinary launches, but both differential launches refused with stale custody (903/302). That failed cohort is retained. The fix preserves custody around only the private comparison transaction; it does not relax the custody predicate.

Raw numerical summaries and reproducing commands:

- [Current JSON](20261030T060208.977757Z-maps-view-2db2ae642d5b.json) and [CSV](20261030T060208.977757Z-maps-view-2db2ae642d5b.csv).
- [Preceding failed JSON](20261030T054929.394862Z-maps-view-63f258813c46.json) and [CSV](20261030T054929.394862Z-maps-view-63f258813c46.csv).

The next experiment retains a bounded generated unroll of a real loader loop, with original hardware data loads and genuine source-head/stop faults. It must pass full-state and actual generated-fault checks before application performance measurement. The historical 10×DynamoRIO target is 263.060775 ms; current measurements do not attain it.

All six required checks passed at the same source revision: recorder 350, formatting, strict Clippy, workspace 3,623 passed / 0 failed / 37 ignored across 104 harnesses, all-targets/all-features check, and serial 1,039 passed / 0 failed across 27 harnesses. [Exact check receipt](20261030T061345.400842Z-checks-2db2ae642d5b.json) records commands, toolchain, bounds and source/configuration/cleanup closure.
