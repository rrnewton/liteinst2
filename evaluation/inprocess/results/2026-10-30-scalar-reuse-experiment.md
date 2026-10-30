# Scalar block-cache experiment: qualified ownership, failed performance cohort

At revision `cd351812fc2eb293548b0ec29f00308c780595d8`, the in-process scalar
graph cache can replace completed generations within its original 64 slots.
All 43 owner subjects passed: 13 native references, 13 generated/native pairs
and 17 required owner refusals, including six genuine generated read faults
and their six native references. Full GPR, arithmetic flags, 65,536 FP bytes,
stack, data, source-generation, mapping and cleanup comparisons remain exact.
The 4,102 owner, 1,964 terminal and 348 application supplied refusals passed.
The separate eight mapping refusals, 152 mapping-reader controls and 754
range-predicate cases retain their separate scope. This supports claims 1
and 4; it is not a whole-program performance qualification.

The required 82-attempt release comparison **failed**. All attempts ran;
81 passed, while the required `ls` differential run exited -9 at the original
30 CPU-second limit: 29.995002 CPU seconds and 30.217050091 elapsed seconds,
without a wall timeout. All 166 commands were reaped, source and artifacts
closed, cleanup completed, and there were zero final closure errors. No run
was replaced or excluded. The original resource limits remain unchanged.
No medians, IQR, ratios or aggregate timing credit are issued for this failed
cohort. The 10× DynamoRIO target is unmet.

The following are the observed intervals across all ten ordinary attempts
per row, retained to expose the regression rather than qualify a speedup.
All executions used reserved CPU 6 on one AMD EPYC 9D85 host, Linux 7.1.3,
microcode `0xb101066`, with release builds and an unprivileged runner.

| Program and lane | Elapsed seconds | SIGTRAP | Physical fresh maps acquisitions |
| --- | ---: | ---: | ---: |
| `ls -d .`, unrolled | 9.394773415–11.853595443 | 188,101 | 59,472 |
| `ls -d .`, scalar reuse | 14.781328808–17.918027311 | 168,720 | 56,107 |
| `true`, unrolled | 3.501909397–4.193550884 | 74,897–74,905 | 21,928–21,929 |
| `true`, scalar reuse | 5.387478979–6.313620950 | 68,840 | 20,912 |

The first declared `ls` pair took 9.590152828 seconds unrolled and
14.787975619 seconds with scalar reuse. Scalar execution reduced traps but
increased elapsed time. Each scalar `ls` run completed 9,046 regions from
1,024 publications and 8,022 hits, with 960 completed-generation retirements.
It still made 20,076 plan checks, 28,162 rseq checks, 14,664–14,666 planner
misses and 78,039 generic single-step executions. These are event counts,
not a measured attribution of elapsed seconds. Route counts overlap and
must not be summed. Total handler events were 198,664–198,666; maps queries
were 941,284–941,320. Physical acquisitions are refreshes plus differential
comparisons, not the number of mapping queries.

The fresh native `ls` samples were 5.531915–9.163177 ms and DynamoRIO samples
27.683384–29.698479 ms. Native `true` samples were 5.141559–8.742723 ms and
DynamoRIO samples 20.880769–24.590097 ms. All ten samples per lane remain in
the receipt without aggregate timing credit. DynamoRIO used SDK 11.91.0 and
an empty release client; independent loader diagnostics authenticated the
client and target. Its existing 16 GiB virtual-address allowance is recorded
separately from the other lanes' unchanged 512 MiB limit.

The required `true` differential run completed in 14.049870505 seconds:
345,711 cached-versus-fresh comparisons, 20,912 refreshes, 366,623 physical
fresh acquisitions, and zero mismatches. The killed `ls` differential run
has no complete terminal counters or equivalence claim.

Source inspection identifies repeated static graph and instruction-footprint
proof on warm hits; the cache currently reuses emitted code while rebuilding
that proof. An immutable proof bound to the exact slot generation is a next
experiment, requiring explicit certificate retirement and all current live
source, permission, rseq and frame checks. It would not remove the remaining
single-step boundaries. The separate maintained-view cold-admission candidate
is still awaiting native qualification. Neither candidate has a measured
speedup or a justified model reaching the target.

The exact command, bounds, compiler versions, hardware, SDK manifest, release
artifacts, all 82 numerical rows and private-receipt digest are in
[the performance JSON](20261030T114155.079495Z-scalar-reuse-performance-cd351812fc2e.json)
and [CSV](20261030T114155.079495Z-scalar-reuse-performance-cd351812fc2e.csv).
The tracked driver is `evaluation/inprocess/unrolled_hash_performance.py`
with `--scalar-reuse`; its recorded reproduction command requires all five
same-revision, same-CPU prerequisite receipts. Obtain the recorded SDK and
set `SDK` to its local directory when reproducing.

Those prerequisites are the
[decoder 8](20261030T112453.821236Z-region-decoder-cd351812fc2e.json),
[scalar component 11](20261030T112530.391705Z-scalar-region-component-cd351812fc2e.json),
[scalar reuse owner 43](20261030T112605.416153Z-scalar-region-reuse-owner-cd351812fc2e.json),
[original component 9](20261030T113839.319371Z-unrolled-hash-component-cd351812fc2e.json)
and [original owner 25](20261030T113907.371735Z-unrolled-hash-owner-cd351812fc2e.json).
Each passed independent closed-data review. Earlier failed owner and
performance cohorts remain failed. The earlier CPU 1 decoder success is
retained separately; its orchestration wrapper failed after that success
and it does not substitute for these CPU 6 prerequisites.
