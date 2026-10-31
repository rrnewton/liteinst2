# Startup reuse census

The admitted graph cache repeatedly rebuilds graphs with identical source-key and registry identities and refuses direct
branches outside its two-page source pair. This diagnostic supports claims 1 and
4; it does not qualify the whole profile or establish a performance improvement.

At revision `c876a6bdc9e4a793510c292a60d17c293bf41c64`, the unchanged 52-instruction
startup fixture reached the original 30-second CPU limit (`SIGKILL`). The process
ran for 30.210 seconds; the wrapper interval was 30.377 seconds. The closed
committed prefix contains 12,210 attempts, with the last attempt unfinished.
The native reference completed in 157.509 ms with 12 full frames and 32 controls.

| Observed committed-prefix event | Count |
| --- | ---: |
| Graph publications | 3,573 |
| Exact graph publications repeated after recorded eviction | 2,577 |
| Cold refusals | 6,071 |
| Exact refusals repeated | 4,379 |
| Root hits / internal hits / peer touches | 2,529 / 36 / 1,414 |
| Completed entries | 6,138 |
| Outside-pair planning refusals | 2,308 |

Thus 72.1% of publications repeat an exact source key and registry after its
recorded eviction. Saved source bytes identify all 2,308 outside-pair planning
refusals as canonical direct branches: 1,484 `E9 rel32` incidents at 24 sites and
824 near conditional branches at 63 sites. These are planning incidents, not
executed branch counts. They motivate admitting direct targets and connecting
already admitted graphs. The census cannot predict an eight-slot cache: its
counterfactual state becomes unknown at attempt 5.

Independent ABI2 counters report 19,820 handler events (6,694 SEGV, 13,040 TRAP,
86 ILL), 590,197 maps queries, 589,058 maintained-view hits, and 1,139 fresh
acquisitions. This maintained-only run performs no differential comparisons.
The ABI2 retirement cell is 3,572; the committed census records 3,571 retirements.
Those observations remain separate because the prefix ended during an attempt.

The run used one reserved CPU on an AMD EPYC 9D85, family 26/model 17/stepping 0,
microcode `0xb101066`, Linux 7.1.3, Rust 1.97.1 and GCC 11.5.0. Exact source,
hardware, bounds, artifact hashes and commands are in the
[JSON receipt](20261031T153448.082324Z-startup-reuse-census-c876a6bdc9e4.json)
and [CSV results](20261031T153448.082324Z-startup-reuse-census-c876a6bdc9e4.csv).

Reproduce the collection on that revision with one reserved CPU:

```sh
python3 -B evaluation/inprocess/startup_reuse_census.py \
  --expect-revision c876a6bdc9e4a793510c292a60d17c293bf41c64 \
  --interpreter REFERENCE_INTERPRETER
```

`REFERENCE_INTERPRETER` must match the receipt's interpreter bytes/hash.
The portable `evaluation/inprocess/reuse_census_analysis.py` additionally accepts
`--root`, `--receipt`, `--expect-revision` and `--expect-receipt-sha256`; it verifies
the closed private receipt, historical parser source and raw capture hashes
before deriving these counts. The raw capture stays private; this public report
contains compact numeric summaries. The analyzed receipt SHA256 is
`c28f17e16f136cbce04c3b188e35bd9bd20d06e8391ea5de81b173b847cfd5af`.

Original 392/522-instruction qualification and real-program completion remain
required. This killed prefix satisfies neither and receives no speedup credit.
