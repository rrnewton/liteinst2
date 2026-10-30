# Same-run event budget and the code-cache target

The [event receipt](20261030T042205.505845Z-page-event-budget-22e5225612c4.json) and [CSV](20261030T042205.505845Z-page-event-budget-22e5225612c4.csv) report all twelve fixed launches passed at `22e5225612c495f63bc5fedc6960e8f1a6a33c0e`. The [derived model](2026-10-30-page-architecture-model.json) reproduces the arithmetic below from public artifacts only. The three `/bin/ls -d .` unobserved launches have a 19.411150371 s median (IQR 2.116492946 s); the three observed launches have a 20.671929099 s median (IQR 0.321144062 s). The observed/unobserved median ratio is 1.06495. These are separate actual populations; no observer overhead is subtracted. Both retain 30 CPU seconds, 512 MiB address space, 16 MiB file size and 60 seconds wall time.

The ledger below is **actual ordinal 6, `ls-1-events`**, not a synthetic median. It happens to be the observed median run. Its exact accounting is:

`20,150,374,970 handler ns + 521,554,129 residual ns = 20,671,929,099 process ns`.

The residual covers all unmeasured startup, ingress prefixes, application execution, signal transitions, observer edges, reporting and reap work. It is not isolated trap latency. Child CPU accounting is 8.982981 s user plus 11.527450 s system; it is a separate view, not another term to add. Boundary clocks and bookkeeping remain in the recorded intervals.

| Exclusive region | Actual calls | Mean µs/call | Total ms | Whole process |
|---|---:|---:|---:|---:|
| Handler other | 271,299 | 27.476 | 7,454.286 | 36.06% |
| Maps other | 379,086 | 1.046 | 396.610 | 1.92% |
| Maps open | 379,086 | 12.379 | 4,692.623 | 22.70% |
| Maps read | 822,421 | 3.693 | 3,036.872 | 14.69% |
| Maps close | 379,086 | 3.818 | 1,447.310 | 7.00% |
| Maps parse | 379,086 | 3.953 | 1,498.568 | 7.25% |
| Decoder decode | 446,300 | 0.521 | 232.602 | 1.13% |
| Decoder classify | 332,499 | 0.714 | 237.332 | 1.15% |
| Decoder footprint | 202,312 | 0.732 | 148.117 | 0.72% |
| Decoder scan | 0 | — | 0 | 0% |
| Native policy | 38,103 | 7.799 | 297.175 | 1.44% |
| Admission prepare, excluding nested work | 38,103 | 10.913 | 415.820 | 2.01% |
| Admission publish, excluding nested work | 5,376 | 17.505 | 94.104 | 0.46% |
| Native close, excluding nested work | 3,276 | 60.731 | 198.955 | 0.96% |
| Unmeasured residual | — | — | 521.554 | 2.52% |

Rounded means are presentation only: the model JSON retains every integer duration/count pair, so `Σ count × (duration/count)` equals the exact handler sum. Maps' five exclusive rows total 11.071982928 s (53.56% of the process). Making that entire subtree free, with everything else fixed, still leaves **9.599946171 s**. Making all four decoder wrappers free leaves **20.053877386 s**. These are isolated zero-cost counterfactuals, not speedup predictions. Handler-other is a broad remainder, not a measured single function.

The overlapping signal view records 40,156 SIGSEGV handlers at 174.554 µs mean body time, 230,995 SIGTRAP handlers at 55.994 µs, and 148 SIGILL handlers at 1,396.299 µs. There are no SIGSYS/other handlers. The signal durations sum to the same 20.150374970 s; do not add this view to the ledger.

| Incoming route | Count | Mean handler-body µs | Inclusive ms |
|---|---:|---:|---:|
| NO_STEP | 38,195 | 155.980 | 5,957.668 |
| OLD_STEP | 15,807 | 46.351 | 732.669 |
| GENERIC_TF | 215,109 | 56.721 | 12,201.173 |
| REGISTER_RUN | 1,961 | 536.328 | 1,051.740 |
| ONESHOT | 148 | 1,396.299 | 206.652 |
| REPEAT_LEASE | 79 | 5.993 | 0.473 |
| REPEAT | 0 | — | 0 |

Routes are ingress states, not an extra instruction partition or the exclusive cost of a mechanism. Their durations also sum to the same handler total. These are post-guard handler-body measurements, **not complete trap/exit round trips**. Original COST admission durations use CLOCK_MONOTONIC_RAW and overlap these CLOCK_MONOTONIC regions; neither their endpoints nor totals are combined here.

The same row exposes the amplification:

- **271,299 measured handlers** include 230,995 SIGTRAP entries (85.14%), 40,156 SIGSEGV entries and 148 SIGILL entries. The incoming-route view contains 215,109 GENERIC_TF, 15,807 OLD_STEP and 1,961 REGISTER_RUN entries. These expose control-transfer amplification, not the total retired instruction count. Same-page TF reuse still returns after each stepped instruction; this diagnostic does not establish the count of all application instructions.
- **379,086 fresh maps traversals** perform 822,421 reads, consume 1,447,609,923 bytes and parse 14,300,411 rows: 1.397 fresh traversals per handler. The terminal 703,085 reuse hits coexist with this physical work. A maps phase ID is not a handler count.
- **981,111 decode/classify/footprint calls** are 3.616 per handler; their combined 618.052 ms is only 2.99% of whole-process time. This is the four instrumented wrapper population, not all decoder internals or all retired instructions.
- **9,768,115 ordinary C RAW calls** are 36.005 per handler, including 4,860,430 getpid/gettid and 2,669,342 fstat/fcntl calls. Another **7,352,066 diagnostic clock calls** are separately recorded and excluded from that ordinary RAW count. This measures the observer's amplified workload, not unobserved syscall timing. Ordinary C ptrace requests are zero; external ptrace stops remain unmeasured.
- The bounded fallback table records **1,094 unique tuples** for 18,757 fallback events; its top32 cover 15,225 events, with zero overflow. These are neither all basic blocks nor unique translations. Private terminal details such as copied-instruction counts and cache hits are not reproduced by this public model and are not used to fill the coverage gap.

The structural experiment should therefore keep ordinary instructions and internal branches inside a qualified generated region with TF clear, amortize source/lifetime checks across that region, and eventually link qualified exits. It must preserve current source generations, selected-effect exits, original-page NX, full-state/fault reconstruction and rseq authority. The existing DR fragment-cache design illustrates how to avoid instruction-by-instruction returns; its null-client timing does not establish equivalent interception guarantees. The bounded region component can establish a mechanism, not whole-`ls` coverage.

The target remains **263.060775 ms**, ten times the [separate f7dd baseline](20261030T030044.789458Z-page-cost-compare-f7dd159db74f.json) DR-null median 26.3060775 ms (CPU3; event cohort CPU6, same reported hardware). Against the current unobserved median it requires **73.7896×**, or 98.6448% less elapsed time. That is a target, not an achieved or predicted speedup. Use:

`Tnew = Tnative + unique_translations × unit_cold + remaining_exits × unit_exit + incremental_linked_execution_overhead`.

The last term is overhead **above native execution**, not total generated execution, avoiding double counting. One algebraically feasible allocation is the historical 4.1683375 ms native median + **100 ms cold translation/publication + 100 ms complete exits + 50 ms incremental linked execution overhead = 254.1683375 ms**, leaving 8.8924375 ms below the target. Only the native reference is measured; the three allocations are assumptions, not demonstrated costs. They require `unique_translations × unit_cold ≤ 100 ms` and `remaining_exits × unit_exit ≤ 100 ms`. Qualified cold/exit measurements must determine the permitted counts; no count or coverage is invented here.

Cold construction/publication, complete exit costs, incremental linked execution overhead and application coverage remain unmeasured here. Component results are pending and are not an input to this model. The initial `510e75cf0b5e26ceea133c1e6bfb8005141e736e` attempt failed at case six. The production-helper correction at `375aa7cb203086971a9bcebaa8b8b0283d154485` passed eight cases before case nine was killed; both fault probes remained unexecuted. Both attempts remain failed; no completed component cohort or target attainment is claimed here. For proven bypassable elapsed work `D`, remaining fixed work `F` and new overhead `O`, the conditional requirement is `f ≥ 1 − (263060775 − F − O)/D`. It is a **time-weighted** removal fraction, not instruction coverage. If `F+O` exceeds the target, no coverage fraction suffices. Even deleting every measured handler while freezing this observed residual leaves 521.554 ms; the residual includes observer work and is not a lower bound for a new architecture. This rules out extrapolating a whole-application result from the handler mean alone.

Reproduce the public arithmetic from a checkout (or supply `--root` for a retained-artifact root) with:

```sh
python3 -B evaluation/inprocess/page_architecture_model.py \
  --check evaluation/inprocess/results/2026-10-30-page-architecture-model.json
```

The [script](../page_architecture_model.py) accepts `--output NEW_FILE` to create the same JSON, or emits it on stdout. Four exact byte/hash pins cover the event JSON/CSV and [original f7dd baseline CSV](20261030T030044.789458Z-page-cost-compare-f7dd159db74f.csv)/JSON. It reconstructs the complete event CSV, checks all twelve event outcomes and all sixty baseline outcomes, and recomputes all medians, inclusive quartiles, counts and timing partitions before output. It imports no evaluator and runs no workload. The 2,299,865-byte private event receipt, SHA256 `9de0f3e1180f7e70bef6e81fa2540d33578b8609b351f3219167cfae867ec014`, is provenance already recorded in the public receipt, **not a reproduction prerequisite**. Source and cleanup facts remain those reported by the original qualified run; this arithmetic does not re-execute their validation.

The independent private DATA_CLEAR review is 7,140 bytes, SHA256 `e6abe9ebae07244efdec87f5f00a9b1461943574322b0cfbfc0d98f5756b4ef1`; its identity is retained as provenance, not an additional script input.

Component results: **pending the complete new cohort**. This placeholder carries no completion or speedup credit.
