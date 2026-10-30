# Same-run event budget and the code-cache target

The event-budget cohort passed; the implemented region experiment has not completed qualification or attained the application target. The [event JSON](20261030T042205.505845Z-page-event-budget-22e5225612c4.json)/[CSV](20261030T042205.505845Z-page-event-budget-22e5225612c4.csv) retain all twelve launches at `22e5225612c495f63bc5fedc6960e8f1a6a33c0e`. Unobserved `/bin/ls -d .` median: 19.411150371 s (IQR 2.116492946); observed: 20.671929099 s (IQR 0.321144062), three runs each. The ratio is 1.06495, with no overhead subtraction. Both retain 30 CPU/60 wall seconds, 512 MiB address space and 16 MiB file size. The [model](2026-10-30-page-architecture-model.json) preserves exact public arithmetic.

The ledger below is **actual ordinal 6, `ls-1-events`**, not a synthetic median. It happens to be the observed median run. Its exact accounting is:

`20,150,374,970 handler ns + 521,554,129 residual ns = 20,671,929,099 process ns`.

Residual includes startup, application work, signal transitions, observer edges, reporting and reap; it is not isolated trap latency. Child CPU is separately 8.982981 s user + 11.527450 s system. Clock/bookkeeping costs stay in measured intervals.

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

Integer count/duration pairs ensure `Σ count × (duration/count)` equals the exact handler sum. Making all five maps rows (11.071982928 s, 53.56%) free still leaves 9.599946171 s. Making every decoder wrapper free leaves 20.053877386 s. These counterfactuals predict no speedup; handler-other is a broad remainder.

The overlapping signal view records 40,156 SIGSEGV handlers at 174.554 µs mean body time, 230,995 SIGTRAP handlers at 55.994 µs, and 148 SIGILL handlers at 1,396.299 µs. There are no SIGSYS/other handlers. The signal durations sum to the same 20.150374970 s; do not add this view to the ledger.

Incoming routes count 38,195 NO_STEP, 15,807 OLD_STEP, 215,109 GENERIC_TF, 1,961 REGISTER_RUN, 148 ONESHOT and 79 REPEAT_LEASE; REPEAT is zero. Their mean handler-body times are respectively 155.980, 46.351, 56.721, 536.328, 1,396.299 and 5.993 µs. Route durations sum to the same handler total and must not be added to the ledger. They measure ingress-state bodies, not complete trap round trips. Existing RAW-clock admission timing also overlaps; its endpoints are not mixed with these MONOTONIC intervals.

The row records 271,299 handlers (230,995 SIGTRAP), 379,086 fresh maps traversals, 1.448 GB read and 14,300,411 rows parsed. Ordinary C RAW calls number 9,768,115; 7,352,066 observer clocks are separate. These are observed-run counts, not unobserved syscall timings. C ptrace requests are zero; external stops remain unmeasured. The 1,094 unique fallback tuples describe 18,757 events (top 32: 15,225; overflow 0), **not all blocks, translations or application coverage**.

The structural contrast with DynamoRIO's retained code-cache model is ownership lifetime. This bridge's actual row records 215,109 GENERIC_TF ingresses, 271,299 handler entries and 379,086 fresh maps traversals. Retained translated blocks and linked direct edges aim to amortize translation and boundary checks across hot execution under valid lifetime authority, instead of revisiting those owners for each instruction or short run. A generation-owned region cache would need to demonstrate that reduction while preserving its interception and state contracts. The DR-null baseline supplies only an elapsed-time reference: this experiment did not measure DynamoRIO's internal translations, links or invalidations, and does not establish equivalent interception guarantees.

The candidate is a **generation-owned linked block cache**: genuine original-PC NX authenticates bytes, object/generation and legal entry heads; supported regions execute from non-writable generated storage with TF clear and original pages NX. Link direct edges only to qualified generated heads with compatible state/lifetime contracts. Indirect, selected-effect and unsupported exits enter an owned boundary at the original logical PC; existing selected owners remain authoritative. Fallback never licenses an unsupported original page.

A bounded immutable slab should amortize allocation, sealing, map checks and synchronization. Retain source generations and PC maps for every block/link; never permit a writable alias with RX. Before an application effect invalidates a source mapping, revoke incoming links and generated execution, synchronize, then retire the generation; metadata outlives all permitted execution, and reused source gets a new identity. Exact generated-to-original fault PC and full-state/memory semantics must precede any recovery/resume. Rseq, signals, mutation, foreign entry and teardown need explicit owner composition. These remain design obligations.

The implemented [fixture](../../../tools/page-entry/selected/tests/region_cache/README.md) uses the unchanged closed-scalar core planner, sealed publisher, retained disabled controls, original NX and guarded exit. Original/generated/actual-TF lanes compare identical trips and full GPR/flags/FP/stack/data. Its finite singleton/no-rseq, sole-entry, valid-pointer contract is not application coverage. Inter-region direct links, amortized slabs and runtime generation invalidation are absent. Inaccessible-load probes revoke/terminate; they do not establish fault resumption.

All four closed cohort attempts remain **FAILED** under the original eleven cases, ten hot invocations per lane, 5 CPU seconds, 15 wall seconds, 512 MiB address space and 16 MiB file-size limit:

| Attempt | Positive cases with complete records | Failed case | Fault probes |
|---|---:|---|---:|
| [510e75cf](20261030T042741.446280Z-region-component-510e75cf0b5e.json) | 5 | 2×256, exit −9 | Not run |
| [375aa7cb](20261030T043453.765438Z-region-component-375aa7cb2030.json) | 8 | 4×256, exit −9 | Not run |
| [ed12a0c3](20261030T044214.742186Z-region-component-ed12a0c358a9.json) | 8 | 4×256, exit −9 | Not run |
| [6084d0ee](20261030T044709.410653Z-region-component-6084d0ee3692.json) | 8 | 4×256, exit −9 | Both required exits 125 |

The first attempt left five cases unexecuted; the next two left both fault probes unexecuted. The 6084 collector attempted all eleven: both genuine inaccessible-load probes qualified their required 125 exits with zero completed operations/timing credit; the maximum positive case still failed. Cleanup passed with zero final errors. Its eight positive records have 33 completed operations and 8 authority controls each:

| Unroll × trips | Instructions/invocation | Prepare ms | Generated hot median µs | TF hot median ms |
|---|---:|---:|---:|---:|
| 1×1 | 10 | 2.820755 | 82.659 | 1.441364 |
| 1×16 | 100 | 2.938472 | 81.202 | 13.958581 |
| 1×256 | 1,540 | 2.940144 | 82.143 | 211.448206 |
| 2×1 | 14 | 3.088417 | 79.835 | 1.953968 |
| 2×16 | 164 | 2.689968 | 82.294 | 22.533870 |
| 2×256 | 2,564 | 3.064561 | 82.263 | 355.454319 |
| 4×1 | 22 | 3.024661 | 80.956 | 3.089412 |
| 4×16 | 292 | 2.921025 | 81.092 | 40.290163 |

Latest preparation spans 2.689968–3.088417 ms: source construction/sealing/hash, core planning and publication, excluding earlier setup. Invocation timing includes capture/guards; `cold_ns` means first observed invocation, not cache-cold construction. Attempting every case did not relax any gate or qualify the whole cohort.

The whole-application target remains **263.060775 ms**, ten times the [f7dd DR-null median](20261030T030044.789458Z-page-cost-compare-f7dd159db74f.json) of 26.3060775 ms (CPU 3; event cohort CPU 6, same reported hardware). Relative to the current unobserved median, it requires 73.7896×, or 98.6448% less elapsed time. The model is:

`Tnew = Tnative + Ncold × Ucold + Nexits × Uexit + incremental linked-execution overhead`.

The last term is additional execution overhead above native, avoiding double counting. A conditional allocation is the historical 4.1683375 ms native median + 100 ms cold construction/publication + 100 ms complete exits + 50 ms incremental linked execution = **254.1683375 ms**, 8.8924375 ms below target. This is feasible algebra, not demonstrated architecture performance. For example, assumptions of 25 constructions at 4 ms and 250 complete exits at 400 µs spend the two 100 ms allocations. Neither count nor complete-exit cost is measured for `ls`.

The partial preparation observations constrain cold work: at the latest measured composite costs, 100 ms buys only **32–37 constructions**; the earlier ed12 maximum 4.117842 ms allows 24. These are failed-cohort observations, not future cost bounds or pure translation costs. Amortized publication, cheaper construction or sufficiently few actual regions must be demonstrated. Signal-body means omit parts of the complete round trip and cannot substitute for `Uexit`; linked overhead and covered paths remain unknown. Fallback tuples fill none of these gaps.

Coverage must remove enough **time-weighted work**, not merely instructions. Even deleting every measured handler while freezing this observed residual leaves 521.554 ms; observer work makes that residual unsuitable as a new-architecture lower bound. **The experiment is implemented, its whole qualification remains failed, and the architecture target is not attained.**

Reproduce the unchanged public event/baseline arithmetic from a checkout, or supply `--root` for retained public artifacts:

```sh
python3 -B evaluation/inprocess/page_architecture_model.py \
  --check evaluation/inprocess/results/2026-10-30-page-architecture-model.json
```

The [script](../page_architecture_model.py) pins both JSON/CSV pairs, reconstructs the complete event CSV and checks all twelve event and sixty baseline outcomes. It runs no workload/evaluator. The component table is separate arithmetic from the linked 6084 receipt. Private event receipt SHA256 `9de0f3e1180f7e70bef6e81fa2540d33578b8609b351f3219167cfae867ec014` is provenance, not an input. Source/cleanup statements remain those of the retained runs.

Repository validation at `ec2dd4d5307b7b64013102f19f717428e975f49b`, including merged main `6b10dbd0ac6b251d508d16e8c7e3fad19d767944`, passed all six [required checks](20261030T045512.638556Z-checks-ec2dd4d5307b.json): recorder 350; workspace 3,623 passed and 37 ignored across 104 harnesses in 738.5 seconds; serial 1,039 passed across 27 harnesses in 140.8 seconds; formatting, strict Clippy and the all-features/all-targets build check. Source, configuration and cleanup checks passed under unchanged limits. Runtime, core and component source bytes match the audited 6084 experiment. These repository checks do not qualify the failed region cohort or establish the application target.
