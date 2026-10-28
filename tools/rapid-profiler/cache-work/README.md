# Exact linked-memory work

`cache_work_linked` is a fixed 39-byte, normally loaded read-only integer leaf.
The caller supplies a complete aligned 1024-byte slice: sixteen 64-byte nodes
with a u64 next-node byte offset at +0 and payload at +8. Node zero holds the
iteration count at +16. Every link is aligned and inside the same slice; the
only supported counts are 16 and 64. RSI receives the complete slice length.
The body performs no writes, calls, stack adjustment or callee-saved write.

The result is a wrapping payload sum XOR `0x9e3779b97f4a7c15`. Each invocation
executes `5n+6` original instructions including RET, `n` conditional branches,
`n-1` taken branches, `2n+1` input qword reads and one RET qword read. Every
case is a **dependent** linked walk, including the sequential walk; this is
not an independent-address stride or hardware latency experiment.

| Case | Node cycle | Iterations | Model misses / hits |
|---|---|---:|---:|
| reuse4 | 0,1,2,3 | 64 | 5 / 125 |
| cold16 | 0..15 | 16 | 17 / 17 |
| chase8 | 0,3,6,1,4,7,2,5 | 64 | 9 / 121 |
| fit2 | 0,4 | 64 | 3 / 127 |
| conflict3 | 0,4,8 | 64 | 65 / 65 |
| capacity12 | 0..11 | 64 | 65 / 65 |

The declared cache has 64-byte lines, four sets and two ways with true LRU;
all lines start invalid **for each invocation**. Only original architectural
data operands participate, in order: count, payload/link pairs, then RET.
There is no instruction fetch, speculation, prefetch, translation, coherence,
background traffic or write policy. Addresses remain the actual full-width
virtual addresses; set is `(address/64)%4`. Each complete eight-byte read must
fit one line, and the real RET stack line must be disjoint from all input
lines. The count read accesses node zero first; the final RET contributes its
own first-use miss and updates the same cache. Warm reuse means hits after the
initial pass in this model, not a prewarmed hardware cache.

`truth.rs` independently interprets the literal bytes, emits all eleven heads,
ordered branch/read/value semantics and the saved RET successor. Its separate
closed-cycle read vector and scalar result do not follow fixture links or
reuse interpreted state. `model.rs` checks the case's complete read shape and
joins every simulated LRU hit with a separate per-set reuse-distance oracle,
then with the hand-derived totals above. A fixed model-only sequence
`0,4,0,8,4` distinguishes LRU from FIFO; the six native cycles alone do not.

These source modules supply no execution authority. Qualification must load
and authenticate the complete DSO and actual symbol, join actual native
register/memory observations to both exact read vectors, and retain the
existing full-state comparator, real CALL/RET, owner/report, deadline and child
cleanup checks. The model does not authenticate payload values or the saved
RET value; the exact read and scalar joins do. Two fixed state seeds over all
six cases require twelve original/instrumented pairs with zero trace/model
mismatches. No result is claimed merely by adding these files.

Operand reads reconstructed from single-step state are not hardware memory
events. Ptrace's own reads perturb hardware caches. These counts are not AMD
L2 misses, PMU measurements, calibrated durations, perf comparisons or evidence
of timing accuracy. Larger cache levels, physical indexing, stores, split-line
reads, callees, concurrency and hardware-event qualification remain outside
this finite model. Existing workloads and their failed campaigns remain
separate and unchanged.

Reproduce from a clean checkout using the full 40-character source revision and
canonical absolute paths for a new directory under `ignored/`, the stable Rust
toolchain, the process home and Cargo cache:

```sh
python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision "$CACHE_REVISION" --raw "$CACHE_RAW" \
  --toolchain "$CACHE_TOOLCHAIN" --user-home "$CACHE_USER_HOME" \
  --cargo-home "$CACHE_CARGO_HOME" --exact-work --cache-work
```

The recipe builds release artifacts with optimization level 3, assertions and
overflow checks, four jobs, and incremental compilation off. It requires the
existing ordinary and exact-work populations, all 58 validator controls, and
all twelve cache pairs. `--cache-work` without `--exact-work` fails before
creating output. The complete campaign can additionally enable all nine
pre-existing mode flags through `--reference-timing`; that optional reference
mode requires its documented AMD host qualification. The cache model itself
makes no hardware-cache qualification claim. Raw captures stay in `ignored/`;
`cache-state-pairs.csv` and the recipe receipt carry the complete model hit bits,
revision, artifact hashes, commands and closed child outcomes. Parser controls
are reproducible with `python3 -B tools/rapid-profiler/cache-work/test_recipe.py`
and `python3 -B tools/rapid-profiler/reference-work/test_recipe.py`.
