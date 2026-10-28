# Exact linked-memory work and cache-model qualification

Six normally loaded linked-memory cases now pass the ordinary profiler's real
publication, CALL/RET and full-state oracle. Across two fixed state seeds, all
12 original/installed pairs completed: 24 children, **3,564 state comparisons**,
3,432 original instructions, 672 conditional branches and 660 taken branches.
The exact original trace contains 1,356 input qword reads and 12 actual RET
reads. All 1,368 per-read model outcomes agree: **1,040 hits and 328 misses**,
with zero state, trace or model mismatches. This supports claim 4.

The declared demand-read model has 64-byte lines, four sets, two ways and true
LRU, initially invalid for each invocation. It uses actual full-width virtual
addresses and includes count, payload/link and RET operands. Every operand is
authenticated against native registers/memory, literal instruction truth and
an independent closed cycle before modeling; LRU and a separate reuse-distance
oracle must agree at every event. All six cases are dependent linked walks.
These are model results, not hardware-cache misses, PMU observations, latency,
timing accuracy or throughput measurements. Ptrace perturbs hardware caches.

Exact native revision: `ee535389b414118681651fca1fca0b0dc11d1c58`.
Hardware: AMD EPYC Zen 5 dev host, family 26/model 17/stepping 0. Rust 1.97.1
release optimization 3, assertions and overflow checks enabled. The recorded
campaign reserved four CPUs with cpuset-alloc; this does not claim exclusive
host execution. All 39 recipe stages passed, including all 35 inherited stages
and the complete 58-test validator target. All stage helpers proved ECHILD;
all parents exited normally with zero rescues. The original 15-second pair
deadline and continuous 20,000-step child budget remain unchanged.

`cache-state-pairs.csv` is the complete numerical export, including every model
hit bit, actual step counts, seed/case identity and scalar result. `receipt.json`
records the exact command, artifact hashes, model, numerical totals and closure
receipts. Its separate parser controls ran on precommit working source; the
recorded input hashes match this native revision. No native success is inferred
from those parser controls. Earlier failed campaigns retain their original
status. Full register/memory snapshots and process logs stay under `ignored/`.

Reproduce from the exact revision with canonical absolute paths and a fresh
directory under `ignored/`:

```sh
python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision ee535389b414118681651fca1fca0b0dc11d1c58 \
  --raw "$CACHE_RAW" --toolchain "$CACHE_TOOLCHAIN" \
  --user-home "$CACHE_USER_HOME" --cargo-home "$CACHE_CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --streamed-epochs --stream-history --optional-frontend \
  --optional-backoff-control --reference-timing --cache-work
```

The receipt adds the allocator wrapper used for this run. The reference mode
retains its documented AMD qualification requirement. The cache-only recipe
and model limits are documented in `tools/rapid-profiler/cache-work/README.md`.
Hardware-event qualification, broader workloads, statistical/perf comparisons
and remaining A5 exit gates remain open.

All seven final gates passed at the same source revision: formatting, strict
workspace Clippy, all-target/all-feature check, default-parallel workspace
**2,720 passed / 0 failed / 11 ignored**, serial launch **1,039 / 0 / 0**, three
staged allocation checks and 36 prefixed-pun checks. The workspace retained all
316 available CPUs and default test threading; only serial launch explicitly
uses one test thread. `gates.json` records exact commands, limits and normal
zero-rescue closures. Its grouping excludes five nested summaries from the
workspace total. Gate wall durations are operational, not performance results.
