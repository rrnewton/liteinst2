This opt-in benchmark measures the public generic LiveJumpPatch bind/apply/revert
path. It adds no production API and runs no Hermit Tool, RapidProbe callback,
context-save scaffold or counter in the function. The two fixed cohorts contain
256 seeded-random sites each: aligned AtomicWord at offset 16, and GuardedSplit
at offset 60 on a checked 64-byte cache line. The 3000-TSC-tick staleness budget is
the existing stress test's configured empirical policy. These measurements do
not prove architectural instruction-fetch coherence or a remote fetch ACK.

Run only inside an externally bounded, exclusive benchmark recipe. For example,
after choosing an absolute output path that does not exist (its parent must
exist):

```bash
LITEINST_PATCH_BENCH_OUTPUT=/absolute/new-output-directory \
LITEINST_PATCH_BENCH_TRIALS=100 \
LITEINST_PATCH_BENCH_THROUGHPUT_CALLS=10000 \
LITEINST_PATCH_BENCH_THROUGHPUT_REPEATS=2 \
LITEINST_PATCH_BENCH_WALL_SECONDS=60 \
cargo test --release --test stress \
  patch_latency::patch_activation_latency_benchmark -- --exact --ignored --nocapture
```

For measurements, build once, retain the compiler/build command and the exact
stress executable SHA256, then run that executable with the same exact test
selector; avoid rebuilding between cohorts. The existing run_isolated boundary
executes the ignored body in a child and accepts only its authenticated exit 102.
The normal test selection never runs this ignored benchmark. The two small
ordinary helper tests are patch_latency::nearest_rank_keeps_tail_and_handles_empty
and patch_latency::window_classifier_matches_every_offset_in_small_envelopes.

All environment names start with LITEINST_PATCH_BENCH_. OUTPUT is required.
TRIALS defaults to 20000 per cohort (range 1..100000); SEED is a nonzero decimal or
0x-prefixed u64 (default 0xd1b54a32d192ed03). CALL_CAPACITY defaults to 4000000 raw
samples per cohort, maximum 16000000, and must hold at least TRIALS*33 samples.
MAX_CALLS_PER_TRIAL defaults to 4096 (range 33..65536). THROUGHPUT_CALLS defaults to
1000000 per batch (range 1..10000000), THROUGHPUT_REPEATS to 5 (range 1..32), and
WALL_SECONDS to 180 (range 1..900). No invalid value is clamped. The measurement
deadline is shared by both cohorts; the isolated parent grants 60 additional
seconds for evidence writing and cleanup. The external recipe must bound CPU,
memory, pids, wall time and disk separately. No host-global configuration changes
are made. Set both RUNNER_CPU and PATCHER_CPU to allowed CPU IDs, or leave both
unset for checked selection of distinct physical cores within the initial mask.

Each process-lifetime RX/RW dual mapping contains disjoint 128-byte slots.
The indirect entry is ENDBR64; mov eax,1; a single five-byte NOP; ret. The patch
replaces the NOP with a direct jump to ENDBR64; direct jmp back to that same ret.
Both paths return 1 with the same call/return stack. Planning and concurrent bind
finish before any timing. One pinned patcher owns all patch objects. A trial
selects a single seeded-random site; runner and patcher use that same site for
16 pre-calls, the publication window, and 16 post-calls. Command/ready/GO/complete/
quiescence/reset atomics occupy separate cache lines. Revert occurs only after
all runner calls return, outside the measured samples. Exact RX bytes are read
after apply and after revert, outside the timestamps, including throughput state
commands. Any observed-byte mismatch refuses the cohort. Result1 alone would
not prove that the redirect was installed.

The timer uses compiler fences plus inline asm with a compiler memory clobber.
A preliminary RDTSCP obtains TSC_AUX outside the interval; the start is
LFENCE/RDTSC/LFENCE. Calls end with RDTSCP/LFENCE; apply ends with
MFENCE/RDTSCP/LFENCE, including the complete real apply API, its waits and store
completion. The post-RDTSC LFENCE prevents later payload execution before the
start read. Intel execution-serializing LFENCE semantics are assumed; AMD must
advertise CPUID 0x80000021:EAX bit2, LFENCEAlwaysSerializing. Other vendors or missing
TSC/RDTSCP/invariant-TSC/64-byte geometry are refused. Singleton sched affinity,
actual CPU placement and TSC_AUX are checked. Endpoint AUX checks do not prove
the absence of a hypothetical migrate-away-and-back event; the singleton Linux
affinity is part of the contract. Every call uses preallocated storage, with no
allocation, logging, formatting or harness counter between its timestamps.

Before and after a cohort, 32 request/ACK exchanges retain all four raw clock
endpoints. Causality bounds theta=patcherTSC-runnerTSC to
[patcherLast-runnerLast, patcherFirst-runnerFirst]; no half-RTT estimate is used.
The 32 bounds must have a nonempty intersection in each phase, and the before/
after intersections must overlap. Classification uses their wider envelope.
It remains conditional on equal constant TSC rates and no intervening offset
excursion outside that envelope. Endpoint calibration cannot prove that
assumption. A call is pre only if its whole timestamp envelope precedes every
possible apply start, post only if it follows every possible apply end, and
during-envelope-overlap only if it intersects apply for every possible offset.
Boundary ambiguity is retained as uncertain. These labels describe timestamp
envelopes, not when an instruction was fetched or which instruction caused a
stall. Empty-overlap trials are counted explicitly, including the possibility
that AtomicWord has no unambiguous during samples.

Each raw call and publication endpoint, actual return value, migration/error,
byte observation and actual activation guard-trap count is retained. Capacity
or wall-budget exhaustion refuses the measurement and retains partial counts;
it never silently stops sampling and reports success. Any API, checksum, byte,
clock, affinity, migration, identity or cleanup error makes the cohort INVALID.
Statistics from an invalid cohort are explicitly marked invalid. No outlier,
max or uncertainty sample is trimmed. Quantiles use exact nearest rank
ceil(q*N), with N and NA for empty sets. The empty call and empty apply brackets
are measured separately 4096 times each using the same fences. They are never
subtracted from distribution tails. TSC ticks are primary, not core cycles;
CPUID leaf 0x15 crystal/ratio supplies the frequency when complete, otherwise five
CLOCK_MONOTONIC_RAW timestamp-bracket calibrations retain a frequency range.
Nanosecond conversions are approximate and retain that range.

Throughput uses separate batches without per-call timestamps. Each repeat
selects one function and measures both its unpatched and patched states at
that same site, with apply/revert outside the batch and the runner quiescent
during those transitions. The timed loop includes the indirect call, local
checksum, branchless bad-value OR and loop overhead. It has no atomic per call.
The bad-value OR also includes 16 untimed warmup calls. Both states require
checksum==batch calls and all values 1. Five default repeats of one million
calls each are reported separately using raw TSC and CLOCK_MONOTONIC_RAW
brackets; this is not a Tool-work or end-to-end Hermit throughput claim.

The output root contains metadata.tsv, frequency-calibration.tsv, and status.tsv.
Each cohort directory (atomic-word, guarded-split) contains metadata.tsv,
calibration.tsv, calls.tsv, apply.tsv, controls.tsv, state-changes.tsv,
throughput.tsv, summary.tsv and diagnostics.tsv. fixture-original.bin and
fixture-sites.tsv retain the exact emitted image, all 256 addresses, original/
replacement words, ENDBR64 entries and bare trampoline bytes. fixture-final.bin
is captured only after the sole writer joins, and a valid cohort requires it
to match the complete original image. Raw files are lossless TSV, with headers
and decimal timestamps; byte images are lowercase hex or binary. Summary
columns are metric, cohort_valid, N, p50_ticks, p99_ticks, p99_9_ticks, max_ticks
and approximate max-ns bounds. Diagnostics retain empty-overlap/uncertainty,
partial counts and errors. Top status rows must be atomic-word VALID,
guarded-split VALID and overall VALID; cohort metadata/diagnostics also contain
status VALID. INVALID causes test failure. Missing files or an incomplete status
are never success. All writers are flushed/dropped before the isolated _exit.
An unexpected fatal signal, initialization panic or external kill can leave
incomplete output; the external receipt must retain that failure, not credit it.

The owning recipe must additionally capture the exact command/environment,
compiler and flags, executable hash, CPU model/topology and mitigations, kernel,
CPU governor/frequency context and load. Raw output is intended for independent
review; the benchmark source and a successful exit do not establish a measured
latency bound without those actual artifacts and a valid measurement receipt.
