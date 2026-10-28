# Fixed native caller/child profiling

A loaded two-function tree now records the original caller and child through
a real CALL and both real RETs. Each entry retains its own admitting epoch:
the root remains owned by A, the child by B, and rearming C cannot take either
completion. The child completes at its original caller continuation; the root
completes only after the outer return and full postflight. This A5 increment
supports claim 4; the general profiler remains incomplete.

Exact revision: `c2db96897b3a86cec7803a0b00a6f06a17b811aa`.
Hardware: AMD EPYC Zen 5 dev host, family 26/model 17/stepping 0.
Rust 1.97.1 release optimization 3, assertions and overflow checks enabled.
The campaign used a shared four-CPU reservation, without an exclusive-host
or performance claim.

All **44 release stages passed**: the 40 inherited stages and four new tree
stages. Four original/installed pairs across two seeds and two memory cases
completed **1,372 state comparisons**, **24 immediate physical CALL/RET
witnesses** and **eight outer returns**. Comparisons retain complete GPR,
flags, XSAVE, input and unmasked protected stack coverage. The candidate also
releases an unused prepared guard, then uses the same ID and first gate
sequence for its only real invocation. A separate native A/B/C control checks
both owners remain pending before their respective physical returns and joins
the actual completed invocation before accepting the root Report.

The negative control changes exactly the saved eight-byte child return word
after a witnessed original CALL. It refuses before resuming a restored
application instruction, exits normally with code 123, and is reaped with
ECHILD. Its runtime cause is **undifferentiated**; it receives no successful
return or decoded-cause credit. Every required stage and parent closed normally
with zero rescue cleanup. Both complete calibration runs passed 76 methods;
10 tree and 10 reference parser controls also passed.

The continuous software cache model observes all 528 original memory events:
392 hits, 136 misses and zero writebacks. Each fit case has three misses; each
conflict case has 65. The model starts cold once at root entry and includes
the original CALL store, all input reads and both RET reads. These are model
results, not hardware-cache measurements. Callback ticks remain uncalibrated.

The first native campaign, revision `5c629044bd1f9b4cbb8307097d5216042ff6b331`,
remains **FAILED**: all 40 prerequisites and tree build completed, but the
first candidate exhausted 20,000 steps before its gate. Its ownership and
negative stages were unrun. The corrected API performs complete preflight
before the controlled ready stop through an exclusive prepared-call guard,
inside the same 15-second deadline. Consumption rechecks caller, input,
counters and idle state. The continuous 20,000-step execution limit and full
comparator are unchanged; preparation no longer has instruction-step coverage.
The successful source is a separate result, not a relabelled failed attempt.

`pairs.csv` retains every positive pair and full model hit vector;
`refusal.csv` retains the negative result. `receipt.json` records exact command,
revision, hardware, release artifacts/tools, stage closure and failed lineage.
Raw logs and captures remain ignored. Reproduce with canonical tool paths and
a fresh raw directory under `ignored/`:

```sh
python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision c2db96897b3a86cec7803a0b00a6f06a17b811aa \
  --raw "$TREE_RAW" --toolchain "$TREE_TOOLCHAIN" \
  --user-home "$TREE_USER_HOME" --cargo-home "$TREE_CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --streamed-epochs --stream-history --optional-frontend \
  --optional-backoff-control --reference-timing --cache-work \
  --counter-probe --call-tree
```

The receipt includes the allocator wrapper used here. This closed depth-two
fixture does not qualify arbitrary nested/recursive calls, tail calls,
nonlocal exits, CET, foreign threads, unload/fork or real-application profiling.
Statistical accuracy, hardware-event calibration and matched performance
comparisons remain open A5 gates.

All seven final checks passed at the same source revision: formatting, strict
workspace Clippy, all-target/all-feature check, default workspace **2,824
passed / 0 failed / 12 ignored**, serial launch **1,039 / 0 / 0**, three staged
allocation tests and 36 prefixed-pun tests. The ignored tree ownership test ran
explicitly in the release campaign. Workspace affinity retained all 316 CPUs,
with four compiler jobs and no test-thread override. All successful check
closures were normal with zero rescue cleanup. Wall durations describe
validation operations, not performance.

The first workspace attempt remains **FAILED** at its unchanged 360-second
limit after 44.35 seconds of compilation; cleanup rescued four descendants.
No complete workspace total is credited to that attempt. One separate
warm-cache run completed in 342.658 seconds (compilation 0.04 seconds), using
the same command, limit, parallelism and test population. This qualifies the
warm run and does not establish cold-build completion within the limit.
`gates.json` retains both outcomes and exact commands. The final total counts
both independent rustdoc suites (two positive/compile-only and 36 compile-fail
checks) and excludes five nested child summaries. An initial private summary
misclassified the positive rustdoc suite as nested and was rejected; correcting
the counting rule changed no source, test or gate.
