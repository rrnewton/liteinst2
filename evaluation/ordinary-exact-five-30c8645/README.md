# Five fixed qualifications with reserved CPUs

The prospectively fixed campaign at
`30c86454037e385f669b4b88d59cd5c2e37d81d8` completed all five attempts:
**PASS, FAILED, FAILED, PASS, PASS**. It did not fully qualify. The 2 ms arm
deadline remains unchanged, and no additional attempt was substituted.

| Attempt | Result | Failing stage | Seconds | Load average, 1 minute, before → after |
| ---: | --- | --- | ---: | ---: |
| 1 | PASS | — | 170.984 | 26.95 → 57.07 |
| 2 | FAILED | Exact37 short, K=10 | 131.056 | 57.07 → 122.96 |
| 3 | FAILED | Two-worker full session, K=1000 | 135.424 | 122.96 → 145.73 |
| 4 | PASS | — | 213.935 | 145.73 → 88.98 |
| 5 | PASS | — | 171.296 | 88.98 → 39.91 |

Runs began at 17:00:47 and ended at 17:14:30 Eastern on 2026-10-28, within
the requested window. One cooperative reservation used CPUs 19/44/74/183,
enforced through hard AllowedCPUs for the process tree: controller 19, workers
44/74, and producer 183. The single-worker prerequisite uses worker 44.
The allocator's emitted reservation matches every campaign affinity snapshot.
No other root build, test or benchmark ran during the campaign. The host was
not exclusive; load rose substantially. Loads are observations, not filters or
measurements of these four CPUs' utilization.

Both failures report `clock arm-completed: Deadline`, after the third and first
arm respectively. Their incomplete-arm diagnostic brackets are 2,193,324 and
2,302,128 ns. Corresponding thread-accounting deltas show 152 and 154 minor
faults, and zero voluntary/involuntary context switches. These brackets are
neither exact arm lateness nor exact off-CPU time; they do not establish the
cause of the failures. Successful sessions do not emit a maximum lateness
measurement. Reserved CPUs alone did not make this implementation meet the
strict gate on all five attempts.

All five owners closed normally with zero rescue reaps; the outer owner took
825.109 seconds and returned 1 because two attempts failed. Partial producer
diagnostics are retained privately and hashed after closure; the failed
producer paths did not publish their usual finalized stream digests. No partial
population is promoted to a successful cohort.

The three passing attempts completed 24 Exact37 cohorts and 1,152 calls in
total. Of the fixed 40 Exact37 cohort slots, one failed and 15 were UNRUN.
`cohorts.csv` preserves all 100 slots, including the mandatory single-worker
and earlier two-worker cohorts. `stages.csv` has 445 planned stage rows:
417 PASS, two FAILED and 26 UNRUN. These are stage outcomes, not a count of
independent native cases. The CSV retains both worker rows and their combined
row; aggregate only `worker=combined`. All six original-work quantities and
all admitted/retained/dropped/unsampled partitions remain visible.

The signed instruction error is retained-minus-population mean original-body
instructions, `(S*N - P*R)/(R*N)`. It includes the original RET and excludes
instrumentation/caller instructions. It is not a duration or PMU estimate.
In all three completed late-long cohorts at K=10, the ten retained calls
average 11 instructions while the complete 48-call population averages 231.5:
an error of -220.5 instructions per call. Alternating cohorts have errors
-37.8, 0 and -37.8 across the three passing attempts. These finite observations
demonstrate selection bias; they do not estimate a broader trial distribution.
Native prerequisite repetitions do not enlarge the distinct fixed case set.
The [four earlier failed campaigns](../ordinary-exact-progress-20261028/README.md)
remain failed.

Reproduce on Linux x86-64 with Rust 1.97.1, GCC 11.5.0, Python 3.12.15 and the
recorded allocator revision/source hashes:

```sh
python3 -B "$AGENT_UTILS/py/dagrun/cpuset_allocator.py" run \
  --cores 4 --sample-s 1 --tag li2core-normal-exact-five-30c8645 -- \
  python3 -B evaluation/ordinary-exact-campaign/run.py \
  --revision 30c86454037e385f669b4b88d59cd5c2e37d81d8 \
  --raw "$PWD/ignored/NEW_FIXED_FIVE_RUN" --toolchain "$TOOLCHAIN" \
  --user-home "$HOME" --cargo-home "$CARGO_HOME"
```

The runner freezes five whole `verify_normal_session_two.py --exact-work`
commands before attempt 1. Each has a 1,200-second / 8 MiB outer bound; the
recorded root owner had a 7,200-second bound. The recipe uses release
optimization level 3, no debug info, and enabled assertions/overflow checks.
It preserves 520 epochs, the 10 ms period, 2 ms lateness limit, original
shutdown deadline, and all inherited native/control checks. Normal failures
continue through the fixed attempt count; loss of source/affinity authority
or unproven cleanup aborts with remaining slots UNRUN. A new reproduction is
a separate fixed campaign and must report every outcome.

The seven pre-campaign checks passed at the measured source revision:
formatting, strict Clippy, all-target/all-feature check, default-parallel
workspace (3,056 top-level passes, zero failed, 36 ignored, plus two custom
harnesses), serial launch (1,039), staged allocation (3), and prefixed pun (36).
The workspace took 326.727 seconds; serial launch took 124.745 seconds.
All seven historical admission/allocation regression names passed under the
default 316-CPU harness. The workspace count excludes nested child summaries
while retaining both positive and compile-fail rustdoc batches. The preceding
collector report's 3,061 count included five nested summaries twice and is
corrected to 3,056 without changing any raw receipt or log.

After merging main `abab69594a19140fe5e6f78492da883803dfbe4c`, all seven
checks passed again at `55f15f6183a29c78b1d7a8872e69721c834420f5`:
workspace 3,056 top-level passes in 337.401 seconds, serial launch 1,039 in
125.694 seconds, staged allocation 3 and prefixed pun 36. All seven historical
regression names passed. See `merge-checks.json` and `merge-checks.csv`.
All 507 campaign source inputs remain byte-identical. This merged-tree check
does not rerun or relabel the five-attempt campaign.

This supports claim 4 through a reproducible negative qualification result
and complete finite work accounting. It supplies no accuracy, throughput,
matched-perf, arbitrary-interleaving or full-A5 claim. Hardware is the AMD EPYC
Zen 5 dev host. Raw logs, source manifests and captures remain in `ignored/`;
tracked files contain compact numbers and exact receipts only.
