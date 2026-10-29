# Epoch storage reuse: reserved-CPU qualification

The ordinary consumers now reuse exactly E prepared epoch-storage banks, with
fresh generation IDs and exclusive ownership of both Arc layers before reuse.
This removes recurring admission-vector allocation. Resetting storage, copying
reports, locks, output work and two new Arc allocations remain within the
original deadline. The qualification now requires all fourteen session controls,
including four new storage/custody controls, under the same exact inventory check.

At source revision `4ff42f19a839352bc159101b977cbf4280741504`, the five fixed
release qualifications returned **FAILED, PASS, PASS, FAILED, PASS**. The
strict 2 ms deadline therefore remains unmet. There was no sixth attempt.

| Attempt | Outcome | Failure | Closed duration (s) |
|---|---|---|---:|
| 1 | FAILED | Exact37 late-long, K=10: polling deadline after 491 arms | 162.606435 |
| 2 | PASS | — | 170.319602 |
| 3 | PASS | — | 170.219199 |
| 4 | FAILED | Single-worker full, K=10: polling deadline after 440 arms | 74.516169 |
| 5 | PASS | — | 171.699139 |

The campaign ran on an AMD EPYC Zen 5 dev host from 22:21:17 to 22:33:47 UTC
on 2026-10-28. cpuset-alloc reserved CPUs 19/55/64/80 and recorded hard
AllowedCPUs for the whole process tree: controller 19, single worker 55,
two workers 55/64, producer 80. One-minute load observations ranged from
23.16 to 38.50. No other local build or benchmark ran concurrently.
Reservation is cooperative and does not establish host-wide isolation.
Outer duration was 751.664 s; every attempt closed normally with complete
cleanup and zero rescued descendants. These durations are operational costs,
not application-throughput comparisons.

Both failures occurred during polling, after a requested 1 ms wait was observed
as 9,605,403 ns or 11,459,548 ns. Each last-iteration accounting bracket recorded
one involuntary context switch and zero minor/major faults. These are observations
from closed partial streams without final producer stream hashes; the bracket
is wider than the wait. They do not identify exact off-CPU time or prove an
exclusive cause. No numeric maximum lateness is available for successful sessions.
The earlier arm-completion failures remain failures; these separate campaigns
do not establish a causal speedup from storage reuse.

All forty planned Exact37 cohorts remain visible: thirty passed, one failed and
nine were unrun. The thirty passing cohorts cover 1,440 calls, including six
cohorts completed before attempt 1 failed and twenty-four from the three whole
passes. Their numerical work is retained without promoting attempt 1 to a pass.
The complete cohort table also retains all single/two-worker legacy outcomes.
Of 445 planned stage rows, 410 report PASS, two FAILED and 33 UNRUN; this is not
445 completed stage receipts. Attempt 4's nested observations lack a successful
ancestor result-hash join and are labelled with their narrower custody.

Selection bias remains visible in the passing work. Each of the three complete
late-long K=10 cohorts retained ten short calls: mean 11 original instructions
against the population mean 231.5, a signed error of **−220.5 instructions/call**.
All four passing alternating K=10 cohorts have mean error −37.8. These are finite
original-body work observations, not hardware instruction counters, duration
accuracy, confidence intervals or a perf comparison. Failed/unrun cohorts have
no invented work or zero-error values. The full A5 accuracy and release gates
remain open.

The same source revision passed all seven full checks: 3,081 workspace tests,
zero failures and 36 ignored, plus two custom harnesses; 1,039 serial-launch
tests; three staged-allocation tests; 36 prefixed-pun tests; formatting; strict
workspace Clippy; and all-target/all-feature checking. The default-parallel
workspace retained all eight historical mapping/allocation cases. The preceding
[inventory-failure campaign](../ordinary-epoch-storage-50e5bd2/README.md) and
[earlier deadline/bias results](../ordinary-exact-five-30c8645/README.md) are
preserved. No previous failure is reclassified.

The compact observations are [attempts](attempts.csv), [failures](failures.csv),
[cohort statuses](cohorts.csv), [exact work](exact-work.csv), [checks](checks.csv)
and the [receipt](receipt.json). The receipt records exact revision, release
profile/binary/tool hashes, reservation, commands and custody limits. Raw logs
stay under ignored/. To reproduce this fixed population at the exact revision:

```sh
python3 -B "$AGENT_UTILS/py/dagrun/cpuset_allocator.py" run \
  --cores 4 --sample-s 1 --tag li2core-normal-exact-five-4ff42f1 -- \
  python3 -B evaluation/ordinary-exact-campaign/run.py \
  --revision 4ff42f19a839352bc159101b977cbf4280741504 \
  --raw "$REPO/ignored/NEW_RUN" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

Use a fresh output directory and the recorded tools. Each whole qualification
retains every prerequisite and workload, 520 arms, a 10 ms period, the 2 ms
lateness gate, and its original shutdown/cleanup bounds. The fixed runner keeps
normally closed failures and runs all five attempts without retrying them.
