# Bounded epoch storage: fixed five-attempt qualification

Source revision: `50e5bd2b32ce4c0e0a4e13216f098b506f8b05f9`.
The ordinary one- and two-caller consumers now prepare exactly E fixed-configuration
storage banks before activation. Reclamation requires exclusive ownership of both
Arc layers; each staged incarnation gets fresh shells and a fresh generation ID.
This removes recurring admission-vector allocation. Clearing, report copying,
locks, output work and two Arc allocations remain inside the original deadline.

All five whole qualifications **failed before the timed sessions**. Each stopped
at the exact single-session test inventory: the executable listed the ten old
required controls plus four new storage controls, while the recipe still required
only ten. No old required control was missing. The follow-up must require all
four new controls and retain exact inventory equality. This is a validation
integration defect, not a measured deadline miss or a successful latency result.
All 100 session cohort slots, including all 40 Exact37 slots, remain UNRUN.
There is no work-error or throughput result from this campaign.

The campaign ran on an AMD EPYC Zen 5 dev host, with allocator-reserved CPUs
1/6/25/40 (controller 1, single worker 6, two workers 6/25, producer 40).
The allocator recorded hard AllowedCPUs for the complete tree. The five attempts
ran from 22:01:17 to 22:07:53 UTC on 2026-10-28; outer duration was 397.076 s.
Observed one-minute load averages ranged from 27.32 to 32.15. Reservation is
cooperative and does not guarantee host-wide isolation. Every attempt closed
normally with exit 1, complete cleanup and zero rescued descendants.

The [attempt table](attempts.csv) retains all five durations and before/after
load averages. The [cohort table](cohorts.csv) retains every known UNRUN slot.
The [receipt](receipt.json) records revision, commands, source/tool digests,
reservation and failed delegation custody. A failed parent did not publish a
successful child-result hash; those nested observations are explicitly labelled
as root-hashed partial evidence. No such observation is promoted to a successful
whole qualification. Missing top-level setup metadata stays unavailable.

The preceding full checks at the same revision passed: 3,081 workspace tests,
zero failures, 36 ignored, and two custom harnesses; 1,039 serial-launch tests;
three staged-allocation tests; and 36 prefixed-pun tests. Formatting, strict
workspace Clippy and all-target/all-feature checking passed too.
[Check durations](checks.csv) are operational wall times, not performance numbers.
The eight historical mapping/allocation cases each passed in the default-parallel
workspace run. Twenty-five added storage/custody controls passed in the workspace.

Earlier [fixed-five results](../ordinary-exact-five-30c8645/README.md), including
both 2 ms failures and the selection-bias results, remain unchanged. Two
pre-commit Clippy failures and one exact-head formatting failure are retained in
this receipt's development history. No accuracy, perf comparison, causal speedup,
whole-session native-state or full-A5 claim follows from this change.

To reproduce the five-attempt population, check out the exact revision and run:

```sh
python3 -B "$AGENT_UTILS/py/dagrun/cpuset_allocator.py" run \
  --cores 4 --sample-s 1 --tag li2core-normal-exact-five-50e5bd2 -- \
  python3 -B evaluation/ordinary-exact-campaign/run.py \
  --revision 50e5bd2b32ce4c0e0a4e13216f098b506f8b05f9 \
  --raw "$REPO/ignored/NEW_RUN" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

Use a fresh output directory, the pinned toolchain, and no concurrent local
build or benchmark. Each attempt invokes the full release qualification with
520 arms, a 10 ms period and the unchanged 2 ms deadline. The fixed runner
retains normally closed failures and runs all five; it never retries a failed
attempt. Raw captures remain under ignored/; the public files contain summarized
numeric observations and hashes.
