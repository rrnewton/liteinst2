# Nested-call validation and fixed-five session qualification

Exact source: `73157d117ee3eca82512f9f6f8c3c24be1ff5251`, including main
`469fa27fa400e7d0617d3c04706f88af72cf8834`. Hardware: AMD EPYC Zen 5 dev host;
Rust 1.97.1. Claim 4 validation only. A5 remains open; no performance or
application-deadline claim follows from these command durations.

The implementation caches immutable call-pair encoding within an invocation,
retaining all 512 volatile journal reads and the full zero-tail validation.
It also adds a session recipe with five fixed qualifications, 64 installed
cases per qualification, original-address reference results, authenticated
native prerequisites and public launch/freeze commands. Its 2 ms arm,
10 ms period and 2 s shutdown gates are unchanged.

The one native prerequisite attempt **FAILED** its unchanged 510-second wall
limit (510.067 s). The preceding 36 stages passed 356 controls, with one existing
ignore. Native execution emitted 187 of 192 ordered pair records: 17,243
comparisons, 748 target CALLs and RETs, 374 outer RETs and 374 normal reaps.
Every record remains **OBSERVED_UNQUALIFIED**; five slots have no accepted
result, including interrupted work. Two children required rescue reaping.
Candidate steps ranged from 15,967 to 17,537. No replacement attempt occurred.
**All five session qualifications remain UNRUN** because their required native
prerequisite failed. There is no accepted native manifest or session result.

CPUs 6/139/162 were hard-reserved; native tracer and tracees used 139. Owner
load was 55.83/54.67/63.02 before and 24.02/31.69/47.03 after; native-stage load
was 50.44/52.39/60.61 to 23.50/31.72/47.13. Root ownership closed normally with
no rescue. The post-closure audit authenticated 322 retained files (59,026,816
bytes) and 1,171 source pins. Raw logs remain ignored. The three CSV files retain
all 192 pair slots, 37 stages and seven workspace checks; receipt.json records
commands, tools, geometry, reservations, limits and exact evidence hashes.

The workspace suite separately **FAILED** its unchanged 360-second limit
(360.067 s; one rescue reap). Its completed terminal observations contained
2,146 passes, zero assertion failures and one ignore. These are a prefix and
may include nested summaries; they are not suite success. Formatting, strict
workspace/all-target/all-feature Clippy and check passed. The three checks the
fail-stop run never started then ran once: serial launch 1,039 passes, staged
allocation three, prefixed pun 36. Each closed normally without rescue. Both
phases reserved eight CPUs. The first did not record load; null is intentional.
No full-suite or 316-thread pass is claimed.

Development evidence retains all 20 invocations, including three failures:
wrong package name, a test array type inference error, and a runner inheritance
error (16 of 17 controls passed). Corrections preceded their successors. Final
checks include 18 runtime tests, 57 session Python controls, four C controls,
two freezer refusal controls, four launcher controls, CLI checks and source
freeze. The launcher controls exercise actual guards and the final deadline
expression using fabricated fixtures, not native or lifecycle evidence.
`development.json` records exact commands and base-plus-changed-source hashes;
`development.csv` records every outcome, including failed development attempts.

To reproduce, check out the exact source revision and use the public
[native protocol](../ordinary-call-pair-native/ROOT_PROTOCOL.md). Its tracked
`freeze.py` records explicit local tool, home and allocator paths, then `launch.py`
runs one bounded attempt. The allocator revision is
`d0c2867be75b495eb64239e664c6306af9747783`. Release optimization is 3, with
assertions/overflow checks enabled and four compiler jobs. Keep the 20,000-step,
15-second pair, 480-CPU/510-wall cohort and 1,200-second outer limits. Failed
attempt destinations are immutable. The [session protocol](../ordinary-call-pair-session/ROOT_PROTOCOL.md)
requires a fully qualified native result at that same source revision before
its fixed five-run campaign may start.

Workspace reproduction uses `evaluation/admission/check_exec_identity.py
--checks-only` and the recorded arguments. The existing
[tail generator](../ordinary-call-pair-native-cfc8d76/reproduce_tail.py) reconstructs
the exact three-check script used here. Those commands run only when the
fail-stop runner has left them UNRUN; their success cannot replace the timeout.
