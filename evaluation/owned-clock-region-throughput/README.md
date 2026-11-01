# Owned two-backedge clock throughput

Draft measurement protocol; results are pending. The proposed source is
`0c96d5770e0da3c58a2988ddd92f645e72ba70da`. The final report must identify the
actual release build, bounded command, CPU assignment and closed results.
This document does not report a benchmark execution.

The fixed 36-byte nested-loop function returns 12. Each call encounters the two
backedge sites 15 times and takes 11 backedges. The instrumented arms use the
same verified whole-region relocation with two clock gates. The three arms are:

- **Native:** ordinary indirect calls to the original body, with no clock guard.
- **Counter:** one shared clock lease per batch and one call guard per call.
- **Stop q64:** the same lease and guards, plus a real worker/controller handoff
  after every 64 taken backedges. There is no artificial parked delay.

Each batch makes 2,048 calls: 30,720 encounters, 22,528 taken backedges and checksum
24,576. Stop performs exactly 352 handoffs: 288 at the inner site and 64 at the
outer site. Every handoff authenticates the site, count, managed control, PID and
TID, preserves the saved 18-word context and full clock canary, and refills only
the remaining quantum. The lease has a finite 30,720-encounter work obligation.

Each cohort process first runs three untimed qualification batches and two fresh
child controls that submit actual wrong-site or wrong-count replies. Both must
produce the exact rejection witness before refill, then exit and be reaped as
required. Each arm then runs three warmup and 64 measured batches. The CSV retains
all 204 rows: 3 qualification, 9 warmup and 192 measured. Rejection children are
controls, not timing samples. A failure or incomplete process remains failed;
there is no retry, replacement cohort or discarded outlier.

The worker timer starts after a bounded Ready/Go exchange. Worker affinity,
TLS setup and any clock lease acquisition/reset are complete; thread creation has returned
and the controller counters are initialized. Timing includes indirect calls,
per-call guards, checksum bookkeeping, callback checks and real controller
handoffs/scheduling. Mapping, startup, lease acquisition, final verification,
thread join and CSV writing are outside timing. Both CPUs are disjoint and
externally reserved. The existing two-second handoff deadlines remain enforced.

The planned campaign uses 12 independent cohort processes, sequentially, with
all six arm orders appearing twice and shuffled with recorded seed `20261101`.
The release binary accepts `region-bench ORDER NEW_OUTPUT`, where `ORDER` is a
comma-separated permutation of `native,counter,stop` and the output directory
must be fresh. The published invocation must retain the process owner, exact
release/source pins and cleanup checks. Each cohort is bounded by 60 CPU seconds,
90 wall seconds, 1 MiB per-file and capture limits, and a zero core-file limit.
Aggregate CPU reservation must stay within 12 CPUs.

Only a complete, successful 12-process cohort supports statistics. Within each
process, sum the 64 measured durations per arm and report nanoseconds per call.
Compute paired Counter/native and Stop/native ratios from those process totals;
report geometric mean ratios with 95% Student-t intervals on their logarithms
(11 degrees of freedom). Batches are not independent-process samples. Retain
all warmup and measured rows, including outliers and failed outcomes.

This tiny fixture includes substantial per-call admission and callback validation
work. Its results cannot isolate gate cost or establish general application,
production publisher or full machine-state-after-callback performance. The
existing region correctness oracle remains a separate prerequisite.
