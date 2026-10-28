# Whole-invocation raw counter acquisition

Twelve original calls to six loaded linked-memory cases completed with fresh
per-thread perf events, matching IDs, positive full running time and successful
scalar, return-stack and complete-input checks. All **84 syscall operations**
succeeded. This adds usable one-shot counter acquisition with retained failures
and supports claim 4. It is an availability/read-consistency result.

Exact revision: `78c5ff8ab0e27555ba6e0d3d091db9cc0fc6e639`.
Hardware: AMD EPYC Zen 5 dev host, AMD family 26/model 17/stepping 0.
Rust 1.97.1 release optimization 3, assertions and overflow checks enabled.
The campaign used a shared four-CPU reservation; each probe observed singleton
thread affinity. This does not establish exclusive host execution.

The requested raw event is `0x0964`. Counts ranged from **992 to 1,931**
(sum **18,539**), unscaled. The enabled window includes the whole original API,
including owner checks and dispatch. It is not a callee-body measurement.
Linux's Zen 5 table names the event as combined instruction/data core-to-L2
request misses excluding L2 prefetch. The available AMD manual covers models
00h–0Fh; exact model-11h semantics and errata remain unqualified. These numbers
do not establish cache-model equality, event accuracy, timing accuracy or
performance. The source README records the event-document references.

All **40 release recipe stages passed**, including all 39 inherited stages.
The separate cache oracle again completed 12 original/installed pairs,
24 children and 3,564 state comparisons, plus all 1,368 model events
(1,040 hits / 328 misses). Those model/state results are separate from these
untraced PMU calls. Every stage helper proved ECHILD, every parent exited
normally, and no rescue cleanup occurred. No stage or bound was relaxed.

The three CSVs retain the complete fixed population, raw attributes/endpoints
and every syscall result. `receipt.json` records exact commands, revision,
hardware, artifacts, numerical totals and process closure. Eight parser controls
passed on precommit working source whose exact parser/control bytes match this
revision. Sixteen scripted acquisition controls passed separately; these are
protocol tests, not native PMU observations. Raw logs and captures remain ignored.

Reproduce with canonical paths and a fresh directory under `ignored/`:

```sh
python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision 78c5ff8ab0e27555ba6e0d3d091db9cc0fc6e639 \
  --raw "$PROBE_RAW" --toolchain "$PROBE_TOOLCHAIN" \
  --user-home "$PROBE_USER_HOME" --cargo-home "$PROBE_CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --streamed-epochs --stream-history --optional-frontend \
  --optional-backoff-control --reference-timing --cache-work --counter-probe
```

The receipt includes the allocator wrapper used here. A failed probe remains
a failed required stage and leaves the remaining population explicitly unrun;
a parseable refusal cannot count as success. Earlier failed campaigns retain
their original status. Hardware qualification, body-positioned counters,
statistical/perf comparisons and the remaining A5 exit gates stay open.

All seven final gates passed at the same source revision: formatting, strict
workspace Clippy, all-target/all-feature check, default-parallel workspace
**2,741 passed / 0 failed / 11 ignored**, serial launch **1,039 / 0 / 0**,
three staged allocation checks and 36 prefixed-pun checks. Workspace affinity
retained all 316 CPUs with no test-thread override. Its total excludes five
nested summaries; the increase includes 16 new acquisition tests and five
existing cache-truth tests instantiated by the new driver module. `gates.json`
records exact commands and normal zero-rescue closures. Wall durations are
operational, not performance measurements.
