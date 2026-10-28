# Independent bounded backoff

`frontend_native::backoff::prepare` consumes a sealed ordinary site and returns
an owned `Driver`, one attachment-only `Client`, an idempotent `StopHandle`, and
a bounded export receiver. The application runs the driver, native worker and
sink on its own threads and retains their actual `JoinHandle`s. The driver
owns no thread and cannot cancel an entered call or reclaim its input.

Use `Policy::ten_ms(K, epochs, call_limit)` with K10 or K1000. Attach the client
on the actual pinned worker with its readable stack and journal, then invoke
through the ordinary CALL/RET facade. Flush before a long idle period; finish
on that same worker. Consume exports concurrently, retaining an unsent item
on Full/disconnect. `StopHandle::request` requests cooperative stop; an
already-started arm may complete before acknowledgement. Keep the driver and
receivers alive through worker join on errors, then recover queued/pending
records and the separately qualified terminal history window. Report readiness,
queue acceptance and detach are not OS join or physical-RET proofs.

`Policy::ten_ms` retains immediate worker Full refusal by default. Explicit
`with_worker_backpressure()` enables bounded waiting only after a real return
and completed drain, while retaining the single unsent owned packet. The
worker checks controller failure and the original start + periods + 2 s cap
before sending and after every wait; no Full renews it. Normal cooperative
stop permits the final flush while the controller still drains. Controller
failure is published before its cleanup, and terminal failures keep the first
error and unsent packet. Controller-to-sink Full still refuses immediately.
The earlier controller shutdown deadline and actual thread joins are unchanged.
OS sleep/send scheduling is not a hard real-time transfer guarantee.

The unsafe ordinary readonly-leaf ABI, source/stack/input lifetimes,
no-reentry/signal/fork/nonlocal-exit/CET restrictions and normal termination
remain required. Keep source/generated code process-lived. K closes sampling,
not redirects, context/XSAVE, entry/RET callbacks or raw/journal bookkeeping.
This is useful independent rearming and bounded export, not cheap-off,
asynchronous preemption or an indefinite daemon.

## Reproduce the finite functional qualification

From a clean committed checkout, supply absolute existing toolchain/home paths
and a fresh directory under the checkout's `ignored` tree:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/backoff-work/verify.py \
  --revision "$REVISION" --raw "$REPO/ignored/backoff-run" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --worker-backpressure
```

Omit `--worker-backpressure` to preserve the existing immediate-refusal
`backoff-work` command, original terminal, parser and CSV grammar. The explicit
flag instead selects `backoff-work-wait`; only that mode emits and requires the
additional `worker_backpressure=bounded-wait` field. Both keep the same fixed
workload and all qualification predicates. An output marker alone cannot opt
in the parser or change the requested policy.

The wrapper first runs the unchanged `verify_ordinary_interval.py` with all six
prerequisite flags. All 27 existing stages, populations, comparators and child
bounds remain required. Its parent has a 900-second wall/1 MiB log bound and
owned-descendant cleanup. The clean exact revision, source/tool hashes and
actual release artifacts are authenticated before reuse. Cargo cache hits are
permitted and recorded; no rebuild is inferred. Release optimization is 3,
debug info 0, with assertions and overflow checks enabled.

Two fresh children then run the existing C-checksum client, K10 and K1000,
each with 520 ten-millisecond periods and a 100000-call ceiling. The opt-in
`backoff-work-wait` command selects `with_worker_backpressure()`; its terminal,
CSV and receipt require `worker_backpressure=bounded-wait`. Waiting may change
the actual call population, which is still measured without an offered-work or
performance claim. Earlier immediate-refusal attempts stay FAILED.
The application uses its existing independent 23-call bursts, 250 us spacing
and 3 ms idle gaps. Calls are measured, not tied to epoch boundaries. Parent
and build use four allowed CPUs; the native worker, controller, sink and joining
main thread each pin one distinct CPU within that set. The sink uses a fixed
8 KiB buffer and compact Debug formatting with all fields/array elements. It
counts underlying file writes and explicitly flushes before sync.

Each new child has 20 CPU seconds, 30 wall seconds and a 64 MiB file limit,
inside a 55-second/1 MiB parent. These bounds are fixed before observations;
there is no workload retry, deadline extension or shortened-population fallback.
The named opt-in worker transport may retry Full only within its original cap. The
helper requires ECHILD, unchanged request/helper inputs, authenticated streams,
no unexpected descendants/cleanup events, and zero rescued descendants in the
parent. The wrapper separately authenticates subject/source/tool contents.

`COMPLETE` alone can describe an early stopped prefix. Qualification requires
520 arms/reports, 521 history actions/batches, more than 32 actual calls below
the ceiling, a returned entry prefix above 512, matching owner/batch/export
counts and the exact synced export size. K10 additionally requires genuine
FunctionClosed calls followed by sampling in a later generation. K1000 need
not complete 1000 calls in any period. Maximum arm lateness is 2 ms; observed
stop/removal/controller-final times must be ordered after the 5.2 s scheduled
end and strictly before `min(stop_ack + 2 s, 7.2 s)`.

`removed_ns` observes `close()` completion, which can be a no-op in an early
stopped prefix; it alone is not proof of a Removed action. The full-run counts
and source-checked final history are also required. Controller completion
time is not a sink-sync or OS-thread-join timestamp. Actual joins and sync
remain separate source assertions in the terminal.

`RAW/public/receipt.json` and `cases.csv` contain compact safe metadata, exact
normalized commands, source/tool/artifact hashes, hardware and two outcomes.
Exact commands, helper/parent receipts, failures and complete private Debug
exports remain under ignored RAW. Public metadata includes only each export's
hash and size. Failed cases remain FAILED and later cases UNRUN. The call
ceiling minus actual returns is not an offered or unstarted population.

This qualifies finite functional driver behavior and metadata. Input, journal
and gate-return checks and Report counts are source-attested. The wrapper
does not independently replay all Debug history/Report contents or add
new-driver in-flight stop, full-state, cheap-off, timing-accuracy, throughput
or full-A5 credit. The old forced-history/native-state controls remain separate.
Earlier failures are retained in [history-stream-4f2ddf8](../../../evaluation/history-stream-4f2ddf8/README.md)
and its linked reports; a successful new attempt does not relabel them.

Synthetic parser controls need no native subject:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/backoff-work/test_recipe.py
```

Both entry points refuse optimized Python before work. This recipe does not
claim a result by its existence; each execution records its exact committed
revision and observed outcomes in the receipt.

## Optional pre-context sampling

The API and mandatory qualification above remain available unchanged. For an
RBX-free leaf certified for the optional profile, build and publish an
`OptionalSitePreparation`, then pass its sealed site to
`backoff::prepare_optional(site, install, function, policy)`. The returned
`OptionalPrepared` contains an `OptionalDriver`, one `OptionalClient`, a stop
handle and a bounded receiver. Attach, invoke, flush and finish on the actual
worker; retain input, code and the real thread handles through join.

The optional driver uses the same clock loop, policy, queue limits and error
custody. It scans the current generation and disables selection once K closes,
then rearms at the next scheduled epoch. A replacement does not change an
already admitted Slow call's owner. `OptionalCallResult` distinguishes a
physically returned `FastBypass` from a `Slow` observation. Count physical
calls separately from raw rows: a four-call packet can contain no Slow rows,
and Fast calls are not unsampled Slow calls. A history window's `enabled`
field describes recorded history; it is not a read of the live selector.

Select the optional qualification explicitly:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/backoff-work/verify.py \
  --revision "$REVISION" --raw "$REPO/ignored/optional-backoff-run" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --optional --worker-backpressure
```

This first requires all 30 existing mandatory/optional frontend stages and one
new 13-call native control, then runs fresh optional K10 and K1000 trials.
The native control holds the controller unchanged around one real Fast call
after disable and before rearm, and checks an entered B call returning to B
after C replaces it. It exercises driver operations and queues, not the clock
loop. The two 520-epoch trials exercise that loop independently at the original
cadence. They keep the same 2 ms lateness, absolute shutdown, 20 CPU/30 wall
seconds, 64 MiB file limit and 55-second parent. No failed attempt is retried.

Without `--worker-backpressure`, the optional worker refuses Full immediately;
with it, only the existing bounded worker wait is enabled. The commands are
`optional-backoff-work` and `optional-backoff-work-wait`. Both emit their
requested policy explicitly. Omitting `--optional` preserves the original
mandatory commands, prerequisite set, parser and CSV fields.

Optional qualification requires 520 arms/reports and `521 + D` history
actions/batches, where D is the actual Disabled count, 0 through 520. Physical
calls equal Fast plus Slow, and sampled plus unsampled counts equal Slow.
Every Disabled generation accounts for K sampled completions by successful
finish. K10 requires a positive D and Fast count; K1000 need not close K or
make 1000 calls. Both require actual Slow entry prefix above 512, complete
batch/export counts, synced size and actual joins. These aggregate checks do
not locate a Fast call between disable and rearm: the trial keeps
`post_disable_rearm_coverage=not-qualified`. Only the separate deterministic
control supplies that bracket evidence.

Whole input, journal, return and Report assertions in the native control are
source-attested; the wrapper parses its exact one-test terminal and strict
closure. Timed trials export Report counts, not independent complete Report
replay. Neither run adds full-state, cost, timing accuracy, arbitrary ABI or
indefinite-service qualification. The earlier seven mandatory campaigns remain
FAILED in [backoff-independent](../../../evaluation/backoff-independent/README.md),
including attempts with a passing K10 prefix and a failed or unrun K1000 case.
See [the optional recipe controls](../optional-backoff-work/README.md).
