The ordinary interval frontend can run metadata epochs concurrently with an
attached worker. `PreparedIntervalController::activate_concurrent()` waits for
writer and registry authority before choosing an epoch. The original `activate()`
keeps its nonblocking refusal behavior. Every admitted return retains its original
epoch; contention never becomes an unsampled call. Same-thread controller reentry
is refused before waiting. See the method's safety contract for allocator, signal
and wait-dependency obligations.

`ordinary-interval timed-work CANDIDATE TRUSTED` loads the existing exact-work DSO,
checks 24 originals, then invokes 24 preassigned alternating 1/64-byte calls while
the controller independently requests three 30 ms active / 10 ms inactive windows.
Controller and worker use separate allowed CPUs. There is one startup rendezvous;
calls and transitions have no shared application mutex or per-call acknowledgements.

The client joins every call to its raw interval and every sampled interval to its
final epoch record. It checks all six history actions, original results, entry/RET
addresses, stack restoration, unchanged input, and completion sequences across
epochs. Actual monotonic operation/call brackets must demonstrate at least one
complete call in each stable active and inactive window. Missed windows remain
failures; requested deadlines are never substituted for observed coverage.

Run the complete release qualification from a clean committed tree:

```sh
python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision REVISION --exact-work --concurrent-epochs \
  --raw ABSOLUTE_NEW_IGNORED_DIRECTORY --toolchain RUST_TOOLCHAIN_DIRECTORY \
  --user-home USER_HOME_DIRECTORY --cargo-home CARGO_HOME_DIRECTORY
```

This preserves the ordinary checksum oracle/client and all twelve exact-work
populations. It adds the unchanged state comparator under concurrent activation,
a separate forced native contention test, and the timed client. The forced test
is explicitly invoked from a release library-test artifact: six original and
six installed calls, two actual writer contentions, one in-flight rearm, twelve
exact journal rows, and two retained reports. Its private atomic rendezvous exists
only under `cfg(test)`; the normal workspace run reports it as ignored because
it requires the reproducer's independently built fixture. The full-register
comparator runs without a competing controller. The forced-contention test checks
gate/stack/input/journal/report state and does not add concurrent XSAVE comparison
credit.

Pure protocol controls can also run directly:

```sh
python3 -B tools/rapid-profiler/timed-work/test_recipe.py
python3 -B tools/rapid-profiler/exact-work/test_recipe.py \
  --runner tools/rapid-profiler/verify_ordinary_interval.py
```

These are bounded functional trials. Mandatory native hooks remain active during
inactive epochs. Raw RDTSCP starts precede any controller wait and are neither
calibrated duration nor original-work truth. This does not implement indefinite
daemon service, arbitrary-function discovery, or a performance
claim. The existing epoch, history, thread and journal limits remain enforced.

`ordinary-interval streamed-work CANDIDATE TRUSTED` combines completed-buffer
draining and explicit epoch retirement. It checks 160 original calls, then runs
160 alternating 1/64-byte calls across twenty 30 ms active / 10 ms inactive
windows. Three epoch slots hold the current and upcoming owners. After a batch
proves that a call returned wholly after disarm, the controller retires the old
epoch, checks and drops its final report, and stages a replacement before its
fixed cutoff. Retirement does not establish code-unload quiescence.

The worker exports forty owned four-call batches through a channel of capacity
two. Each batch carries the complete journal and raw rows; the controller checks
them against actual returned-call observations and cumulative accounting. The
32-row local buffer can be reused without resetting ordinals, completion
sequences, registration or history. Export backpressure, a missed staging cutoff,
or missing actual whole-call coverage fails the trial. There is no per-call
acknowledgement or shifted timer schedule. Calls and retirements must finish by
the recorded window end, within the fixed two-second deadline.

Add `--retire-epochs --drain-completed --streamed-epochs` to the release command
above to require this client alongside every preceding qualification stage.
The resulting CSV records actual transitions, calls, batches, retirement and
reports. The complete journal arrays are checked in process and are not exported.
On an ordinary error, the client preserves the validated prefix and the worker's
unsent or partial result; disconnecting the channel can discard queued packets.
This finite example retains forty history actions and twenty report summaries;
it does not provide an indefinitely running sink or timing-accuracy evidence.
