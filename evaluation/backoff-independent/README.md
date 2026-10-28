# Independent backoff: qualification remains failed

The driver rearms sampling independently of its worker and exports bounded owned batches. Revision `035a4bdb6cb03c2664da7f319527d03be96870ec` adds explicitly selected worker backpressure after a real return and completed drain; the existing immediate-Full policy remains the default. **The new finite qualification failed. All seven recorded campaigns remain FAILED.**

At this revision, all 27 prerequisite stages passed. The K10 trial then failed `Deadline` after 5,236 actual entries and returns: 2,330 sampled and 2,906 unsampled. K1000 was UNRUN. The root's failure record reports `ClockPoll`, scheduled at 2,330,000,000 ns, with limit 2,332,000,000 ns and observation 2,332,884,596 ns. The 884,596 ns excess remains a failure. It does not establish a scheduling cause. The worker recorded `ControllerFailed`, detached, and retained unexported data; these partial counters are not a complete exported population.

The separate seven required gates **PASS at this same revision**: workspace 2,609 passed, 0 failed, 9 ignored; serial launch 1,039 passed; staged allocation 3 passed; prefixed-pun 36 passed; formatting, strict Clippy and check passed. All seven commands closed with exit 0, complete cleanup and zero rescues. Workspace and serial wall durations were 332.645 s and 124.390 s; these are operational durations, not profiler performance. Passing gates do not change the failed native qualification.

## Evidence and preserved attempts

[receipt.json](receipt.json), [cases.csv](cases.csv) and [gates.json](gates.json) are byte-exact producer outputs. Failed case fields remain empty. [attempts.csv](attempts.csv) preserves all seven campaigns and root-recorded partial counters; [checks.json](checks.json) adds provenance, deadline diagnostics, development closures and allocator fingerprints, referring to gates.json without duplicating it.

The initial three attempts used the first four allowed logical CPUs. The later four used allocator-selected reservations and are a distinct environment. The first reserved attempt at `0f27b73` passed K10 with 520 arms/reports and 12,006 calls, but K1000 failed `Deadline` after 6,726 calls: that campaign is FAILED. Subsequent source changes and the opt-in transport did not turn earlier failures into passes. Populations across sources and environments are not pooled.

All seven failing case summaries record exit 101, ECHILD, no wall timeout, zero cleanup events/unexpected descendants and zero parent rescues. The development compile `controls-backpressure-v1` remains FAILED (exit 101); its source review records a test-only received-Box binding correction. Later development controls and strict Clippy closed successfully; eight parser methods and two optimized-Python refusals are separate. Development checks are not final-head native qualification.

Input, journal and gate-return checks and Report counts are source-attested, without independent history/Report replay. The eleven-file source review is joined to exact Git bytes. Artifacts and raw logs/exports were not reopened. Gate counts are producer-derived from each Cargo group's last libtest terminal: 100 workspace terminal groups, five nested summaries excluded, custom cleanup harness excluded from the libtest aggregate.

## Reproduce the same bounded policy

Use a clean checkout of the exact revision, Python 3.12 (recorded 3.12.15), Rust 1.97.1 and GCC 11.5.0. Supply absolute existing paths for `REPO`, `PYTHON`, `TOOLCHAIN`, `USER_HOME`, `CARGO_HOME` and the installed `CPUSET_ALLOC` executable. `RAW` must be fresh under the checkout's `ignored` tree. Select the Python allocator engine and fixed defaults, without manual CPU selection or policy overrides:

```sh
env AGENT_UTILS_ENGINE=python PYTHONDONTWRITEBYTECODE=1 \
  "$CPUSET_ALLOC" run --cores 4 --tag li2core-backoff -- \
  env -u PYTHONOPTIMIZE "$PYTHON" -B \
  "$REPO/tools/rapid-profiler/backoff-work/verify.py" \
  --revision 035a4bdb6cb03c2664da7f319527d03be96870ec \
  --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --worker-backpressure
```

The flag selects this attempt's `backoff-work-wait` mode; omitting it selects the distinct immediate-refusal policy. The wrapper requires all 27 old stages using `--exact-work --concurrent-epochs --retire-epochs --drain-completed --streamed-epochs --stream-history`, then attempts fresh K10 and K1000 children in order, stopping on failure. It never shortens the population. checks.json retains four allocator source hashes and the fixed sampling/IRQ policy. The source plan remains PLANNED_UNRUN, without runtime-containment credit.

Each backoff case requests 520 ten-millisecond periods and a 100,000-call ceiling, with unchanged 2 ms arm lateness and shutdown limits. Independent 23-call bursts use 250 us spacing and 3 ms idle gaps, without per-call acknowledgement; the ceiling is not an offered worklist. Worker, controller, sink and main use distinct CPUs within the four-CPU allocation. The owner-specified label is **AMD EPYC Zen 5 dev host**; observed fields are AuthenticAMD, family 26, model 17, stepping 0. Tool-reported reservations are not exclusive-host containment or a hard real-time guarantee.

Each backoff child retains 20 CPU seconds, 30 wall seconds and a 64 MiB file bound, inside a 55-second/1 MiB parent. The prerequisite parent retains 900 seconds/1 MiB and all old stage bounds. Release optimization is 3, debug info 0, assertions and overflow checks enabled. Bounded waiting retains one unsent worker packet and the original cap; controller-to-sink Full still refuses. Queue sizes, cadence and deadline comparisons are unchanged. The 8 KiB buffer and compact Debug output retain every field and journal word.

Synthetic protocol checks use the existing script:

```sh
env -u PYTHONOPTIMIZE "$PYTHON" -B \
  "$REPO/tools/rapid-profiler/backoff-work/test_recipe.py"
```

Run the seven gates separately, outside the allocator reservation, from the same clean revision with a fresh output directory. The recorded run retained all 316 allowed CPUs and default libtest parallelism, except the explicit serial-launch command; compiler jobs remained four:

```sh
env -u PYTHONOPTIMIZE "$PYTHON" -B \
  "$REPO/evaluation/admission/check_exec_identity.py" \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/NEW_GATES" --checks-only
```

After closure, reproduce the count projection with its actual receipt hash:

```sh
env -u PYTHONOPTIMIZE "$PYTHON" -B \
  "$REPO/evaluation/merged-af5a1ef/summarize.py" \
  --closed "$CLOSED_GATES" --sha256 "$CLOSED_GATES_RECEIPT_SHA256" \
  --revision 035a4bdb6cb03c2664da7f319527d03be96870ec \
  --output "$NEW_GATES_JSON"
```

## Limits

Stop cannot cancel an entered call. Report readiness, detach and close-completion timestamps are not physical-RET or OS-thread-join proofs. The unsafe leaf ABI, lifetime, no-reentry/signal/fork/nonlocal-exit/CET and normal-return obligations remain. Sampling closure keeps mandatory entry/RET and context bookkeeping installed.

This evidence gives no successful new 520-epoch campaign, complete independent history/Report replay, new-driver in-flight-stop or full-state qualification, cheap-off measurement, timing accuracy, throughput, indefinite service or completed-A5 claim. Earlier unrelated failures remain linked through [history-stream-4f2ddf8](../history-stream-4f2ddf8/README.md); no fix credit is inferred here.
