# Finite optional backoff with bounded sink waiting

Both 520-epoch optional-backoff trials **PASS** at `bbaacce1dedbe5188fa6eb1d2ececacd18a57c4e`, after all **31 prerequisite stages PASS**. The new transport policy retries a full controller-to-sink queue within a fixed 1 ms window, using requested sleeps of at most 250 us and preserving the original arm and shutdown deadlines. These trials explicitly enabled both worker and sink waiting. Queue capacities remain two worker packets and four sink packets; immediate-refusal modes remain available.

| K | Actual calls | Fast | Slow | Sampled | Unsampled Slow | Disabled actions | Maximum arm lateness, ns |
|---|---:|---:|---:|---:|---:|---:|---:|
| 10 | 12,052 | 6,481 | 5,571 | 5,200 | 371 | 520 | 142,519 |
| 1000 | 12,062 | 1 | 12,061 | 12,061 | 0 | 0 | 101,535 |

Each trial completed 520 arms and 520 reports after eight original reference calls. K10 exported 3,014 call batches, 1,041 history batches and 520 reports; K1000 exported 3,017 call batches, 521 history batches and 520 reports. Accepted and written exports agree at 4,575 and 4,058. Producer-recorded synced export sizes are 15,966,292 and 21,632,150 bytes; this publication did not reopen those exports. Actual entry prefixes reached 1,039 and 520. Both stop reasons were `epoch-limit`; all three application threads joined.

The prerequisite suite includes a separate 13-call control for post-disable Fast execution, later sampled rearm and retained old ownership. It also includes eight optional-gate full-state pairs (16 children, 1,956 comparisons), a separate 96-call functional/accounting case, and the inherited ordinary/exact/concurrent regressions. These are distinct schedules: the timed aggregates do not establish the ordering of individual post-disable calls, and the full-state fixture does not cover all timed executions. No timing accuracy, cheap-off cost, throughput, indefinite-service or completed-A5 claim follows.

[receipt.json](receipt.json) and [cases.csv](cases.csv) preserve the wrapper's public output verbatim. [commands.csv](commands.csv) contains 31 prerequisite and two timed-trial rows. [qualification.json](qualification.json) summarizes pinned metadata and keeps the scopes separate. All 33 saved helper receipts report ECHILD, unchanged inputs and zero cleanup/rescue events; their 33 parents plus the prerequisite-driver parent exited normally with zero rescues. The 97 source descriptors were checked against the exact Git revision. Request, binary and export digests are recorded metadata; their bodies were not read. Whole input, journal and physical-return checks are source-attested; timed trials check Report counts, while deterministic controls check complete Reports. Separate [required gates](gates.json), [development checks](development.csv) and the [outer execution receipt](execution.json) are included below; the native projection does not infer their outcomes.

Hardware metadata reports x86-64 AuthenticAMD family 26/model 17/stepping 0; the owner label is AMD EPYC Zen 5 dev host. The wrapper used four CPUs, with one distinct CPU for worker, controller, sink and main. Recorded tools are Rust/Cargo 1.97.1, GCC 11.5.0 and Python 3.12.15. Cargo reported all three executable artifacts rebuilt, with release opt-level 3, debug info 0, assertions and overflow checks enabled; hashes and exact versions are in the receipt. Trial bounds stayed 20 CPU seconds, 30 wall seconds and 64 MiB per output file, within a 55-second parent bound. The inherited prerequisite limits were unchanged.

Reproduce from a clean checkout at the exact revision, using absolute local paths:

```sh
env -u PYTHONOPTIMIZE "$PYTHON" -B "$REPO/tools/rapid-profiler/backoff-work/verify.py" \
  --revision bbaacce1dedbe5188fa6eb1d2ececacd18a57c4e --raw "$RAW" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --optional --worker-backpressure --sink-backpressure
```

`RAW` must be fresh under the checkout's ignored directory. To reproduce only this publication from the already closed, supplied metadata manifest (without running a workload):

```sh
env -u PYTHONOPTIMIZE "$PYTHON" -B project.py --repo "$REPO" \
  --revision bbaacce1dedbe5188fa6eb1d2ececacd18a57c4e \
  --manifest "$CLOSED_MANIFEST" \
  --manifest-sha256 c96cd16885663d642365c0b2f12a3efe0230c3389d8eac5bd44353fce8810ed8 \
  --out "$NEW_PUBLIC"
```

The [earlier optional campaign](../optional-backoff-398203e/README.md) remains FAILED (K10 controller-to-sink Full, K1000 UNRUN). The [seven mandatory campaigns](../backoff-independent/README.md) and their linked historical failures also remain FAILED. This separately selected policy and finite successful campaign do not explain the operating-system cause of those failures or erase them.


All seven required checks passed at the same source revision. Default-parallel
workspace: **2,683 passed / 0 failed / 11 ignored** in 329.552 seconds, with all
316 available CPUs and no test-thread override (five nested summaries excluded).
Serial launch: **1,039 passed** in 124.885 seconds. Staged allocation: 3 passed;
prefixed-pun: 36 passed. Formatting, strict workspace Clippy and all-target,
all-feature checking passed. All commands closed normally with zero rescued
descendants. The explicitly ignored native controls ran in the release
prerequisites. Reproduce the seven checks with
`python3 -B evaluation/admission/check_exec_identity.py --checks-only
--toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME"
--output "$REPO/ignored/NEW_GATES"`; project with
`evaluation/merged-af5a1ef/summarize.py` as documented there.

The eight development records include 53 SDK controls (16 added), 12 optional
recipe controls and eight legacy recipe controls, all passing. The formatter
row is an intentional source mutation. Dirty-tree rows identify their actual
parent and before/after source hashes; they are not extra native qualification.
Development commands used 180-second/8-MiB bounds and four compiler jobs.

The actual release command used the shared CPU allocator around the recipe
above: `AGENT_UTILS_ENGINE=python PYTHONDONTWRITEBYTECODE=1
PYTHONNOUSERSITE=1 "$AGENT_UTILS/bin/cpuset-alloc" run --cores 4
--tag "$RESERVATION_TAG" -- <recipe command>`. The allocator selected logical
CPUs 13, 15, 19 and 25. Its normalized exact command and tool hashes are in
execution.json. This is a cooperative reservation, not exclusive access to the
host. Source and CPU placement both differ from the earlier failed optional
attempt; this result does not isolate either one's causal effect. The outer
command took 67.965 seconds, closed normally and rescued no descendants.
All stated durations are operational measurements. Raw logs and complete
exports remain under ignored/; only compact summaries are committed.
