# Finite B2 completion-cost protocol

This is a separate measurement protocol for the five checked scripted fixtures
shared with `b2_mode_reference`. A complete record measures synchronous selected
completion latency through the existing static trap and dynamic page APIs.
It does not establish a production block backend, a native no-op equivalence,
real-application coverage, complete B3/B4 support, a pure hardware-hook cost,
or a performance pass threshold. No measurement result is implied by the source
inventory or synthetic recorder tests.

The exact source must first pass all six unchanged commands in `run.py`.
That prior receipt, its SHA-256, the six retained private capture hashes and
the replayed evidence are required before release build or measurement. The
source map, Git blob identities and modes must match. The measuring revision
may be a receipt-only descendant; a changed code, fixture, recorder, catalog,
configuration or documentation file requires a new exact-source correctness
receipt. The prior receipt recorded compiler launchers and versions; current
actual compiler binary hashes are new observations, not a retrospective claim
that the prior run authenticated those binary bytes.

## Inventory and boundaries

`hook_cost_inventory.json` freezes five fixtures, their 17 instruction rows,
relative site offsets, encodings, scripts, and every pair's order. Each fixture
has three warmup pairs and ten measured pairs. There are 65 fresh raw reference
processes, 130 fresh production sessions and 442 selected completions: 102 warmup
and 340 measured. The embedded ordinary MOV contributes 26 collateral
completions and zero selected callbacks. The two production lanes compare
against one independently handwritten semantic/raw reference per pair; raw
reference time is outside the reported completion intervals.

Seed-one wrapping xorshift64 chooses the first order of each ABBA/BAAB block.
The following odd round reverses it. State carries across phases and fixtures;
the third warmup is the explicit unpaired seed-selected pair. The parser binds
the literal 65-pair catalog and independently reconstructs this order.

For each exact selected invocation, four `Instant` observations bound the
synchronous call, entry to the checked scripted provider, return from that
provider, and return of the required Completed event. The exported integers
obey exactly:

```
completion_ns = before_provider_ns + checked_provider_ns + after_provider_ns
```

The before-provider interval includes actual ordinary fixture instructions,
faults/traps, admission/scan work, scheduling and transport. The after-provider
interval includes the backend's actual state, control and publication work.
Provider cost includes the unchanged input/result checks. These are inclusive
observations; neither raw-reference time, timer calibration nor overlapping
internal publication/scan intervals is subtracted. Validation, serialization,
metrics queries and physical cleanup are outside these four timestamps.

Launch, validation and cleanup durations are retained separately. All metric
snapshots and cumulative publication-duration arrays are retained. Page gauges
can decrease after dynamic revocation. History/callback/scan counters must keep
their actual monotonic values. A repeated site is still identified by its
trajectory ordinal; a later dynamic completion is not labelled a warm hook.

## Reproduction and resource proof

Run the tracked outer entry after reviewing and qualifying the final committed
source. Supply the already pinned allocator entry digest and the prior public
receipt digest. The actual absolute allocator location is an input kept private;
the public command records its basename and digest. The exact portable token
`cpuset-alloc` resolves through the controlled absolute PATH; an explicitly
supplied absolute entry is also accepted. Both forms require the same digest.

```sh
python3 evaluation/admission/hook_cost_invoke.py \
  --expect-revision "$LI2ADM_REVISION" \
  --correctness-receipt "$LI2ADM_CORRECTNESS_RECEIPT" \
  --correctness-sha256 "$LI2ADM_CORRECTNESS_SHA256" \
  --allocator "$LI2ADM_ALLOCATOR" \
  --allocator-sha256 "$LI2ADM_ALLOCATOR_SHA256"
```

The wrapper uses the Python `cpuset-alloc` engine and its existing shared
reservation ledger. It never redirects that ledger into the private run TMPDIR.
Validated runtime/bus locations needed by the user scope are retained only for
the allocator; Cargo and the example receive the unchanged controlled
environment, with ambient compiler/test/loader overrides excluded. The shell
resolver, Python entry, every package Python source, and `systemd-run` executable
and version are hash-bound before and after. The package manifest is a
conservative source closure, not an observed runtime import trace. A fresh
private Python-cache prefix excludes stale external package bytecode.

Exactly two logical CPUs on two distinct package/core identities are required.
Their numeric IDs, sibling lists, affinity, effective cgroup-v2 cpuset and
governor observations are retained; paths, hostnames, process IDs and raw
application state are not. The allocator's mutation-verified assignment must
match the inner read-only effective-cgroup/affinity witness. Selecting two SMT
siblings refuses before build or measurement. Other SMT siblings are not
claimed reserved, and whole-physical-core exclusivity is not claimed. There is
no unpinned fallback, private hardcoded CPU pool or automatic retry.

The prior correctness receipt and outer recorder must have exactly matching
hardware observations, including both positive integer CPU counts. Inside the
verified hard scope, `affinity_cpu_count` must equal its two assigned CPUs.
`logical_cpus_visible` is an `os.cpu_count()` observation, not a physical CPU
identity: it must either retain the exact prior/outer value or equal that same
two-CPU placement count. No other count change, missing value, Boolean or zero
qualifies. The prior counts must also be at least the scoped count. Every
non-count field, including CPU model, ISA, microcode, kernel, privileges and
ptrace policy, remains exactly equal. Outer finalization checks this relation
again after matching allocator assignment, effective cpuset and distinct-core
topology. The receipt retains the prior, outer and actual inner hardware values
separately and records the closed count-relation witness; it never normalizes
the inner observations. Within the inner measurement process, before/after hardware equality is
still exact.

The allocator runs `systemd-run --scope` synchronously as the command's parent,
not detached service mode. The unchanged `processes.py` supervisor therefore
retains its real descendant wait domain even across sessions. Its existing
exclusive-subreaper embedding preconditions apply. Each command must exit zero,
complete bounded cleanup and leave zero adopted descendants; a child reaped by
cleanup still disqualifies the run. Placement alone does not prove cleanup.

| Command | Absolute wall budget | Private output bound |
|---|---:|---:|
| outer allocator plus inner collection | 600 s | 8 MiB |
| offline release example build, four jobs, existing target, incremental off | 180 s | 8 MiB |
| fixed 65-pair measurement executable | 300 s | 8 MiB |

The inner build is `cargo build --offline --release -p liteinst-launch --example
b2_hook_cost`. The executable receives exactly `--warmup-pairs 3
--measured-pairs 10 --order-seed 1`. Its binary digest is recorded before/after
execution and again at outer promotion. The existing native fixture 3-second
timeouts, default 64 MiB lifetime budget, six correctness-command budgets and
all previous cohorts remain unchanged.

## Evidence and failure semantics

`hook_cost_wire.json` specifies closed objects and integer domains. Calibration
contains exactly 1,000 back-to-back `Instant` deltas and the observed monotonic
clock resolution. A session and its rows are emitted after its complete checks
and physical cleanup. Pair comparison still follows the second session. Only
the final run terminal can attest the exact pair and completion denominators.

The inner recorder writes an unqualified private staging receipt. The outer
recorder independently parses the hash-bound capture and requires exact staging
agreement, complete source/config/tool/executable/resource stability, matching
assignment, both inner commands and outer physical cleanup before qualifying
any row. Its JSON and session/completion/summary CSVs are published under
`results/`; each CSV is hash-bound by the JSON. Private logs remain ignored.

Every attempt creates a public preflight record before allocator setup. A
reservation refusal is a terminal failed record even if inner collection never
starts. Failures and partial rows are retained. Already emitted successful
session rows remain unqualified if a later pair, sample, cleanup or metadata
check fails. The native failure record retains completed prefix observations
without claiming completion/cleanup of the active interval. If interruption
prevents the inner's final write, the outer recovers the bounded capture prefix
before fallible post-run identity checks. Absent rows mean `not_observed`, not
proved unexecuted. No rows are silently retried or replaced, and no timeout or
refusal is relabelled success. As with the existing recorder, an external hard
kill of the recorder itself may leave its durable preflight/running record;
such a record is unqualified, never a completed measurement.

Each recorder retains one catalog authenticated against its source inventory
before any command. Capture recovery uses that in-memory catalog even if the
on-disk catalog later changes; the source check still disqualifies the attempt.
If initial catalog authentication fails, the terminal failed receipt has no
invented row inventory or CSV observations.

The public receipt is the qualification authority for its hash-bound CSVs.
An incomplete publication without that final passed receipt cannot qualify a
standalone CSV. Failed command metadata is projected through fixed command
specifications and a closed status/termination vocabulary; arbitrary staging
fields and exception strings remain private. If a CSV rename fails midway,
surviving CSVs are explicitly listed as partial and unqualified in the failed
JSON, even if their already-written rows had passed measurement checks. No
measurement is retried. The recorder adds 81 synthetic
Python methods (200 total recorder methods). They test evidence contracts and
failure accounting, and add no native measurement sessions or correctness
fixtures to the declared 65-pair inventory.

Measured summaries require all 10 independent process pairs for each exact
fixture/ordinal. They report per-lane median/range and the median of paired
dynamic-minus-static differences with a declared percentile bootstrap interval:
10,000 resamples, seed 20261026, nearest-rank 2.5/97.5 percentiles, resampling
whole pairs with both lanes together. Warmups remain in raw CSV rows but are
excluded from these summaries. Calibration is never subtracted. No p99,
speedup, raw-baseline subtraction or performance acceptance threshold is
reported. With only ten pairs, the interval is a finite descriptive uncertainty
summary, not broad application-performance evidence.
