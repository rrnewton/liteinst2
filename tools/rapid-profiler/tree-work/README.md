# Fixed ordinary call tree

`tree_work.S` contains a protected 23-byte root and the existing 39-byte
linked-memory child at root+32. Its original E8 at root+9 pushes root+14;
the root adds one to the child's result. Both functions execute ordinary RET.
The closed input population is the two existing seeds crossed with `fit2`
and `conflict3`, each with 64 iterations. This fixture does not exercise
recursion, tail calls, unwind, signals or arbitrary application call graphs.

`truth.rs` independently describes the literal instructions, uses the existing
child interpreter, and joins it to a separate cycle/stack operand formula.
Each invocation has six root and 326 child instructions, 129 input reads,
two RET reads and one CALL store. Predictions alone do not establish native
execution. The native adapter must witness the source E8 and both physical
C3 successors before destination callbacks execute, then the real outer RET
and normal postflight. All original state comparisons remain required.

`model.rs` starts one cache at root entry: 64-byte lines, four sets, two ways,
true LRU, write allocate and write back. It uses actual virtual addresses,
input base in set2 and both return slots in one set3 stack line. The CALL
allocates that line before either RET. Every event is checked against both
reuse distance and a literal miss vector. Fit2 has three misses; conflict3
has 65. Exclusive attribution uses the instruction's function identity;
inclusive totals come from the same continuous simulation. The sole dirty
line is never evicted here. These are demand-cache model results, without
hardware-miss, timing-accuracy or performance claims.

Run the finite truth and output-protocol controls with:

```sh
cargo test --locked --offline --release -p liteinst2 --test call_tree_truth
python3 -B tools/rapid-profiler/tree-work/test_recipe.py
```

The release reproduction uses the existing ordinary-interval runner with
`--call-tree`, retaining the inherited populations. From a clean exact revision,
use a fresh directory under `ignored/` and absolute toolchain/cargo-home paths:

```sh
python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision "$(git rev-parse HEAD)" --raw "$PWD/ignored/tree-run" \
  --toolchain "$TOOLCHAIN" --user-home "$HOME" --cargo-home "$CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --streamed-epochs --stream-history --optional-frontend \
  --optional-backoff-control --reference-timing --cache-work \
  --counter-probe --call-tree
```

The required tree state population is four pairs/eight children, 1,372 complete
boundary comparisons, 24 immediate application-transfer witnesses and eight
real outer returns. The 1,328 original instructions produce 528 model events,
392 hits and 136 misses. A run earns those counts only after exact source,
input, stack, register, flag, XSAVE, row, journal, Report and child-reap checks.
The original 15-second and 20,000-step child limits and 90-second/1MiB state
stage limit apply. Failed witnesses or limits remain failures.

Complete source preflight runs before the controlled trace stop through an
exclusive, one-use prepared-call guard. Preparation stays inside the original
15-second deadline; the continuous step budget starts at the ready stop.
Consumption rechecks the actual caller, input, counters and idle gate before
starting a call. Full source/input postflight still precedes root completion.
The candidate also drops an unused guard, then uses the same invocation ID;
only the consumed guard may advance the gate sequence and call counters.

Raw logs and capture state remain in `ignored/`. A paper-facing receipt records
the exact source revision, release profile, command, sanitized hardware and
the four-row CSV; it must describe the actual completed run. This document
states the fixed contract, not an execution result. Concurrent epoch ownership
requires its separate real-call control and cannot be inferred from these
single-epoch pairs.

The required owner control pauses the actual root entry under epoch A, replaces
it with B before child entry, and replaces B with C at the child's pre-RET
pause. It checks that B stays pending until the original caller continuation
and A stays pending until the actual outer return and source postflight. The
caller retains its local loader and attachment; only the controller moves to
the joined helper thread.

A separate malformed-word child authenticates the original E8, changes only
its eight-byte saved return word, and requires bounded normal exit 123 plus
exact reaping. Its one-row `EXPECTED_REFUSAL` result is separate from the four
successful pairs. Exit 123 is the existing undifferentiated fatal policy; the
receipt makes no claim to have decoded the internal runtime error.


The ordinary `tree-population` client exercises this same loaded tree over a
fixed population: ten `fit2` calls followed by fourteen `conflict3` calls,
alternating the two seeds. Add `--tree-population` to the reproduction above
for three fresh release processes with K=1, K=10 and K=24. Each checks 24
original and 24 installed root calls, 48 node intervals, three eight-root
journal drains and the full retained Reports. The actual installed gate
sequences must be 25 through 48, following the 24 successful originals.

Both functions retain their first K invocations. K=1 and K=10 miss the later
conflicting phase entirely; K=24 retains all fourteen conflicting calls.
The exact retained-label fraction errors are -14/24, -140/240 and 0/576.
Each root has 332 inclusive instructions and six exclusive instructions;
its child has 326 instructions. These counts describe the authenticated fixed
source. Inclusive root and child totals overlap and must not be added as
disjoint work. This ordinary client does not trace instruction counts or
satisfy the native cache model's stack-set placement requirement. Its raw
callback timestamps remain uncalibrated.

Run its consumer and output controls with:

```sh
cargo test --locked --offline --release -p rapid-profiler --bin ordinary-interval tree::
python3 -B tools/rapid-profiler/tree-work/test_population.py
```

The output is a compact 48-row CSV and exact terminal per process. The Rust
client checks the complete 512-word journal pages, hidden record identities,
Reports, input guards, real returns and retained batch stability before
printing it; those checks are not all projected into the CSV. Each added
process keeps the existing 20 CPU-second, 30 wall-second and 1 MiB bounds.
The inherited native state, owner and malformed-return controls remain
required; their results cannot be inferred from this functional population.

`tree-throughput MODE CANDIDATE TRUSTED` measures the guarded SDK consumer
for `original-sdk`, `k1`, `k10` and `k24`. Each process performs 64 repetitions
of the same 24-call worklist (1,536 root calls). Installed modes reuse one
attachment and one epoch slot: stage, arm, call and drain, disarm, retire,
validate and drop the Report, then stage the next epoch. They retain bounded
sealed batches across reuse and check the full journal and Report joins.
The original mode uses the original SDK call path, including source/input
checks. It is an SDK baseline, not bare native execution. Mandatory entry and
return hooks remain active after K is reached.

Add `--tree-throughput` to the full reproduction command above, together with
`--tree-population`. The runner preserves its existing 47 stages and then runs
52 fresh processes in the literal order in `throughput_stats.py`: three warmup
blocks followed by ten measured blocks, each containing all four modes.
The order was generated once with seed `0x4c49544554524545` and frozen before
observations. Every trial must satisfy the functional checks and the unchanged
20 CPU-second, 30 wall-second and 1 MiB bounds. A failure stops the campaign;
remaining trials stay unrun. All twelve warmup results remain in the receipt
but are excluded from the estimator by this fixed policy. No trial is retried,
trimmed, discarded as short or unstable, or adjusted by empty-hook subtraction.

Each clock snapshot reads `CLOCK_MONOTONIC`, then `CLOCK_PROCESS_CPUTIME_ID`,
then `CLOCK_MONOTONIC` again. S0 precedes source loading, input preparation and
SDK setup; affinity and clock-resolution queries precede S0. S1 follows setup
and precedes the first epoch stage or original call. S2 follows all 64 blocks,
including the last installed retirement and Report validation/drop. S3 follows
final detach, history/input checks and flushing the 64 block summaries.
Process startup, affinity/resolution setup, the final timing line and process
exit are outside these regions. Per-call scalar, return and full guarded-input
checks, and installed drains/joins, are part of the measured consumer cost.
The instruction interpreter is not replayed on each timed call.

The primary whole wall duration is `S3.wall_after - S0.wall_before`; the loop
wall duration uses S2 and S1 with the same enclosing endpoints. Lower spans
are also exported, using end.wall_before minus start.wall_after, but never
substitute for the primary spans. CPU deltas use their own endpoints. All four
raw triples and both positive clock resolutions are retained. Clock resolution
is metadata, not a bound on measurement accuracy. No cross-clock CPU<=wall
inequality or minimum-duration threshold is imposed.

For each installed mode and metric, ten measured blocks provide ten paired
ratios `original-sdk / installed`. The reported ratio is the geometric mean.
The conditional 95% interval is Student t with nine degrees of freedom on
the mean log ratio, assuming independent approximately normal log ratios.
All ten ratios are retained. Cost increase is `100 * (1/ratio - 1)`;
wall-only throughput loss is `100 * (1 - ratio)`. Negative values are retained.
The primary metric is whole wall time; loop wall and both CPU deltas are
secondary. These intervals do not establish empirical coverage, timing
accuracy, isolation from shared-host effects or completion of the A5 gate.

Run the additional source/protocol controls with:

```sh
cargo test --locked --offline --release -p rapid-profiler --bin ordinary-interval tree::throughput::
python3 -B tools/rapid-profiler/tree-work/test_throughput.py
python3 -B tools/rapid-profiler/tree-work/test_throughput_stats.py
```

Keep the 64-row transcripts and process logs in `ignored/`. A compact public
receipt should retain all 52 per-process numeric summaries (including raw clock
endpoints), the paired statistics, exact revision, release settings, command
and sanitized hardware. This protocol document records no measurement result.

`--tree-native-baseline` adds a fresh native comparison to the full functional
reproduction command (all thirteen prerequisite flags, including
`--tree-population`, `--reference-timing` and `--counter-probe`). It does not
require `--tree-throughput`; that separate 52-process experiment remains an
independent opt-in. The new route runs the same 47 functional stages, nine
additional prerequisite stages, and 65 fresh processes. Rust builds use release
opt3 with assertions and overflow checks enabled; the small C timer uses
`gcc -O3 -std=c11 -Wall -Wextra -Werror`. The source receipt records all inputs.

The separately built `tree-native-baseline CANDIDATE TRUSTED` loads the same
trusted caller/child DSO and guarded inputs. Its hot loop calls through a fixed
15-byte SysV ABI stub without SDK planning, TLS, callbacks or repeated source
scans. Complete source and input checks precede and follow the loop. The SDK
comparison route is `ordinary-interval tree-comparison MODE CANDIDATE TRUSTED`;
all existing SDK guards, retirement, journal and Report checks remain. Every
mode collects and validates all 1,536 indexed results and 64 block sums. Native
retains extra cycle validation during setup; the comparison therefore measures
these complete consumers, rather than isolating instrumentation overhead.

Before timing, four new native-call differential pairs compare a genuine
five-role Tree144 no-op candidate against the original at every original head
and every fixed-stub head: 339 full-state comparisons per pair, 1,356 total.
The original GPR/flags/XSAVE/data/unmasked stack comparator, absolute 15-second
pair deadline and continuous 20,000-step limit remain. Independent transfer,
callee-save and real-return checks qualify the exact stub used by the native
client. The inherited SDK state and ownership stages are also required. The
complete calibration target now contains its 76 original methods plus six
NativeCall methods, with all original expected panics retained.

All five modes use `process_timer.c` under the unchanged bounded-command and
outer process owners. The timer forks one child and records MONOTONIC immediately
before fork and after its terminal wait4. This primary wall enclosure includes
fork/wakeup scheduling, exec/loader/startup, setup, work, export, shutdown and
exit. It excludes timer startup, record serialization and later helper cleanup.
Separate wait4 user/system CPU includes the child exec stub, but excludes the
timer parent's CPU. The timer adds no timeout, adoption, cleanup or limit reset.
Every process retains the existing 20 CPU-second/30 wall-second/1 MiB policy;
recorded wall must also be at most 30 seconds. The launch request, exact subject
argv token, sidecar, functional transcript and both clean owners must all join.
Neither a timing record nor a successful subject exit overrides a cleanup rescue.

The fixed 13-by-5 order in `comparison_stats.py` was frozen before observations
using SHA256 of `tree-native-baseline-v1`, zero-based block as u32 big endian,
and the full ASCII mode name, sorted within each block. Three complete warmup
blocks (15 processes) remain in the raw results; ten measured blocks (50
processes) supply native/mode pairs for original SDK, K1, K10 and K24. Every
process performs the same 64-by-24 worklist, for 99,840 roots across the cohort.
The primary statistic uses process wall; child CPU and internal whole/loop
wall/CPU are secondary. The estimator and conditional t9 interval use the same
paired log-ratio method described above. Raw zero wait4 CPU is retained and
makes its entire CPU comparison unresolved; no pair is dropped or replaced.
All outliers, raw endpoints and fixed warmups remain. The source attestation
covers every indexed result and full SDK records; compact rows do not reproduce
those objects. No hardware-event accuracy, isolated hook latency, general-module
coverage or completion of the A5 matrix follows from this finite experiment.

The recipe executes nine new protocol methods, six estimator methods, five
timer/join methods, four collection controls and eleven bounded live timer
cases (two positive, nine negative). The live controls include failed exec,
signal/nonzero exit, a child with closed output that remains alive, a killed
timer, an acknowledged detached descendant, existing record refusal and file
truncation. Keep full logs/64-row transcripts in `ignored/`; publish compact raw
CSV/JSON per-process numbers and the exact revision, hardware and command.
