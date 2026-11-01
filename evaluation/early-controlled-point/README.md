# Early optional point observers

`PointObservationAction::EarlyIfEnabled` checks a retained control before the
ordinary register/extended-state capture. A false byte restores RCX and RSP and
continues at the original instruction. A true byte enters the existing helper,
whose dispatcher performs its unchanged acquire check. Every instruction in the
gate preserves flags; its temporary stack word lies below the application red
zone within the existing helper's writable descriptor extent.

`AfterCapture` retains ordinary controlled observation. The additive planner
requires live Observe/RelocationOnly with Legacy128, one mapping and at most
8,192 page-rounded bytes, honoring smaller caller limits. The caller must prove
that an optional callback can independently disappear: opaque callback pointers
cannot reveal hidden interval or clock obligations. Existing code/stack/control
lifetimes, callback exclusions and eventual visibility apply. Disable does not
drain callbacks or authorize reclamation.

The finite qualification adds the existing CFG, single-publication and grouped
populations under this separate profile, plus a fixed RCX/RBX/red-zone fixture
and four same-process real-writer races. Original comparators, seeds, masks,
trace limits and old populations remain in place. Gate-PC witnesses distinguish
early bypass from a captured frame whose dispatcher suppressed the callback.
The profiler runs its reservation/rearm/K/group/owner contract through both
ordinary and early point actions; mandatory callbacks keep AfterCapture.

This is correctness evidence for an opt-in point mechanism. It supplies no
performance result, interval conversion, signal/unwind qualification, topology
coverage or complete A4 release claim.

The [focused results](focused.json) passed at `0a9d29ed3cd13e0de7ff5112f0844d2bbbaeed69`:
9 core tests, 2 planner tests, 1,264 static trace comparisons, four real-writer
race cases (eight candidate traces and 40 restored-state boundaries), and both
profiler contract paths. The straight-line fixture checks 24 actual post-load
visits: 12 helper entries and 12 bypasses. The race cases toggle the real control
after its byte load; they distinguish a bypass from dispatcher suppression.
The 86 selected top-level harness passes include 70 inherited calibrations;
eight nested child passes are recorded separately.

The [full gate](validation.json) passed at
`c905387ff48720a1e0230d4b2e966edea167f8f8`: formatting, strict workspace Clippy,
all-target checking, 4,502 top-level workspace tests (39 unchanged ignores;
11 controlled child passes counted separately), and 1,039 serial launch tests.
All prior allocation, mapping-identity and exec-map regressions passed under
the 12-thread parallel harness. This revision stores two finalized private
arrays as boxed slices; all emitter operations and test assertions remain
unchanged from the focused revision. The full suite executes every new oracle
on the final source. Command durations in the records are operational wall
times, not performance measurements.

All earlier outcomes remain visible: a compilation failure before tests ran,
a straight-line exact-byte failure caused by a redundant MOVZX displacement,
and the first full gate's enum-size Clippy failure. Fixes changed names/types,
emitted encoding and private storage respectively. No comparator, exact-byte
witness, test population, lint or resource bound was weakened. No failed run
was relabelled as a pass.

From a clean checkout at the recorded source revision, use a direct installed
stable Rust toolchain in PATH, create `ignored/a4`, then run:

```sh
cpuset-alloc run --cores 12 --tag li2core-early-point -- \
  python3 -I -B evaluation/early-controlled-point/reproduce.py \
  SOURCE_REVISION ignored/a4/early-point-v1 li2core-early-point
```

The recipe fixes one attempt per command, twelve Cargo jobs and harness threads,
nonincremental debug-zero development/test builds, a single target directory,
per-command wall/output bounds and the existing descendant owner. It records
revision, toolchain, hardware, commands, affinity, load, exit/cleanup outcomes
and every harness summary. Failed outcomes and undispatched commands remain
visible. Raw captures stay private under ignored/; compact reviewed JSON results
belong here. Required full workspace checks use the unchanged
`evaluation/short-neighbor-parallel/validate.py` recipe separately.
