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
coverage or complete A4 release claim. Qualification results are pending.

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
