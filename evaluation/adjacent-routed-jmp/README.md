# Adjacent backward branch and routed successor

Claim 4 / A3 core increment: the explicit artifact planner now handles a
backward two-byte JBE immediately before a forward two-byte JMP and an unselected
three-byte MOV R12→RDI. It relocates the JMP/MOV, retains a separate routed MOV
entry, then places the JBE generalized pun against the resulting source bytes.
The ordinary planner and existing forward-Jcc pair profile retain their guards.

The API is `plan_adjacent_routed_jmp_with_emission_after`. Its opaque result
contains upper Relocation and lower GeneralizedPun members. Original byte and
entry authentication, pending ownership, transactional composition and separate
cumulative upper/lower/continuation budgets remain mandatory. Pair accounting
covers its two new members; callers must also enforce predecessor and whole-file
limits. Native/router/frontend/artifact qualification remains false.

At merged revision `7bbc027f91ab271c27f47a4893b53a7e61e71606`, **21 new controls
pass**. They exercise actual emitted images and both entry paths, original-byte
and entry mutations, prior compositions, pending suffix ownership, rollback,
page permits, hook reachability and independent budget exhaustion.

The required parallel workspace passes **3,670 tests, 0 failures, 37 ignored**
in 868.41 seconds; serial launch passes **1,039 tests, 0 failures** in 127.62
seconds. Formatting, strict workspace Clippy and all-target checking pass.
The run retains 316 test threads on 16 reserved CPUs. All 21 short-neighbor
tests, both previously flaky staged-drop tests, the prefixed-pun native campaign
and both Rapid rejection regressions pass. Five nested child summaries are
excluded; two custom harnesses complete separately.

[receipt.json](core-7bbc027/receipt.json) records exact source revisions/hashes,
commands, CPU reservations, load, hardware and raw-log hashes.
[controls.csv](core-7bbc027/controls.csv) lists all 21 controls. It retains two
initial compile failures on identical source, including the accidental repeat
after an edit precondition failed, and two subsequent lint failures. Six
verifier calls were inlined to fix temporary-borrow lifetimes; `inspect_err`,
direct Copy and formatting preserve their predicates. No fixture, assertion,
budget or comparator was relaxed. Raw logs stay in ignored storage.

These are debug-build correctness checks on an AMD EPYC Zen 5 dev host.
Elapsed times are command receipts, not performance measurements. Native
execution of this mixed pair, routed fault delivery, frontend integration and
full-program corpus success remain pending. Existing corpus refusals remain
recorded in [the earlier diagnostic](../adjacent-b2/corpus-21728d7/README.md).

To reproduce, use Rust 1.97.1 and Python 3.12 at the tested revision, reserve
16 disjoint CPUs, and run the existing bounded driver with a fresh output path:

```sh
env CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true \
  CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
  CARGO_PROFILE_DEV_OPT_LEVEL=0 CARGO_PROFILE_TEST_OPT_LEVEL=0 \
  CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true \
  CARGO_PROFILE_DEV_OVERFLOW_CHECKS=true CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true \
  LITEINST_EVALUATION=1 \
  python3 -B evaluation/short-neighbor-parallel/validate.py \
    --revision 7bbc027f91ab271c27f47a4893b53a7e61e71606 \
    --output ignored/adjacent-routed-jmp-core-reproduction
```

The focused command is
`cargo test -j 4 -p liteinst2 --lib quiescent::adjacent_routed_jmp::tests:: -- --test-threads=4`.
The full driver runs the same controls within its 316-thread workspace run.
