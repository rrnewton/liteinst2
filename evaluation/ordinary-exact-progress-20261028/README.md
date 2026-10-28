# Ordinary-call semantic work: incomplete qualification

**UNQUALIFIED.** All four complete campaign attempts in `whole-attempts.csv`
failed. Three missed the unchanged 2 ms clock deadline; the first instead
returned callback-fatal exit 123 while refusing a duplicate request, where the
recipe required exit 1. No later partial result fills an earlier missing case.

At revision `abe8b945795ceed5ce36b5b826a943f94543999c`, the four native
original/installed pairs completed 1,696 full-state comparisons with zero
mismatches, including both real target returns and the outer return. Six of
the eight concurrent cohorts completed; late-long K10 failed and late-long
K1000 was unrun. `native-pairs.csv` preserves the four numeric rows;
`partial-work.csv` preserves three rows per completed cohort (two workers and
their combined population). These are observations within a failed campaign.

The alternating K10 population averaged 200 original semantic instructions per
call; its ten retained calls averaged 162.2. The exact error is
−18,144/480 = −37.8 instructions per call. Alternating K1000 retained all
48 calls and had zero error. This is a finite semantic-work observation, not
a PMU measurement, timing-accuracy result or general sampling guarantee.

The diagnostic fixes a maximum of ten late-long K10 sessions and stops on
the first failure, never the first success. The initial diagnostic at
`6d031ea62ad463073c49d6ea36a8f6642109e4ae` stopped at case 3 with a
3.19 ms poll gap. Independently bracketed thread accounting recorded one
involuntary context switch. That supports scheduling delay in this observation;
it does not establish exact off-CPU time or the cause of previous failures.
The tracked portable recipe at `29c90d1cda9e161279aa73bf83391c9b4381788f`
then completed its fixed ten sessions: 480 calls, 5,200 arms, no rescues.
Its result is **NO_FAILURE_REPRODUCED**, not whole-campaign PASS. The consumer
binary is byte-identical to the earlier diagnostic binary. The portable recipe
replaces the earlier private fixture/build inputs with fresh authenticated
build commands; it reproduces that diagnostic design, not its observed outcome.

All native/session observations use release optimization 3 with assertions and
overflow checks enabled. Cargo reported the portable consumer artifact as fresh
(reused), which the receipt records. Hardware was an AMD EPYC Zen 5 dev host,
family 26, model 17, stepping 0. `receipt.json` binds revisions, commands,
tool versions, profiles, artifact/receipt hashes, all eight cohort statuses and
the CSV files. Raw logs and captures remain under ignored storage. The entire
public record is under 26 KiB.

To reproduce, use a clean checkout at the desired recorded revision and a new
absolute output directory under its `ignored/`. Supply absolute toolchain,
user-home and Cargo-home directories. The portable diagnostic requires exactly
four inherited CPUs; the reservation is not a guarantee against unrelated host
tasks. With `cpuset-alloc` installed:

```sh
cpuset-alloc run --cores 4 --sample-s 1 --tag ordinary-diagnostic -- \
  python3 -B tools/rapid-profiler/diagnose_normal_session.py \
  --revision "$LI2_REVISION" --raw "$LI2_RAW" \
  --toolchain "$LI2_TOOLCHAIN" --user-home "$LI2_USER_HOME" \
  --cargo-home "$LI2_CARGO_HOME"
```

Use revision `29c90d1cda9e161279aa73bf83391c9b4381788f` for that recipe.
The earlier four whole attempts have their own exact revisions in the receipt:

```sh
cpuset-alloc run --cores 4 --sample-s 1 --tag ordinary-exact -- \
  python3 -B tools/rapid-profiler/verify_normal_session_two.py \
  --revision "$LI2_REVISION" --raw "$LI2_RAW" \
  --toolchain "$LI2_TOOLCHAIN" --user-home "$LI2_USER_HOME" \
  --cargo-home "$LI2_CARGO_HOME" --exact-work
```

`checks.csv` records the seven development gates at pre-merge revision
`6d031ea62ad463073c49d6ea36a8f6642109e4ae`: 3,010 default-parallel workspace
tests passed, 36 ignored; all seven historical admission/allocation regression
tests passed. These checks make no claim about a later merged revision. They
can be rerun with `evaluation/admission/check_exec_identity.py --checks-only`
and its `--toolchain`, `--cargo-home`, and fresh `--output` arguments.
