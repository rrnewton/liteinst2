# Finite cached CALL and RET owner experiment

This opt-in experiment retains three cases: a cached CALL and cached RET hit, a loaded RET miss, and the same miss with an observer-only eight-byte change to the consumed guest stack word. Each case runs native, maintained and maps-differential subjects. It checks all ten native frames, complete GREG/FP/context state, 520-byte stacks and the existing five-phase private-C3 continuation record. A loaded miss consumes the saved target once; it never replays or rereads the original RET.

The finite result is not whole-profile or performance qualification. The original 392/522 gates and the within-10x-DynamoRIO objective remain pending. The observer and seed interpreter belong to this finite fixture; they are not a real-program startup result.

From a clean checkout, hold CPU 3 for the entire command:

```sh
taskset -c 3 cpuset-alloc run --cores 1 -- python3 -B evaluation/inprocess/reproduce_ret_owner.py --expect-revision "$(git rev-parse HEAD)" --cpu 3 --output target/evaluation/inprocess/ret-owner-fresh
```

The new driver retains the existing seven public recipes, then runs the separate [compile-only predecessor](../ret_runtime_compile/README.md) and this nine-subject collector. A failed stage stops the chain; no retry or prior-result substitution occurs. Every receipt joins the same clean revision, CPU, hardware and complete decoder archive in place. The four finite prerequisites remain the CALL owner, combined RET32/model671/planner8-model924 and separate low/high native16-case24-lane result, RET15 ordering observation, and two-profile compile-only result. The native subjects retain 5 CPU seconds / 15 wall seconds; gated subjects retain 30 CPU seconds / 60 wall seconds, 512 MiB address-space and 16 MiB output limits. The protected record retains its separate 4 MiB cap. Both fresh bridge builds must complete the full byte oracle before any subject.

For an already completed fresh prerequisite chain, `run.py` accepts explicit `--archive-receipt`, `--call-owner-receipt`, `--ret-receipt`, `--ret15-receipt` and `--runtime-compile-receipt`, with a corresponding `--NAME-receipt-sha256` for each. It also requires `--expect-revision`, `--cpu 3` and a fresh `--output`. All receipts and raw captures remain private; a compact public projection may be produced only after independent data review.

The sealed CALL/RET window still uses MAP_32BIT. RET's loaded-miss jump at offset 190 now reads the exact absolute landing from the sealed slot literal at offset 504, so that edge has no signed-rel32 placement restriction. The original-source before-load branch and spill references retain their exact rel32 checks. The standalone high-cluster/low-window matrix is a mandatory separate prerequisite; these nine owner subjects retain their original fixture geometry. The approved image-role classifier is not extended to arbitrary DSOs, and generic dynamic-program coverage remains pending.

The installed portable runner is a source adapter of the tested private collector. Earlier private attempts, including the initial six gated failures, retain their original status; they are not rewritten as installed-source executions.
