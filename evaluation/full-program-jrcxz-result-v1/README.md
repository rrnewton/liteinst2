# Finite artifact JRCXZ support

At revision `3c1972d634428f7f73cd3ca0ac8cc8ec247481b6`, a canonical two-byte JRCXZ original has an explicit position-independent artifact bridge. Four new pure controls pass. One release native control passed 16 linked and 16 restored full-state comparisons, with eight observing callbacks, across RCX values 0, 1, 2^32 and MAX and two seeds. The existing comparator and child limits are unchanged. This native fixture exercises an observing T3 plan; it does not establish whole-program execution or other native forms.

One release planner attempt per unchanged profile retained all 2,053 requested sites. The 16 MiB result remains 1,749 local plans withheld and 304 primary refusals. The 2 GiB result improves from 2,013/40 to 2,014/39: only site 1425 changes, from an unsupported JRCXZ expansion to a local T1 plan. **Both complete programs still refuse atomically and emit no candidate.** Prior failures remain recorded.

[receipt.json](receipt.json) records the exact source, hardware, inputs, commands, CPU reservations, load, bounds and results. Times are correctness-operation durations, not performance comparisons. The separately required full workspace gate has its own receipt.

To reproduce the release native control, retain [reproduce_native.py](reproduce_native.py) outside a clean checkout of the exact revision, put Rust 1.97.1 on PATH, and run it under one externally reserved disjoint CPU:

```sh
cpuset-alloc run --cores 1 --tag li2-jrcxz-reproduction -- \
  python3.9 -I -B "$RECIPE" \
  --revision 3c1972d634428f7f73cd3ca0ac8cc8ec247481b6 \
  --out target/evaluation/jrcxz-native-reproduction
```

`RECIPE` names that retained script. The output directory must be fresh. The script is a source-reviewed portable reproduction of the private historical build/run controllers; this later script itself was not executed for the recorded result. It uses the same build/native argv, release settings and bounds, and retains failures without retry. Pure controls are `cargo test -p liteinst2 --lib jrcxz -- --test-threads=12` with the receipt's debug0/nonincremental environment.

The complete-program pair uses the unchanged [whole-program runner](../offline-corpus/run_full_program_attempt.py) and the prior [protocol](../full-program-long-t3-result-v1/receipt.json), substituting this revision, build/product pins and fresh output paths. Its earlier GNU protocol supplies the full command arrays. Keep both frozen placement policies. No larger search, reduced roster, E9 retry, runtime parity, profiler accuracy or A5 qualification is credited here.
