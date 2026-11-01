# Owned-placement policy: complete-program regression

At `4451a77540526c382f5fd82bd3674c4fddc4878e`, the new `full-e9patch-owned-placement-2g-v1` policy **regressed** from 2,014 to 1,982 locally planned sites. Primary refusals increased from 39 to 71. Both reports retain exactly the same **13,143 instruction heads and 2,053 selected jumps**. Forty sites newly refuse and eight previously refused sites now have local plans. Every local plan is withheld by the unchanged atomic complete-program requirement; no complete candidate was emitted or executed.

The 71 primary refusals are 36 `NoPatchWindow`, 32 `ExpectedBytesChanged`, two `AllocationUnavailable` and one `OwnershipConflict`. The 1,982 withheld plans comprise 1,542 B1, 285 B2, 67 T1, 26 T2 and 62 T3. [results.csv](results.csv) compares both profiles; [receipt.json](receipt.json) records exact commands, input/tool/product/report hashes, bounds, CPU assignments, load and normal process closure. The new policy retains the original 2 GiB span, mapped/image/file budgets and one candidate per allocation role. It changes input policy bytes, not the planner's checks or the identity of the old failed policy.

All nine pure Python controls passed, including complete pinned-input generation, outside Cargo. The cached release build check passed on CPU 13; controls and generator/planner ran on reserved CPU 3 on an AMD EPYC Zen 5 dev host. The planner exited 2 after 18.110431045060977 seconds; its owner closed normally without rescue. These shared-host durations are operational measurements, not a performance comparison. This receipt covers the controls, release build and planner; the workspace gate is recorded separately.

To reproduce, check out the exact revision. Supply the 93,520-byte original with SHA256 `890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb`; the [upstream source recipe](../e9-upstream-corpus-c66ea06/README.md) identifies the historical source/tool build, but a changed build must not be substituted. Use the [tracked provider](../full-program-provider/README.md) with explicit `--source MODERN_SOURCE --original ORIGINAL --out FRESH_PROVIDER_OUT` to produce the pinned complete CSV. Its source revision and CSV hash are in the receipt. Coverage and non-code RX-gap premises remain explicit caller inputs.

Build both release examples with the exact `build.argv` and `build.environment` in the receipt (one Cargo job, assertions and overflow checks enabled). Then obtain the legacy material files using:

```sh
target/release/examples/full_program_bridge --trusted-complete-code \
  "$ORIGINAL" "$CSV" \
  591845048470e947952fe064286d61f4a06413e5d01ae80c8504597e6c089562 \
  "$MATERIALS"
```

This legacy bridge deliberately refuses its old 1,024-site limit **after writing the complete** ledger and inventory. Require ledger SHA256 `727d43acbbb31ac419ba2a87f75433a495c2b838fa9d6d08a138d16c6e52e60d` and inventory SHA256 `7d3e1d485fad55ed75139a40fc456374f9fcdbda101096a5d137d1df758b4f5f`; do not reduce the roster. Write `policy.target_text` from the receipt verbatim to `$TARGET`. Set `$LEDGER` and `$SITES` to those files. Use fresh output directories:

```sh
/usr/bin/prlimit --cpu=45 --as=536870912 --fsize=16777216 --core=0 -- \
  /usr/bin/python3.9 -I -B evaluation/offline-corpus/full_program_owned_policy.py \
  --original "$ORIGINAL" --ledger "$LEDGER" --inventory "$SITES" \
  --target "$TARGET" --out "$OUT/policy"
/usr/bin/prlimit --cpu=180 --as=3221225472 --fsize=536870912 --core=0 -- \
  target/release/examples/disassembly_sites --whole-program-4096 \
  "$ORIGINAL" "$LEDGER" \
  727d43acbbb31ac419ba2a87f75433a495c2b838fa9d6d08a138d16c6e52e60d \
  "$OUT/policy/policy-owned-2g-v1.txt" \
  e2cec9db2100a39966f883efdea2fbb4f01d38aefd20e6a494c97ebc755e18f5 \
  "$OUT/li2-owned-2g"
```

These are the portable workload commands. The measured run used a private controller around the existing [process owner](../admission/processes.py), a retained disjoint one-CPU reservation, 60/240-second stage wall limits and 1/8 MiB combined-log caps. Preserve those limits and owner closure when reproducing; `prlimit` alone does not supply them. Exact controls argv, outer bounds and clean environment are in the receipt. Retain every outcome; no retry or emitted-code execution is part of this experiment.

The [previous complete-program failures](../full-program-jrcxz-result-v1/) and all prior profiles remain failed. The earlier strict 1,342/2,048 profiler result, E9 execution diagnostics, PIE startup, runtime parity and A5 qualification receive no new credit here.
