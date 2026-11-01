# Bounded hull: atomic refusal

At `2dc600f31e1803043e8d56abda721cc8a32b9d4f`, seven controls passed and one 512 MiB policy was generated. All **2,053 sites / 13,143 heads** reached planning: **2,034 local plans withheld; 19 primary refusals** (15 AllocationUnavailable/four OwnershipConflict). [CSV](refusals.csv) lists the two-byte failures. Exit2, no candidate; native templates unactivated.

The new profile clips permissions to `[262144,536870912)` and the hull to 512 MiB. Other caps/search/hints/order stay. Compared with [packed 2 GiB](../full-program-rx-runs/): 19 new refusals, 1,769 unchanged local tactics/265 changed; all identities match, not a plan-byte comparison. [Receipt](receipt.json) binds commands/bounds/CPU/load and measured revisions: reused c622 release, dd71 Rust gate, 2dc controls/planner. No new build/gate. Normal owners/zero rescues; preparation missed independent live observation. Root corrected a collector pin-schema error without rerunning work. All prior failures remain, including [strict profiler](../ordinary-accuracy-results/coordinate-01ca/). Host: AMD EPYC Zen 5 dev host; no startup/native/performance qualification.

## Reproduce

Copy [script](reproduce.py) outside the checkout; source-authored/unexecuted. It runs exact controls, policy generation, a fresh offline release build and one planner with bounded public owners. Obtain the five pinned [inputs](../full-program-entry-veneer/#reproduce-the-measured-revision); TARGET is `target_text` in [this receipt](../full-program-whole-result-v1/receipt.json). Reserve one HARD CPU at100%; absolute paths, fresh OUT directly under ignored:

```sh
/usr/bin/git switch --detach 2dc600f31e1803043e8d56abda721cc8a32b9d4f
/usr/bin/python3.9 -I -B "$REPRODUCER" "$ORIGINAL" "$LEDGER" "$SITES" "$POLICY_2G" "$TARGET" "$OUT" "$TOOLCHAIN_BIN"
```

No retry/native execution. Exact inputs, seven-test census, policy/summary hashes and full output/storage limits remain. Durations are operational only.
