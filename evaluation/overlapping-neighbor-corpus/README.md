# Complete artifact; LI2 help matches original

One planner attempt at `392e4fbf82df434da0e782ff15556ad1a2b66812` emitted a complete artifact for all 2,053 selected sites and 13,143 heads, with zero refusals. Tactics: B1 1,817; B2 125; T1 24; T2 23; overlapping T3 64. This does not mean 2,053 uses of the new tactic.

In the subsequent single `e9patch --help` attempt per arm, original and LI2 both exited 0 with identical 947-byte stdout and empty stderr. E9 received SIGSEGV (exit -11), with empty streams. **The three-arm comparison remains FAILED_OUTCOME_RETAINED**: LI2/original parity is true; E9/original parity is false. This finite help observation does not establish all-sites execution, live-publication, whole-program equivalence or performance qualification.

The artifact has 2,140 generated pages, 647 RX runs, 652 loads and 661 headers. Its rounded load span is 521,179,136 bytes (497.03515625 MiB). The native subject cap stayed 1 GiB. The retained E9 artifact has an 8,857,190,400-byte virtual load span, above that cap; this static constraint does not identify the first failing kernel check. The [old 512 MiB profile](../full-program-bounded-hull/README.md) remains failed with 2,034 withheld plans, 19 refusals and no candidate; earlier [LI2 ENOEXEC and E9 SIGSEGV](../full-program-entry-veneer/README.md) failures also remain. Initial native preparation timed out at a 5s capacity query, before any copy or subject. Only the metadata-query allowance changed; the later comparison used unchanged subject/runner limits.

[receipt.json](receipt.json) records exact hashes, commands, CPU/load, UTC and closed owners. [results.csv](results.csv) retains planning and native outcomes; failed-planning tactics count withheld plans. Hardware: AMD EPYC Zen 5 dev host. Durations are not benchmarks. The [correctness campaign](../overlapping-neighbor/README.md) is separate.

Copy both public scripts to absolute paths **outside** a clean checkout before switching to the measured revision. Obtain the five exact [pinned inputs](../full-program-bounded-hull/README.md): `ORIGINAL`, `LEDGER`, `SITES`, `POLICY_2G`, `TARGET`. Set `TOOLCHAIN_BIN` to the selected installed toolchain; the measured build used rustc 1.97.1. Reserve one external HARD CPU at 100% quota through each closure. `OUT` and `HELP_OUT` must be fresh absolute paths directly under checkout `ignored/`.

```sh
cp evaluation/overlapping-neighbor-corpus/reproduce.py "$REPRODUCER"
cp evaluation/overlapping-neighbor-corpus/run_help.py "$HELP_REPRODUCER"
/usr/bin/git switch --detach 392e4fbf82df434da0e782ff15556ad1a2b66812
/usr/bin/python3.9 -I -B "$REPRODUCER" "$ORIGINAL" "$LEDGER" "$SITES" "$POLICY_2G" "$TARGET" "$OUT" "$TOOLCHAIN_BIN"
```

[reproduce.py](reproduce.py) runs seven controls, generates the exact policy, then builds and plans once. The measured campaign reused the unchanged policy from `2dc600f` before its fresh build. Both retain complete inputs and the 2 GiB output cap plus 64 MiB reserve under the 20 GB slot ceiling. No retry or native execution occurs in this script.

For [run_help.py](run_help.py), authenticate the receipt's candidate and [E9 artifact](../full-program-backend-result-v1/README.md) pins first. Set `LI2_ARTIFACT` to `$OUT/planner/candidate.elf` and `E9_ARTIFACT` to the retained E9 candidate. Supply fresh, distinct mode-0500 copies (9,179,143 bytes combined), preserving originals. Before copying, require max(allocated, apparent) slot usage plus 64 MiB to stay below 20 GB, counting hard links conservatively. The wrapper relies on this external capacity premise.

```sh
mkdir -m 700 "$COPIES"
cp --reflink=never -- "$LI2_ARTIFACT" "$COPIES/li2"
cp --reflink=never -- "$E9_ARTIFACT" "$COPIES/e9"
chmod 0500 "$COPIES/li2" "$COPIES/e9"
/usr/bin/python3.9 -I -B "$HELP_REPRODUCER" "$ORIGINAL" "$COPIES/li2" "$COPIES/e9" "$HELP_OUT"
```

Each subject retains CPU5s/AS1GiB/wall10s/file+stream+log64KiB/core0/cleanup3s, canonical argv, identical environment and an empty private cwd. The runner has CPU30s/AS2GiB/file1MiB/wall60s/log128KiB. One attempt per arm; matching failures never pass. The wrapper copies verified raw captures only after durable closure and cleanup. Both portable wrappers are source-authored/unexecuted; the generated help runner equals the executed runner byte-for-byte. The measured comparison's nonzero exit remains a failure.
