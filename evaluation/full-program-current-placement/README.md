# Reproduce one current-composition placement attempt

[reproduce.py](reproduce.py) performs one release build and one offline planner attempt against exact source `fc13f85bf8345b79a222a3bc24a8cee0b9d714d3`. It uses the original 2 GiB policy, SHA256 `ef09bcd4c78949ff4b93a928c59e04b545081f9e56c2056f2cfcdfe068604cce`, with `--whole-program-current-placement-4096`. It never invokes a generator, backend, original program or emitted candidate. This unexecuted reproduction recipe supplies no measured result; all earlier failed profiles remain failed.

Provide the exact original ELF, complete ledger, site inventory and old policy. Their sizes and full hashes are enforced independently by the script. The [original source recipe](../e9-upstream-corpus-c66ea06/README.md), [complete provider](../full-program-provider/README.md) and [whole-program input recipe](../full-program-whole-result-v1/README.md) describe input preparation. If needed, reconstruct the old policy with the existing [full_program_policy.py](../offline-corpus/full_program_policy.py) and that receipt's exact target text before this attempt; require the hash above. Do not substitute the owned-policy generator or reduce the 13,143-head/2,053-site roster. Complete-code and both non-code RX-gap premises remain caller supplied.

Use a fresh reproduction checkout, its offline Cargo dependencies, and a retained disjoint HARD singleton CPU reservation. The owner must enforce the lane quota; the script checks affinity but does not allocate CPUs. Set `ORIGINAL`, `LEDGER`, `SITES`, `POLICY` to four distinct absolute input paths, `TOOLCHAIN_BIN` to the Rust toolchain's bin directory, and `OUT` to a fresh absolute direct child of the checkout's `ignored/` directory.

The script was published after the source it reproduces. Preserve it outside the fresh checkout before switching to the exact historical source:

```sh
RECIPE_COPY=$(mktemp "${TMPDIR:-/tmp}/li2-current-placement.XXXXXX.py")
cp evaluation/full-program-current-placement/reproduce.py "$RECIPE_COPY"
git switch --detach fc13f85bf8345b79a222a3bc24a8cee0b9d714d3
/usr/bin/python3.9 -I -B "$RECIPE_COPY" \
  "$ORIGINAL" "$LEDGER" "$SITES" "$POLICY" "$OUT" "$TOOLCHAIN_BIN"
```

The unchanged [process owner](../admission/processes.py) bounds the release build at CPU240s/AS4GiB/file128MiB/wall300s/log8MiB, then the planner at CPU180s/AS3GiB/file512MiB/wall240s/log8MiB. The output ceiling remains2GiB. Jobs/harness threads are1; release opt3/debug0, assertions/overflow checks, offline/nonincremental and one target are explicit. It records tool/source/input identities, owner results and logs; stops on build or custody failure; and never retries. Exact tracked state, inputs, tools and the built planner are checked before planning and afterward. A different toolchain's binary is not the historical measured binary.

Raw artifacts go under `OUT`; bounded logs initially use the owner's required `target/evaluation` path and are copied only after normal closure. Retain every outcome. Before interpreting it, authenticate every `COMPLETE` member and the exact directory census, full inventory and mode labels: `current-composition-single-candidate-v1`, `B1,B2,T1`, `legacy-T2,T3`, `inherited-long-T3`. Exit2 is an atomic refusal; exit0 means only an offline candidate exists. Qualification remains false.

This portable recipe is distinct from measured campaigns' private controller, which additionally authenticates the root-pinned closed build receipt and verifies the manifest/inventory automatically. Published numbers must cite their own closed receipt; this recipe establishes no runtime, parity, all-site completion or speedup result.

## Closed result at fc13f85

The single current-composition attempt **refused the complete program**: 2,042 local plans were withheld and 11 sites had primary refusals. No candidate was emitted. All 13,143 heads and 2,053 site identities match both historical comparisons. The original 2 GiB policy bytes, one-candidate and resource limits are unchanged; the opt-in mode changes B1/B2/T1 selected-address placement while retaining legacy T2/T3 placement and inherited long-T3 ownership.

| Profile | Withheld local plans | Primary refusals | Complete candidate |
| --- | ---: | ---: | --- |
| Historical original 16 MiB | 1,749 | 304 | No |
| Historical original 2 GiB | 2,014 | 39 | No |
| Historical owned 2 GiB | 1,982 | 71 | No |
| Current-composition 2 GiB | 2,042 | 11 | No |

The 11 current refusals are eight `NoPatchWindow`, two `ExpectedBytesChanged` and one `AllocationUnavailable`. Relative to original 2 GiB, 28 previously refused sites now have withheld local plans, with no new primary refusals. Relative to owned 2 GiB, 61 do so, while site 1392 newly refuses. All complete-program outcomes remain failed. [results.csv](results.csv) and [receipt.json](receipt.json) retain counts, transition IDs and evidence hashes.

One HARD CPU (CPU 3) on an AMD EPYC Zen 5 dev host was used. The planner exited 2 normally after 16.827642s; its outer owner exited 2 after 17.706127s. No rescues occurred; source was unchanged and owner identities/scope were absent afterward. All 4,133 manifest members were verified. These are operational durations, not performance results. No generator, backend or native invocation occurred in this corpus attempt.

The script above remains the exact approved, unexecuted portable recipe; these numbers come from the separately closed private campaign. Earlier failures, including the strict profiler's 1,342/2,048 short result, remain failed. This receipt covers the release build and planner; the workspace gate is recorded separately.
