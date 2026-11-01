# Fitting mixed-neighbor mode

At `a840edc6abdedd8f79a03f6c5d89cb845a23e9c1`, the fitting corpus attempt remains **FAILED: 2,052 local plans withheld, one primary refusal, no complete candidate**. Site **1888**, at PC/file offset 57,842, still reports `AllocationUnavailable`. All 2,053 selected sites and 13,143 heads remain. The focused controls passed **17 core + 2 rewrite-library + 2 CLI tests** with no failures or ignores. The [workspace gate](../full-program-fitting-full-validation/) passed **4,318/0/39**, with serial launch **1,039/0/0**, subject to its explicit raw root-stat retention limitation.


Against the closed mixed-neighbor 2,049/4 baseline, primary refusals **1392, 2040 and 2041** now have local plans; there are **no new primary refusals** and 1888 remains. Thirteen report rows changed and 2,040 are unchanged. Withheld tactics are **B1 1,623; B2 355; T1 38; T2 13; T3 23**. This is a fitting-versus-mixed comparison only; it does not infer new row comparisons to the older profiles or promote a local plan into a complete candidate.

The release build closed normally on CPU 1 in **38.439899761928245 s**, but its review ordering was wrong: root's metadata collector expected 13 top-level functions instead of the actual 15 unchanged functions. The collector and dependent preflight failed, and root did not stop dependent execution, so the build began before the source-review/preflight seal. Runtime exact-source/tool/single-CPU checks and normal closure passed; the build was retained without repeat. The source review was completed after the build and before the separately completed corpus preflight and dispatch. The receipt preserves this limitation; later review does not retroactively satisfy the missing build ordering.

The planner ran once on CPU 6 and closed normally with refusal exit 2 in **18.98995495494455 s**; its enclosing owner also exited 2 in **19.86935737519525 s**. Source remained unchanged, cleanup completed with zero rescues, and root authenticated owner/scope release. The product namespace contains 4,152 retained files totaling 425,649,711 apparent bytes; the broader private output scope totals 439,767,040 allocated bytes, below the unchanged 2-GiB post-stage gate. No generator, backend, original or candidate was executed. These durations are operational wall times, not a performance comparison.

| Focused sequence | Revision | Core pass/fail | Library pass/fail | CLI pass/fail | Outcome |
|---|---|---:|---:|---:|---|
| 1 | `0db9d61f` | 15/2 | not started | not started | FAILED |
| 2 | `9190c687` | 17/0 | 1/1 | not started | FAILED |
| 3 | `a840edc6` | 17/0 | 2/0 | 2/0 | PASSED_FOCUSED_21 |

The first correction fixed two new test assumptions: longer observing instructions use the existing window constructor, and an unresolved hook is rejected at final linking. The second correction reads the exact two `EngineAttempt` tactic fields, preserving **GeneralizedPun then Relocation**, rather than matching an earlier winning-plan metric. Both corrections changed tests only. The failed sequences remain failed; no case or required assertion was waived.

[receipt.json](receipt.json) binds the three root-authenticated closures, exact source revisions, final commands, CPU set, loads and tool hashes. The final sequence used twelve reserved CPUs, twelve jobs/test threads, 180 seconds and 8 MiB per child, and a 600-second/8-MiB outer owner. All dispatched owners closed normally with zero rescues; root authenticated unchanged source and release. Its 5.816143165109679-second outer duration is operational wall time, not a performance result. The first failed controller left final source flags unknown; its separate root checks and that collector refusal remain recorded.

The new explicit CLI is `--whole-program-fitting-mixed-neighbors-4096`. It retains all 2,053 selected sites and 13,143 heads, the original 2-GiB policy, one candidate/mapping/4-KiB limit per role, complete pending-selected ownership and final atomic checks. B1/B2/T1 and both mixed-T3 roles use a conservative capacity certificate followed by one actual emission. T2 placement remains legacy. Complete first-four bundles must pass inherited and pending ownership before tactic success; a refusal consumes the attempt and advances once, while forced tactics stay forced. The exact mode metadata is in the receipt.

[results.csv](results.csv) preserves the five historical corpus rows literally: original 16-MiB **1,749/304**, original 2-GiB **2,014/39**, owned policy **1,982/71**, current placement **2,042/11**, and mixed neighbors **2,049/4** (withheld local plans/primary refusals). The appended fitting row is **2,052/1**. Every row remains a complete-program refusal with no complete candidate. The strict profiler short result remains **FAILED 1,342/2,048**.

## Reproduce one build and one corpus attempt

The [portable script](reproduce.py) is source-authored and remains unexecuted. It changes only the prior script's fixed revision, CLI mode and docstring; its input, source, lifecycle and bound checks remain. The closed build and corpus above used separate private controllers; the portable script has not run and adds no execution credit.

Supply the exact original, complete ledger, site inventory and unchanged policy in four distinct files. Their byte lengths and SHA-256 values are in the receipt. The [original artifact recipe](../e9-upstream-corpus-c66ea06/README.md), [provider recipe](../full-program-provider/README.md) and [whole-program input recipe](../full-program-whole-result-v1/README.md) describe their public provenance. The original executable is externally supplied unless its exact hash matches. The existing [policy generator](../offline-corpus/full_program_policy.py) documents the input policy; this reproduction does not rerun it.

Copy `reproduce.py` outside the checkout before checking out the historical revision; the script is not present at that source commit. In a clean checkout with offline caches, use a fresh output directly under `ignored`, an external one-HARD-CPU reservation and a 100% CPU quota. Set `REPRODUCER`, `ORIGINAL`, `LEDGER`, `SITES`, `POLICY`, `OUT` and `TOOLCHAIN_BIN` to absolute paths, with `OUT` not yet existing:

```sh
git switch --detach a840edc6abdedd8f79a03f6c5d89cb845a23e9c1
/usr/bin/python3.9 -I -B "$REPRODUCER" "$ORIGINAL" "$LEDGER" "$SITES" "$POLICY" "$OUT" "$TOOLCHAIN_BIN"
```

The script builds the release examples offline/locked with one job, optimization 3, debug information 0, debug assertions and overflow checks enabled, no incremental build, and the sole `target` directory. It uses the existing process owner, closes each stage before reading its bounded log, pins the built planner before dispatch and retains refusal exit status. Build limits are 240 CPU seconds, 4 GiB address space, 128 MiB/file and 300 seconds wall; planner limits are 180 CPU seconds, 3 GiB, 512 MiB/file and 240 seconds wall. Each combined log is capped at 8 MiB. The 2-GiB output gate checks apparent and allocated totals after closure; it is not an instantaneous aggregate quota. There is one attempt, no retry, no backend invocation and no original/candidate execution.

To reproduce the focused source checks separately, use the three exact `focused.commands` vectors and inherited-environment overrides in the receipt under a disjoint twelve-CPU owner with the recorded 180/600-second and 8-MiB bounds. The complete required census is 17+2+2; compilation alone or an empty filter is not a pass.

The [workspace receipt](../full-program-fitting-full-validation/) remains separate. Its five-command gate and final metadata reader closed normally with zero rescues. Earlier metadata attempts remain failed, including one reader owner that rescued 134 descendants; the independent raw root-stat string was not retained and cannot be replayed. Complete-code and non-code RX-gap premises are caller supplied. These receipts make no native-equivalence, PIE-startup, performance or A5 claim. Raw logs stay private.
