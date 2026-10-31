# Dynamic cyclic-region experiment

The opt-in dynamic owner selects two adjacent source pages from a real TRACE handoff. Generated execution can cross direct and back edges and guard four scalar MOV-store forms. Full source and registered-rseq custody cover each epoch; completed permits control warm reuse and resident replacement. The default profile is unchanged. Finite publication and tactic validation support claims 1 and 4; whole-process coverage and performance remain unqualified.

Fresh [fixed five](results/20261031T024528.851994Z-persistent-epoch-adb63e09a06f.json) and [dynamic five](results/20261031T024718.412313Z-persistent-dynamic-adb63e09a06f.json) pass at `adb63e09a06f8560c00a93f06e5d0c0710c61af7` on one reserved AMD EPYC 9D85 CPU. Dynamic qualification requires both complete native/generated state pairs, actual classified-miss cancellation, two cold publications, one warm entry, one completed replacement, and zero interior signals across three focal generated epochs. Full source, registered-rseq, code, memory-effect and revocation checks remain.

The selected-root correction adds a diagnosis for the seven existing selected instruction kinds. It requires a second complete decode of the same held bytes and exact whole-object refusal matches, then follows the existing source/rseq release and selected-instruction route. Pure tests add 116 selected encodings, 19 terminal cases and 13 corruption controls; all 26 historical plan comparisons, 14 classified misses, 10 terminal cases, 56 corruptions and 42 placement cases remain. Three selected-reason controls supplement the unchanged 115 owner, 32 application, eight pair and 180 terminal controls. The complete 4,181,696-byte capture fits the original 4 MiB bound. The finite hardware cohort records no ROOT_SELECTED cancellations; its actual classified miss is the inherited unsupported-root case. Selected-root evidence here is pure classification and counter-validation coverage.

The following [current release LS run](results/20261031T024847.538211Z-persistent-dynamic-ls-adb63e09a06f.json) ([CSV](results/20261031T024847.538211Z-persistent-dynamic-ls-adb63e09a06f.csv)) **fails** with exit -9 after 30.181648940 s from process launch to reap. Its terminal output is empty, so event counts are unavailable. Source and cleanup checks close successfully. This is a failed bounded experiment, not completed-program timing or a speedup. The target of at most ten times DynamoRIO remains unmet.

## Retained failures and corrections

The [85b4e8b run](results/20261031T014006.564222Z-persistent-dynamic-85b4e8bdca70.json) remains **FAILED; four of five cases passed**: generated success hit the unchanged 30 CPU-second limit; late-fault and protected-word cases passed. The portable `8555314` sampler captured [30 attributed samples](results/20261031T021946.423894Z-persistent-dynamic-sample-85b4e8bdca70.json) ([CSV](results/20261031T021946.423894Z-persistent-dynamic-sample-85b4e8bdca70.csv)) from that old runtime; its subject still exited -9. Saved signal PCs are progress observations, not live PCs or qualification. Two earlier [sampler failures](results/20261031T021900Z-persistent-dynamic-sampler-failures.json) remain failed.

`c22e7c2` declines provably unreachable code-bank placement before taking ownership, preserving the existing fallback. Its [run](results/20261031T020227.639512Z-persistent-dynamic-c22e7c2efdbb.json) also remains **FAILED; four of five cases passed**: generated success exited zero in 14.281605374 s, but the strict reader failed. `76231a0` requires the actual nonwrapping rseq-check increment; `d650fc7` requires decoder JMP family 3. Whole-state comparators remain, with four added causal controls. Retained-reader replay passes owner/native-pair/terminal checks and 55/16/4/60 controls; this does not replace fresh hardware qualification.

For fresh reproduction at `adb63e09a06f8560c00a93f06e5d0c0710c61af7`, use one reserved-CPU shell. Set `fresh_fixed_json` to the first command's newly produced passing public JSON. Run each successor only after its predecessor passes:

```sh
rev=adb63e09a06f8560c00a93f06e5d0c0710c61af7
python3 -B evaluation/inprocess/persistent_epoch.py --expect-revision "$rev"
python3 -B evaluation/inprocess/persistent_dynamic.py --expect-revision "$rev" --fixed-receipt "$fresh_fixed_json"
python3 -B evaluation/inprocess/persistent_dynamic_experiment.py --revision "$rev" --output target/page-region-next/dynamic-ls-reproduction
```

Use a fresh output directory. Program limits remain 30 CPU seconds, 60 wall seconds, 512 MiB and 16 MiB output. One LS diagnostic provides no aggregate speedup or ten-times-DynamoRIO qualification.

Earlier [fixed five](results/20261031T022029.794763Z-persistent-epoch-85553148b7c3.json) and [dynamic five](results/20261031T022141.356429Z-persistent-dynamic-85553148b7c3.json) pass at `85553148b7c3509c25d8525074bf8a7050558c46` on reserved CPU 6. Dynamic evidence retains both native/generated state pairs, 115 owner rejection controls, one focal classified miss, two cold publications, one warm entry, one completed replacement and zero interior signals across three focal epochs.

The following [release LS experiment](results/20261031T022310.993410Z-persistent-dynamic-ls-85553148b7c3.json) ([CSV](results/20261031T022310.993410Z-persistent-dynamic-ls-85553148b7c3.csv)) **fails** exit 125 at the strict planner guard after 23.539372017 s. Its partial population is 6,938 completed generated epochs, 5,742 publications, 1,196 hits, 7,051 cancellations, 54,889 inherited events (38,261 traps), and 29,733 fresh maps acquisitions from 802,858 queries. This is neither completed-program timing nor a speedup. The later selected-root correction does not turn this historical failure into a pass. Retained interpreter bytes identify an RDTSC at the next root: it has the correct selected-effect refusal, but lacked a typed dynamic diagnosis.

The published passive sampler remains scoped to its exact historical 15-reason runtime layout; reproducing its result uses sampler revision `8555314` and runtime revision `85b4e8b`. A newer runtime layout is not accepted by that sampler.

All [six required checks](results/20261031T025008.440750Z-checks-adb63e09a06f.json) pass on the same source revision: 362 recorder tests; formatting; Clippy with warnings denied; workspace tests (4,071 passed, 37 ignored, 109 harnesses); the all-feature/all-target check; and 1,039 serial launch tests across 27 harnesses. Four reserved CPUs and the original timeouts were used.
