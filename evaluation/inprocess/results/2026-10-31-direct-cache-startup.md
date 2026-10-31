Neither `/bin/ls -d .` nor `/bin/true` completed with the direct-frontier runtime at revision `22613d9b26f8be5438fe389d690feb221f62d3db`. Both counted processes ended with `SIGKILL` under the unchanged 30-CPU-second limit. Execution within 10× DynamoRIO remains unestablished. The finite cold-admission and direct-frontier fixtures passed on this source; they do not establish real-program completion or performance.

| Program | Native reference, elapsed | Counted process, elapsed | Counted outcome |
| --- | ---: | ---: | --- |
| `/bin/ls -d .` | 4.273176 ms | 30.197187081 s | Exit −9; no stdout; no terminal record |
| `/bin/true` | 4.710532 ms | 30.347596422 s | Exit −9; no terminal record |

These are single-process elapsed intervals, not user/system CPU measurements or completed slowdown ratios. The [closed real-program result][program226] used one reserved CPU, a 60-second wall backstop, 512 MiB address-space limit and 16 MiB file-size limit per program, with `LD_BIND_NOW=1`. Both counted namespaces were authenticated; source and cleanup closure succeeded with no finalization errors. The receipt binds the original programs, interpreter, dependencies, carriers and generated bridges. Counter pages were read only after reaping. Empty output from killed `true` is not completion.

The actual post-reap ABI2 prefix cells are:

| Cell | `ls` | `true` |
| --- | ---: | ---: |
| Linked handler events | 17,727 | 16,714 |
| SEGV / TRAP / ILL events | 6,084 / 11,544 / 99 | 6,188 / 10,441 / 85 |
| Cold attempts / publications | 8,612 / 3,382 | 7,440 / 3,481 |
| Retirements / root hits | 3,380 / 1,953 | 3,479 / 2,150 |
| Completed entries | 5,383 | 5,685 |
| Unsupported-root / exit-limit / link-limit refusals | 3,009 / 325 / 1,895 | 2,749 / 276 / 932 |
| Outside-pair planning refusals | 0 | 0 |
| Maps queries / maintained hits / fresh reads | 523,089 / 521,780 / 1,309 | 523,389 / 522,252 / 1,137 |

These are independent retained cells, not a completed transaction or a count of all kernel traps. Direct-edge hits, subentry terminal totals and stage timings are unavailable. Both runs used the maintained view; differential comparisons were not performed. The frequent retirements do not prove repeated source identity or predict larger-cache admission. Zero outside-pair refusals does not establish completion. The earlier [11ff real-program result][program11] also remains failed: `ls` and `true` ended at −9 after 30.147825 and 30.152785 elapsed seconds. The two interrupted prefixes do not support a speedup comparison.

The complete 226 chain ran cold9 → native41 → real programs on CPU3, retaining the same source, hardware and decoder archive at every stage. Cold9 and native41 passed; the program stage failed. The closed chain receipt records unchanged source and retained receipts, no finalization error, and no whole-profile credit (SHA256 `f12a2c7ddd3a7d283169b9f0e40c89342e52a40827d85e5a4dcec24068dbf33a`). The three public stage receipts remain separate.

The [cold9 result][cold226] contains nine successful processes: native, maintained and differential lanes for canonical `E9`, taken near-JNZ and fallthrough near-JZ. Each native reference follows 19 original instructions and retains 12 full frames. Each generated lane demonstrates two cold publications and one warm entry, with exact 17-page closure for each activation, 12 modeled generated instructions and seven ordinary instructions, and zero measured interior signals in the three focal epochs. Complete source, GPR/FP, data, stack, permissions and lifetime comparisons passed. All 2,886 subject controls passed: 40 application controls per mode and 270 owner, 32 pair, 73 terminal, 33 TLS, 22 probe, 19 subentry and 12 effect controls per generated lane. The original 216-case handoff component, new cold-direct component and actual decoder/planner seed gate remained mandatory.

The seed correction was specific: `MOV EAX,EAX` replaced the unsupported seed NOP, and the model includes its actual zero-extension and register effects. The added actual decoder/planner gate still requires the old NOP's typed `ROOT_UNSUPPORTED` refusal and full miss validation, then validates both corrected full and compact plans. Its exact 3-case / 5-descriptor / 6-validation / 4-refusal result passed. No opcode whitelist, observer assertion, resource limit or old failed receipt was relaxed.

The [native41 result][finite226] also passed all three lanes and 1,222 subject controls. Its 41-original-instruction fixture retains 12 native full frames and demonstrates two cold publications followed by one shared two-member lifetime: 27 modeled retired instructions in that lifetime, one final ordinary frontier instruction, three modeled cross-certificate transfers, zero measured interior signals in the three focal epochs, and actual RX-to-NX closure of 34 pages. All 23 GREG values and all 65,536 FP bytes remain compared at every paired frame, including the exact flag and CR2 history. The same finite cohort previously passed at [f7eee9f][finitef7], [830790b][finite830], [11ff0bb][finite11] and [4baa1c9][finite4baa]. These fixtures use a source-owned tiny interpreter and retain `whole_profile_qualified=false`.

The first [226 six-check attempt][checks226fail] failed when recorder discovery reached its original 180-second deadline: exit −9 after 180.078 seconds, with the other five commands unexecuted. Its retained partial observations are not a 366-test pass. A separate [second attempt][checks226] passed all six commands on the same unchanged source and corpus. Recorder discovery completed all 366 exact identities; workspace tests completed 112 harnesses with 4,229 passed, 37 ignored and zero failed; serial launch completed 27 harnesses with 1,039 passed. The recorder, workspace and serial command intervals were 172.312, 581.934 and 139.709 seconds, within their unchanged 180/900/180-second limits. Formatting, clippy and workspace check also passed. The second result does not relabel the first timeout.

Earlier closed failures remain part of the evidence:

| Revision / attempt | Closed outcome |
| --- | --- |
| [88a8065 census][census-fail] | Protocol failure before either subject. The synthetic eight-slot replay first diverged at attempt 4, not the asserted 5. The successor retained the parser and added exact prefix and sticky-unknown checks. This synthetic sequence differs from the actual c876 sequence. |
| [e3a9c35 direct fixture][direct-fail1] | Component preparation failed; all three subjects unexecuted. |
| [e611f0d direct fixture][direct-fail2] | Failed before all three subjects; no native qualification. |
| [f11be7f direct fixture][direct-fail3] | All processes exited 0, but the gated reader/control pipeline failed. Exit alone was not accepted as qualification. |
| [830790b program probe][program830] | All four program subjects unexecuted: the prerequisite expectation omitted the already-required 118 registered-address controls. The successor added that exact expected count. |
| [830790b six checks][checks830] | All six passed on that source; this did not cover the later merge. |
| [11ff0bb six checks][checks11] | Inventory precheck failed after the main merge; all six commands remained `not_run`. |
| [4baa1c9 cold9][cold4baa] | Three native references passed; all six gated lanes exited 125 before owner/pair qualification. No cold target was reached. The chain stopped before the real programs. |

The 4baa failure exposed a fixture-model error: `66 90` at the seed root was supported by ordinary trap stepping but excluded by the unchanged translated-region whitelist. All six captured prefixes showed the seed offer cancelled with `ROOT_UNSUPPORTED`, then ordinary NOP execution and a later predecessor assertion failure. Both handoff components had passed; that did not qualify the generated fixture. Its failure remains preserved alongside the [4baa six-check pass][checks4baa] and finite41 pass.

The [inventory preflight summary][preflight] also preserves failed R1 and passed R2 separately. R1 failed before its worker because it treated Git's executable-bit metadata as a full Unix mode. R2 checked regular-file type and the Git executable bit, preserved every full mode, and checked all 374 original files before and after copying. Its current-inventory check and two unchanged original test methods completed in 8.077 seconds with zero failures/errors/skips. This staged facade was neither installed six-check qualification nor native/performance evidence.

The earlier [c876 startup census][census] hit the original CPU limit too. It recorded 3,573 publications, including 2,577 repeated exact source-key/registry identities after eviction (72.1%), and 2,308 outside-pair direct-branch planning refusals. Planning incidents are not executed branch counts; the eight-slot counterfactual becomes unknown at attempt 5. The [unchanged census narrative][old-census], [bounded analysis execution][analysis-run] and [complete numeric summary][analysis-summary] preserve the exact counts, provenance and reproduction commands. Raw captures remain private.

Whole-profile qualification still requires the unchanged original 392- and cross-pair 522-instruction cohorts with their original prerequisites, completed real programs, and the same-host ten-run native/DynamoRIO comparison. None is supplied by a finite fixture, a passing reader or a killed prefix. No result here establishes execution within 10× DynamoRIO.

The process measurements used one reserved CPU on an AMD EPYC 9D85, family 26/model 17/stepping 0, microcode `0xb101066`, Linux 7.1.3, Rust 1.97.1 and GCC 11.5.0. The second six-check run reserved CPUs33/43/45/64. Linked compact receipts retain exact source, artifact, hardware, bounds and reproduction arguments; this report contains no raw logs or host-specific paths.

[program226]: 20261031T185004.241929Z-direct-frontier-program-22613d9b26f8.json
[cold226]: 20261031T174316.286742Z-cold-admission-loop-22613d9b26f8.json
[finite226]: 20261031T182658.760413Z-direct-frontier-loop-22613d9b26f8.json
[checks226fail]: 20261031T182940.516711Z-checks-22613d9b26f8.json
[checks226]: 20261031T185241.095736Z-checks-22613d9b26f8.json
[program11]: 20261031T165732.782322Z-direct-frontier-program-11ff0bba39c6.json
[census]: 20261031T153448.082324Z-startup-reuse-census-c876a6bdc9e4.json
[old-census]: 2026-10-31-startup-reuse-census.md
[analysis-run]: reuse-census-analysis-execution-public.json
[analysis-summary]: reuse-census-analysis-summary-public.json
[finitef7]: 20261031T154723.215276Z-direct-frontier-loop-f7eee9fdc21b.json
[finite830]: 20261031T160827.189217Z-direct-frontier-loop-830790b658d6.json
[finite11]: 20261031T163735.974967Z-direct-frontier-loop-11ff0bba39c6.json
[census-fail]: 20261031T152815.530649Z-startup-reuse-census-88a806549dff.json
[direct-fail1]: 20261031T153754.524293Z-direct-frontier-loop-e3a9c353f550.json
[direct-fail2]: 20261031T154015.112828Z-direct-frontier-loop-e611f0dabe8d.json
[direct-fail3]: 20261031T154240.293428Z-direct-frontier-loop-f11be7fc6d50.json
[program830]: 20261031T162943.321868Z-direct-frontier-program-830790b658d6.json
[checks830]: 20261031T160828.372032Z-checks-830790b658d6.json
[checks11]: 20261031T163737.154262Z-checks-11ff0bba39c6.json
[preflight]: inventory-preflight-summary-public.json
[checks4baa]: 20261031T170931.170530Z-checks-4baa1c99b763.json
[finite4baa]: 20261031T170931.714485Z-direct-frontier-loop-4baa1c99b763.json
[cold4baa]: 20261031T172937.195590Z-cold-admission-loop-4baa1c99b763.json
