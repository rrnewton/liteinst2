# In-process release observations

Both release experiments passed at revision `40d520a453cabde29a1fcceeef8da30b96a72e9b` (tree `b3d2d8e8c65c19951fed1959c5e99c0cb27e2dfa`). The four required Cargo checks and 330 recorder controls passed. A focused full serial run then passed in 139.431 seconds within the unchanged 180-second bound. The earlier aggregate run timed out in serial validation and remains failed; these are separate experiments.

Hardware: AMD EPYC 9D85, x86-64 family 26/model 17/stepping 0, microcode `0xb101066`, Linux 7.1.3. Both release workloads pinned fresh children to CPU 3 within the runner's eight-CPU affinity; no effective capabilities, seccomp mode 0. Rust release used rustc 1.97.1/Cargo 1.97.1; dynamic C used GCC 11.5.0 with `-O2`. Exact flags, environment, executable hashes and kernel-release hash are retained in the receipts.

Commands, from committed source:

```sh
python3 evaluation/inprocess/run.py --iterations 1000
python3 evaluation/inprocess/dynamic.py --repeats 5
python3 evaluation/inprocess/checks.py --expect-revision 40d520a453cabde29a1fcceeef8da30b96a72e9b
```

## Owned-region patches and NX admission

All ten cases passed. CPUID, RDTSC and returning syscalls used real core `ReplaceFirst` patches published eagerly before NX arming; the signal handler admitted permissions, not instruction patches. Cross-page instruction, cross-page E9 redirect and CALL return into a pending page passed their separate boundary checks. No INT3 or ptrace was used.

Median nanoseconds per call, each from 17 batches of 1,000 calls; fixture-loop overhead is included:

| Case | Native | Patched + admitted |
|---|---:|---:|
| CPUID | 44.227 | 254.583 |
| RDTSC | 13.059 | 221.192 |
| getpid | 72.208 | 287.051 |
| gettid | 69.976 | 289.044 |
| read | 82.223 | 296.014 |
| write | 77.376 | 294.272 |
| read/EBADF | 71.728 | 291.548 |
| Cross-page E9/getpid | 76.564 | 308.133 |

The two gate-only controls had native → admitted medians of 2.754 → 2.784 ns (cross-page instruction) and 20.141 → 22.153 ns (boundary CALL). The boundary CALL admitted two pages through two faults; each other case had one fault, admitting one page or a two-page bundle. All timed steady batches caused zero additional gate faults. The nine state-comparison cases checked 17 register words, 2,287 qualified XSTATE bytes and 128 red-zone bytes; boundary CALL separately checked the pushed original return PC and pending return page.

First-call timings, including each fixture's wrapper, ranged 13.791–21.152 µs across cases. Single-fault handler service ranged 4.016–8.022 µs; boundary CALL's two handlers totaled 11.007 µs, maximum 5.619 µs. Handler clocks exclude kernel signal delivery/return, while external first-call timing includes capture overhead. These are not interchangeable latency measures.

## Dynamically linked program

The dynamic backend used kernel CPUID/TSC/Syscall User Dispatch traps and lazy NX permissions with `source_patches=0`. Coverage began in the preload constructor; earlier loader/startup execution is excluded. Own runtime/vDSO pages were excluded from NX gating. The closed syscall/signal/mapping profile in [tools/page-mode/README.md](../../tools/page-mode/README.md) applies; in particular ordinary `ls -l` may require unsupported NSS sockets, whereas the measured command explicitly used numeric IDs.

Five fresh-process pairs each ran `/bin/ls -d .`, `/bin/ls -ln --color=never .`, and `dynamic_probe` on the same fixed directory. All pairs exited successfully with byte-identical stdout. Every activation passed actual CPUID output/zero-extension, syscall getpid/RCX/R11, and RDTSC bounds/zero-extension checks.

| Measurement | Reference median | Instrumented median | Observed ranges, reference / instrumented |
|---|---:|---:|---|
| `ls -d .`, full process | 2.173 ms | 2.983 ms | 2.076–3.112 / 2.780–3.229 ms |
| `ls -ln --color=never .`, full process | 1.952 ms | 2.703 ms | 1.757–2.460 / 2.570–3.117 ms |
| 1,000 warmed directory scans | 49.965 ms | 57.102 ms | 27.754–63.831 / 35.026–76.453 ms |

Numeric listing consistently faulted on 98 of 575 gated pages and forwarded 34 syscalls. Its NX handler service totaled 197.560–219.321 µs, with maximum individual service 8.623–10.696 µs. These internal service clocks exclude signal delivery/return.

The dynamic probe also exercised real data mmap/mprotect/munmap and application CPUID/RDTSC. After one fixed warm scan, each measured interval performed 1,000 real directory scans and two clock calls: exactly 4,002 dispatched/forwarded syscalls with unchanged NX count. The ratio of median loop durations was **1.143x**. Later formatting/exit touched other pages; zero additional faults is claimed only inside the measured interval.

These observations show substantial run-to-run variation and share host/filesystem caches; pairs ran reference first. Gated boundary-CALL batches ranged 22.123–782.546 ns/call after admission. Process-wall timings include child creation/reaping and harness overhead. No universal overhead, cold-cache or complete arbitrary-application claim follows.

## Evidence

- [Owned-region release receipt](results/20261027T124310.317193Z-40d520a453ca.json): ten complete cases, all child exits zero.
- [Dynamic release receipt](results/20261027T124311.040792Z-dynamic-40d520a453ca.json): all 15 pairs complete. Saved raw rows equal receipt rows; all 84 release stdout/stderr hashes, tested executable hashes and bound source hashes authenticated.
- [Required-check receipt](results/20261027T123050.994258Z-checks-40d520a453ca.json): fmt, strict all-feature/all-target Clippy, workspace test and workspace check passed; workspace observed 2,335 passed + 4 previously ignored across 98 harnesses. Recorder observed 330 passed. Serial timed out after 180.137 s with 794 passed in eight complete harnesses, below the required 1,029 tests/27 harnesses; cleanup completed. All six saved check-log hashes authenticated. No serial success is inferred.

The 900-second workspace profile is explicitly new; the observed workspace command took 412.984 s including build. Earlier 360-second failures and this serial timeout remain preserved failures. The focused serial run completes the remaining required check at the same unchanged source and configuration. Results publication changes no Rust, C or assembly code.

- [Focused serial receipt](results/20261027T124739.135382Z-serial-40d520a453ca.json): all 1,029 tests/27 harnesses passed in 139.431 s, with 50 native cases, 15 dynamic fixtures, 388 matrix records, 108 required native fixtures and complete backing cleanup. The raw capture was replayed through the unchanged strict parser. Its embedded `reproduction_python` preserves the exact focused runner; save it as `target/run-serial-40d.py` at the tested revision, with the referenced prior receipt at its recorded path. `aggregate_qualified=false` keeps this distinct from the failed aggregate.
- [Focused-run preflight refusal](results/20261027T124624.021258Z-serial-40d520a453ca.json): generated Python bytecode caused an untracked-input refusal before Cargo ran. The corrected wrapper disabled bytecode generation; no source-cleanliness predicate changed.

In the earlier aggregate receipt, detail fields named `*_count.observed` count catalog rows, including incomplete rows; they are not completed-case counts. Its qualified counts remain zero. Later summaries use `catalog_rows` for this quantity. The explicit harness observed totals retain their actual meaning.

## Selected instructions and mapping lifecycles

Exact source revision `6f779d0ba8f58473d2b414ae49532d1faab2a5ea` (tree `a4e01ae0739670709c29ed21fc2d207c98c37390`) adds real RDRAND/RDSEED/RDPID/RDTSCP source patches and opt-in executable mapping lifecycles. Hardware and release toolchains match those above; fresh native children were pinned to CPU 3. Reproduce from this committed source:

```sh
python3 evaluation/inprocess/selected.py --iterations 1000
python3 evaluation/inprocess/lifecycle.py
python3 evaluation/inprocess/run.py --iterations 1000
python3 evaluation/inprocess/dynamic.py --repeats 5
python3 evaluation/inprocess/checks.py --expect-revision 6f779d0ba8f58473d2b414ae49532d1faab2a5ea
```

All 118 selected native cases pass: 90 random-instruction width/destination combinations, 15 RDPID destinations, RDTSCP, four actual CPUID-masked dispatch cases and eight accepted-prefix/cross-page cases. Each checks one native and two patched machine states, including 17 register words, 2,287 qualified XSTATE bytes and 128 red-zone bytes. Actual counter records total 2,006,236 completed replacements and 781,409 carry-clear random outcomes. The random oracle checks architectural outcomes and preserved state, not equality with a separate random sample. Seven RSP-destination and six invalid-encoding preparation controls refuse before executing and leave source unchanged. RSP output remains unsupported; this is not complete B2 coverage.

Median nanoseconds per call, from 17 batches of 1,000 calls including fixture-loop overhead:

| Case | Native | Patched + admitted |
|---|---:|---:|
| RDRAND r64/rax | 28.162 | 256.165 |
| RDSEED r64/rax | 810.667 | 1,031.348 |
| RDPID rax | 6.390 | 220.851 |
| RDTSCP | 26.480 | 242.633 |

RDSEED availability varies: 16,210 of this case's 17,002 patched calls returned carry clear. These timings do not compare equal random outcomes or equal success mixes. First calls including the fixture wrappers ranged 10.336–19.209 µs. There was one admission fault per case, admitting 126 pages in total; all measured steady batches caused no additional admission faults. Source patches are published eagerly before NX arming, using the existing qualified core publisher.

The optimized C lifecycle probe performs genuine sealed-DSO dlopen/call/dlclose twice, partial sealed-VMA protection changes, private RW→RX JIT rewrites/address reuse (17→29→41), cross-page fetch and boundary CALL/RET, and actual partial-ENOMEM mprotect cases. Its output equals native. It observes 15 successful mappings, 52 generations all retired, 14 executable admissions and 14 sync-core operations, with zero owned pages left. Twelve separate negative processes require exact failure identities, including a writable alias after partial failure and brk shrink over an owned JIT page. No lifecycle throughput claim is made from this validation run.

The lifecycle backend remains post-constructor, singleton and `source_patches=0`. Original syscalls retain their arguments/results; trusted-handler RX windows are revoked before application return. This demonstrates no application fetch before admission within the stated profile, not literal NX throughout mapping creation. Ordinary unsealed DSOs, original loader startup, threads/process lifecycle and general application signals remain open. See [the lifecycle contract](../../tools/page-mode/LIFECYCLE.md).

All ten prior owned-region probes and 15 dynamic pairs also pass on this revision. Numeric `/bin/ls -ln --color=never .` again observes 98 first-touch faults over 575 gated pages and 34 forwarded syscalls. Its full-process median is 1.349406 ms native versus 2.162245 ms instrumented; observed ranges are 1.315284–1.389926 and 2.123767–2.335635 ms. Median total NX-handler service is 186.992 µs (range 176.542–217.889 µs), excluding signal delivery/return. The warmed 1,000-directory-scan interval has exactly 4,002 forwarded calls and no further admission faults: 27.589144 ms native versus 31.471250 ms instrumented median, a 1.141x ratio. Ranges are 27.208092–27.687572 and 31.160534–32.150590 ms. These remain shared-host observations with filesystem/cache effects, not universal overhead bounds.

Receipts retain numeric observations, command/revision/hardware identities and capture hashes; raw captures stay under target. Four release receipts total 436,479 bytes:

- [Selected instructions](results/20261027T132655.289429Z-selected-6f779d0ba8f5.json)
- [Mapping lifecycles](results/20261027T132704.378460Z-lifecycle-6f779d0ba8f5.json)
- [Existing owned-region probes](results/20261027T132706.724838Z-6f779d0ba8f5.json)
- [Existing dynamic pairs](results/20261027T132708.192893Z-dynamic-6f779d0ba8f5.json)

[Required checks](results/20261027T132714.815648Z-checks-6f779d0ba8f5.json) all passed: fmt, strict workspace/all-target/all-feature Clippy, workspace tests (2,339 passed, four ignored across 98 harnesses), and workspace/all-feature/all-target check. Recorder observed 330 tests. Serial observed all 1,029 tests in 27 harnesses, 50 native cases, 15 dynamic fixtures, 388 matrix records, 108 required native fixtures and complete backing cleanup. Workspace took 327.814 seconds; serial took 128.954 seconds within its unchanged 180-second bound. All command exits were zero, source/configuration remained unchanged and cleanup completed. The five receipts total 447,446 bytes.

Independent audit authenticated all 354 release captures and six required-check logs. Saved command logs replayed through the unchanged strict parsers and reproduced the receipt totals. No workloads were rerun for this audit. The results commit changes documentation and numeric receipts only; executable sources remain the tested revision.

## Qualification after merging the inline clock

Revision `8ff8b1ac0ff2dd0a7d2c33745137b72149e5e605` (tree `b3bd653fa9d3ce975eb8d50d7774dfad37e69d14`) includes core `7ab79270767a2b1fcf817f05dfec61ef01d5f38f`. The merge preserves the selected patch and mapping lifecycle capabilities above, and incorporates core's inline software preemption and complete ELF tactic corpus. The only reconciliation changes authenticate the eleven added tests and preserve exact historical assertions; no runtime contract or prior negative case was relaxed.

All four required Cargo checks pass, with 2,350 passed and four previously ignored workspace tests across 98 harnesses. Recorder controls pass all 330 cases. Serial validation passes all 1,029 tests across 27 harnesses, including the required native collections and backing cleanup. Workspace took 378.706 seconds and serial 129.299 seconds, within their existing 900/180-second bounds. Source and configuration stayed unchanged. Reproduce with the five commands in the preceding section, substituting this revision for the checks argument.

The four release runners also pass: 118 selected native cases and 13 preparation refusals; the genuine mapping lifecycle and twelve negative processes; ten existing owned-region probes; and fifteen dynamic pairs. Selected counters record 2,006,236 actual completions, 779,710 carry-clear outcomes, 118 admission faults and 126 admitted pages, with no additional steady-batch faults. Lifecycle counts remain 15 successful mappings, 52 generations all retired, 14 admissions/sync-core operations and zero live pages.

Release hardware/toolchains match the preceding experiment, with fresh children pinned to CPU 5. Numeric listing has 98 first-touch faults over 575 pages, 34 forwarded calls, median handler service 196.387 microseconds, and native/instrumented full-process medians 1.752199/2.557789 milliseconds. The warmed 1,000-scan interval has no further admission faults and 4,002 forwarded calls; medians are 27.698314/31.925207 milliseconds (1.153x). The same timing, random-outcome and post-constructor scope qualifications apply. These runs validate admission compatibility after the merge; core's separate inline-clock experiment supplies its performance evidence.

The five compact receipts total 447,601 bytes; raw captures remain private:

- [Required checks](results/20261027T135642.092658Z-checks-8ff8b1ac0ff2.json)
- [Selected instructions](results/20261027T140648.476121Z-selected-8ff8b1ac0ff2.json)
- [Mapping lifecycles](results/20261027T140658.041231Z-lifecycle-8ff8b1ac0ff2.json)
- [Owned-region probes](results/20261027T140700.387482Z-8ff8b1ac0ff2.json)
- [Dynamic pairs](results/20261027T140706.935685Z-dynamic-8ff8b1ac0ff2.json)

Independent audit authenticated all 354 release captures (177 commands), actual binaries and source bindings, and replayed all six check logs to the exact receipt totals. All four release runners remain byte-identical to the preceding tested revision. This results commit changes only documentation and numeric receipts.

## Original-linker first-entry admission

Source `c696f8f55f5b8c8c69d0f035c4d17cecea26695a` adds a freestanding ELF interpreter bridge that arms in-process page admission before entering the original dynamic linker. It also fixes protected-descriptor checks to use Linux's unsigned-32-bit close argument, including high-bit aliases. This retains core `7ab79270` ancestry. Reproduce on the recorded Linux x86-64 profile:

```sh
python3 evaluation/inprocess/first_entry.py --expect-revision c696f8f55f5b8c8c69d0f035c4d17cecea26695a
python3 evaluation/inprocess/first_entry_abi.py --expect-revision c696f8f55f5b8c8c69d0f035c4d17cecea26695a
python3 evaluation/inprocess/lifecycle.py
python3 evaluation/inprocess/dynamic.py --repeats 5
python3 evaluation/inprocess/checks.py --expect-revision c696f8f55f5b8c8c69d0f035c4d17cecea26695a
```

The optimized first-entry runner passes all 65 commands: ten native/gated ls pairs, sixteen native/gated refusal controls, two supported-operation pairs, the first-opcode fixture, carrier corruption controls, malformed sealed ELF and five namespace tests. Both ls modes produce native-identical output in all five repeats. Directory/numeric listing observes 117/143 NX admissions and 100/122 forwarded syscalls, with 38 CPUID and ten RDTSC traps each. Numeric listing additionally handles one vDSO RDTSCP; vDSO pages remain outside NX gating. Both perform real linker relocation, TLS, tid/robust-list and rseq setup against five sealed dependencies.

On CPU 3, AMD EPYC 9D85, Linux 7.1.3 and GCC 11.5.0 `-O2`, native/gated whole-process medians are 2.210256/58.507034 ms for directory output and 2.276104/61.257590 ms for numeric listing. Gated times include Python namespace copying/sealing and bridge preparation. These are complete-launch observations, not pure instrumentation overhead or a warmed first-entry measurement. The existing post-constructor dynamic regression also passes fifteen pairs: its warmed 1,000-scan medians are 27.891830/32.246858 ms with 4,002 forwarded calls and no additional admission faults. Shared-host and filesystem/cache effects remain.

The independent ABI cohort passes 35 commands and seven actual endpoint records. It compares sixteen GPRs, flags, FS/GS/selectors, qualified XSAVE state, the full 135,168-byte initial stack except the authenticated AT_BASE value, and 504 PHDR bytes. Both actual corruptions are rejected, alongside 84 supplied comparator controls and twelve resource-profile controls. This observes a separate fixture interpreter after the unchanged production entry body; it does not measure real ld.so's entry registers. The separate first-opcode fixture requires interpreter CPUID and main RDTSC interception.

The lifecycle regression retains all prior cases and adds native/gated protected-FD and ordinary-close controls: 21 commands, twenty rows, fifteen successful mappings, 52 generations all retired, fourteen admissions/sync-core operations, and zero remaining owned pages. Ordinary high-bit close retains Linux behavior; high-bit protected report/retained/original descriptors refuse in their applicable profiles.

The initial first-entry run at `874c6958f21e4c37cc657a5ded8cb6dc70c7555a` failed before its first gated target exec: the 1 MiB per-file limit also capped a sealed dependency memfd. Its receipt remains failed. The explicit replacement preparation profile permits 16 MiB per file while preserving 64 KiB capture acceptance, CPU/memory/wall limits, native thread behavior and every semantic check. The earlier ABI pass at that source is retained separately.

This is a singleton, explicit sealed-namespace profile using kernel traps with `source_patches=0`, distinct from the owned-region source patches above. RDRAND/RDSEED/RDPID interception in arbitrary original-loader code, general signals, threads/process lifecycle, transparent loader identity and complete B2/B3/B4 remain open. See the [first-entry contract](../../tools/page-entry/README.md).

All four required checks pass on the exact source: formatting, strict all-feature/all-target Clippy, workspace tests (2,350 passed, four previously ignored, 98 harnesses), and workspace all-feature/all-target check. Recorder passes all 330 controls. Serial passes all 1,029 tests/27 harnesses, required native collections and backing cleanup in 131.443 seconds, within its unchanged 180-second limit. Workspace takes 419.569 seconds within the existing 900-second profile; source and configuration remain unchanged.

Seven numeric receipts total 363,119 bytes; raw captures and ABI records remain under target. The results commit changes documentation and receipts only.

- [First-entry release cohort](results/20261027T143750.079470Z-first-entry-c696f8f55f5b.json)
- [Independent ABI cohort](results/20261027T143755.660824Z-first-entry-abi-c696f8f55f5b.json)
- [Lifecycle and FD controls](results/20261027T143758.366580Z-lifecycle-c696f8f55f5b.json)
- [Existing dynamic regression](results/20261027T143801.355503Z-dynamic-c696f8f55f5b.json)
- [Required checks](results/20261027T143827.811380Z-checks-c696f8f55f5b.json)
- [Earlier ABI pass](results/20261027T143128.363549Z-first-entry-abi-874c6958f21e.json)
- [Earlier preparation failure](results/20261027T143141.869332Z-first-entry-874c6958f21e.json)

Independent audit authenticates all 152 commands and 304 captures in the four new passing native cohorts, including seven ABI records, and replays all six required-check logs to their exact totals. Source, input, binary and namespace bindings agree; raw logs are not published. Earlier receipts retain their original statuses.


## Page admission after raw fork

Source `315b2712115f71631fddd37dd61303018b0abc7a` adds opt-in `exec-fork`: one actual raw `SYS_fork` and at most eight `wait4` calls for its child. The child authenticates inherited mappings, sealed owners, admission generations and its copied alternate-stack frame, then reestablishes CPUID/TSC controls, sync-core registration and syscall dispatch before returning to the original application PC/RSP. The default loader still refuses fork. Original syscall arguments and kernel results are preserved, including kernel-width aliases, WNOHANG and EFAULT copyout that can already reap the child. See the [profile contract](../../tools/page-entry/README.md).

The optimized native/gated cohort passes 39 commands: 24 fork/wait/default-refusal cases, six continuation commands and nine supervisor controls. Parent and child continuation records check all sixteen GPRs, full RFLAGS, FS/GS/selectors, the 128-byte redzone and qualified architectural XSTATE. Both actual corruption pairs retain eight rejected records, and all thirty supplied mutations are rejected. Timeout, SIGINT, close, reap and parser controls retain their actual failures; three cleanup-operation failures retain `cleanup_complete=false` while separate checks establish terminal ownership. This covers two singleton address spaces using NX admission and kernel traps (`source_patches=0`), not libc fork/atfork, clone, exec, threads, general application signals or complete B3. Child counters explicitly inherit the parent's pre-fork prefix.

Reproduce with `python3 evaluation/inprocess/fork.py --expect-revision 315b2712115f71631fddd37dd61303018b0abc7a`. The receipt records the exact source, ten binary hashes, toolchain and bounded command recipe. The run used one reserved CPU (3), AMD EPYC 9D85, Linux 7.1.3 and GCC 11.5.0 `-O2`; no fork performance claim is made. Exact binaries, captures and full state records are retained privately for replay.

The four prior native profiles also pass unchanged at this source: 65 first-entry commands, 35 ABI commands, 21 lifecycle commands/twenty rows and 31 dynamic commands/fifteen pairs. Independent saved-data replay authenticates all 152 commands and 304 captures, seven ABI records, 84 supplied ABI mutations and twelve resource controls. Lifecycle records fifteen mappings, 52 generations all retired, fourteen admissions and zero live pages. With fresh children on CPU 15 and the same hardware/compiler, first-entry native/gated whole-launch medians are 2.320342/59.770358 ms for directory listing and 2.560522/62.477130 ms for numeric listing. Gated launches include Python namespace copying/sealing. The existing post-constructor warmed 1,000-scan medians are 28.688874/33.426514 ms, with 4,002 forwarded calls and no further NX faults. These retain the preceding profiles' timing and coverage qualifications; the compact regression summary preserves raw timing arrays, hashes and reproduction commands.

All four required checks pass: formatting, strict all-feature/all-target Clippy, workspace tests (2,350 passed, four previously ignored, 98 harnesses), and all-feature/all-target check. Recorder passes 330 controls; serial passes 1,029 tests/27 harnesses and every required native collection in 149.787 seconds, within its unchanged 180-second bound. Workspace takes 388.844 seconds within the existing 900-second profile. Source and configuration remain unchanged. Reproduce with `python3 evaluation/inprocess/checks.py --expect-revision 315b2712115f71631fddd37dd61303018b0abc7a`.

Independent replay authenticates all ten preserved binaries and 176 fork captures, reproduces every continuation/supervisor result, and strictly reconstructs all six check logs. Expected failure rows remain failed.

The results commit adds documentation and three numeric receipts totaling 106,316 bytes. Full old-profile receipts and raw captures remain private; their original hashes are bound in the regression summary.

- [Raw-fork and continuation cohort](results/20261027T153503.221425Z-fork-315b2712115f.json)
- [Existing native regression summary](results/20261027T152247.353033Z-regressions-315b2712115f.json)
- [Required checks](results/20261027T152326.379750Z-checks-315b2712115f.json)

## Original-entry random and ID completion

Source `906e92f061d501d170c256c46d93cd91df4dd988` (tree `332329e58df58e99aa119f1ea3f1225f47716f0d`) adds the opt-in [selected original-entry profile](../../tools/page-entry/selected/README.md). It completes RDRAND/RDSEED at 16/32/64 bits and RDPID at 64 bits from the original interpreter entry, preserving native random carry results and destination-width semantics. Ordinary NOP and immediate/register MOV instructions execute at their original addresses through a qualified TF step; original source syscalls use the checked lifecycle dispatcher. Application code remains NX between instructions. This profile performs no source patching and makes no performance claim (claims 2 and 4).

Reproduce with one externally reserved CPU for each native runner:

```sh
python3 evaluation/inprocess/page_selected_components.py --expect-revision 906e92f061d501d170c256c46d93cd91df4dd988
python3 evaluation/inprocess/page_selected.py --expect-revision 906e92f061d501d170c256c46d93cd91df4dd988 --library-root /usr/lib64
python3 evaluation/inprocess/checks.py --expect-revision 906e92f061d501d170c256c46d93cd91df4dd988
```

The component cohort passes 437 commands: 112 decoder forms, two actual fatal outcomes (102/106), a freestanding seven-class/4,110-start scan, 385 provider cases, twenty native/stepped state pairs, thirteen decoder and thirteen false-candidate refusals, four process controls, and eighteen fetch cases. The provider cases include native and separately labeled scripted carry-clear results, actual corruption controls and an actual nested fault. Independent replay checks all twenty step pairs, 23 source-page opens and revocations, 100 kernel-frame observations with 2,444 FP bytes each, eighty live GPR/flags/selector observations, source/redzone/FS/GS state, and actual default-signal preparation. Full state records remain private.

The connected cohort passes 55 commands covering sixteen declared outcomes, including original-entry random/ID instructions, operand-size semantics, immediate/register MOV, cross-page instructions and protected-signal queries. The actual system linker executes its initial MOV, then refuses the next CALL with exact error 632/detail 693 after one step and two NX faults. This is an expected unsupported-instruction outcome; this selected profile does not yet run real ls to completion. The preceding default loader remains a separate profile. Arbitrary instructions, selected RSP destinations, threads, general process lifecycle and application signal handling remain outside this profile; B2/B3/B4 are incomplete.

Both native cohorts use Linux x86-64 on AMD EPYC 9D85, kernel 7.1.3, GCC 11.5.0 `-O2` and Rust/Cargo 1.97.1 release builds, on reserved CPUs 3 and 17 respectively. Exact tool hashes, bounds, source identities and commands are recorded. No timing is interpreted as a performance result.

Independent saved-data replay authenticates every actually executed component binary, 1,269 component captures and all 110 connected captures. The later connected build overwrote the component run's bridge binary, used there only for static inspection. Its original ELF and empty-undefined-symbol observations remain captured, but its raw bytes are no longer available for independent authentication. The final connected bridge is retained and its ELF checks replay exactly. This retention limit does not apply to the executed component binaries.

All four required Cargo checks pass: formatting, strict workspace/all-feature/all-target Clippy, workspace tests (2,350 passed, four previously ignored across 98 harnesses), and workspace/all-feature/all-target check. Recorder passes 330 tests. Serial passes all 1,029 tests across 27 harnesses, including 50 native cases, fifteen dynamic fixtures, 388 matrix records, 108 validation fixtures and complete backing cleanup. Workspace takes 308.288 seconds and serial 128.181 seconds within their unchanged 900/180-second bounds. Source and configuration remain unchanged. Independent replay authenticates all six saved check logs and reproduces the strict totals, native collection qualification and backing cleanup.

The results commit changes documentation and three numeric receipts totaling 98,734 bytes only. Raw captures remain under target.

- [Component cohort](results/20261027T164153.849695Z-page-selected-components-906e92f061d5.json)
- [Connected controller cohort](results/20261027T164325.624061Z-page-selected-906e92f061d5.json)
- [Required checks](results/20261027T164324.111142Z-checks-906e92f061d5.json)


## Original-address memory and control flow (claims 2 and 4)

Source `504071ca5087133e69b8b310845e66e34c5b7958` (tree `20eb320e036376ff3008b582d41e4d344bcd1582`) adds a separate generic TF owner to the selected original-entry profile. A closed classifier enumerates 301 instruction codes for integer/memory operations, stack operations, near branches/CALL/RET and selected SSE2 operations. The CPU executes original bytes and supplies the actual result. Source pages are revoked and synchronized before the actual continuation is authenticated as owned and NX. The original NOP/MOV route and selected-instruction precedence remain intact.

Reproduce on one reserved CPU, except the required-check command may use up to four:

```sh
python3 evaluation/inprocess/page_selected_generic_oracle.py --expect-revision 504071ca5087133e69b8b310845e66e34c5b7958
python3 evaluation/inprocess/page_selected_generic.py --expect-revision 504071ca5087133e69b8b310845e66e34c5b7958
python3 evaluation/inprocess/page_selected_components.py --expect-revision 504071ca5087133e69b8b310845e66e34c5b7958
python3 evaluation/inprocess/checks.py --expect-revision 504071ca5087133e69b8b310845e66e34c5b7958
```

The O2 native runs used an AMD EPYC 9D85, microcode `0xb101066`, Linux 7.1.3, GCC 11.5.0 and Rust 1.97.1, with no effective capabilities. Exact hardware and commands are in the receipts. These are correctness results, not performance measurements.

The generic oracle passes 20 same-address native/stepped pairs, 47 supplied classifier refusals and three actual failed-operation controls. It compares all 16 GPRs, logical flags, original/endpoint RIP, all six live selectors, FS/GS bases, complete 2,444-byte kernel FP records, 2,440 qualified live XSAVE bytes, 8 KiB stack and 4 KiB data. Both boundary CALLs push the original return address while leaving the never-executed return page outside the opened source bundle. Negative controls retain actual memory-fault, unowned-target and out-of-domain-RSP failures; they remain exit 125 operations. Independent saved-data replay derived layouts from the retained binary and passed 3,064 assertions.

The connected cohort passes all 15 previous streams plus five programs for branch/stack/memory, boundary CALL/RET, CPUID, RDTSC and RDTSCP (97 build/cohort commands). The CALL program reports original return `0x402000` and result 42. CPUID matches all four native outputs; timestamp cases satisfy strict serialized native/gated brackets without tolerances. Exact old/generic instruction counts, NX fetches, source syscalls and complete close/query/release prefixes pass. Independent replay also reproduces the public receipts from their private records.

The real system linker now completes its initial MOV and CALL, then refuses canonical ENDBR64 (`f30f1efa`, decoder code 1054) before opening pages or executing that instruction: status 125/error 100, old 1/generic 1, NX 3 and zero source syscalls. This is progress in the selected profile, not a completed gated `ls` run. The separate default loader's earlier real-program results remain separate. Exhaustive native qualification of all 301 classifier codes remains open, along with general signals/threads/process lifecycle, selected RSP destinations and complete B2/B3/B4.

The existing 437-command component cohort passes unchanged: 112 decoder forms, two fatal controls, freestanding scan, 385 provider cases, 20 old step pairs, 13 decoder and 13 forged-candidate refusals, four step-process controls and 18 fetch cases. All four required workspace checks pass, with 2,350 tests passed and four ignored; recorder 330 and serial 1,029 also pass. Serial validation includes 50 native fixtures, 15 dynamic fixtures, 388 matrix cases, 108 validation fixtures and backing cleanup, within the unchanged 180-second bound (134.976 seconds).

Each run now retains its build outputs before another build can overwrite them. The generic runners authenticate source archives against Cargo.lock, compare all 186 extracted dependency files with those archives, and require actual dep-info to name exactly the six committed decoder sources. An earlier committed-source attempt correctly failed that dependency check when Cargo reused a prototype artifact; it executed no native case. A distinct product metadata identity fixes the collision without changing the check. Its compact failed receipt is retained. Full records and binaries stay private; the four successful public receipts total 171,595 bytes.

- [Generic native oracle](results/20261027T173116.281005Z-page-selected-generic-oracle-504071ca5087.json)
- [Connected controller](results/20261027T173127.299656Z-page-selected-generic-504071ca5087.json)
- [Existing component cohort](results/20261027T173153.058717Z-page-selected-components-504071ca5087.json)
- [Required checks, recorder and serial](results/20261027T173155.520498Z-checks-504071ca5087.json)
- [Retained pre-native build failure](results/20261027T172916.041538Z-page-selected-generic-oracle-69e73f9dbbc9.json)

## Original-address integer families (claims 2 and 4)

Source `9c7ada5c39b7385d689f8fdf8c517612b713b08f` adds canonical ENDBR64 and ordinary integer shifts/rotates, multiply/divide, conditional results, bit operations and exchanges to the selected original-entry controller. Its classifier now enumerates 534 exact instruction codes. The original prefix, selected-provider, CPU-state, revoke/sync and closed-continuation contracts remain intact; the no-user-CET assumption remains explicit.

Two new cohorts pass forty native/TF instruction cases plus a real startup pair in each. Independent literal expectations check register widths, flags, memory effects, signed division, false CMOV32 zero-extension, XADD and both CMPXCHG outcomes. The unchanged full comparison retains all sixteen GPRs, logical flags, live selectors, FS/GS, 2,444 kernel-FP bytes, 2,440 live XSAVE bytes, 8 KiB stack and 4 KiB data. Flags the ISA leaves undefined remain compared exactly between native and TF lanes; their observed values are not a portable guarantee. All records fit the unchanged 16 MiB limit. Independent replay of the retained binaries and actual DWARF verifies all forty cases.

The original generic oracle also passes all 21 pairs, 47 supplied refusals and three actual failed operations. The existing 437-command component cohort and twenty connected streams pass unchanged. Across these five native runners, all 594 commands complete with their required outcomes. Optimized builds used GCC 11.5.0 and Rust 1.97.1 on CPU 13, AMD EPYC 9D85, microcode `0xb101066`, Linux 7.1.3, with no effective capabilities. No performance result is claimed.

The actual system linker now executes 44 older steps, 1,805 generic steps and two RDTSC callbacks across 1,852 NX faults, then refuses REP STOSQ (`f348ab`, decoder code 346). This is an unsupported-program result, not completed selected-profile `ls` execution. REP needs a separate iteration protocol; its existing refusal controls remain unchanged. Application divide-fault delivery, selected RSP destinations, general signals/threads and full B2/B3/B4 remain open. The earlier successful default-loader `ls` results are a separate profile.

Reproduce each native command on one externally reserved CPU; the last command may use four:

```sh
python3 evaluation/inprocess/page_selected_generic_oracle.py --expect-revision 9c7ada5c39b7385d689f8fdf8c517612b713b08f
python3 evaluation/inprocess/page_selected_integer.py --expect-revision 9c7ada5c39b7385d689f8fdf8c517612b713b08f --group 0
python3 evaluation/inprocess/page_selected_integer.py --expect-revision 9c7ada5c39b7385d689f8fdf8c517612b713b08f --group 1
python3 evaluation/inprocess/page_selected_generic.py --expect-revision 9c7ada5c39b7385d689f8fdf8c517612b713b08f
python3 evaluation/inprocess/page_selected_components.py --expect-revision 9c7ada5c39b7385d689f8fdf8c517612b713b08f
python3 evaluation/inprocess/checks.py --expect-revision 9c7ada5c39b7385d689f8fdf8c517612b713b08f
```

All four required checks pass: formatting, strict workspace/all-target/all-feature Clippy, workspace tests (2,350 passed and four previously ignored across 98 harnesses), and workspace/all-feature/all-target check. Recorder passes 330 tests; serial passes 1,029 tests across 27 harnesses, including every required native collection and backing cleanup. Workspace takes 310.127 seconds within the unchanged 900-second bound; serial takes 134.679 seconds within its unchanged 180-second bound. Source and configuration remain unchanged.

The native summary copies the measured results, exact source/hardware and reproduction commands, and binds all five full receipts by hash. Their full command/capture records remain private. The results commit changes only documentation and two numeric receipts totaling 53,093 bytes.

- [Native results and per-class counts](results/20261027T175910.211918Z-integer-summary-9c7ada5c39b7.json)
- [Required checks, recorder and serial](results/20261027T180123.253835Z-checks-9c7ada5c39b7.json)

## Actual alternate entry into embedded CPUID (claims 2 and 4)

Source `eeae25e563be5e9288416979ac73c431f2d34dd3` adds two original-entry programs that first consume CPUID bytes as part of a MOV immediate, then actually CALL those same bytes as instructions. One uses a direct CALL; the other uses an indirect CALL with CPUID crossing a page boundary. Both finish under the in-process selected controller with zero source patches and return the complete native 40-byte result, including all four CPUID outputs, the MOV result, and the original CALL return address (`0x40102b` or `0x402030`). The existing twenty streams remain unchanged.

All 22 streams satisfy their required outcomes: 19 complete and three retain their required refusals. The runner completes all 119 build/cohort commands, with no timeout, capture error or cleanup failure. Independent replay authenticates the saved inputs, binaries and captures and reproduces the public receipt. This closes the concrete embedded-entry example; the independent explicit-trap/strict-block reference and full B2/B3/B4 coverage remain open. The real system linker's diagnostic still stops at unsupported REP STOSQ after 1,805 generic steps, 44 older steps and two RDTSC callbacks.

The optimized native run used GCC 11.5.0 and Rust 1.97.1 on CPU 2, AMD EPYC 9D85, microcode `0xb101066`, Linux 7.1.3, with no effective capabilities. This is correctness evidence, not a performance measurement. Reproduce the native cohort on one externally reserved CPU and checks on four:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/page_selected_embedded.py --expect-revision eeae25e563be5e9288416979ac73c431f2d34dd3
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/checks.py --expect-revision eeae25e563be5e9288416979ac73c431f2d34dd3
```

All four required checks pass, including 2,350 workspace tests with four previously ignored across 98 harnesses. Recorder passes 330 tests; serial passes 1,029 across 27 harnesses, including 50 native fixtures, 15 dynamic fixtures, 388 matrix cases, 108 validation fixtures and backing cleanup. Workspace takes 306.561 seconds within its unchanged 900-second bound; serial takes 129.608 seconds within its unchanged 180-second bound. Source and configuration remain unchanged. An earlier preflight correctly rejected an untracked Python import cache before executing any check; its failed receipt remains failed. Removing that generated cache from the source directory and disabling parent-process bytecode generation resolved the invocation error without changing source or assertions.

- [Native embedded-entry results](results/20261027T182224.247893Z-page-selected-embedded-eeae25e563be.json)
- [Required checks, recorder and serial](results/20261027T182556.716129Z-checks-eeae25e563be.json)
- [Retained preflight failure](results/20261027T182313.312067Z-checks-eeae25e563be.json)

## Original-address canonical REP STOSQ (claims 2 and 4)

Source `b809f35817e79de828c9b0661ce897354bd80c28` joins original-address canonical `f3 48 ab` execution to the in-process selected controller and includes main `223e5f3543884adfa6cda04e72671be4cebc8f76`. A separate owner retains the original fetch borrow through every actual TRACE. Each cycle revokes and synchronizes the source, authenticates exact bounded RCX/RDI progress, including count-zero completion and a fresh closed continuation, then reopens for an intermediate iteration or releases after final completion. The old 534-code generic classifier and its 47 refusal controls remain unchanged. This increment does not add general repeated-string instructions or application fault delivery.

The portable native oracle passes six same-PC native/owner pairs at counts 0/1/3 and DF 0/1, with ten actual TRACE events, one genuine startup pair, all 47 old and six REP refusals, and a real failed first store. Full comparisons retain all GPRs, logical flags, selectors, FS/GS, complete kernel FP, qualified live XSAVE, stack and data. The failed store remains terminal exit 125 with a held borrow, closed source and zero completed iterations. The unchanged generic oracle separately passes its 21 pairs, 47 refusals, three actual failed operations and three command controls.

The connected runner retains all 22 earlier streams and adds ten programs for the six count/direction combinations, crossing and page-end fetches, owner reuse, and a read-only store fault. All 32 cases satisfy their required outcomes: 28 complete and four retain required refusals. Each successful REP program matches all 128 output bytes against both literal expectations and native execution. The fault remains native SIGSEGV versus terminal gated 125; it is not completed instruction support. All 189 connected build/cohort commands and 44 oracle commands are reaped without timeout or cleanup failure. Independent replay authenticates saved source/tool/artifact/capture identities, complete state records and the compact public projections.

The real system linker completes a REP with 52 actual TRACE/closed-query cycles, then refuses padding NOP `662e0f1f840000000000` (code 1056). Its prefix includes 47 old steps, 2,035 generic steps, two RDTSC callbacks and 2,086 NX faults. Selected-profile `ls` remains incomplete. The earlier default-loader program results remain a separate profile. General signals/threads, selected RSP destinations, fast-page publication and full B2/B3/B4 remain open.

Optimized correctness runs used GCC 11.5.0 and Rust/Cargo 1.97.1 on reserved CPU 1, AMD EPYC 9D85, microcode `0xb101066`, Linux 7.1.3, with no effective capabilities. No performance result is claimed. Reproduce each native command on one reserved CPU; checks may use four:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/page_selected_repeat_oracle.py --expect-revision b809f35817e79de828c9b0661ce897354bd80c28
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/page_selected_repeat.py --expect-revision b809f35817e79de828c9b0661ce897354bd80c28
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/page_selected_generic_oracle.py --expect-revision b809f35817e79de828c9b0661ce897354bd80c28
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/checks.py --expect-revision 96038db8aae478c9ae37f05ddfa4e37b773755db
```

The subsequent `96038db8aae478c9ae37f05ddfa4e37b773755db` commit changes only three inventory files. Independent verification rehashes all 604 recorded native input bindings (282 distinct paths) and confirms they remain byte-identical. Native results retain their actual `b809f358` revision; required checks use the corrected inventory revision.

All four required checks pass at `96038db8`: formatting, strict workspace/all-feature/all-target Clippy, workspace tests (2,457 passed, four previously ignored, 98 complete harnesses), and workspace/all-feature/all-target check. Recorder passes 330 tests; serial passes all 1,029 across 27 harnesses, including 50 native fixtures, 15 dynamic fixtures, 388 matrix cases, 108 validation fixtures and backing cleanup. Workspace takes 335.587 seconds within the unchanged 900-second bound; serial takes 139.150 seconds within its unchanged 180-second bound. Source and configuration remain unchanged.

An earlier connected run at `f090e7b7` failed an observer assertion that incorrectly expected selected disposition 8 for an unchanged old NOP/MOV classification. The correction requires its actual existing disposition 0; it changes no decoder or owner rule. The first merged required-check attempt at `57f5d652` failed historical source pins after core's ELF additions. An authenticated exact source/catalog projection reconstructs historical inputs while preserving every old assertion, ignored count and serial collection. Its first catalog counted 17 new declarations but omitted 90 instances compiled through shared integration support. The full workspace process at `b809f358` exited zero, and the unchanged parser correctly rejected its incomplete catalog. The corrected inventory requires all 107 added instances. All three failed receipts remain failed.

- [Portable REP native oracle](results/20261027T191051.898010Z-page-selected-repeat-oracle-b809f35817e7.json)
- [Connected REP programs](results/20261027T191100.763033Z-page-selected-repeat-b809f35817e7.json)
- [Unchanged generic native oracle](results/20261027T191135.955137Z-page-selected-generic-oracle-b809f35817e7.json)
- [Retained observer failure](results/20261027T185233.377700Z-page-selected-repeat-f090e7b7a848.json)
- [Retained merged inventory failure](results/20261027T185710.617370Z-checks-57f5d6527bc5.json)
- [Retained compiled-inventory failure](results/20261027T191052.175479Z-checks-b809f35817e7.json)
- [Required checks, recorder and serial](results/20261027T192329.459383Z-checks-96038db8aae4.json)

The results commit adds documentation and seven numeric receipts totaling 117,232 bytes. Full captures and state records remain private.

## Exact canonical padding NOPs (claims 2 and 4)

Source `ca0f9c3616e52da81e5415815a38133b2f2a999c` adds the exact ten-byte `66 2e 0f 1f 84 00 00 00 00 00` padding form before the unchanged general prefix policy. The existing 534-code set and prior refused encodings remain unchanged. Twenty new native/stepped pairs cover lengths 1–10 ending at a page boundary, every split of the ten-byte form, and a nine-byte crossing. All preserve literal no-op effects and full state, including 2,444 kernel-FP bytes, 2,440 live-XSAVE bytes, 8 KiB stack and 4 KiB data. The genuine startup pair and all 47 prior plus twelve new refusal controls pass. All 31 opened-page prefixes revoke, synchronize and close.

All seven optimized native runners pass: padding, original generic, REP oracle, connected REP, both integer groups and components. The connected cohort retains all 32 cases (28 completed and four required refusals), 189 commands, and every previous predicate. Components retain 112 decoder forms, two fatal cases, one freestanding decoder, 385 provider cases, twenty ordinary-step pairs, thirteen arm/false-claim refusals, four control processes and eighteen fetch cases. No performance result is claimed.

The real linker progresses to 6,040 completed generic steps, 458 original steps, nine CPUID callbacks, two RDTSC callbacks and one source syscall, with 6,512 NX faults and the completed 52-iteration REP. It then refuses canonical XGETBV `0f01d0` (code 825) before effect, status 125/error 100. Selected-profile `ls` remains incomplete. This observed failure remains a failure; accepting padding does not establish general prefix or XGETBV support.

Native runs used one reserved CPU (16), optimized builds and the exact tool/hardware identities in the receipts. Reproduce on one reserved CPU at the source revision:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/page_selected_padding.py --expect-revision ca0f9c3616e52da81e5415815a38133b2f2a999c
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/page_selected_generic_oracle.py --expect-revision ca0f9c3616e52da81e5415815a38133b2f2a999c
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/page_selected_repeat_oracle.py --expect-revision ca0f9c3616e52da81e5415815a38133b2f2a999c
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/page_selected_repeat.py --expect-revision ca0f9c3616e52da81e5415815a38133b2f2a999c
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/page_selected_integer.py --group 0 --expect-revision ca0f9c3616e52da81e5415815a38133b2f2a999c
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/page_selected_integer.py --group 1 --expect-revision ca0f9c3616e52da81e5415815a38133b2f2a999c
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/page_selected_components.py --expect-revision ca0f9c3616e52da81e5415815a38133b2f2a999c
```

All four required checks pass at this same revision: formatting, strict workspace/all-feature/all-target Clippy, workspace tests (2,457 passed, four previously ignored, 98 harnesses) and workspace/all-feature/all-target check. Recorder passes 330 tests. Serial passes 1,029 across 27 harnesses, with all 50 native, 15 dynamic, 388 matrix and 108 validation cases qualified and backing cleanup complete. Workspace takes 350.613 seconds within its unchanged 900-second bound; serial takes 136.627 seconds within its unchanged 180-second bound. Source/configuration stay unchanged. Reproduce checks with `PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/checks.py --expect-revision ca0f9c3616e52da81e5415815a38133b2f2a999c` on four reserved CPUs. Saved-log replay reconstructs the full strict qualification and compact receipt without changing any parser or assertion.

- [Padding full-state oracle](results/20261027T193927.693722Z-page-selected-padding-ca0f9c3616e5.json)
- [Unchanged generic oracle](results/20261027T193936.034753Z-page-selected-generic-oracle-ca0f9c3616e5.json)
- [REP full-state oracle](results/20261027T193944.698558Z-page-selected-repeat-oracle-ca0f9c3616e5.json)
- [Connected REP and linker diagnostic](results/20261027T193953.503973Z-page-selected-repeat-ca0f9c3616e5.json)
- [Integer group zero](results/20261027T194030.946840Z-page-selected-integer-0-ca0f9c3616e5.json)
- [Integer group one](results/20261027T194040.986892Z-page-selected-integer-1-ca0f9c3616e5.json)
- [Complete components](results/20261027T194049.391917Z-page-selected-components-ca0f9c3616e5.json)
- [Required checks, recorder and serial](results/20261027T194241.260102Z-checks-ca0f9c3616e5.json)

The eight numeric receipts total 118,423 bytes. All 727 native/build commands are reaped without timeout or cleanup error; raw captures and state records remain private.

## Canonical XGETBV with ECX zero (claims 2 and 4)

Source `52bb8423ede1af98b198335e6c6fc585c778fa7c` executes exact `0f01d0` at its original address after checking the actual saved ECX is zero, before opening either source page. The previous 534 generic Codes and prefix policy remain unchanged. Six new XCR0 native/stepped pairs cover a page-end and both instruction splits, each with zero or nonzero ignored high RCX bits. All six plus startup pass the full architectural, FP/XSAVE, stack and data comparisons. Actual XCR0 is 743; RAX is 743 and RDX zero, with both results zero-extended. All 47 old and nine added encoding refusals pass. Three genuine nonzero-index entries refuse before opening; native ECX=2 produces its actual original-PC general-protection fault. All four operations remain failures with exit 125. ECX=1/XINUSE and unsupported hardware are outside this completion claim.

All eight optimized native runners pass, totaling 750 build/native commands with complete reaping, no timeout and no cleanup error. The connected cohort retains 32 cases: 28 complete and four retain required refusals. The real linker advances to 7,468 generic steps, 725 original steps, 38 CPUID callbacks, two RDTSC callbacks and two source syscalls, with 8,237 NX faults and the completed 52-iteration REP. Its next refusal is `660f74e0`, PCMPEQB xmm4,xmm0 (code 1715), status 125/error 100 before effect. Selected-profile `ls` remains incomplete. These correctness runs do not measure performance.

Independent saved-data review authenticates all seven XGETBV pairs, four failed operations, source/build/capture identities and the public projection. Separate connected replay retains all previous predicates and 189 commands. The original generic, padding, REP, both integer groups and complete component suites also pass. All four required checks pass: formatting, strict all-feature/all-target workspace Clippy, workspace tests (2,457 passed, four previously ignored across 98 harnesses), and all-feature/all-target workspace check. Recorder passes 330; serial passes 1,029 across 27 harnesses, including all 50 native, 15 dynamic, 388 matrix and 108 validation cases plus backing cleanup. Workspace takes 323.615 seconds within its unchanged 900-second bound; serial takes 133.556 seconds within its unchanged 180-second bound. Saved-log replay reproduces strict qualification without parser changes.

Runs used AMD EPYC 9D85, microcode `0xb101066`, Linux 7.1.3, GCC 11.5.0 and Rust/Cargo 1.97.1, with no effective capabilities. Exact commands, affinities and identities are in the nine numeric receipts (137,866 bytes); raw logs and state captures remain private. Reproduce native runners on one reserved CPU and checks on four, at the source revision:

```sh
revision=52bb8423ede1af98b198335e6c6fc585c778fa7c
for runner in page_selected_xgetbv page_selected_padding page_selected_generic_oracle page_selected_repeat_oracle page_selected_repeat page_selected_components; do
    PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/"$runner".py --expect-revision "$revision" || exit
done
for group in 0 1; do
    PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/page_selected_integer.py --group "$group" --expect-revision "$revision" || exit
done
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/checks.py --expect-revision "$revision"
```

- [XGETBV full-state oracle](results/20261027T195803.295091Z-page-selected-xgetbv-52bb8423ede1.json)
- [Connected programs and linker diagnostic](results/20261027T195847.677501Z-page-selected-repeat-52bb8423ede1.json)
- [Required checks, recorder and serial](results/20261027T195913.896278Z-checks-52bb8423ede1.json)
- [Padding regression](results/20261027T195924.548747Z-page-selected-padding-52bb8423ede1.json)
- [Original generic oracle](results/20261027T195932.874008Z-page-selected-generic-oracle-52bb8423ede1.json)
- [REP full-state oracle](results/20261027T195941.489390Z-page-selected-repeat-oracle-52bb8423ede1.json)
- [Integer group zero](results/20261027T195950.279353Z-page-selected-integer-0-52bb8423ede1.json)
- [Integer group one](results/20261027T195958.438387Z-page-selected-integer-1-52bb8423ede1.json)
- [Complete components](results/20261027T200006.957765Z-page-selected-components-52bb8423ede1.json)

## Legacy SSE2 comparisons and movemasks (claims 2 and 4)

Source `e3e3c792292ececff1d6da4c9f566d9db649f653` adds nine exact legacy XMM Codes for PCMPEQB/W/D, PCMPGTB/W/D, PMINUB, PMAXUB and r32 PMOVMSKB. The previous 535 Codes, prefix policy and original-address owners remain unchanged. Two bounded cohorts pass 36 new full-state comparisons plus two startup comparisons: sixteen register-vector cases, sixteen aligned-memory cases and four movemasks, with fourteen page endings and twenty-two crossing fetches. Independent literal lane/mask checks supplement exact GPR, flags, kernel-FP, live-XSAVE, selector, FS/GS, stack and data comparisons. All 47 old and 27 new encoding refusals pass in each of three processes. An inaccessible-memory load retains its actual native and stepped faults and exit 125; it is not completed instruction support.

All nine native suites pass, totaling 772 build/native commands with no timeout or cleanup error. The connected cohort retains 32 outcomes: 28 completed programs and four required refusals. The actual system linker completes four additional generic instructions, reaching 7,472 generic and 725 original steps, 38 CPUID callbacks, two RDTSC callbacks, two source syscalls and 8,241 NX faults. It then refuses `0fbcc2`, BSF eax,edx (code 2119), before effect. Selected-profile `ls` remains incomplete. The canonical REP still completes all 52 iterations.

All four required checks pass at this source: formatting, strict workspace/all-feature/all-target Clippy, workspace tests (2,457 passed, four previously ignored across 98 harnesses), and workspace/all-feature/all-target check. Recorder passes 330; serial passes 1,029 across 27 harnesses, including 50 native, 15 dynamic, 388 matrix and 108 validation cases plus backing cleanup. Workspace takes 372.895 seconds within its unchanged 900-second bound; serial takes 129.937 seconds within its unchanged 180-second bound. Source/configuration remain unchanged. Independent native saved-data review passes 18,598 checks; the connected replay and its adaptation also pass.

These are optimized correctness runs, not performance measurements. Hardware is AMD EPYC 9D85, microcode `0xb101066`, Linux 7.1.3, GCC 11.5.0 and Rust/Cargo 1.97.1, with no effective capabilities. Each native run uses one reserved CPU; checks use four. Exact commands, hardware, numeric outcomes and hashes of the ten original receipts are in the [consolidated receipt](results/20261027-sse2-milestone.json), totaling 50,779 bytes instead of publishing 154,571 bytes of repeated per-run records. Original evaluators and their qualification rules are unchanged; complete logs and state captures remain private.

Reproduce each `runs[].reproduce` command in that receipt at the source revision. The additional [summary script](summarize_selected.py) only projects those generated receipts; it preserves failure labels and does not perform validation. Its actual projection and mixed-revision/duplicate/failure controls were checked separately after the source tests. Recreate the publication with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/summarize_selected.py --revision e3e3c792292ececff1d6da4c9f566d9db649f653 --output target/sse2-milestone-reproduced.json evaluation/inprocess/results/*e3e3c792292e.json
```

## Immutable register runs and original-address NOTRACK

Revision `89a91d2a59dd87b83b6cbe57d03fdfd3e611e42b` adds an opt-in register-run cache: closed NOP/MOV prefixes execute from immutable private RX pages while their original source pages remain NX. A genuine fetch fault at the original guard completes the run, releases its borrow and dispatches that guard. Publication uses fresh RW storage, source reauthentication, RW-to-RX protection, synchronization and full-page verification. The cache remains opt-in; the default build continues original-address execution and retains the same all-start admission policy. This supplies finite evidence for claims 1/4; it does not establish general B2/B3 coverage.

The native oracle passes 18 semantic pairs (nine publications and nine hits), fills all 64 slots, takes one genuine capacity fallback and subsequently hits an existing slot. Generated runs cause zero TRACE events; the two-instruction fallback causes two. All 23 retained full records and four startup pairs were independently replayed, including complete GPR/flags/kernel FP/live XSAVE/selectors/FS/GS, 8 KiB stack and 4 KiB data. All 64 capacity rows were checked; 61 intermediate capacity cycles do not retain full-state records. Fourteen terminal controls verify stale/corrupt identities, permissions, failed publication, reset and interruption handling. Their attempted operations all fail, with zero generated executions or completion credit; three explicit raw-error injections and one actual signal remain distinguished.

Three connected programs complete both copied runs and original CPUID/syscall guards. Direct and crossing-first-instruction cases each execute six generated runs, four publications and two hits. The crossing-guard case correctly falls back before publication for that loop and executes three other generated runs. Together they complete nine CPUID guards and six source syscalls. All native outputs match an independent hardware observation and the literal dependent-register values.

The same revision supports thirty exact NOTRACK register CALL/JMP encodings in the existing no-user-CET profile, and scalar BSF/BSR at original addresses. NOTRACK passes 40 branch pairs plus two startup pairs, with 20 exact original CALL return words; 15 pushed return addresses point into a next page excluded from the opened fetch bundle. Ten cases cross source-page boundaries. All 42 full states and 182 refusal checks were independently authenticated. BSF/BSR passes 48 instruction pairs plus three startup pairs, 355 refusal checks and two actual memory-fault controls. These extend claim-2/4 evidence without granting unsupported prefixes or general CET support.

The explicit real-program experiment attempts `/bin/true` and `/bin/ls -d .`, both with the default environment and separately with `GLIBC_TUNABLES=glibc.pthread.rseq=0`. Both lanes use `LD_BIND_NOW=1`; sealed dependency identity and the actual target environment are authenticated. All four native baselines exit zero. All four gated programs stop before executing unsupported `66 0f 12 0f` (MOVLPD, Code 943), so **zero real programs complete**. Each default attempt completes 138 generated runs using 41 publications and 97 hits; each rseq-disabled attempt completes 146 using 43 publications and 103 hits. These are partial execution counts, not successful whole-program or performance results. Every timing field remains null.

All 14 finite/native evaluator runs pass their specified outcomes (924 build/native commands); the separate failed real-program experiment adds 37 commands. Hardware is AMD EPYC 9D85, family 26/model 17/stepping 0, microcode `0xb101066`, Linux 7.1.3; Rust 1.97.1 and GCC 11.5.0. Native children use one reserved CPU and no effective capabilities. C fixtures and bridges use `-O2`, and the decoder uses the release profile. No throughput or first-touch/steady-state performance result is claimed here.

All four required checks pass at the exact source: formatting, strict all-feature/all-target Clippy, workspace tests and workspace check. Workspace validation observes 2,457 passed and four previously ignored across 98 harnesses in 310.162 seconds. The recorder has 330 passed; the serial launch run has 1,029 passed across 27 harnesses in 132.594 seconds. Source and configuration remain unchanged throughout.

The [compact milestone receipt](results/20261027-register-run-milestone.json) retains each evaluator's exact revision, command, bounds, hardware, numeric outcomes and original receipt hash. Reproduce each `runs[].reproduce` command at the recorded source under its stated CPU reservation, then project the resulting receipts with `summarize_selected.py`. For the retained original records, the projection command is:

```sh
python3 evaluation/inprocess/summarize_selected.py \
  --revision 89a91d2a59dd87b83b6cbe57d03fdfd3e611e42b \
  --output target/register-run-milestone-reproduced.json \
  evaluation/inprocess/results/*89a91d2a59dd.json
```

The projection publishes numbers and hashes only. Full raw process captures and retained binaries remain private; its source hash is recorded in the compact receipt. Earlier fixture setup failures (ambiguous BSS symbol and an incorrect expectation of the existing refusal-helper success sentinel) remain failed and provide no native completion credit.

## First publication and repeated register-run hits

At revision `aa3f8f7eedd9d7acbc1dc6f22d8ebb47c2dd0962`, an optimized six-case experiment executes one two-MOV run at the same original address, first by publication and then through 1, 10 or 100 cache hits. Every native result, output byte, publication count and guard count passes; all 59 build/native commands finish without timeouts or cleanup errors. This supplies finite measurement evidence for claims 1/4. It does not complete the real-program milestone.

For the 100-hit case, the measured source intervals are:

| Execution | First interval (TSC ticks) | Mean of 100 later intervals (TSC ticks) |
| --- | ---: | ---: |
| Native two-MOV program | 4,758 | 126.02 |
| Page-gated two-MOV program | 2,677,051 | 2,545,967.53 |
| Native bracket-only control | 4,324 | 127.87 |
| Page-gated bracket-only control | 1,959,510 | 1,927,641.35 |

The first interval includes the first publication of this run. Startup precedes it. Both first and later intervals include the serializing CPUIDs, source-clock handling and intervening page-gate work; they are not isolated publisher or cache-lookup durations. The control omits the two MOVs and therefore has different later instruction addresses. No control subtraction, clock-frequency conversion, outlier removal or whole-program speedup is claimed. The very high remaining overhead limits practical performance.

The [numeric receipt](results/20261027T212306.556161Z-page-selected-register-perf-aa3f8f7eedd9.json) retains all 456 first/later interval samples across the six native/gated pairs, exact sums/counts, hardware, revision, build mode and reproduction command. Hardware is AMD EPYC 9D85, family 26/model 17/stepping 0, microcode `0xb101066`, Linux 7.1.3. The bridge uses `-O2`, the decoder uses the release profile, and every child runs on one reserved CPU. Reproduce with `python3 evaluation/inprocess/page_selected_register_perf.py --expect-revision aa3f8f7eedd9d7acbc1dc6f22d8ebb47c2dd0962` under the same one-CPU reservation contract. The independent saved-data review reparses all twelve 4 KiB outputs, verifies the actual hardware brackets and literal register values, and recomputes every published timing sample and aggregate.

## Further loader instruction coverage

The original-address owner now executes legacy SSE2 MOVLPD/MOVHPD half moves, PSLLDQ/PSRLDQ byte shifts and MOVD XMM/rm32 transfers, plus the exact observed eleven-byte alignment NOP. Their separate release native oracles pass respectively 38, 42, 38 and 33 state pairs, including startup pairs. The eleven-byte NOP was previously refused and is now positively qualified; its historical failed run is retained. All other refusal cases, prefix restrictions, full-state comparators and owner predicates remain. These finite results support claims 2/4; the original source remains gated throughout generated register runs (claim 1).

At MOVD source revision `8749b6adfba72a311ca3d168cdae729be52790cc`, the [native receipt](results/20261027T214324.285338Z-page-selected-sse2-movd-8749b6adfba7.json) records 36 new pairs plus two startups, 284 refusal checks and two genuine failed-memory controls. Register writes zero-extend, XMM loads clear the upper 96 bits, and memory writes change exactly four bytes. The cases include eight instruction-page endings and 28 crossings, with guarded and unaligned memory. Both fault controls retain exit 125 and zero completion credit. Reproduce its recorded command under one reserved CPU; the receipt includes hardware, exact revision and optimized build provenance.

The corresponding [real-program receipt](results/20261027T214340.821771Z-page-selected-register-real-8749b6adfba7.json) still has zero completed gated programs. All four native baselines exit zero; all four gated attempts exit 125 at `660f60c9` (PUNPCKLBW, Code 1484). Default `/bin/true` reaches 12,203 ordinary TF steps and 180 generated runs; its explicitly rseq-disabled variant reaches 13,559 and 188. Every real-program timing field remains null. The required workspace checks reported above apply to their stated earlier revision; this source has only its targeted native qualification at this point.

## Mapping-query reuse and further loader coverage (claims 1/2/4)

The [unpack/shuffle oracle](results/20261027T215145.808998Z-page-selected-sse2-string-setup-61aa7f537b38.json) at `61aa7f537b389f088b439e0591a690225f2ae6fb` passes 36 new PUNPCKLBW/PUNPCKLWD/PSHUFD state pairs, two startups, 415 refusal checks and three genuine failed-load controls. The [real programs](results/20261027T215203.383538Z-page-selected-register-real-61aa7f537b38.json) advance to RDSSPQ and still fail.

At `fbe862a2b3623aa27ded57231855f6f3981432ed`, the opt-in register build shares physical maps rows within one uninterrupted handler phase, preserving every per-query ownership, seal, permission and source-byte check. Execution, application syscalls, unwhitelisted raw calls, nested events and failures invalidate the rows. The [27-process oracle](results/20261027T220510.775294Z-page-selected-maps-fbe862a2b362.json) retains all four existing positive/capacity cases and fourteen terminal controls. Nine new modes contain two successful and seven failed operations, including real partial mutation, nested signal and source corruption. Each initial shared phase observes one acquisition and three reuses. The [three connected programs](results/20261027T220554.285508Z-page-selected-register-connected-fbe862a2b362.json) complete 15 generated runs, 11 publications, four hits, nine CPUID guards and six source syscalls.

The [release measurement](results/20261027T220607.693006Z-page-selected-register-perf-fbe862a2b362.json) retains all 456 numeric intervals and passes all 59 commands. For 100 repeated two-MOV hits:

| Execution | First interval (TSC ticks) | Later mean (TSC ticks) |
| --- | ---: | ---: |
| Native | 4,526 | 125.70 |
| Page-gated | 1,437,827 | 1,308,093.36 |
| Native bracket-only control | 3,782 | 135.48 |
| Page-gated bracket-only control | 1,084,116 | 1,084,203.63 |

Intervals include clock/CPUID/page-gate costs; startup precedes them. The prior gated mean was 2,545,967.53 at `aa3f8f7e`. These are individual measurements, with no control subtraction, outlier removal or statistical causal claim. Hardware remains AMD EPYC 9D85, microcode `0xb101066`, Linux 7.1.3; C uses `-O2`, the decoder uses release mode, and children use one reserved CPU. Receipts record exact revisions and reproduction commands.

Preserved failures: the [first maps run](results/20261027T220218.123706Z-page-selected-maps-6f460d3367b4.json) exposed a 16-byte expected literal for a 15-byte field; only that exact expectation changed. A [later preflight](results/20261027T220426.731857Z-page-selected-maps-fbe862a2b362.json) rejected diagnostic Python cache files before any command. The [four real-program cases](results/20261027T220624.355297Z-page-selected-register-real-fbe862a2b362.json) still exit 125 at RDSSPQ, with zero completions and null timings. The [strict RDSSPQ oracle](results/20261027T220812.414062Z-page-selected-rdssp-ac1d2387367f.json) at `ac1d2387367f37f1086767a41f4679f9e7f58ade` stops before target execution because the actual `ARCH_SHSTK_STATUS` query returns `-EINVAL`; this is a failed prerequisite, not an instruction fault. No newer workspace-check or real-program timing credit is claimed.

## Adjacent RDSSPQ observations (claims 2 and 4)

Revision `61c451939393fec892f042f265e9bea0e1720883` adds a distinct original-address RDSSPQ path. Before opening either source page, it executes two adjacent RDSSPQ instructions with different destination seeds. Disabled shadow stacks preserve both seeds; enabled shadow stacks return the same SSP to both destinations and cannot satisfy both equalities. The actual status syscall is retained diagnostically and never grants permission. The strict query API, its four refusal controls, and its historical failed prerequisite remain unchanged.

The [native oracle](results/20261027T222516.830892Z-page-selected-rdssp-observed-61c451939393.json) passes 32 RDSSPQ full-state comparisons plus two startups, covering all 16 r64 destinations at ending and crossing instruction positions. Actual emitted probe bytes match in the production bridge and both fixture ELFs. Four strict query failures and one genuine NX refusal with explicitly supplied equal probe outputs terminate before source opening; none receives completion credit. All 441 encoding-refusal checks and 56 separate supplied-record rejection checks pass. This does not establish execution with enabled CET.

The [real-program retry](results/20261027-rdssp-regression-milestone.json) passes RDSSPQ and reaches later loader instructions. `/bin/true` stops at RIP-relative LOCK ADD (`f08305326e020001`), and `/bin/ls -d .` stops at MOVQ (`66480f7ec6`), both with default and separately rseq-disabled environments. All four native baselines exit zero; all four gated attempts exit 125. Zero real programs complete and all performance fields remain null. The same opt-in immutable cache completes 262/248 generated runs for the default true/ls cases and 268/254 for the rseq-disabled cases.

The scripts reproduce at the exact source on one reserved CPU. These optimized correctness builds use C `-O2` and the Rust release decoder, on AMD EPYC 9D85, microcode `0xb101066`, Linux 7.1.3, GCC 11.5.0 and Rust 1.97.1. Receipts retain numeric outcomes, commands, hardware and hashes; raw captures remain private.

All four required checks pass at `61c4519`: 2,457 workspace tests (four previously ignored), 330 recorder tests and 1,029 serial tests. Nineteen native regression evaluators pass. The twentieth passes its 32 finite outcomes, then its default-bridge `ls` diagnostic receives SIGKILL after 3.024 seconds under unchanged three-CPU-second/15-wall-second limits. Enabling the already qualified mapping-row reuse in the default bridge at `9058d98efb82970a9fb3a049d518d407c53198db` also leaves that diagnostic failed. Neither result is relabelled. The [compact regression receipt](results/20261027-rdssp-regression-milestone.json) covers all 23 evaluator runs and 1,225 commands; [two diagnostic records](results/20261027-default-diagnostic-failures.json) preserve their exact failed outcomes. Reproduce each recorded command at its stated revision. The [release finite benchmark](results/20261027T223502.491322Z-page-selected-register-perf-61c451939393.json) retains all 456 raw intervals; it provides no completed-real-program timing.

At `c3b8ab3f65c81fc2ffaa52855c3dc95585bb886d`, nine canonical MOVQ encodings pass [48 full-state pairs](results/20261027T223710.859540Z-page-selected-sse2-movq-c3b8ab3f65c8.json), including 45 new cases, every instruction split, guarded eight-byte operands and two genuine failed-memory controls. The [MOVD regression](results/20261027T223724.567929Z-page-selected-sse2-movd-c3b8ab3f65c8.json) preserves 38 pairs and both faults. Its two formerly refused MOVQ bytes now receive separate positive qualification; 22 other neighbor refusals remain. The [real retry](results/20261027T223736.526833Z-page-selected-register-real-c3b8ab3f65c8.json) moves `ls` past MOVQ. All four programs now stop at the same LOCK ADD, with zero completions and null timings. Workspace checks for this successor remain pending.

## Canonical locked arithmetic and merged-tree checks (claims 2 and 4)

Source `a3a71a85743a9ed9093cf8176c38e2443ea1a39d` adds original-address LOCK ADD and LOCK SUB for exactly `f0 83 05 disp32 imm8` and `f0 83 2d disp32 imm8`. The CPU executes each atomic operation. The [ADD](results/20261027T224902.083214Z-page-selected-lock-add-a3a71a85743a.json) and [SUB](results/20261027T224848.315784Z-page-selected-lock-sub-a3a71a85743a.json) native oracles each qualify 32 arithmetic pairs plus two startup pairs, every ending/crossing position, 248 refusal checks and four separately counted positive SUB classifications. The original ADD neighbor table remains intact; its exact SUB row now requires successful classification and has separate native qualification. Full register, flags, stack, FP/XSAVE and data comparisons remain required.

Both suites retain two genuine failed RMW controls: populated no-access and read-only operands. Native and stepped execution fault at the original PC, preserve the complete operand page, revoke and synchronize source pages, and exit 125 without completion credit. The finite operands are aligned four-byte words in one cache line. These results do not qualify split locks, device memory, cross-page partial faults or concurrent atomicity. The first ADD build at `4c4fa64f` failed on signed/unsigned displacement comparison under `-Werror`; `57157b56` fixes only that signed cast and passes its native oracle. Both receipts remain recorded.

The [merged-tree receipt](results/20261027-locked-arithmetic-milestone.json) binds 26 evaluator runs and 1,296 commands. The requested `7ab79270` is an ancestor. All four required checks pass: formatting, strict workspace Clippy, workspace tests (2,457 passed, four previously ignored) and all-feature/all-target checking. Recorder tests pass 330; serial tests pass 1,029. Twenty-three of 24 native evaluators pass. The remaining repeat evaluator passes all 32 finite cases but its default-bridge `ls` diagnostic receives SIGKILL after 3.028 seconds under the unchanged three-CPU-second/15-wall-second bounds. Its aggregate remains failed in the summary and the [diagnostic records](results/20261027-default-diagnostic-failures.json).

The [real-program retry](results/20261027T224914.293039Z-page-selected-register-real-a3a71a85743a.json) still completes no gated workload. Default true/ls exit 125 at PMAXUD (`660f383fc1`, Code 2993). Explicitly rseq-disabled true reaches a dependency BND JMP (`f2ff25d52a1d00`, Code 765) after 128,769 generic steps, then exits 125; rseq-disabled ls receives SIGKILL under its unchanged 30-CPU-second/60-wall-second bounds. All original-native baselines exit zero. Real first-touch, steady-state and whole-process timing fields remain null.

Receipts include exact source, hardware and reproduction commands. Run each native evaluator at its recorded revision with one reserved CPU; C uses `-O2` and the Rust decoder uses release mode. Hardware remains AMD EPYC 9D85, microcode `0xb101066`, Linux 7.1.3, GCC 11.5.0 and Rust 1.97.1. The separate release finite benchmark retains all 456 numeric intervals; it supplies no completed-real-program measurement.

### Further original-PC coverage and the finite clock observer (claims 2 and 4; real programs incomplete)

At `152a8650c18e5d50b4871cb72c8c669762042f2d`, five canonical PMAXUD forms passed 18 new native/TF pairs plus startup, 294 decoder refusals and two genuine failed memory operations. Exact BND indirect JMP `f2 ff 25 disp32` passed 14 new pairs plus startup, both signed displacement directions and every fetch split, 315 decoder refusals, a genuine failed pointer read and three explicitly supplied pre-open MPX refusals. Successful BND execution requires a fresh actual XCR0 observation with both MPX components disabled; supplied controls do not qualify enabled MPX.

At `bb425428e4d4e9cd51b9e431d819ac6a9bafdd8d`, the exact unmasked VPBROADCASTB `62 e2 7d 48 7a c6` passed 36 new pairs plus two startups and 154 decoder refusals. The source byte is broadcast into all 64 ZMM16 bytes. Every fetch split, high source bits, independently initialized nonzero ZMM/opmask state and actual standard-layout CPUID/XSAVE geometry are covered by the finite oracle; all other captured state and memory comparisons remain. This adds no general EVEX or target data-memory fault coverage.

The retained 152 suite has 27 evaluators/1,337 commands: 23 passed, two passed finite cohorts, and two failed. Its connected REP run retained all 32 finite outcomes (28 completed, four required refusals; 168 finite commands) before real `ls` exited −9. At bb425, VPB plus seven non-timing targeted evaluators total 278 commands: six passed, one passed its finite cohort, and real programs failed. The separate timing evaluator ran 47 commands and also failed discovery. Default `true`/`ls` still refuse rseq (601/detail334); rseq-disabled `true` now reaches `62e1fe486f0f`/Code1605, while rseq-disabled `ls` exits −9 without a report. None completed a gated real program.

The opt-in clock observer passed its three finite outcomes at 837d15d, 152a865 and bb425: 11 native/cache pairs with 22 actual nanosecond intervals per run, plus genuine invalid-clock and pending-signal failures (exit 125/errors 803/808). Real discovery remained failed and timing null: historical837 reported VPBROADCASTB, 152's explicit `true --disable-rseq` exited −9 without a report, and bb425's default `ls` refused rseq. The historical erroneous public whole-process duration is excluded, with its original receipt and the 152 projection correction bound. All 66 finite observer intervals and all 456 finite two-MOV/CPUID-guard TSC intervals at152 are retained. They include gate and clock costs and establish neither application speedup nor isolated cache cost.

All six required commands passed at `bb425428e4d4e9cd51b9e431d819ac6a9bafdd8d`: recorder 330, format, workspace Clippy, workspace tests (2,457 passed plus four ignored across 98 harnesses), all-feature/all-target workspace check, and serial launch (1,029 passed across 27 harnesses). Both earlier failures remain failed: the 152 workspace ordinary32 test exhausted its original three-second deadline at instruction 31; the 645b7c3 test-only serialization preserved that deadline but its recorder rejected the stale source pin (328 tests/28 errors, other five commands not run). The pin correction is distinct from a new qualification run. The first bb425 native/check invocations also failed preflight on generated Python bytecode with zero workload commands; they receive no execution credit.

The compact projection binds each exact public/private receipt, revision, hardware, tools, source/artifact hashes, commands, outcomes and raw intervals. Native runs used one reserved CPU on AMD EPYC 9D85, Linux 7.1.3, GCC 11.5.0 and Rust 1.97.1. Every evaluator's exact command is retained; e.g. `python3 evaluation/inprocess/page_selected_vpbroadcast.py --expect-revision bb425428e4d4e9cd51b9e431d819ac6a9bafdd8d`. The tracked projection script reproduces the aggregate from those retained receipts without rerunning or replacing any qualification gate.

The [compact numeric receipt](results/20261027T234020.381282Z-bnd-vpb-timing-summary-bb425428e4d4.json), [projection command](results/20261027T234020.381282Z-bnd-vpb-timing-summary-bb425428e4d4-argv.json), and [projection script](summarize_selected_milestone.py) retain the result and its reproduction recipe.

### TRACE handoff and exact VMOVDQU64

The [20-receipt numeric projection](results/20261028-trace-vmov-milestone.json)
retains the historical attempts and final source
`cdac5a7fd5d95c090048ec7be3d7ce901d4fbfee`. It makes no claim about a later
merge. The opt-in TRACE path hands a genuine completed event to a qualified
ordinary successor at its original address, preserving closure and ownership
checks. Selected and guarded routes keep their explicit entry paths; instruction
coverage remains bounded.

The finite TRACE oracle passed 23 processes: 12 native/all-NX/chained programs
(36 completed lanes) and 11 failed-operation controls, with 1,081 old refusal
checks and 345 route checks. The exact `62e1fe486f0f` VMOVDQU64 load passed 36 new
aligned/unaligned pairs plus two startup pairs, 320 encoding-refusal checks, and
two genuine failed reads. Those reads still exit 125 and remain uncompleted
operations. Their actual native/owner/live XSTATE and fault observations are
retained. System headers were not individually archived, and failed-step final
memory checks are enforced in C without separate final memory snapshots.

The first TRACE selector (`dd05a9e`) and geometry (`70a4572`) attempts remain
failed; `15b7e99` retains the first qualified TRACE cohort and its five regression
receipts. VMOV's `057442d` attempt failed compilation before native execution;
explicit unsigned casts preserved the flags predicate. A separate invocation
with incorrect expected revision `5737d065` was refused at source preflight with
zero commands and observed source `cdac5a7`; it is kept outside valid-revision
runs.

At `cdac5a7`, the VPB, generic, maps and register-control regressions passed;
the connected runner passed its finite cohort. All six required checks passed: 330 recorder tests, workspace 2,457
passed plus four ignored across 98 harnesses, and serial launch 1,029 passed
across 27 harnesses, with native collections and backing cleanup qualified.
Exact commands, hardware, source and original receipt hashes are retained.

All four real-program cases still failed, while their native baselines exited 0.
The last gated `ls` exited -9 without a complete report; partial chain counters
are observations, not completion credit. Real timing discovery also failed.
All 22 finite clock interval values remain public, while real-program timing
stays null. No real-program completion or performance qualification is claimed.

The [projection script](summarize_trace_vmov.py) and
[exact input inventory](results/20261028-trace-vmov-inputs.json) reproduce the
numeric bytes from retained original receipts, without running workloads:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/summarize_trace_vmov.py --inputs evaluation/inprocess/results/20261028-trace-vmov-inputs.json --output target/reproduced-trace-vmov.json
```
