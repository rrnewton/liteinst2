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
