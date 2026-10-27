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
