The corrected fixed native campaign passed: focused tests 69/0/0 and parallel core-library tests 398/0/1 (passed/failed/ignored). Workspace Clippy passed. Five closed commands are retained, including the initial 52/17/0 failure and formatter operation. Whole-workspace tests are not included.

The initial run failed 17 positive rows: after a witnessed hardware CALL and successful helper entry/context checks, the observer continued at the same PC into its unowned-entry assertion. The correction steps exactly the first helper instruction using the existing budget before continuing. The guard, hardware RET checks, comparators, cases and bounds remain unchanged. The next run used corrected source; the initial failure remains a failure.

Each complete campaign contains 31 rows, two seeds, two hooks and three phases: 372 subject traces plus 124 seed children. There are 19 distinct static artifact mutant classes, executed 2,413 times across 127 owners per complete campaign. Counts derive from mandatory source loops and passing tests, not individual trace logs. The failed initial run receives no complete-campaign credit. rows.csv retains all rows and each run's result; B/L/U/F addresses are in receipt.json and B+4 is 0x401bc2.

The claim covers this private fixture with the actual production SIGILL handler, child-owned counters and real rt_sigreturn. It retains hardware CALL/RET, ordered full GPR/defined-FLAGS/canonical native-XSAVE/data/stack comparisons, immutable pages and exact null/recording logs with zero tail. No post-seed PC/state repair is used. This does not qualify public install/retire, general artifacts, ELF execution, whole corpus, performance or exact FXSAVE bytes.

Receipt/log hashes, source revisions, CPUs, load, limits and cleanup are recorded in receipt.json without host/account identifiers. Two nested one-test summaries are excluded from the 398/0/1 total; its ignored test is a release-mode latency benchmark. Timings are provenance, not performance evidence.

Use the build environment and CPU reservation described in the parent README. Focused reproduction command:

```sh
cargo test -j 4 -p liteinst2 --lib entry_router::imp::routed_jmp_native_tests:: -- --test-threads=4 --nocapture
```

The existing evaluation/short-neighbor-parallel/validate.py provides broader reproduction. From the repository root, pass --revision bba07c2c682948faf81a210837c9d61f2bf40eb0 and a fresh --output under ignored/. Its hash is recorded; it was not run while drafting this packet. Preserve declared resource bounds.
