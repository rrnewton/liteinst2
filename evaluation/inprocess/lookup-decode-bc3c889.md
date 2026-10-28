ADDS positive page-record lookup reuse and reuse of the qualified TF decode in write-footprint queries, plus an explicit CPUID-NX real-program evaluation mode.

Tested revision: `bc3c88937d7a0db229a4f98badbcef79baf5c49d`, containing main `0a8fb30d7ac98cc47b62ba16eccab0b5bfd6a368` and the requested `7ab79270` integration. The memo returns the current mutable page record; it caches no permission, backing or rseq decision. The footprint query consumes an owned instruction from the existing classifier and retains its policy, identity, operand and address checks.

The [native summary](results/page-lookup-decode-bc3c889.json) records nine passing oracle runs, 400 commands and 439 full-state pairs. The page lookup oracle compared 3,716 queries against both the original reverse scan and literal expected slots through 8,192 appends and retirements. The original 38-row footprint, generic, vector load/store/memory-fault and 17-subject rseq checks passed. All 38 expected nonzero native fault/refusal operations retain their original required outcomes. Each summary row records its exact reproducer, revision, hardware, bounds and original receipt hashes; these correctness runs supply no performance claim.

The [required checks](results/20261028T161610.859557Z-checks-bc3c88937d7a.json) passed: 350 recorder tests; formatting; strict workspace/all-targets/all-features Clippy; 2,931 workspace tests with 33 ignored across 103 harnesses; workspace all-features/all-targets check; and 1,039 serial launch tests across 27 harnesses. Workspace and serial limits remain 900 and 180 seconds.

Both unchanged five-case release matrices remain **failed overall, four cases passed**. `/bin/true` with default and disabled rseq, `/bin/ls -d .` with disabled rseq, and the boundary fixture passed. Every original output, completion and resource check remains enabled.

| Profile | Disabled-rseq ls process time | First admission service | Median of 16 admission revisits | Default-rseq ls outcome |
|---|---:|---:|---:|---|
| [Legacy](results/native-pages-bc3c889.json) | 18.152593004 s | 81,802 ns | 82,659 ns | Reportless SIGKILL after 30.230252602 s; cause unproven |
| [CPUID-NX](results/native-pages-nx-bc3c889.json) | 18.267841315 s | 97,666 ns | 79,935 ns | Exit 125 after 30.078010811 s; rseq footprint refusal for BZHI |

Measurements used optimized C and Rust builds on one reserved CPU of an AMD EPYC 9D85. The JSON receipts retain all native/gated observations, raw revisit samples, program/library identities, hardware and exact commands. Process time includes namespace preparation. Admission service excludes signal delivery, native execution and close; revisits are to the same address/allocation/generation and do not measure whole-program steady-state throughput. Single observations on a shared host establish no causal speedup.

The [NX failure observation](results/native-pages-nx-bc3c889-failure.json) identifies status 125, failure 1207, instruction Code 3680 and length 5, after 367,309 completed TF steps. All 1,139 native admissions were closed; the refused next instruction never opened its source page. This is an unsupported write-footprint case, not successful completion. The earlier [c456 NX matrix](results/native-pages-nx-c456ec1.json) also remains failed at four of five, with reportless default-rseq ls SIGKILL.

This provides evidence for selected-instruction coverage and systematic validation within the existing in-process envelope. Current-C hook cost, the BZHI footprint gap, stack-pointer random/ID operands, and broader lifecycle/hybrid work remain open. No B2/B3/B4 completion or unrestricted ISA coverage is claimed.
