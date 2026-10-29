# Normal-loader effect-provider fixture

The system interpreter and libc start a PIE executable with a real
`DT_NEEDED` DSO and glibc's default rseq registration. Main and DSO each
export CPUID, getpid SYSCALL and RDTSC sites on file-backed RX pages. The
fixture requires observed registration; it never disables or unregisters rseq.

Build with `build.sh SOURCE_DIRECTORY NEW_OUTPUT_DIRECTORY`. This emits
`provider-app` and `libli2-provider-app.so` without RPATH/RUNPATH. The native
launcher supplies a trusted `LD_LIBRARY_PATH`; the gate uses sealed dependency
roots. The driver authenticates the compiler inputs and actual ELF objects.
Both complete native helper pages and their 14-byte halos must pass the
unchanged native policy.

`state native` performs three rounds through main then DSO, for 18 effects.
`state scripted` expects the six distinct callback results. `stress` performs
1,536 rounds, or 9,216 effects. Native reference execution uses the unchanged
original program. Scripted results are compared with the independent literal
model and the native frame's unchanged architectural state.

The application captures all GPRs and logical flags, 32 ZMM registers, eight K
registers, FCW and FSW. Each private stack retains all 16,384 marker bytes.
Every effect reads its restored original five-byte window; the application
also compares and serializes both complete original site pages. These live
captures are supplemented by complete controller UC/FP records and a genuine
native NT_X86_XSTATE reference. `read.py` checks the publication, restoration,
effect and sigreturn sequence; `reference/read.py:pair` applies the unchanged
B2 full-XSTATE comparators. Output or counters alone do not qualify publication.

`policy.c` receives an immutable six-row table derived from registered sealed
objects and actual ELF offsets. Matching uses the never-reused object ID and
backing-file offset, without assuming a pre-entry DSO load bias. A matching row
with wrong bytes, kind or state refuses. Unmatched loader/libc operations use
the Native policy. `seed_probe` independently checks the exact x87 seed profile
on the same CPU before native/gated pairing; different hardware behavior refuses.

State output is 102,296 bytes. Stress output is 44,024 bytes and retains every
clock scalar for independent aggregate checking. Stress observes full frames
at indices `0..8, 8189..8193, 9212..9215`, plus complete whole-run counters;
it does not claim 9,216 full external frame comparisons. The driver runs state
and stress under both policies with the same 30-second CPU, 60-second wall,
512-MiB address-space and 16-MiB capture bounds. It owns every process through
exit/reap and retains failures.

This fixture alone does not establish full B2 qualification. The all-seven
instruction reference, masked-CPUID cases and negative cohorts remain required.
Performance and real-program completion require separate exact-revision runs.
