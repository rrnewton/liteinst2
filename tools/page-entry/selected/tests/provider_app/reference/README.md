# Native full-state reference

This reference executes the unchanged `provider-app state native`, its real
DSO, system interpreter/libc and default rseq registration. It captures all 18
selected operations. It is a native oracle, not the page gate or a benchmark.

Build with `build.sh SOURCE_DIRECTORY NEW_BINARY`. Run with the original app,
original DSO and a fresh output directory. The caller reserves one CPU, binds
the source/build/environment and supplies a trusted `LD_LIBRARY_PATH`. The
tracer accepts ordinary absolute files or authenticated `/proc/self/fd/N`
inputs with all four memfd seals. It verifies the actual mapped file identity.
The reader requires the independently observed tracer and child PIDs and CPU.
One 15-second deadline covers the trace, plus two seconds for failure cleanup.

A hardware breakpoint stops at each actual `capture_before` helper. The tracer
then temporarily puts INT3 at the selected instruction. At that trap it restores
and reads back the original byte and rewinds only RIP. A second temporary INT3
at the next-PC NOP stops after the real instruction; restoration and RIP rewind
precede observation or application self-reads. No selected instruction is
single-stepped and no effect register or TF/RF flag is edited. Both raw traps,
patch words, readback, rewinds and hardware-stop tuples remain in the record.

Each state includes all 27 GETREGS words, GETSIGMASK, the complete returned
NT_X86_XSTATE, both original 4-KiB site pages and both 16-KiB stacks. The reader
joins actual PID, clock, object, stack and TLS observations to the independent
application model. `pair` compares the gate's actual UC/FP frames using the
unchanged B2 `xstate.pair` and `boundary.fp_payload` predicates.

The same-CPU `seed_probe` must first establish exact zero FIP/FDP for the real
nonempty x87 seed. Both native and gated readers require that explicit profile;
no address-or-zero alternative or architectural-byte normalization is allowed.
All other seed predicates and full architectural XSTATE comparisons remain.
Native capture alone grants no cross-lane or publication qualification.
