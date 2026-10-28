# Configured provider: genuine carrier entries

This finite fixture uses the real carrier, a literal ET_DYN custom interpreter,
and four high-address ET_EXEC mains. The interpreter's very first instruction
is CPUID (`0f a2`), with its actual inherited inputs. It then performs MOVABS/JMP
to the main entry. The four mains start with CPUID, RDRAND64 R15, RDSEED64 R15,
and RDPID R15 respectively. Neither entry is described as independently seeded.
No libc, constructors, rseq registration, or conventional loader executes here.
The interpreter has an actual SONAME and the main has one actual DT_NEEDED;
the real sealed namespace must bind that sole dependency to those same bytes.

After the two entry effects, each main performs 16 seeded operations: CPUID
leaf 1 and leaf 7/subleaf 0; RDRAND and RDSEED at 16/32/64 bits into RAX and R15;
and RDPID into RAX and R15. These instructions execute unconditionally after the
feature bits are masked. The fixture requires 18 configured effects per gated
process. Expected random values are independent named-policy literals; CPUID
expectations retain the actual native sample and clear only the three named
bits after successful rearm. Native physical random results are not compared
to configured values.

A separately admitted, fully scanned native page seeds and captures all 16 GPRs,
logical flags including DF=1, selectors, all 32 ZMMs and all eight K registers.
Every provider sample retains the genuine original-PC NX metadata, complete
before/after ucontext, complete kernel FP image, both complete main code pages,
the complete interpreter code page, and all 16 KiB of fixture data/stack. Actual
CPUID-D offsets and XCR0 bind the initialized ZMM/K kernel state. The following
live capture proves those registers survive sigreturn. The interpreter result
is additionally joined to the genuine first-main frame through its literal
MOVABS/JMP handoff. There is no fabricated NX frame or expected value derived
from a captured after-state.

The record compares the full kernel FP image, including x87/MXCSR and all other
retained bytes. It does not independently execute live XSAVE to capture every
extended state component after sigreturn. The unchanged provider385 cohort and
the separate callback component remain mandatory; this fixture does not replace
their checks or turn component failures into carrier completion.

Two original RDTSC sites and four original syscall sites use the existing
one-shot owner. Actual writes read the restored five-byte syscall/RDTSC source.
All six owners must publish, restore and start their effects; five return and
complete. Exit remains RESTORED (phase 7), with no returned marker. The 58-byte
stdout retains four actual clock words, requires increasing time, and compares
only the stable 26-byte source/marker prefix across native/configured lanes.
No timing, performance, persistent-publication or general-program claim follows.

`prepare.py` inserts seven observation hooks into exact copies of the production
runtime/controller. Reversing them recovers both complete production files.
The observer changes no guard, input frame, source byte or provider result; its
fixed storage is prefaulted before entry. Its hardcoded addresses and FD3 output
are finite-fixture-only and never enter the production recipe. `reports.py`
retains the entire old report/completion implementation under five exact
source adapters: an additional bounded provider line, return value/signature,
and the explicit 32 seed/capture main-admission count. All old chain/register,
TF, rseq, one-shot and cleanup completion predicates remain required.

The reusable helper is `page_selected_provider_launch.launch(builder, products,
root, private, pin, binary, aliases, run, receipt)`. `run` must provide the existing
supervised `(row, stdout, stderr)` interface and `record=True`; both native and
gated lanes use real FD3 preparation. The enclosing evaluator must install the
exact exported `BOUNDS`, use the same-revision Build/archive, bind all source,
tool, alias, artifact and command captures before/after, and call
`finalize(receipt)` again from its finalizer. `summary(receipt)` emits only compact
counts, integers and hashes; final qualification also requires the enclosing
receipt to pass. It emits no raw source/frame addresses or host paths.

The observed bridge is compiled from the actual configured 16-TU release recipe
with only the runtime source path changed to its exact observation adapter.
Actual compiler-M output binds every conditional include. The configured
carrier leaf must support the explicit sole policy `mask-random-v1`; the actual
launch record must contain it in the closed environment. Setting a parent
environment variable alone is insufficient. File-only ELF/DWARF, emitted fast
memset, symbol, source-policy and namespace checks precede all eight processes.
Every case keeps 30 CPU seconds, 60 wall seconds, 512 MiB and 16 MiB output bounds.
Partial artifacts and the original error remain retained when later observation
fails. No build or native execution has been performed for this source freeze.
