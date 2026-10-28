Exact BZHI RBX,RDX,R11 (`c4e2a0f5da`, iced Code3680) uses the original instruction under the existing fetch/TF owner. It changes only RBX and arithmetic flags; its qualified write footprint is NONE. Other register spellings, memory operands, RSP destinations/sources/indices, W0, L1 and added prefixes remain refused.

Two native/TF cohorts contain25 new pairs plus2 startup pairs. Five independent source/index literals cover low-byte indices0/1/63/64/255 and ignored high index bits; each appears at all five fetch tails. There are50 actual-before footprint queries. Initial arithmetic flags and DF alternate. The generic full-state comparator remains unchanged: native and TF lanes compare every actual flag bit, including architecturally undefined AF/PF. Literal assertions additionally check RBX, CF, SF, ZF and cleared OF. Every other GPR, original RSP, selectors, FS/GS, signal mask, initialized kernel FP/live XSAVE, all32 ZMM/all8 K, stack, data and source bytes remain checked.

The full-vector assembly is reused directly from tests/vpxorq128/fixture.S. Its hardware profile remains required, with an additional actual BMI2 CPUID bit. This finite host profile does not claim all BMI2 hardware. The21-slot record layout remains fixed; every unused positive/negative sample and unused trailer row must be zero. Each process is limited to5 CPU seconds,15 wall seconds,512MiB address space and16MiB files on one allocated CPU.

All47 common and109 retained donor refusals are checked, alongside the donor's mandatory typed VPTESTMB/NONE promotion. A separate31-row BZHI refusal array grants no memory-fault execution credit. Existing old suites retain their cases and counts.

ISA provenance: Intel BZHI, https://intel.github.io/SDM/data/sdm/BZHI.docbook, SHA256 ef0f43046dab973cf84b9f636ee2ac1695c3202ed05006eb65fc2e930623dff4. The operation uses original SRC2[7:0]; values>=64 preserve the full64-bit source and set CF. OF clears, SF/ZF reflect the result, AF/PF are undefined. The hardware-versus-hardware comparison still retains AF/PF exactly.

Reproduce after source promotion with one allocated CPU:
`python3 evaluation/inprocess/page_selected_bzhi.py --expect-revision FULL_COMMIT`
The evaluator records actual tools, compiler headers, archive, ELF extents, command/capture identities and final source closure privately. The public result contains numeric counts and hashes. Execution results are reported separately; neither a finite-oracle pass nor source review claims real-program completion or performance.
