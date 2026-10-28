This fixture retains the original exact `62f175407407`, VPCMPEQB K0,ZMM17,[RDI] (Code 1720), native cases and failed-read controls. The product also admits the canonical unmasked W0 [RDI] source/destination family; its separate `vpcmpeqb_memory_family` fixture is mandatory qualification for that extension. The original register encoding `62b1754074c8` is unchanged.

Run with one reserved CPU:
`python3 evaluation/inprocess/page_selected_vpcmpeqb_memory.py --expect-revision <full committed SHA>`.
Build/invoke bind actual source, tools, archive, compiler headers, ELF record symbols, captures and cleanup. The fixture retains -O2/-Werror, the original VMOVDQU64 all-32-ZMM/all-8-K assembly and generic full-state comparator. Limits remain 5 CPU seconds, 15 wall seconds, 512 MiB address space and 16 MiB records per process.

One 19-pair cohort contains the original 18 comparisons plus startup. Three independent K0 results (0, UINT64_MAX and 0x9249249249249249), offsets 0/257/4032 and all six fetch positions are unchanged. Every other initialized kernel FP/live XSAVE byte, all vectors, other masks, GPRs, full flags, selectors, FS/GS, source, stack and data must match. XSTATE_BV is not normalized.

Two genuine failed 64-byte reads retain exit 125: a wholly inaccessible operand and a 32-readable/32-inaccessible operand. Both require #PF/ERR4 at original PC, exact CR2, no TRACE/completion, unchanged full state and full protected-page contents. C checks that protected page; the retained record does not contain separate copies of it. These failed operations are never positive pairs.

All 66 supplied neighbor rows and all 47 common rows retain their bytes. Local rows 33,34,39,40,41 now require explicit Code 1720/FALLTHROUGH/SIMD and NONE results; the other 108 rows remain refusals. Each promotion has exact native cases in the family suite. A separate 1504-byte trailer retains all five supplied register tuples and typed results; these are not actual-before observations. The original 40 actual-before NONE queries remain mandatory. Across three processes: 324 refusals and 15 typed/supplied-NONE promotions.

Record extent is 136+22*sample_bytes+40+5000+96+9024+1504. C and actual ELF symbol sizes enforce the unchanged 16 MiB limit. The Python reader validates the complete record, CPUID, failure prefixes, queries and promotion identities. The authenticated C oracle performs the full architectural comparisons. Execution results are reported separately; no application completion or performance claim follows from this fixture.
