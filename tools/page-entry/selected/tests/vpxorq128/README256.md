# Canonical VPXORQ256 register and memory qualification

Run `python3 evaluation/inprocess/page_selected_vpxorq256.py --expect-revision REV` on one reserved CPU at the full committed revision. It builds the decoder and twelve five-translation-unit fixtures with `VPX_BITS=256`. All twelve successful processes and four required read-fault processes must qualify. Each retains the original limits: 5 CPU seconds, 15 wall seconds, 512 MiB address space and 16 MiB per file.

The 193 selected pairs comprise 97 register and 96 memory cases, including the observed libc encoding, all 32 vector operand roles, 16 GPR bases, 15 usable indices, and 42 instruction-length/page-boundary combinations. One RIP-relative operand crosses source-image pages. Code bytes remain identical between native and TF lanes. The oracle checks the original operands' 32-byte XOR, independently authored expected bytes, zero destination bits 511:256, and exact remaining kernel/live XSAVE, K, GPR, flags, selectors, FS/GS, source, stack and data state. Four genuine full/cross-page read faults, including indexed addresses, preserve failed-state and cleanup checks without receiving completion credit. The Python reader validates complete ELF-sized records, CPUID layouts, all 394 actual-before NONE queries and independently reconstructed effective addresses; it does not perform a second full architectural replay.

Every row in the original 73- and 37-entry neighbor tables remains. Existing Code 2785 and ten Code 2791 positive controls remain mandatory. The old `vpx_refused[9]` literal (`62a1fd20efc0`) now requires an exact Code 2460/FALLTHROUGH/SIMD/NONE result in a separate 352-byte record. The other 36 XOR neighbors and 35 new unsafe encodings still refuse. Each new process checks 180 refusals and 133 unsupported write-footprint queries. Supplied controls do not count as native state pairs.

Run these compatibility evaluators sequentially at the same revision, each with `--expect-revision REV`:

- `evaluation/inprocess/page_selected_vpxorq128.py`: 6 processes.
- `evaluation/inprocess/page_selected_bzhi.py`: 2 processes.
- `evaluation/inprocess/page_selected_bmi1_register.py`: 6 processes.
- `evaluation/inprocess/page_selected_vpminub_register.py`: 6 processes.
- `evaluation/inprocess/page_selected_kortestq.py`: 5 processes.

Those 25 processes retain all 418 native pairs and old literals, and each requires the new 352-byte Code 2460 observation. Historical receipts do not qualify changed source.

Masks, zeroing/broadcast, EVEX512/reserved widths, memory EVEX128, W0, added prefixes and truncated encodings remain outside this predicate. Existing register-only EVEX128 support is unchanged. This finite cohort does not establish exhaustive address coverage, late-DSO completion, full B2 coverage or performance. Execution results are recorded separately; the earlier late-DSO failure remains failed.
