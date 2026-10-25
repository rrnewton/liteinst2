# Sample extraction declaration, before population scan

The initial real-binary cohort consists of 32 straight-line leaf tails from the
system's installed GNU C library ELF. Record the complete file SHA-256, ELF
machine/type/build-id, objdump version, executable PT_LOAD identities, virtual
and file offsets, exact bytes, original heads and complete disassembly privately.
The input is an existing real binary; do not compile fixtures and call them samples.

Eligibility is deliberately narrow and is not representative whole-binary
coverage. GNU objdump independently supplies instruction heads. Consider every
contiguous tail of 2 through 8 decoded instructions ending at an unprefixed RET
(C3). The first instruction must occupy at least five bytes. Every preceding
instruction must be MOV, LEA, NOP, ADD, SUB, CMP, INC or DEC on integer registers
and immediates. LEA may use a bracketed address expression but cannot use RIP/EIP;
it does not dereference memory. All other memory operands, segment overrides,
stack-pointer writes, branches, calls, prefixes reported as separate mnemonics,
and flag-undefined operations are excluded. Instructions must fit the same
executable PT_LOAD, use contiguous addresses and exact file bytes, and contain no
RIP-relative or absolute referenced code/data context. RET uses the oracle's
authenticated return stack. Every alternate original head is thus finite.

Deduplicate exact tail byte strings and retain the earliest original virtual
address for each. Rank eligible unique tails by SHA-256 of the literal tag
`liteinst2-a2-samples-v1` followed by their exact bytes. Select the first 32;
record the complete candidate population and rank manifest, not merely the
chosen positives. If fewer than 32 exist, report insufficient eligibility and
revise the prospective design before execution, preserving all declarations.

The sample native oracle forces ordinary B1 at the first instruction, whose
length independently provides its complete five-byte redirect window. It enters
every declared head with two fixed initial-state seeds, compares installed and
retired full state and ordered selected-hook events, and retains exact source
modification bounds. Source offsets are recorded even though this no-external-
reference grammar permits a single common load bias for the copied tail. The
cohort makes no RIP/data-relocation, CET, call/unwind or whole-binary claim.

This file declares extraction policy only. The final manifest, generator and
campaign identities and all budgets must be frozen and independently reviewed
before native campaign execution. Raw ELF/disassembly/captures stay ignored.
