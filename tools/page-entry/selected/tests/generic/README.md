# Generic-TF native endpoint oracle

This finite component compares 20 same-address native/stepped pairs: the real
NOP startup selftest, followed by ADD64, ADC32, XOR8, STD, load64, store64,
memory ADD64, LEA RSP, PUSH, POP, taken JZ, not-taken JNZ, indirect JMP,
direct CALL, indirect-memory CALL, RET, RET-immediate, a crossing MOV64 and
XMM PXOR. It uses the product decoder, owner and lifecycle implementations.
Both lanes execute the original bytes; operands and results come from the CPU.

Every pair compares all 16 GPRs including RSP, exact logical flags with the
authenticated NX-RF/owned-TF distinctions, original and endpoint RIP, masks,
actual FS/GS bases, all six live user selectors, complete initialized kernel
FP frames and qualified XSAVE bytes. Complete 8 KiB stack and 4 KiB data
allocations are compared before and after. A separate RX observation stub
captures live post-sigreturn state without touching the subject stack.
Unseeded components or reserved-byte differences remain failures.

Actual TRACE must revoke and synchronize the source fetch pages, then query
the genuine closed continuation while the source borrow remains held. The next
NX fault precedes another application instruction. The crossing MOV native
reference has its explicit INT3 endpoint. Boundary CALLs push original PC+length;
the return page remains NX and is absent from the opened source bundle.

The three negative commands remain failed operations (exit 125): a real
PROT_NONE load, a branch into a mapping outside lifecycle ownership and an
actual RSP result of 2^47. Their exact failure and cleanup prefixes are checked
separately. The last native reference suppresses its unrepresentable return
only for diagnostic escape; it is not successful continuation evidence.
The 47 refused decoder encodings are supplied-data controls, not native runs.
Their record retains completed count, failed index and final classification;
the unchanged loop checks each individual refusal before incrementing progress.

After committing all sources, reserve one CPU externally and run:

```
python3 evaluation/inprocess/page_selected_generic_oracle.py --expect-revision <full-commit>
```

The shared builder uses locked/offline Cargo, one target directory, exact tool
and source bindings, and private copies of all seven selected build outputs
plus its generic observer. This oracle executes only its own static fixture.
`build.sh ARCHIVE OUTPUT_DIR` links it against the freshly retained archive and
product C sources; it performs no native execution.

Each native process keeps the original 5 CPU-second / 15 wall-second bounds,
512 MiB address-space and 16 MiB per-file limits, no core dump and 8 KiB accepted
stdout/stderr. Child preparation records the actual reset signal dispositions
and mask. Each attempt owns a fresh record fd3; every process must be reaped
without cleanup errors. There are no retries or widened comparators.

Compact public JSON contains numeric results and hashes. Full private records,
preparation, argv, environments, tools, binaries and DWARF stay under `target`.
Each binary record contains the 17-u64 header, 20 samples, one negative sample
and the final 40-byte classification. The record's actual sample size and the
retained binary's DWARF support independent field replay; no historical layout
is assumed. `OUTCOMES.json` is the expected protocol, never observed results.
Negative stepped-after memory is checked inside the native fixture but lacks
a separate copied after-image in the failed record. SIGBUS/SIGILL are terminal
under the closed profile, with no claimed explicit captured-frame/revoke proof.
This oracle does not establish loader, arbitrary-program, signal transparency,
performance or complete B2 coverage.
