# Four forced tactics under normal exec

These are additive authored fixtures for the existing generic ELF frontend.
They preserve the earlier B1 fixture and its predicates. The source and
selection preparation alone establish no native result or full A3 claim.

Assemble `subject.S` with exactly one explicit GNU assembler definition:
`--defsym TACTIC=2` selects B2, `3` selects T1, `4` selects T2, and `5` selects
T3. There is no default. Link with the adjacent `subject.ld`, then retain both
the original ELF and a separately stripped copy. Record the actual compiler,
assembler, linker and strip invocations and resulting whole-file hashes.
Stripping may retain section headers; the two LOAD images must be identical
except the original ELF header's section-table coordinates. Neither symbol
presence nor a successful link establishes execution correctness.

The original is an ET_EXEC with entry 0x401000, one PT_PHDR, six PT_LOADs and
one non-executable PT_GNU_STACK. All LOAD file and memory sizes are equal.

| LOAD address | Bytes | Permissions | Purpose |
| --- | ---: | --- | --- |
| 0x400000 | 4096 | R | Original ELF/program headers |
| 0x401000 | 4096 | RX | Startup, real CALLs, hooks, ordinary checks |
| 0x403000 | 4096 | RW | Application data, byte i = (37i+11) mod 256 |
| 0x404000 | 4096 | RW | Zeroed instrument-private journal |
| 0x406000 | 65536 | RW | Owned stack, initially every byte 0x5a |
| 0x421000 | 4096 | RX | New subject page |

The page at 0x405000 is an unmapped stack guard. The subject starts at
S = 0x421100, immediately after 16 declared window bytes of NOP padding. No
padding instruction is a declared external entry. Both RX pages are entirely
defined by the source, with unused bytes 0xcc. There is no interpreter,
dynamic loader, manually mapped image or executable stack.

| Family | TACTIC | Body at S | Declared head offsets |
| --- | ---: | --- | --- |
| B2 | 2 | NOP3; MOV EAX,42; RET | 0,3,8 |
| T1 | 3 | MOV EAX,EAX; MOV EAX,42; RET | 0,2,7 |
| T2 | 4 | NOP3; NOP8; MOV EAX,42; RET; padding; MOVABS RAX,42; RET at 64 | 0,3,11,16,64,74 |
| T3 | 5 | JNZ +1; NOP; RET; padding; MOVABS RAX,42; RET at 64 | 0,2,3,64,74 |

The source bodies, selected lengths 3/2/3/2, basic-block lengths 9/8/17/2,
window prefix and entry declarations reproduce the existing forced integration
fixtures. T2's rewritten victim starts at offset 3; its tail at 64 is unchanged.
T3's victim starts at 64 and its relay starts at 69. Image numbers can be
victim-first: use actual image roles and routes, never assume image 0 is the
selected hook image.

## Calls, startup and ordinary behavior

The native invocation accepts exactly one single-byte argument naming the
zero-based head index. For example, T2 argument `4` reaches S+64. Index i has
one authored direct CALL at `0x401400+16*i`; its return address and terminal
are CALL+5. Every stub then jumps to the ordinary postcheck at 0x401500. The
call table is at 0x401390 and expected-RAX table at 0x4013c0. Unused table slots
are zero and unused stubs contain only 0xcc.

Before that CALL, startup parses the index without writing application data,
journal or owned stack, sets RSP= 0x415f00 and RSI= 0x403200, sets the ordinary
RAX sentinel to 0x1122334400000011, and follows the selected table entry. The
only native-arrival instruction heads are the fixed `_start` sequence
0x401000,005,00b,010,016,01b,01f,025,029,02d,031,037,03d,040 and the shared
preparation sequence 0x401080,087,08e,098,09f,0a3,0a7. These suffixes denote
addresses in the same 0x401000 page. The native adapter must authenticate the
complete startup bytes and selected CALL target, reject an earlier subject,
hook or different CALL, then seed once at the chosen CALL. It must not accept
an arbitrary PC merely because it falls in the startup page.

With no argument, the executable visits every declared head in order with
ZF=0, then visits every head again with ZF=1. Each call starts with the full
sentinel RAX. MOV42/MOVABS42 paths must return 42; bare RET and T3 branch/NOP
paths must preserve the full sentinel. Any invalid argument, wrong result or
short write exits 9. Success writes exactly `elf tactics ok\n` (15 bytes), no
stderr, and exits 0. Ordinary output is a separate check from architectural
trace equality and private-journal validation.

The null hook is RET at 0x401200. The 19-byte recording hook at 0x401220 reads
the context's logical PC into RAX, stores it at 0x404008, increments the u64
count at 0x404000, and returns. Instrumentation must preserve its application
state effects. Native selected-head rows require the hook; successor, neighbour
and RET entry rows require no hook unless their original path visits S.

The new tactic-only two-seed table retains the existing GPR and XSAVE seeds
and explicitly chooses ZF=0 then ZF=1. This exercises both T3 JNZ successors;
the original B1 seed table remains unchanged. The full state comparator keeps
only its existing TF/RF debugger mask. No zero-padding, state repairs, changed
XSAVE mask or increased step limit substitutes for a required comparison.

## Selection preparation

Run the fixture renderer, not a product-specific planner:

```text
render_tactics.py ORIGINAL TARGET_RECORD B2|T1|T2|T3 null|journal NEW_SELECTION
```

`TARGET_RECORD` is the exact one-line output from the existing driver's
`target` mode. The renderer does not query the host, assemble, load, execute or
rewrite an ELF. It checks the complete two RX pages, all six original LOAD
owners/permissions/file ranges, data/journal/stack bytes, both hook bodies,
family descriptor, real CALL operands, available symbols and complete bounded
target component table. The whole original, selected hook and full permitted
entry declaration are hashed into the selection. A mismatched family refuses.

The carrier is one page at 0x422000. Preferred allocation addresses retain the
original integration formulas:

| Family | Selected address | Victim address |
| --- | --- | --- |
| B2 | S+5+0x2ab80000+0x8000 = 0x2afa9105 | S+0x6000000 = 0x6421100 (unused) |
| T1 | S+6+0x2ab8 = 0x423bbe | S+0x6000000 = 0x6421100 (unused) |
| T2 | S+5+0x56e90000+0x8000 = 0x572b9105 | S+8+0x123456 = 0x54455e |
| T3 | S+0x4000000 = 0x4421100 | S+0x6000000 = 0x6421100 |

Each role retains 256 candidates and an 8192-byte permit starting at its
preferred address's page boundary. The renderer checks those whole permits
against every original LOAD, the carrier and each other. The actual product
verifier must separately check complete emitted LOAD extents and owner bytes;
the permit is not an observed allocation. The original 21 pages plus carrier
and two possible two-page images give a prospective maximum 26 pages. B1's
separate geometry remains unchanged.

Selections retain the existing integration limits, exact forced tactic and
80-byte search displacement bound, full function/window and all declared
entries. T2/T3 require two images. A different easier tactic, missing required
entry, reduced denominator, entry-router requirement or failed second image
is not a successful substitute. The whole-child 20,000-step/15-second limits
and single-seed/no-repair rule remain unchanged for actual native tracing.

All validation and input rereads precede exclusive mode 0600 output creation
under an existing canonical nonsymlink parent. No output is overwritten and
no directory is created. Success stdout is one line, for example:

```text
selection prepared: sites=1 heads=6 tactic=T2 hook=journal qualification_complete=false
```

The head count, tactic and hook fields reflect the requested fixed family.
Actual bounded renderer execution, full metadata/sparse/image verification,
all permitted-entry native traces and ordinary runs remain separate required
checks. This finite extension does not qualify PIE/DSO, mixed loading,
grouping, routed interior entries, unwind, CET, arbitrary programs, E9 parity
or full A3.
