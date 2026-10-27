# Prospective compiled-kernel seed specifications

This pure support module defines 176 controlled one-instruction transactions:
two states for every one of the 87 original heads, then two read-only store
faults. It has no process, mapping, tracing, decoder, filesystem, candidate or
comparison implementation. Its three isolated integration tests are proposed source and have
not been compiled or run. It does not change the eight ordinary datasets,
their observer, the existing seed/comparator implementation, or any limits.

The inspected original is SHA-256
`987b20efe393a0a2ca0293cd5601ba323b3f8292c9f1b5fab8a22b3124d3cff8`,
built at `ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05`. Its ranges are:

| Owner | Original VA interval | File offset | Heads |
|---|---|---:|---:|
| `li2_array_store` | `[0x401840,0x401845)` | `0x1840` | 2 |
| `li2_sift_down` | `[0x401850,0x4018cf)` | `0x1850` | 45 |
| `li2_heap_sort` | `[0x4018d0,0x401951)` | `0x18d0` | 40 |

`authenticate(table, ranges)` requires literal equality of the entire
`e9_common_seed.instructions.tsv` and the three named, ordered source ranges.
All 14 columns, IDs, original bytes, lengths, file offsets, mnemonics, flows,
targets, blocks, flags and static depths are fixed. No header, field, whitespace,
head, order or padding normalization is permitted. This table is a prospective
source-derived expectation, not output of an executed common_sites invocation.
If the eventual complete inventory differs, admission fails. Do not regenerate
the expectation from a failed or reduced selection. The caller must separately
authenticate the whole original ELF hash and its unchanged ownership; this
module's token establishes only the supplied complete table/range bytes.

The internal NOPs at `0x40186e` and `0x40194d` retain `rsp_depth=unproven`
in that table. Their synthetic containing-frame offsets are explicitly −40
and 0. They receive both states. This does not relabel them as naturally reached.
The interfunction padding at `0x401845` and `0x4018cf` is outside the exact
symbol ranges and is not added to the denominator.

## API and initial state

After authentication, `Inventory::case(index, Anchors::new(A,E)?)` returns one
`SeedSpec`. Indices 0–173 are head order, state 0 then state 1; indices 174–175
are the same two store inputs with a read-only array. Any other index is refused.
The future adapter must account for this complete fixed index set once per
admitted artifact pair; a selected-site or dynamic-visit subset is insufficient.

The existing seeds are `0x1234567887654320` and `0xfedcba9801234567`.
Unconstrained integer registers use the original xorshift assignment order,
including RSI=A+512 and RDI=A before explicit live-operand overrides. Every
GPR, RIP, RSP and `orig_rax` is concrete. RFLAGS is exactly `0x202` or `0xad7`
(DF clear); CF/ZF=0/0 or 1/1 exercises both outcomes of each conditional branch.
These are direct machine states, not claims about a naturally preceding CMP.
There is no added flag mask, including for shifts/TEST/XOR's unspecified bits.

Extended state names the unchanged `quiescent_oracle::seeded_xstate` algorithm
and the same seed identifier. The future adapter must supply its authenticated
CPUID/XCR0/NT_XSTATE extent, use identical kernel-normalized seed bytes in both
children, and compare every existing canonical component. CS/SS/DS/ES/FS/GS
and FS/GS bases come from one authenticated parent context and must be equal
in both children. This module deliberately does not invent host-dependent
segment or XSAVE bytes or claim that those runtime prerequisites have passed.

The two array values are `[13,5,21,8]` and `[7,19,3,29]`; they are additional
controlled inputs, not replacements for the eight ordinary inputs. Live operand
overrides in `live_operands` are finite original-PC matches. Loads have exact
in-bounds effective addresses; every CALL has valid four-element-array arguments
for its declared callee entry. Arbitrary unused registers remain deterministically
seeded. This permits the selected single instruction, not an arbitrary complete
sorting suffix from each synthetic internal state.

## Fixed memory and complete access audit

A must be 4 KiB aligned. The array page `[A,A+4096)` is fully initialized with
the stated byte pattern and four u64 values. It is RW for normal cases and R
for the two faults. Adjacent pages are inaccessible. E has page offset 8, so
it has the SysV function-entry RSP alignment. The stack is exactly
`[E−32776,E+32760)` (64 KiB, RW), with an inaccessible page at each end.
Every stack byte is initialized. The anchors reject underflow, overflow,
non-low-canonical extent, overlap with one another and overlap with the
page-rounded original LOAD span `[0x400000,0x425000)`. The caller must also
admit identical owners/permissions and disjointness from actual candidate,
library and other mappings; passing this arithmetic check is not that admission.

The complete fixed application stack comparison is `[E−128,E+32760)`.
The lower owned reserve is prospective instrumentation scratch only after
actual generated-byte/path/extended-state bounds prove all writes stay below
E−128 and above the lower guard. This boundary never follows the moving RSP
and must not be widened after observing a difference. The whole data page,
all other application memory and permissions, immutable code/LOAD ownership,
and full fault state remain future adapter obligations. No journal or ordinary
application memory may be silently classified as scratch.

Each containing frame has all saved-register slots explicitly initialized from
the original deterministic register seed, including slots not yet pushed in a
mid-prologue seed. Sift's slots are RBX/RBP/R12/R13/R14 at E−40/−32/−24/−16/−8;
heap's are RBX/RBP/R12 at E−24/−16/−8. `[E]` is the exact original head
`0x401878`, an owned controlled return terminal. It is not asserted to be a
loader-reached caller. A RET transaction stops on arrival there; it executes
none of that following instruction. Every other stack byte has the fixed pattern.

| Memory-effect heads | Count | Exact access domain |
|---|---:|---|
| `0x40189e`, `0x4018ac`, `0x4018bc`, `0x401910`, `0x401915` | 5 | Read A+8, A+16, A, A+24, A (8 bytes each) |
| `0x401840` | 1 | Write A+8 or A+24, exact RDX word |
| Five sift and three heap PUSHs | 8 | Write old register at RSP−8, then RSP−=8 |
| Five sift and three heap POPs | 8 | Read initialized word at RSP, then RSP+=8 |
| Six direct CALLs | 6 | Write exact original PC+5 at RSP−8; complete at actual callee entry |
| Four RETs | 4 | Read exact `[E]`, complete at `0x401878`, RSP=E+8 |

All 32 heads appear in `HEADS`; `read_registers` records their complete explicit
and implicit integer input operands, as well as scalar/branch operands for all
other heads. RIP is fixed, and conditional branches read the explicit flags.
LEA and every NOP, including memory-shaped NOP encodings, perform no data read.
The exact bytes contain no other explicit/implicit memory access, string, TLS,
RIP-relative data, stack-local or external-call instruction. Within a single
transaction the lowest stack access is E−48. A complete original call chain can
reach E−80; no such chain execution is claimed by this seed-only module.

## Completion and remaining conditions

`Completion::OriginalPc` gives the only allowed next logical original PC and
exact resulting RSP. Each `MemoryEffect` gives the exact original read value or
written word; it is not a substitute for full original/candidate state capture.
For all six CALLs, the original return words are respectively `0x401878`,
`0x401886`, `0x401902`, `0x401927`, `0x401935`, `0x401942`. Current Observe
planning excludes displaced CALLs; actual candidate bytes/ledgers must confirm
these six remain original. A generated return word is never normalized. This
proposal adds no CALL relocation support. Both read-only store faults require
SIGSEGV/SEGV_ACCERR at A+8/A+24, original store PC and unchanged RSP, data and
application stack. A guard miss or another signal/address is not equivalent.

The next adapter still needs successful full-selection candidate production,
exact source/generated/auxiliary-image/LOAD identity joins, unambiguous completion
boundaries, fixed scratch ownership, full comparator and synchronous-fault
capture, and the unchanged 15-second/20,000-stop bounds per transaction. It must
seed once and perform no repairs. Ordinary loader-to-body observations and this
controlled independent-image replay have different scopes; artifact equality
joins them without turning either into the other. No tested head, candidate,
native equivalence, ordinary run, source revision qualification or full A3 claim
is granted by this proposal.

## Proposed test inclusion

`tests/e9_common_seed_contract.rs` imports this pure module and owns its three
focused tests. Normal required Cargo gates can compile and run them once through
ordinary integration-test discovery. The reusable support module contains no
test module, so later driver inclusion does not duplicate these checks in the
existing oracle consumers. No driver or native oracle is modified here. The
new three tests remain prospective until actually run on an admitted revision.
