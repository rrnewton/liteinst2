# One-Code ADD guard component

This opt-in component admits only `Add_rm64_r64` (Code 8, canonical single
REX.W + opcode 01 + memory ModRM). The real loader instruction
`4d 01 75 00` at offset 0x10021 is included. The immediate ADD at 0x100a0
is a refusal. Old MOV/NONE descriptors, predicates, tests and profiles are
unchanged. The new decoder owns a separate factory initialized before seal;
no decoder allocation is permitted afterward.

The descriptor is 144 bytes, full plan 6488, compact record 1584, image cap
512 bytes and boundary cap 64. The existing immutable `li2_mg_table` supplies
complete protected intervals. The caller must authenticate its full registry,
source and rseq coverage, private spill and no-alias custody before entry.
These descriptive components do not establish that authority themselves.

Each emitted boundary records the state **before** its instruction:

- Four MOV saves mark only their completed spill words valid; no guest GPR or
  flags change. LEA computes the actual EA using untouched operand registers.
- LAHF modifies AH; recovery takes status bits from AH and still-physical OF.
  SETO then stores OF in AL. The complete checked EA interval and tree walk
  use three nonoperand scratch GPRs; repeated loop PCs have identical states.
- ADD AL,127 restores OF, then SAHF restores the other status flags. MOV loads
  restore all four GPRs. The RMW boundary therefore has no dirty GPRs and
  physical original flags. Its one copied original ADD is the only guest
  memory operation; RIP-relative displacement alone may be relocated.
- The immediately following JMP is AFTER: actual new memory and status flags
  survive, and recovery names the original next PC. It never reloads old
  flags or replays the ADD. A fault at RMW remains original-PC before-state;
  actual signal/trap/error/address and any native split-access effects stay
  actual. Rejection restores before-state before a distinct UD2.

`build.sh SELECTED ARCHIVE OUTPUT` builds the pure descriptor/emitted-byte
interpreter. Its shared byte address space makes spill writes visible to
later reads at the same address; numeric private-alias refusals inspect the
actual resolved bytes, not a separate guest backing array. It exercises 349
descriptors, 5096 models, 20 refusals, 21 corruptions and 465 interval edges.
This includes all GPR base/source choices, SIB scales, RIP/absolute forms,
all 64 status inputs, arithmetic boundaries, wrap/overlap/touch endpoints,
131-node trees, and synthetic read/write failures. Synthetic write failure
is not a claim about real cross-page atomicity.

`build-native.sh SELECTED ARCHIVE OUTPUT` builds the separate Linux/x86-64
native oracle. 402 original/generated pairs compare all 16 GPRs, status and
other flags, and all 8192 destination bytes. TF observes actual intermediate
recovery boundaries and the first AFTER boundary; non-TF successes execute
the successor JMP. 16 fault pairs cover read-only, inaccessible and split-page
operands with both TF modes, preserving actual SIGSEGV/code/ERR/CR2 and
comparing actual memory effects. Native input/source bytes are ordinary
component allocations. This is not production lifecycle, full FP/TLS state,
rseq qualification, guest fault-handler continuation, or performance credit.

Both recipes retain strict compiler flags. The parent runner owns the original
finite resource bounds and execution authorization. These files were authored
without compilation or execution; source counts are expectations, not results.
