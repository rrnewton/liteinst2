# Controlled core-null pairs for the compiled common kernel

This source adds `replay-common-core` beside the frozen original-image mode. It
does not run from Cargo tests. Its compilation does not establish an execution
or equivalence result. It consumes
an actual, separately admitted complete core candidate; it never plans a smaller
selection or substitutes modeled results for the original hardware reference.
Actual candidate identities and outcomes are unknown until production closes.

The original-reference mode, seed module, Tracee, canonical XSAVE conversion and
full comparator remain unchanged. Original support factoring shares the fixed
image constants and returns the two snapshots already captured by `reference`;
its original CLI, assertions,
files and stdout remain literal. Its local `paired_replay=UNIMPLEMENTED_UNRUN`
field still describes that original-only child. The new pair and root records
separately describe the new mode. Neither record supplies E9 or loader credit.

## Caller admission and two commands

The caller first preserves the complete actual producer cell, all eight static
inventories, producer failures/unrun tails, original observations and required
normal-loader/ordinary-run evidence. A successful build alone is insufficient.
No command here replaces or narrows those obligations. Both original whole-file
digests are fixed in the verifier; the 87-row inventory and all three original
function byte ranges must equal the committed seed material.

Build the explicit native driver by its existing Cargo target and the new
`verify_common_core` example in the existing `liteinst-rewrite` crate. The example
uses its existing formats and direct iced-x86 dependencies; no dependency is
added to shared native-helper consumers or to the product's runtime API.

```
verify_common_core ORIGINAL INSTRUCTIONS TARGET INVENTORY_DIRECTORY BUNDLE NEW_WITNESS
elf-exec-oracle replay-common-core ORIGINAL INSTRUCTIONS TARGET BUNDLE WITNESS NEW_CAPTURES
```

All coordinates are canonical absolute paths. Outputs must be fresh. TARGET is
the complete LI2TARGET record, while the inventory's compact target line is
checked as its exact projection. INVENTORY_DIRECTORY must be the complete,
indexed common_sites null-hook output for the whole jump-site or heap-write
selection. No visited-site filtering or individually replanned selection is
accepted. The fixed application limits and search policy are checked literally.
The verifier authenticates the complete `LI2COMMON 1` fixed allocation policy
or the explicit `LI2COMMON 2` original-derived policy. For the latter it derives
all selected/victim permits independently from the original bytes and complete
head table. Its four-byte displacement ceiling uses a separate algorithm from
the selector. Neutral permits retain otherwise unplaceable sites; they do not
make a refused complete candidate eligible for replay.

The read-only example checks the complete inventory, indexed bundle, metadata,
sparse transaction, ordered source reads/writes, whole carrier bytes, every
actual image and its field/route/PC-range relationships. It uses the existing
format/ELF/dynamic readers, but never calls planning or emission. The carrier
check reconstructs only the published file layout from actual image bytes and
the authenticated metadata/plan hashes; it checks all padding, old headers,
payload and appended headers. No expected register result is generated there.

Each generated helper must match the exact existing ordinary save/null-call/
restore template for the declared target. Its logical-PC, hook-call, branch and
return fields must match the actual operand bytes. Nonbranch original operations
retain their whole original bytes. Only the inspected direct Jb/Jae/Jbe/Jne/JMP
encodings may change displacement or short/near width, with an exact condition
and target join. CALL displacement remains refused. Unknown layouts, duplicate
routes, indirect/expanded original operations, missing boundaries, unsupported
fields or any incomplete producer outcome refuse the entire cell; no head is
removed. A future legitimate but unsupported representation requires a separate
source correction and review, not a silent exemption.

The example's success is **structural witness construction**, not execution
permission. Before native launch the caller must authenticate the exact built
verifier and driver, the actual verifier request/receipt, complete original/
inventory/bundle/witness file hashes and owners, and unchanged producer source
identity. Native input hash strings are bindings to that external admission;
the native module does not implement SHA-256. It holds every bundle file open,
checks complete bytes and owners repeatedly, and independently checks mapped
bytes, declared instructions, exact physical boundaries and full live states.
An arbitrary hand-written witness is not an admitted input. Keep the complete
bundle beside the captures; `bundle-inputs.tsv` retains its witness bindings,
not another raw bundle copy. No script here invents caller authority.

## Exact state machine and memory

Every admitted artifact gets all **176** cases: 87 heads times the two unchanged
seed identifiers, plus both read-only store faults. Six original CALLs, four RETs
and both unreachable NOPs remain. Each case uses two fresh same-address siblings:
one original hardware instruction attempt, followed by the candidate path.
The parent reserves the complete original/added page union and the same guarded
array and stack with MAP_FIXED_NOREPLACE. It never searches another address or
clobbers an existing mapping. Page installation happens with no live child,
uses writable non-executable preparation, then exact final permissions. The
original parent view is restored before the next case.

The shared pure page reader retains the four exact original LOAD owners and
all 37 original pages. Generated pages may lie below or above the half-open
original image interval. Full page bytes, LOAD order, nonoverlap, permissions,
page count and span limits remain checked. Its standalone byte-array tests do
not substitute for actual emitted-image replay.

Candidate execution has three comparisons: seeded original-PC entry; the exact
restored boundary immediately before its original operation; and the exact
completion or declared fault. Every prefix PC, instruction byte string and edge
is fixed in the verified witness before execution. One actual original operation
then reaches the physical endpoint derived from the seed and opcode. The walker
does not search for an equal state, execute the following head's hook, or repair
registers, xstate or memory after the single before-execution seed.

The comparator remains all 26 non-RIP raw register fields plus logical PC, full
canonical XSAVE, all 4 KiB of array data, and `[E-128,E+32760)` (32,888 bytes).
Only the old TF/RF flag mask exists. All 27 raw registers and exact physical RIP
are also captured and checked before assigning logical correspondence. Pointers,
CALL words and memory values are never normalized. The six CALL return words
are the original eight-byte values; the six actual CALL encodings must remain at
their original PCs.

The whole 64 KiB stack is captured. Original children retain the original full
stack-effect checks. A candidate with an authenticated null helper may change
only the exact lower scratch interval
`[align_down(S-304,alignment)-L-8, S-128)`, with alignment 64 for standard XSAVE
or 16 for FXSAVE, and L the unchanged declared allocation length. It must remain
inside the existing stack and below E-128. Every byte outside that interval is
compared with the original full-stack reference. Helpers without a hook have no
scratch exemption. Actual code/template and all executed edges establish this
specific interval; the record is not a generic writable-stack allowance.

Before, restored and after snapshots retain whole original LOAD pages, all added
page bytes and maps. Globals, journal, BSS and each version's immutable code and
metadata pages must remain exact. Array/stack guards and permissions remain
unchanged. No dynamic linking, startup or constructors are emulated. The exact
closed kernel and null RET hook have no admitted external initialization or
data-read dependency; dynamic relocation ownership is checked for all their
bytes. Both faults must retain SIGSEGV/SEGV_ACCERR, the exact A+8/A+24 address,
the authenticated faulting physical instruction and unchanged application state.

Each child retains the existing 15-second deadline and 20,000-stop limit,
including helper and gateway instructions. Existing exact-child cleanup and
ECHILD confirmation remain. No additional supervisor or time/resource override
is introduced. Root must freeze the existing bounded helper's whole-cell request
before any execution; this proposal supplies no new successful request or receipt.

## Captures and remaining scope

Per artifact: **352 children, 528 cross-version full-state comparisons and 8,636 files** if
everything actually completes. Each case owns 49 files: 18 original files,
29 candidate files and two pair/witness records. Twelve root records include the
complete 176-row plan and exact filename inventory. Candidate snapshots have
raw registers, canonical/raw XSAVE, full array, fixed/full stack, original LOAD
bytes, complete added pages and maps. PC/byte/edge tracing and child completion
are separate. Failure leaves the plan, actual prefix and missing required suffix;
only completion of all cases writes the root complete record. Missing files or
an unrun case cannot be relabelled a pass. The private capture contract expands
every expected filename independently of actual output.

Four required null core cells (two styles times two strip forms) remain separate
actual artifacts, 704 pairs total. Both E9 lanes remain mandatory and explicitly
**UNIMPLEMENTED_UNRUN**: eight null E9 cells, 1,408 more pairs. Recording-hook
pairs remain a separate mandatory extension. This controlled mapping does not
prove normal-loader-to-body reachability, ordinary program behavior, performance,
unwind/CET support, general A3 completion or any other roadmap milestone. All old
fixtures, qualifications and failed attempts remain unchanged.
