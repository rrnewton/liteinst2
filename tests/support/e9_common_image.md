# Controlled common-kernel original references

This support adapter maps the actual prepared heap-sort original
at its linked addresses and obtains one hardware instruction reference for every
committed seed. Its implementation does not establish an execution or equivalence
result. The separate [core paired mode](e9_common_core.md) adds candidate walking;
actual paired runs and E9 candidate replay remain **UNRUN**. The 87 heads,
six CALLs, four RETs, both synthetic
internal NOP frames, both fixed states and two read-only store faults are retained:
174 normal reference cases plus two fault cases, each in a fresh owned child.

## Invocation and admission

Invoke the original-reference mode with:

```text
elf-exec-oracle replay-common-original ORIGINAL INSTRUCTIONS TARGET NEW_CAPTURES
```

All four coordinates are absolute and canonical (the output must be missing).
INSTRUCTIONS is the complete `common_sites` `instructions.tsv`, not sites.tsv or
a visited subset. TARGET is the complete `LI2TARGET` record from the admitted
same-source driver. The native adapter requires literal complete-table equality
with the committed seed table, actual original range bytes, independently decoded
instruction heads/lengths/flows/targets, and the exact four original LOAD records.
It accepts neither a reduced table nor a different compiled kernel.

Before invocation, a caller must authenticate whole ORIGINAL, complete inventory
bundle, TARGET, driver and source identities and preserve their before/after
owners. This deliberately retains the existing elf-exec recipe/driver split:
the driver does not implement SHA-256 and a caller-supplied filename is not hash
admission. It retains every original byte and input owner, rereads them after
each completed case, and verifies the complete consumed table/ranges/page views.
There is no proposed execution recipe or current runtime admission in this
package. The known unstripped original is SHA-256
`987b20efe393a0a2ca0293cd5601ba323b3f8292c9f1b5fab8a22b3124d3cff8`;
the distinct stripped original is
`1c7c66c58376c98df1dc3e5fd76d3c22a82ad7e96ef7aee1543a7c5b90a6f529`.
Each invocation covers one admitted original. Its file hash is never inferred
from identical kernel bytes. The full expected table SHA is
`74afc406acb8eb7742695afdf0e610a7e77afbaa6fb1498463a9e8ae85901fcd`.

The original contains dynamic-loader metadata, but this mode does not invoke
its interpreter, constructors, startup or relocation machinery. The admitted
three exact kernel ranges have no RIP-relative data access, external transfer,
TLS read or unresolved operand: the reviewed seed grammar assigns every memory
operand to the owned array or stack. Every direct target is another retained
original head. Relocations whose destination can overlap kernel instruction
bytes are explicitly refused. Relocations and initialization outside this closed
kernel are not performed, and the mapped globals/journal/BSS must remain exactly
the admitted original view. This is a controlled independent-image reference,
not proof of normal-loader-to-body behavior. The separate original observations
and ordinary eight datasets keep their original scope and identities.

## Address and state contract

The driver first reserves the whole page union `[0x400000,0x425000)`, the guarded
array at `A=0x600000000000`, and the guarded stack anchored at
`E=0x600000100008`. All reservations use `MAP_FIXED_NOREPLACE`; there is no
clobbering fallback, alternate-address search, or pointer normalization. Any
collision refuses the run. The image consists of actual complete file-page
views, including leading file-page bytes, with the declared BSS and final BSS
partial page zeroed. The exact inspected LOAD flags are restored after copying;
no page is RWX. The original page union is anonymous owned memory, not a claim
of file-backed kernel exec mappings. Full original bytes and exact geometry
bind that distinction explicitly.

A is one fully initialized 4 KiB page, RW normally and R for the fault cases,
with an inaccessible page on each side. The 64 KiB stack is
`[E-32776,E+32760)`, with inaccessible pages on both sides. Every frame word and
byte is initialized by the unchanged seed module. The shared comparator always
uses `[E-128,E+32760)`; its boundary never follows the changing RSP. This
original-only adapter additionally verifies and retains the entire owned stack,
including the lower reserve. Future instrumentation scratch is not admitted by
this check; it needs actual generated-path ownership proof.

One parent-owned image and one parent context are retained for all cases. Each
child inherits the same selectors and TLS bases, receives exactly one SETREGS
and one SETREGSET using the unchanged seeded-XSTATE function, and has its
kernel-normalized before-state checked by the unchanged `assert_state`.
Every target component must be present at its exact CPUID extent; raw and
canonical state are both saved. No new RFLAGS mask is introduced: only the old
TF/RF mask exists. Actual RIP is checked, never rewritten into a logical PC.
After the seed there are no child register, XSAVE or memory repairs.

All completions are frozen before the first child. A normal case performs one
`Tracee::step(&[])`, checks the exact declared next original PC/RSP and complete
specified memory effect, and saves the hardware result. CALLs complete at the
callee entry with the true original PC+5 word in the stack. RETs complete at the
owned original terminal `0x401878`. Both read-only store cases use the unchanged
synchronous-fault primitive and require SIGSEGV/SEGV_ACCERR at A+8 or A+24,
original RIP/RSP and full unchanged state through the old comparator. There is
no search for a state that happens to match. Normal scalar GPR results are the
captured hardware reference, not a new instruction emulator or a paired result.

The original Tracee implementation, 15-second child deadline, 20,000-stop cap,
SIGILL ownership behavior, canonical XSAVE, full comparator and bounded exact
child cleanup are unchanged. This mode charges exactly one stopped instruction
attempt per case. It then uses the existing cleanup and additionally checks
ECHILD before emitting the case completion record. No child is live when parent
memory is initialized for the next seed. A finite outer command/resource profile
must still be selected and recorded before any execution; none is invented here.

## Captures and failure scope

The successful fixed inventory is 3,175 files: seven at the root and eighteen
per case for `case-000` through `case-175`. Each before/after snapshot has eight
files: `.regs` (all 27 raw register words), `.xstate` (unchanged canonical format),
`.xstate-raw` (complete NT_X86_XSTATE), `.data` (whole array page), `.stack`
(the fixed comparator interval), `.stack-owned` (whole 64 KiB), `.loads`
(whole original page union), and `.maps` (raw process maps, independently checked
against every owned page and guard). `seed.tsv` records the concrete contract;
`complete.tsv` is written only after completion checks and exact-child reaping.
Maps and full state bytes are saved before their content assertions where
possible, so an observed mismatch is retained rather than reported as a pass.

The seven root files are `original.elf`, `instructions.tsv`, `runtime-target.tsv`,
`original-pages.bin`, `input-owners.tsv`, `planned-cases.tsv`, and the final
`complete.tsv`. The full plan precedes all children. A failed case leaves its
available captures; missing case completion and later case directories remain
failed/unrun evidence, and no root completion is emitted. The input-owner file
explicitly says whole-hash admission is caller-required. The exact final stdout
is:

```text
original references complete: heads=87 normal=174 faults=2 pairs=UNRUN qualification_complete=false
```

That statement gives no candidate pair, ordinary execution, performance, full
A3, other roadmap milestone, or later-revision credit. A future adapter must
still admit whole actual core/E9 artifacts, every selected and auxiliary path,
exact restored completions, scratch ownership and fault boundaries, then pair
all mandatory heads using the unchanged comparator. This implementation does
not replace that denominator with original-only coverage.

## Integration and review

Add `e9_common_image.rs` as a child of the existing `elf_exec_oracle` module and
one early driver dispatch; all old source bodies recover literally by deleting
those additions. The already committed seed source/table are imported unchanged.
No Cargo dependency, binary, product API, test filter, test limit or old fixture
is changed. In particular, the scanner is used through the existing public
liteinst2 API, so helper consumers need no new direct iced-x86 dependency.
No formatter, compiler, native execution or default gate has run for this
proposal. The existing pure seed tests remain unchanged; concrete future
admission-refusal controls are specified separately, without adding an executed
test or outcome claim.
