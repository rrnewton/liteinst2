# Complete common-corpus selections

`common_sites` prepares the existing LI2TOOL selection from one immutable
ET_EXEC and an independently authenticated finite policy. It inventories the
entire three-function heap-sort kernel. It does not plan, rewrite, map, run,
or approve a candidate, and it does not infer policy authority from its inputs.

```sh
cargo build --offline --locked -p liteinst-rewrite --example common_sites
COMMON_SITES ORIGINAL POLICY TARGET_RECORD jump-site null NEW_DIRECTORY
COMMON_SITES ORIGINAL POLICY TARGET_RECORD heap-write journal NEW_DIRECTORY
```

`COMMON_SITES` denotes the authenticated built example. Both styles accept
`null` or `journal`. `NEW_DIRECTORY` is an absent absolute path with an existing
canonical parent. Each cell needs its own directory. These are recipe commands,
not claims of an executed build or result. Run them within the existing bounded
validation process. The focused pure tests are part of the explicitly enabled
example test target; `cargo test --offline --locked -p liteinst-rewrite --example
common_sites` runs that finite inventory. No new supervisor is supplied.

The caller pins the complete policy digest independently, and authenticates its
range/provenance evidence before invocation. The adapter checks the whole
original and target hashes stated by that policy, every range hash, the exact
`.text` section/LOAD join and all output selection identities. The provenance
digest is a reference to caller-owned evidence, not a signature or evidence that
the adapter reads or manufactures. In particular, the caller establishes the
actual compiler profile, symbol-size function ledger, stripped/unstripped
relationship, hook ABI/readiness, target observation, no external entry/resume
obligations, and fixed input corpus. A stripped input uses its independently
authenticated companion's range ledger with exact loaded bytes; this tool does
not guess symbol coordinates from stripped text.

## Finite policy

ASCII, LF, one final newline, exactly the following ordered records, one space
between fields. There are no comments, duplicate records, or optional defaults.
Numbers use decimal or explicit `0x` hexadecimal. Hashes are 64 lowercase hex
characters. Angle-bracket labels below denote values, not literal tokens.

```text
LI2COMMON 1
original <whole-original-sha256>
target <whole-compact-target-record-sha256>
provenance <independent-caller-evidence-sha256>
text <virtual-address> <file-offset> <byte-length> <sha256>
function li2_array_store <virtual-address> <byte-length> <sha256>
function li2_sift_down <virtual-address> <byte-length> <sha256>
function li2_heap_sort <virtual-address> <byte-length> <sha256>
hook 2 <null-hook-virtual-address> <byte-length> <sha256>
hook 3 <journal-hook-virtual-address> <byte-length> <sha256>
carrier <page-aligned-virtual-address>
arena selected <base> <stride> <slot-bytes> <max-candidates>
arena victim <base> <stride> <slot-bytes> <max-candidates>
limits <input-bytes> <sites> <images> <image-bytes> <new-load-pages> <output-bytes> <added-file-bytes> <program-headers> <virtual-span>
search <upstream-bytes> <displaced-bytes> <max-sites> <max-victims> <max-pairs>
END
```

The target file is the exact one-line compact `target fxsave64` or
`target xsave64 MASK FEATURE:OFFSET:SIZE ...` record, with final LF. It is copied
literally into LI2TOOL and validated by the existing selection parser. The full
LI2TARGET ledger format is a different record and is not accepted here.

The source hard bounds are 16 MiB original, 64 KiB policy, 4 KiB target, 1 MiB
`.text`, 64 KiB total enclosing kernel span, 4,096 complete instruction heads,
and 1,024 selected sites. Aggregate limits retain the existing parser's field
semantics and ceilings, with the input bound above, added bytes at most 512 MiB
and virtual span at most 4 GiB. Search fields are all positive and bounded by
the unchanged parser ceilings: 65,536 upstream/displaced bytes, 4,096 sites,
65,536 victims and 1,048,576 pairs. No limit is raised after seeing a refusal.

Each selected static site receives one selected and one victim permit at
`base + selection_rank * stride`; rank is ascending original PC, starting at
zero. The stable site ID is instead its one-based ordinal in the complete
kernel instruction inventory, so both styles preserve common identities.
Each slot is 4–64 KiB, page-aligned, with a stride at least its size and
1–65,536 allocation candidates. Every slot, the maximum bounded carrier
reservation and every original LOAD page must be disjoint. Addresses must fit
the low canonical user range. The original core decides whether these finite
permits and simultaneous plans suffice; this adapter does not relocate them
after a failure or retry a smaller site set.

### Explicit original-derived placement

The preceding `LI2COMMON 1` format and fixed arena behavior are unchanged.
`LI2COMMON 2` is an explicit new policy. All records except its version and
allocation records remain identical. Replace the two arena lines after
`carrier` with exactly:

```text
placement original-derived-v1 <domain-start> <domain-bytes>
arena selected 65536 65536
arena victim 65536 65536
```

The domain start and size are page-aligned; its checked end must be in the low
canonical user range. The whole domain must fit `limits.virtual-span` and
contain every original LOAD page and the complete maximum carrier reservation.
Each role retains exactly 65,536 bytes and 65,536 candidates. No image, backing,
site, search or output bound changes. A prospective recipe profile can declare
start 65,536 and size 1,073,741,824 before running any inventory. This is a new
placement policy and evidence epoch, not a reinterpretation of an old refusal.

For each complete selected site, in ascending original PC order, derive address
patterns from immutable original bytes: first its B2 fixed successor bytes,
then B1 source windows in the core's same-site/upstream order, then original T1
prefix counts. B1 takes the existing `max-sites` prefix before rejecting windows
that cannot cover five bytes and the logical instruction in the certified block.
Displaced-byte/upstream bounds, whole instruction ends and the prohibition on
interior control transfers remain. CALL windows are excluded. Every original
head inside the first five bytes constrains the corresponding displacement byte
to the unchanged 14 illegal-entry opcodes. ISA/emission qualification remains
the core's responsibility. B2/T1 preserve the core's unsigned lower-window
conversion; a negative lower bound is not clipped into the declared domain.

A bounded four-digit successor finds the lowest compatible signed-rel32 target
in each free gap. If `T` is the target, its permit is
`[floor_page(T), floor_page(T)+65536)` and its preferred PC is `T`, which need
not be page-aligned. For B1 this preferred PC is reproduced by the unchanged
generator at a mixed-radix index below `14^m <= 38,416`, where `m` counts the
constrained bytes. This guarantees an address in the existing schedule, not an
accepted image. The whole page-rounded slot must fit a gap; checking only the
target byte would be insufficient.

Constrained selected slots are reserved first. A site with no fitting B2/B1/T1
address pattern still receives a neutral selected slot within signed-rel32 reach
of its logical PC. Neutral selected slots are reserved next, then neutral victim
slots in site order. Each victim preferred PC is reachable from every original
head in that site's function, conservatively including all possible victim
origins. All slots are disjoint from one another, original LOAD pages and the
carrier. No free full slot or an out-of-domain owner refuses the whole policy;
no site or entry is removed. This deterministic greedy reservation makes no
claim of globally complete packing.

Neutral means a valid permit only. It does not prove a B1 window, T2's
overlay-dependent selected pun, T3's relay, image fit or simultaneous plans.
The unchanged core still considers all five tactics, using the complete
selection, and retains every refusal. In the retained original kernel,
ID 15 at `0x40186c` is its entire two-byte block: B1 cannot fit; B2's interval
`[1288732273,1288732529)` is outside the prospective one-GiB domain; T1's lower
bound is negative. It remains selected with a neutral permit. Increasing no
bound and removing no head is necessary to report this limitation honestly.
No planner is called while preparing permits and no permit changes after a
planner failure. The focused tests separately call the unchanged pure artifact
planner; those tests are not native or application qualification.

Outputs still use `LI2TOOL 1` and the same ten-file schema. The policy digest
binds the explicit placement version; instruction/site/block/memory inventories
and complete entries retain their existing meaning. E9 consumes the same site
selection but does not implement these core allocation permits, so equivalent
site policies do not imply equivalent placement constraints.

## Complete static policy and its limits

All three exact named ranges are nonempty, disjoint, file-backed RX owners
within the unique uncompressed ALLOC/EXEC `.text` section. The interval between
them must decode entirely as alignment NOPs. Every byte in each function is
decoded once with the existing `InstructionScanner`. Every head, including
nonselected and unvisited heads, becomes an explicit legal entry for that
function. This is conservative caller-owned entry coverage, not recovered
whole-program control flow. The adapter never derives entries from successful
rewrites or a dynamic visit subset.

Jump selection is exactly the lowercase decoded mnemonic prefix `j`, matching
the shared E9 `asm=j.*` policy: Jcc, JCXZ/JECXZ/JRCXZ and direct/indirect JMP.
CALL, RET and LOOP are separate. An indirect/foreign/middle-instruction branch
is still inventoried and, if it is a jump, remains in `sites.tsv`; unsupported
control flow refuses the complete policy. Direct branch targets must be exact
heads in the same function. Calls must be direct to one of the three function
entries and the call graph must be acyclic. Returns must be near `RET` without
an immediate. Basic blocks split at all direct branch targets and after every
control-flow instruction, including a call's return boundary.

Heap classification requires the complete `li2_array_store` body to be exactly
`48 89 14 f7 c3`: MOV qword `[RDI+RSI*8],RDX`; RET. The decoder's one memory
write must separately match the eight-byte DS/RDI/RSI/scale-eight/no-displacement
effect. This is an ABI-bound array-store site, not proof that an arbitrary RDI
is a heap pointer. The independent original execution must witness the actual
array base, index bound, effective destination and full selected-PC sequence
for every finite dataset. An empty or singleton run can legitimately visit the
static store zero times; it cannot remove that site.

`InstructionInfoFactory` inventories every explicit and implicit memory write,
including PUSH/CALL pushes and conditional/read-modify-write effects. Every
other write must have SS/RSP, no index, 64-bit addressing and a known byte size.
A direct per-function CFG propagates exact signed RSP depth from its original
entry. All joins must agree; every reached RET must have depth zero. The finite
stack operations are 64-bit register PUSH/POP (excluding POP RSP), immediate
ADD/SUB RSP, direct CALL with balanced callee contract, and RET. Every other RSP
write refuses. A write must lie wholly below the incoming return slot, no lower
than the current RSP red zone (128 bytes) and within 64 KiB of the incoming RSP.
No RBP alias, indexed address, segment override, dynamic frame alignment or
unknown-width writer is silently treated as private. Unreachable non-NOP heads
also refuse the initial closed corpus. These are explicit finite compiler-ABI
assumptions; unsupported shapes remain visible for a separate source decision.

Hooks 2 and 3 are exact disjoint original RX owners outside the enclosing kernel
span. Their code identity does not itself prove hook safety or target readiness.
The journal ABI and all later runtime checks remain separate. No pointer masks,
architectural comparator, old fixture, or comparator calibration is changed.

## Output and refusal

All TSVs have a header. Instruction/site IDs and file offsets are decimal;
PCs, block boundaries, direct targets and encoded displacements are `0x` hex.
`instructions.tsv` contains every head with exact bytes, mnemonic, flow,
direct target, block owner, independent jump/heap flags and proved RSP depth.
`memory-writes.tsv` contains every writer effect, operand geometry, access
category and classification, including `unsupported`. `sites.tsv` contains
every selected static site, and `blocks.tsv`/`padding.tsv` preserve the complete
block and inter-function padding inventories. `policy.txt` and `target.txt`
retain exact inputs. `status.tsv` binds the original, policy, target and caller
provenance hashes, full counts, every unsupported reason, and the whole selection
digest when present. `qualification_complete` is always false.

Exit 0 writes a complete static-policy inventory and one full `selection.txt`.
Exit 2 writes the same complete decoded inventory with explicit unsupported
reasons and no selection. Unknown writers do not acquire heap credit merely to
make a list: their complete effects remain in the memory inventory and prevent
a complete selection. Invalid structural input/identity/I/O exits 1; no partial
decode or output is claimed complete. Original, policy and target bytes are
reread before output creation. Files are exclusive, mode 0600 in a fresh 0700
directory. `COMPLETE` is written last and hashes every other output file; it
does not hash itself. A partial directory without that marker is not consumable.

A later planner refusal is different from a static-policy refusal. Feed the
entire exact selection to the existing frontend and preserve every site report.
The full candidate is the unit of comparison. The old site comparator and its
three positive/24 refusal controls remain unchanged. No test execution, producer
coverage, application correctness, performance, or full A3 qualification follows
from this source or a generated inventory alone.
