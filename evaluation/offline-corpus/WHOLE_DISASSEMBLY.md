# Whole authored streams: material adapter

`disassembly.py` prepares trusted-disassembly materials for both existing authored
programs. It does not invoke a compiler, decoder, planner, process owner, candidate,
or runtime. The kernel-only adapter, forced-B1 policies, source workloads and old
80-case campaign are unchanged. The two whole-stream source denominators are:

| Program | Startup heads/jumps | Kernel heads/jumps | Hook heads | Whole heads/jumps |
|---|---:|---:|---:|---:|
| checksum | 61/14 | 18/2 | 1 | 80/16 |
| rle-roundtrip | 61/14 | 45/12 | 1 | 107/26 |

The complete prospective population is 187 heads and 42 jumps. All source paths,
including error branches, belong to those denominators. No reachable-only subset
or partition of a refused input is supported.

The sole entrypoint is `attempt(program, inputs, expected)`. Both dictionaries
have exactly these keys: `source`, `linker`, `object`, `original`, `heads`, `target`.
`inputs` contains bytes (each nonempty and at most 1 MiB). `expected` contains the
independently frozen lowercase SHA256 for each. Do not derive those first pins
from an adapter return value. The source must equal the unchanged `corpus.py`
assembly output, and the linker must equal its unchanged `LINKER` constant.
The adapter authenticates held `corpus.py` and target-grammar source bytes before
compiling those modules. Assertions must be enabled.

The caller must separately authenticate the exact assembler/linker/source build
closure and independently captured original instruction heads. **The adapter
cannot prove that arbitrary object bytes were emitted from the claimed source.**
Compiler identity, source-to-object provenance, complete no-overlap/no-code-as-data
classification, private unexecuted-image ownership and eventual target readiness
remain external premises. Neither a matching digest nor a decodable instruction
establishes them. Synthetic controls exercise structure, not those premises.

Object ownership uses ELF64 ET_REL sections, symbols and all RELA records. The
three nonempty executable input sections must be `.text.start`, `.text.kernel`,
and `.text.hook`. The only other allocated source is the exact buffer/stack data
and fixture note. Every code byte must reach the fixed ET_EXEC image unchanged
except the six checked startup PC-relative relocations. Each relocation's type,
symbol, addend, field, target and final bytes are checked. No GNU display text is
used. The original ELF retains its exact three LOAD geometries, named source
extents, internal symbols, data and note. Linker padding is outside these declared
streams under the admitted source/linker premise; every padding byte remains
covered by the frozen whole-file hash. No map or text-disassembly parser is needed.

The externally captured head transport is bounded ASCII with exactly one space
between fields, one record per LF-terminated line, and this controlled grammar:

```text
LI2AUTHORED-HEADS 1
program checksum
original ORIGINAL_SHA256
object OBJECT_SHA256
head start 0 0 LOWERCASE_INSTRUCTION_HEX
head start 1 NEXT_RELATIVE_OFFSET LOWERCASE_INSTRUCTION_HEX
...
head kernel 0 0 LOWERCASE_INSTRUCTION_HEX
...
head hook 0 0 c3
```

Use the other literal program name for RLE. Roles are ordered start/kernel/hook;
indices restart at zero and every region is gap-free. Integers are canonical
decimal u64. Every instruction has 1..15 bytes. The transport contains exactly
61 startup rows, 18 or 45 kernel rows, and one hook row. These are final linked
bytes; object relocation fields are joined separately. The bridge checks exact
branch destinations and source byte tables. Independent iced-x86 re-decoding by
the trusted disassembly importer remains mandatory after material preparation.

The return value retains `files` (bytes), original first pins and observed bounded
input hashes/sizes, both source-expected counts, and a fixed `MATERIALS_READY` or
`MATERIALS_REFUSED` status. Refusal includes a stage/error class. A checked ledger
and all inventory rows survive a later target-policy refusal. Earlier failures
keep checked counts unavailable, never zero or a successful subset. Oversized
inputs record their size and unavailable observed hash without an unbounded hash
pass. Malformed outer API shape raises; its caller must retain that failed program
attempt and all raw inputs too. Unexpected exceptions are not success.

`MATERIALS_READY` supplies `ledger.txt`, `source-inventory.tsv`, and `policy.txt`.
It does not mean importer, candidate or runtime success: `importer_verified` and
`qualification_complete` remain false. The caller must preserve inputs and files
without overwriting, freeze both produced text hashes before its single importer
attempt, and require the importer's independently decoded inventory to match every
source-selected jump. The immutable policy uses the old offline limits, domain1,
carrier0x480000 and original C3 hook0x403000. It prospectively selects existing
`preferred 64 256 64 none 256 4096` search, one selected page at
`0x500000+(id-1)*4096`, and one victim page at `0x600000+(id-1)*4096`.
IDs are every ascending source jump; there is no outcome-dependent retry or B1
fallback. Any importer/global resource limit is a whole-program refusal.

After integration and independent source review, root may run the eight pure
control methods with `python3 -I -B evaluation/offline-corpus/disassembly_controls.py`
under its bounded owner. This proposal executed none. A thin execution runner,
actual head capture, importer/E9 comparisons, loader admission, all old/future
functional populations and normal closure remain separate. Upstream E9 and
whole-heap completeness, real hooks, architectural state and performance are not
granted by this authored material adapter.
