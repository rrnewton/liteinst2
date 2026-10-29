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

## Explicit window-permit profile

`attempt(program, inputs, expected, profile=WINDOW_PROFILE)` selects
`offline-whole-authored-window-permits-v1`. The default fixed-page profile and
its historical outcomes remain unchanged. Choose a profile before a complete
program attempt; no fallback or retry is performed.

The new profile derives permitted pages from the authenticated original LOADs
and the existing16MiB carrier span, excluding the complete8KiB carrier
reservation. It assigns disjoint64KiB preferred-address lanes per site and
coordinates a short branch's selected/victim addresses using the exact E9
low-order displacement geometry. Wider permitted address ranges do not allocate
those ranges: one candidate and4096-byte mapping budget per role remain, along
with the32-image aggregate limit and all core entry/overlap/image-fit checks.
The complete187-head/42-jump population and all-or-nothing publication remain.

These permissions do not establish that the core can produce a candidate.
Page-end fit, overlap, successor qualification and aggregate-budget refusals
remain possible. Source geometry readiness is neither execution equivalence
nor qualification. The three additive controls use coherent synthetic object,
ELF and head inputs; they do not establish compiler or native behavior.

The bounded reproduction helper accepts the same explicit choice for both
programs, fixed before capture inspection:

```sh
python3 -I -B evaluation/offline-corpus/reproduce_whole.py \
  --capture "$CAPTURE" --capture-sha256 "$CLOSED_SHA256" --output "$OUTPUT" \
  --placement-profile offline-whole-authored-window-permits-v1
```

Use a fresh build capture at the current committed source. All existing capture,
configuration and source-continuity checks still apply. Omitting the option
retains the original fixed-page profile. The helper neither retries a failed
profile nor executes rewritten candidates.

## Explicit ShortOnly profile with unchanged broad placement

`attempt(program, inputs, expected, profile=SHORT_PROFILE)` selects
`offline-whole-authored-short-only-2g-v1`. Its placement is byte-identical to
BROAD_PROFILE: the same fixed 2 GiB virtual-span limit, permits, preferred
addresses, search rows and one-candidate allocation rows. Only these policy
mode bytes differ:

```text
LI2DISASM-POLICY 2
original ORIGINAL_SHA256
ledger LEDGER_SHA256
neighbor-victims short-only
```

All subsequent rows equal the broad policy. The digest covers the complete
policy including the family row. Material production uses the same ownership,
relocation, exact source and complete head joins; a refused input is neither
subsetted nor retried. The three existing profiles retain their exact outputs.

The reproducer's explicit placement choice adds the leading Rust importer
flag `--short-neighbors-only` before the unchanged six positional arguments.
It requires profile `elf-disassembly-null-jumps-short-only-v1` and the
`neighbor_victims\tshort-only` row immediately after the profile in COMPLETE,
verified inventory and any emitted planning/failure metadata. The stdout mode
and candidate-complete value must also match the closed command's exit code.
There is one importer invocation per ready program, with the existing release,
custody, configuration, limits and complete-denominator gates.

The generated selection retains `neighbor-victims short-only` after its
original row. The ordinary selection parser rejects this new row. Neither this
profile nor its runner adapts E9 or other comparators, removes the row for legacy
replay, or grants comparator qualification. The additive supplied-input controls
exercise the actual adapter and dispatch/inventory helpers.
