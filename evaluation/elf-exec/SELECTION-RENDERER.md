# Fixed kernel-exec fixture selection

`render_selection.py ORIGINAL TARGET_RECORD null|journal NEW_SELECTION` prepares one
selection for `tests/fixtures/elf-exec/subject.S` and its linker script. It is
fixture support; the generic ELF frontend accepts the full strict selection
schema and does not embed this instruction grammar.

The original is an authored, separately built ET_EXEC. The target file must
contain the exact one-line stdout of `elf-exec-oracle target`. The renderer does
not execute that driver, infer host state, compile the fixture, or execute a
candidate. It validates the seven program headers/five fixed LOAD owners,
permissions, file extents, stack guard, both real CALL operands, MOV5/RET bytes,
null/journal hook bytes, initialized data/journal/stack, and available source
and hook symbols. A stripped file may retain its section-header table. The
whole original and selected hook bytes are hashed into the selection; both
permitted heads remain declared. Whole original provenance and the two
originals' LOAD-byte equivalence are separate build/oracle obligations, not a
CFG proof created by this renderer.

The read-only carrier is fixed at 0x418000 and RX image at 0x420000, above the
original LOAD end 0x416000. The target record is retained verbatim. B1 selection
uses the existing bounded one-site/one-image profile, exact five-byte source
window, and both 0x401100/0x401105 legal entries. All checks precede exclusive
mode-0600 output creation; input bytes are reread before writing. There is no
executor, retry, output overwrite or candidate admission.

Success stdout is exactly one line:

```text
selection prepared: sites=1 heads=2 hook=null qualification_complete=false
```

The journal variant substitutes only `hook=journal` in that line. Failures
remain nonzero without a selected output unless the write itself fails. Root
runs the renderer and actual frontend under the existing bounded helper, then
joins the resulting ELF and hook effect to normal kernel exec and full-state
comparison. Source-only preparation grants no native or full A3 credit.


The tool-package example `verify_elf_exec ORIGINAL SELECTION OUTPUT_DIRECTORY`
checks the actual output directory without calling the planner or emitter. It
uses the existing metadata and sparse-file decoders and ELF ownership reader.
The expected compatibility profile is independently reconstructed from the
selection using the frontend's canonical target serialization. Metadata must
bind the complete original, complete selection, and the one site-1 B1 outcome.
The decoded sparse record must contain the exact four changed source bytes and
one complete reconstructed source page, equal to the candidate's actual page.
The five-byte jump, preserved RET, and all original file bytes outside the
source edit and two declared ELF-header fields are checked. The generated
image and its ledger record must agree with the RX image at original ELF
address 0x420000. The whole output index, COMPLETE record, and complete file
hashes remain separate recipe checks; this example does not certify native
execution, hook effects, loader semantics or entry completeness.

Build the example with the same pinned toolchain/dependencies as the frontend;
its executable takes exactly those three paths and prints:

```text
elf exec artifact verified: metadata=1 sparse_pages=1 images=1 qualification_complete=false
```

Any mismatched record or file is a nonzero refusal. Both utilities are authored
fixture support. Their actual bounded execution and the independent native
trace comparison are required before reporting an observed result.
