# Whole authored head transport

`head_capture.capture(program, original, object, outputs)` is a pure bounded
parser. `program` is `checksum` or `rle-roundtrip`; `original` and `object` are
the retained final ELF and ET_REL bytes. `outputs` maps exactly `start`, `kernel`,
and `hook` to three stdout byte strings. Each input is bounded by the existing
1 MiB adapter cap. The return value is the existing `LI2AUTHORED-HEADS 1` byte
transport, with 80 or 107 heads. Any invalid input raises; no partial transport
or success receipt is returned. The owner must retain every refusal and capture.

The prospective owner captures each exact command independently, with `LC_ALL=C`:

```text
/usr/bin/objdump -d -w --insn-width=16 --disassemble=_start ORIGINAL
/usr/bin/objdump -d -w --insn-width=16 --disassemble=kernel ORIGINAL
/usr/bin/objdump -d -w --insn-width=16 --disassemble=null_hook ORIGINAL
```

The owner must bind the actual executable/tool/source identities, exact argv,
unchanged original and object bytes, successful normal closure, and complete
stdout/empty stderr before passing captures. This component runs no command and
does not prove that a supplied string came from objdump. The displayed filename
is syntax only and cannot supply file identity. Source-to-object build custody,
source completeness and linker-gap classification retain the existing adapter's
external premises. No synthetic fixture counts as tool provenance.

Accepted text is printable ASCII plus TAB/LF, final LF, at most 4096 bytes per
line. Blank lines are allowed. Each capture contains one `file format
elf64-x86-64` caption, one `.text` section banner, and one exact selected FUNC
header. Instruction rows have a lowercase hexadecimal address followed by TAB,
a space-separated lowercase byte column of at most 48 characters, TAB, and
nonempty opaque rendered text. Actual instructions must contain 1..15 bytes;
16-byte rows, wrapped byte rows, `(bad)` diagnostics, truncation markers and all
unrecognized nonempty lines refuse. Rendered mnemonics/operands do not establish
semantics and are not converted into instruction facts.

Optional local, zero-sized NOTYPE symbol headers must match both object and
linked symbol tables at the next contiguous instruction head. Duplicate labels,
wrong addresses/names, labels beyond the function and additional function/section
bodies refuse. The complete selected body must match its object-derived extent,
actual linked bytes and exactly 61 startup, 18 or 45 kernel, and one hook head.
The existing authenticated ownership and six-relocation validator are reused.
The resulting transport is checked by the unchanged adapter grammar before return.

The caller then freezes the transport digest and supplies all six original
inputs/first pins to `disassembly.attempt`. Independent iced-x86 decoding and
complete jump-inventory equality remain mandatory at the importer; this parser
does not replace them. Existing policies, workloads, cases and refusals are
unchanged. Six additive synthetic controls use the real parser plus the unchanged
fabricated ELF/object fixture helpers. All commands, controls, importer/native
execution and candidate-fit checks are UNRUN in this source proposal.
