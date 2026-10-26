# Artifact metadata and sparse overlays

This crate authenticates complete original-file content identities, bounded
metadata records, and exact sparse byte overlays. `ContentId`, `Metadata`, and
`sparse_wire` are used by the [ELF frontend](../../tools/elf-rewrite/README.md).
The encoders and decoders retain the existing version-one wire formats and
prospective size bounds.

A valid digest proves byte identity. A `Rewritten` metadata outcome records the
producer's structural decision; it does not admit hooks, instructions, selected
entries, CPU state, loader readiness, or execution. Unsurveyed original pages
remain unknown. Sparse reconstruction requires the exact complete original
identity and the declared compatibility values. No API maps or executes code.

The source includes 20 existing test functions: nine metadata, five sparse
composition, and six sparse-wire cases. Their assertions are preserved. Test
execution and exact-source qualification are recorded separately.
