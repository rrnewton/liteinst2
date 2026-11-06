# liteinst-aarch64

Shared descriptive AArch64 (A64) decode and selected-operand facts for
[LiteInst](https://github.com/rrnewton/liteinst2), the ARM counterpart of
`liteinst-x86`.

This crate is a fact-only decoder helper: it reports what an instruction
word decodes to, never instruction-head or execution authority. Walkers
choose their own linear/all-start policy, bounds and error mapping.
Decoded families do not grant CPU support, an emitter ABI, entry
ownership, mapping freshness or a complete control-flow graph.

Decoding is partial and total: every 32-bit word maps to a variant, and
everything outside the decoded subset becomes `Insn::Other`. Callers
that rewrite code must refuse any sequence containing `Other`.

It is unconditionally `no_std`, forbids `unsafe` code, and has no
runtime dependencies. `yaxpeax-arm` appears only as a dev-dependency
differential oracle for encodings it decodes.

## Provenance

The exclusive/RMW subset and its tests are copied and generalized from
Hermit's `detcore/src/aarch64_lse/insn.rs`. Hermit retains its own copy;
the two are reconciled by a later Hermit catch-up, not by a shared
dependency. Additions here (SVC/BRK identification, ADR/ADRP and
load-literal PC-relative forms, complete TBZ/FEAT_CMPBR operands,
BR/BLR/RET and BTI classification) serve the AArch64 patching toolkit:
single-word SVC replacement, near-trampoline islands, and trap-based
fallbacks. Field positions follow the Arm Architecture Reference Manual
for A-profile (DDI 0487); FEAT_CMPBR fields are cross-checked against
LLVM's AArch64 encoding tables (Armv9.6-A extension).

Most users want the main [`liteinst`](../../) crate. Depend on
`liteinst-aarch64` directly only if you need the same decode facts the
core publisher uses without the patching machinery.
