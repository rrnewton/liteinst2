# liteinst-x86

Shared descriptive x86-64 decode and selected-operand facts for
[LiteInst](https://github.com/rrnewton/liteinst2).

This crate is a fact-only decoder helper: it reports what the bytes decode
to, never instruction-head or execution authority. Walkers choose their own
linear/all-start policy, bounds and error mapping. Selected instruction
families do not grant CPU support, an emitter ABI, entry ownership, mapping
freshness or a complete control-flow graph.

It is `no_std` and forbids `unsafe` code. The default feature selects
iced-x86's `std` support. A freestanding consumer disables defaults and must
select iced-x86's `no_std` support in its own dependency graph. This crate
adds no allocator or decoder-table policy.

Most users want the main [`liteinst`](../../) crate. Depend on `liteinst-x86`
directly only if you need the same decode facts the core publisher uses —
for example to build your own admission scanner — without the patching
machinery.

See the [LiteInst guide](https://rrnewton.github.io/liteinst2/) — link
pending; the guide lives in `guide/` in the liteinst2 repository.
