# liteinst-aarch64-patch

Stopped-executor runtime patching for [LiteInst](https://github.com/rrnewton/liteinst2)
on AArch64 Linux, built on the fact-only `liteinst-aarch64` decoder/emitter.
This crate owns the unsafe runtime surface (dual RW/RX mappings, cache
maintenance, the aligned site store) so the fact crate stays `no_std` and
`forbid(unsafe_code)`.

Design: `crates/liteinst-aarch64/RUNTIME-PATCHER-DESIGN.md` (publication
lease, both-valid invariant, failure custody). No lock-free flip and no
BLR low-page path are claimed. Unpublished (`publish = false`) until the
fact crate version carrying `emit` is published.
