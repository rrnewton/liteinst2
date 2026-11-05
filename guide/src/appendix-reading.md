# Appendix C: further reading

* *Living on the Edge: Rapid-Toggling Probes with Cross-Modification
  on x86* (PLDI 2016,
  [doi:10.1145/2908080.2908084](https://doi.org/10.1145/2908080.2908084))
  — WordPatch++ guarded split-site patching.
* *Instruction Punning: Lightweight Instrumentation for x86-64*
  (PLDI 2017,
  [doi:10.1145/3062341.3062344](https://doi.org/10.1145/3062341.3062344))
  — punning and generalized WordPatch++.
* The original C++ implementation:
  [iu-parfunc/liteinst](https://github.com/iu-parfunc/liteinst).
* In this repository: `INTERFACES.md` (core contract),
  `A1-QUIESCENT.md`, `A2-COMPOSITION.md`, `A3-OFFLINE.md`,
  `A4-SYNCHRONIZED.md`, `PATCH_SITE_DECISION_TREE.md`,
  `COALESCED-CONTROLS.md`, and the published crates' READMEs.
* The Reverie guide — for building complete tools on these blocks.
* API reference: [docs.rs/liteinst](https://docs.rs/liteinst) and the
  sibling crates linked from there.

> 🚧 **Under construction — annotated bibliography.** TODO: one-paragraph
> annotations for the neighbouring systems this book compares against
> (e9patch/zpoline, lazypoline, DynamoRIO, Pin, gVisor systrap), each
> saying what to read it for. <!-- UC: reading-annotated -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`reading-annotated`).
