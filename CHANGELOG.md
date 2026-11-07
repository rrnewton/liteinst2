# Changelog

All notable changes to the `liteinst` crate are recorded here. The format
follows Keep a Changelog, and this project uses semantic versioning.

## [Unreleased]

## [0.3.0] - 2026-11-07

Prepared from liteinst2 main `1c150b56de79f88ca0fc1dcb39018a083b314cf2`.
This entry records release preparation only; nothing has been published
from the preparation branch yet.

### Added

- Semantic XSTATE equality for saved-state comparisons:
  `XstateSemanticEq`, `SavedExtendedStateLayout::xstate_semantic_eq`, and
  the preserved-XCR0 mask probes. Format validation runs before any
  equality shortcut, and the x87 legacy matrix is completed.
- Honest off-x86-64 saved-state surfaces: detection refuses by name, the
  XCR0 probe answers `false`, and XSTATE comparison answers
  `NotComparable` instead of referencing unavailable x86-64 items.

### Changed

- The root library now compiles off x86-64 (verified for
  `aarch64-unknown-linux-gnu`). Site patching and trampoline emission
  remain Linux x86-64 facilities; this is a compile-time portability
  change for planning/consumer builds, not AArch64 patching support in
  this crate.
- Workspace consumers in this repository (`liteinst-admission`,
  `liteinst-inprocess`, and `liteinst-launch`) now require `liteinst`
  0.3.0. Their own package versions are unchanged in this preparation;
  publish them only as a separately versioned cohort if they are
  released from this branch.

### Packaging

- `liteinst-x86` and the optional `liteinst-artifact` dependency remain
  on their published 0.2.0 lines; the packaged root crate does not
  request unpublished features from either.
- Verified before the bump at the same tree: `cargo package --locked -p
  liteinst` and `cargo build --locked -p liteinst --lib --target
  aarch64-unknown-linux-gnu` both pass.
