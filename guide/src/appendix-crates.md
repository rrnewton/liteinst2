# Appendix A: crate map

| Crate | Published | Role | Chapter |
|---|---|---|---|
| `liteinst` | 0.2.0 | Patching core: punning, WordPatch++, trampolines, rapid toggles, emission, contracts | [Punning](punning.md), [Tactics](tactics.md), [Contracts](contracts.md) |
| `liteinst-x86` | 0.2.0 | Descriptive decode + selected-operand facts (`no_std`, fact-only) | [Admission](admission.md) |
| `liteinst-artifact` | 0.2.0 | Content identity, metadata, sparse overlays | [Offline rewriting](offline.md) |
| `liteinst-admission` | 0.2.1 | Admission facts + mock publication model | [Admission](admission.md) |
| `liteinst-inprocess` | 0.2.1 | In-process NX first-touch gate | [Page gates](page-gates.md) |
| `liteinst-launch` | 0.2.1 | Stopped first-instruction launch checkpoints + launch gate | [Page gates](page-gates.md) |
| `liteinst-rewrite` (`tools/elf-rewrite`) | no | ELF candidate emission frontend | [Offline rewriting](offline.md) |
| `rapid-profiler` (`tools/`) | no | Rapid-toggle profiling tool | [Tactics](tactics.md) |
| `liteinst2-exception-oracle` (`tools/exception-oracle`) | no | C++ exception-landing test fixture | — |
| `liteinst-bootstrap` (`crates/`, *not* a workspace member) | no | Per-product static `ET_EXEC` router bootstrap | [Safety](safety.md) |

Inside `liteinst`, the public modules (`src/lib.rs`, regenerated for
this appendix; rustdoc — docs.rs per release, `cargo doc` locally —
is authoritative):

* Planning and publication: `contracts` (plans/leases/receipts),
  `quiescent`, `composition`, `bundle`, `engine` (bounded tactic
  selection), `patcher` (+ `patcher::synchronized`), `planner`,
  `rapid`, `probe`, `search` (planning evidence), `sync_core`.
* Code understanding: `scanner`, `cache_line`, `control_flow`,
  `scalar_profile`, and `x86` (re-exported `liteinst-x86` facts).
* Generated code and runtime: `trampoline`, `controls` (callback
  enable bytes), `precontext`, `frame_trace`, `generated_unwind`
  (opt-in CFI), `grouping`, `emission`, `offline_router`
  (feature `offline-router`).
* Specialised profiles: `backedge_clock` (owned-loop clocks),
  `eviction`, `eviction_chain`, `neighbor` (forced-neighbour
  eviction tactics).

The crate README describes the load-bearing modules in prose; module
doc comments are the per-module contracts.

Contract documents that this guide summarizes (read them for the full
obligations): `INTERFACES.md` (the A0 core contract),
`A1-QUIESCENT.md`, `A2-COMPOSITION.md`, `A3-OFFLINE.md`,
`A4-SYNCHRONIZED.md`, and `PATCH_SITE_DECISION_TREE.md`.
