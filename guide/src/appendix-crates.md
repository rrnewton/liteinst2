# Appendix A: crate map

| Crate | Published | Role | Chapter |
|---|---|---|---|
| `liteinst` | 0.2.0 | Patching core: punning, WordPatch++, trampolines, rapid toggles, emission, contracts | [Punning](punning.md), [Tactics](tactics.md), [Contracts](contracts.md) |
| `liteinst-x86` | 0.2.0 | Descriptive decode + selected-operand facts (`no_std`, fact-only) | [Admission](admission.md) |
| `liteinst-artifact` | 0.2.0 | Content identity, metadata, sparse overlays | [Offline rewriting](offline.md) |
| `liteinst-admission` | 0.2.1 | Admission facts + mock publication model | [Admission](admission.md) |
| `liteinst-inprocess` | 0.2.1 | In-process NX first-touch gate | [Page gates](page-gates.md) |
| `liteinst-launch` | 0.2.1 | Stopped first-instruction launch checkpoints + launch gate | [Page gates](page-gates.md) |
| `liteinst-bootstrap` | no | Per-product static `ET_EXEC` router bootstrap | [Safety](safety.md) |
| `liteinst-rewrite` (`tools/elf-rewrite`) | no | ELF candidate emission frontend | [Offline rewriting](offline.md) |
| `rapid-profiler` (`tools/`) | no | Rapid-toggle profiling tool | [Tactics](tactics.md) |

Inside `liteinst`, each module owns one correctness boundary:
`contracts` (plans/leases/receipts), `quiescent`, `composition` +
`bundle`, `emission`, `cache_line`, `scanner`, `patcher` (+
`patcher::synchronized`), `planner`, `rapid`, `probe`, and
`trampoline`. The crate README describes each in one paragraph; the
API reference on docs.rs is authoritative.

Contract documents that this guide summarizes (read them for the full
obligations): `INTERFACES.md` (the A0 core contract),
`A1-QUIESCENT.md`, `A2-COMPOSITION.md`, `A3-OFFLINE.md`,
`A4-SYNCHRONIZED.md`, and `PATCH_SITE_DECISION_TREE.md`.
