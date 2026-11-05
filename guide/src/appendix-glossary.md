# Appendix B: glossary

**Admission** — the decision that a page or region may execute, made
from scanned facts and entry evidence. Distinct from *publication*
(writing a patch).

**Arena** — dual-mapped trampoline storage: separate RW and RX aliases
of one sealed memfd, never a single RWX mapping.

**Gate** — a mechanism that keeps pages non-executable until first
fetch, verifies them, then admits them (in-process or at launch).

**Generalized pun** — replacing one entire 1–4-byte instruction with
`E9` and free low displacement bytes, letting unchanged successor
bytes supply the high displacement bytes, in one atomic store.

**Guest** — (Reverie term) the program being instrumented. LiteInst
itself has no guest concept; it patches regions its client names.

**Hook / probe** — a patched site plus the callback it detours to.
*Install-once* hooks have no toggle; *toggle probes* arm/disarm by
epoch; *rapid probes* toggle by one atomic byte store.

**Interior entry** — a control-flow target inside a multi-instruction
window that relocation would move. Its existence refuses relocation.

**Plan** — an immutable, inspectable description of a patch: snapshots,
edits, dependencies, obligations. Building one writes nothing.

**Publication** — writing a planned patch into live code under the
protocol its tactic requires, yielding a receipt.

**Punning** — reusing existing bytes so one atomic store leaves every
concurrent fetch seeing a complete old or new instruction.

**Quiescence lease** — the caller's scoped proof that no fetcher,
reader, writer, or handler touches the leased ranges.

**Receipt** — a publisher's evidence that a plan was published for an
exact identity/generation with all obligations resolved.

**B-axis / cell** — the shared mechanism numbering (B1 seccomp trap,
B2 SUD, B3 patching, B4 page gates, B5 offline, B6 translation, B7
ptrace). A *cell* combines one mechanism with one activation (A1–A5)
and one tool placement; the Reverie guide uses the same names.
⚠️ Name collision inside this crate: `src/engine.rs` uses `B1`/`B2`
for internal *tactic tiers* (Relocation, GeneralizedPun). Those are
unrelated to the architecture B-axis; context (engine vs toolkit)
disambiguates until one is renamed.

**Refusal** — a named, typed declination to patch or admit
(`TrapRequired`, and `R-*` names at the Reverie layer). Refusals are
fail-closed behaviour, not errors to work around.

**Staleness budget** — caller-supplied, machine-qualified bound on how
long a core may execute stale bytes across a guarded split patch.

**Straddler** — an instruction or patch window crossing a cache-line
(or page) boundary, so no single atomic store covers it.

**Trap fallback** — handling a site by trapping (e.g. `int3`,
seccomp `SIGSYS`, ptrace stop) instead of patching it, when the
planner returns `TrapRequired`.

**WordPatch++** — the guarded cross-modification protocol for split
sites: guard bytes trap racing fetchers while the patch completes.
