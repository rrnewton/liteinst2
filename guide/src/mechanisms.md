# Interception mechanisms compared

LiteInst is one mechanism family among several. This chapter places it
honestly among its neighbours, because choosing the wrong interception
mechanism costs more than choosing the wrong library. Three different
machines are often conflated; keep them separate:

1. **In-place patching** (LiteInst's core) — rewrite bytes where they
   live. Cheapest steady state (native code, one jump detour), but only
   where a sound pun or relocation exists and the code is known and
   stable.
2. **Page capture / first-touch gating** (LiteInst's gates) — pages
   start non-executable; first fetch verifies and admits, still
   executing the original bytes in place. Lazy admission of certified
   code.
3. **Out-of-place translation** (a DBT such as DynamoRIO; our roadmap's
   mini-JIT) — copy and translate guest blocks into a code cache and
   execute there. Handles unknown and dense instrumentation uniformly,
   at a null-client tax on everything.

Around those sit kernel-mediated traps: **seccomp** (`RET_TRAP` →
`SIGSYS`), **Syscall User Dispatch** (SUD, Linux 5.11+), and **ptrace**
syscall stops. LiteInst requires none of them for its core, composes
with all of them (a trap is the standard fallback for an unpatchable
site), and its launch crate uses ptrace for cross-process control.
One precision: SUD appears in this repository's *standalone C
launchers* (`tools/page-entry/`, `tools/page-mode/`) — it is **absent
from the Rust library**, and no published crate depends on it.

The shared names for all of the above — used identically in the
Reverie guide and the architecture document — are the **B-axis**
numbers: **B1** seccomp trap, **B2** SUD, **B3** in-place patching
(this crate), **B4** page-fault gating (this repo's gate crates),
**B5** offline rewriting (this repo's emission path), **B6**
translation, **B7** ptrace stops. A *combination (cell)* pairs one B
with one activation (A1–A5) and one tool placement; validity of a
cell is a property of the design, separate from whether it is built.

## When to use each

| Need | Mechanism | Why |
|---|---|---|
| Sparse, hot hooks on known code | In-place punning | Native speed; one detour per site |
| Probes toggled at extreme frequency | Rapid one-byte puns | Single atomic store per toggle |
| Code known only at first execution | Page gates | Admit lazily, verify on fault |
| Closed code set, no runtime races wanted | Offline rewriting | Decide once, ship an artifact |
| Syscall-only interception, simplest soundness story | seccomp `SIGSYS` / SUD | Kernel is the completeness backstop |
| Full process control from outside | ptrace | The reference semantics; slowest per event |
| *Every* branch/instruction; unknown or JIT code; precise preemption | Out-of-place translation | Counting folds into emitted code; blocks discovered by execution |

The last row deserves emphasis. Punning instruments *chosen points*.
Counting *every* backedge with detours pays trampoline and context
costs per branch and then fights PMU skid for precise preemption.
LiteInst's owned-clock regions cover *bounded owned loops*; whole-program
branch coverage is translation's job. Neither approach wins everywhere
— translation itself struggles with some self-modifying workloads —
which is why the project keeps both.

Literature trap costs (per hook, as cited in our rewriting study) give
the scale: ~41 ns for a zpoline-style rewritten call, ~1.2 µs for SUD,
~1.3 µs for `int3`, ~31 µs for a ptrace stop. [Performance](performance.md)
separates what we have measured from what we cite.

## The Reverie view

At the Reverie layer these mechanisms become *cells* behind one
`Tool` API: the same tool runs under ptrace stops (B7), an in-guest
seccomp trap (B1), in-guest LiteInst patching (B3), KVM exits, or
translation (B6), with the same semantics or a named `R-*` refusal.
Selection there is requirement-driven — a tool states `ToolRequirements`,
environment probes (P1–P10) observe what the deployment allows, and a
cell is chosen or refused by name. That composition is the Reverie
guide's subject. This book's promise is narrower and stronger: each
LiteInst mechanism is sound inside its stated envelope, and refuses
outside it — which is exactly what the layer above needs from a
building block (architecture §4.1: plan-before-publish, exact
context, confinement, explicit signal ownership, no policy).

> 🚧 **Under construction — terminology alignment (pending owner
> approval of L0).** This chapter now uses the architecture
> document's A/B-axis and cell vocabulary
> ([§1–§2](https://github.com/rrnewton/dev-hermit/blob/main/ai_docs/2026-11-04-liteinst-reverie-architecture.md)).
> TODO: re-verify every name against the approved contract once the
> owner decides
> [§6.3](https://github.com/rrnewton/dev-hermit/blob/main/ai_docs/2026-11-04-liteinst-reverie-architecture.md#63-decisions-requested-from-the-owner-via-coord7)
> (items A/B/D), and add the valid-cell table (V1–V11) here if it
> survives review unchanged. <!-- UC: mech-terms -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`mech-terms`).
