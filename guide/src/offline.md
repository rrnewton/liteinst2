# Offline rewriting

Runtime patching races are avoidable entirely if you rewrite the
binary *before* it runs. LiteInst's offline path produces ELF
candidates, metadata, and sparse overlays through the same tactic
engine as the runtime patcher — so a site that is sound to patch live
is planned identically offline — while recording outstanding runtime
requirements separately from structural success.

## The pieces

* **`emission` (in `liteinst`)** — explicit target descriptions and
  symbolic same-module hooks for offline plans. Plans use bound
  virtual addresses; ELF load-bias fixups are later work, and the
  module says so.
* **`liteinst-artifact`** — content identity and format, with no
  execution authority. A valid digest proves byte identity; a
  `Rewritten` metadata outcome records the producer's structural
  decision. It does not admit hooks, entries, CPU state, or loader
  readiness, and unsurveyed original pages remain unknown. Successful
  decoding never publishes code.
* **`tools/elf-rewrite`** (`liteinst-rewrite`, not published) — the ELF
  frontend that drives emission over whole binaries and DSOs.
* **`offline-router` feature** — the opt-in startup authority that lets
  a rewritten image route its sites at load time. It is absent from
  default core builds on purpose: offline authority should be chosen,
  not ambient.

## What offline does and does not buy you

Offline rewriting trades startup work for the absence of runtime
patching races: the bytes on disk are already the instrumented bytes.
It does not solve code the binary generates later (JITs, self-modifying
code, `dlopen`ed text beyond the rewritten set), and it does not turn
LiteInst into a turnkey e9patch replacement — runtime requirements
(the router, trampoline placement, entry proofs) are recorded in the
artifact and must still be satisfied by the embedding client.

Choose offline when the code set is closed, startup cost is
acceptable, and you want the patching decision made once, auditable
as an artifact. Choose runtime patching or page gates when the code
set only exists inside a running process.

> 🚧 **Under construction — end-to-end rewrite.** TODO: walk through
> rewriting one small ELF with `tools/elf-rewrite`, inspecting the
> metadata and sparse overlay, and running the result under the
> offline router — including one site the engine refuses and how the
> artifact records it. <!-- UC: offline-walkthrough -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`offline-walkthrough`).
