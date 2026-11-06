# The safety contract and refusals

LiteInst's most important behaviour is what it *won't* do. This chapter
is the contract: the envelope inside which patching is sound, what you
must provide to stay inside it, and the named refusals you get outside
it. A refusal is never a euphemism for "probably fine."

## The six invariants

The implementation maintains these at all times:

1. A cross-cache-line patch uses guarded publication unless the caller
   proves no concurrent fetch or data access is possible.
2. Probe installation publishes state only after planning and
   allocation pass.
3. Trampoline sizing and emission use the same checked plan.
4. Signal handlers use only async-signal-safe, pre-published data.
5. Trampolines never use one RWX mapping; arenas keep separate RW and
   RX aliases (and therefore do not provide strict W^X).
6. Continuation uses a direct jump when reachable, with a CET `NOTRACK`
   indirect fallback, so a continuation need not begin with `ENDBR64`.
   Unpreservable IBT entries are refused, not approximated.

## What clients must provide

Generic hooks can displace several complete instructions, replace a
short first instruction such as `syscall`, and mutate the saved integer
context. They do not establish arbitrary-binary, probe-anywhere
support. You must provide:

* a **trustworthy code region** with **writable access** to the live
  patch word;
* **mapping-lifecycle ownership** — nobody unmaps, remaps, or rewrites
  the region behind the library's back;
* proof that **no control-flow entry targets the interior** of a
  relocated window;
* a **trap fallback** for when the planner returns
  `PunPlan::TrapRequired`;
* for split (cache-line-crossing) concurrent sites, a
  machine/topology-qualified **`StalenessBudget`** — or route those
  sites to the trap fallback;
* for the controller-owned trampoline form, an external controller
  that performs both documented stack pivots. Using that entrypoint
  without one is unsupported.

Signal obligations are equally explicit. Concurrent WordPatch++
installation owns the process SIGTRAP router and refuses a prior custom
handler (unless the host supplies exact callbacks). Installed
trampolines publish immutable generated-to-application PC ranges;
signal handlers and unwind front ends translate a faulting PC with
`trampoline::translate_program_counter` — allocation-free and
lock-free — before reporting or unwinding. That translation path
synthesizes no DWARF; separately, the opt-in `generated_unwind`
module can publish source-certified CFI for normal backtracing
(no exception or signal admission). Trampoline arenas seal their
memfd against new writable mappings, writes, resizing, and policy
changes, and arena creation *fails closed* when the backing store
cannot provide the required seal set.

## The envelope, in one list

* **Platform:** Linux x86-64 for anything that patches or gates. Per
  crate: the core's live modules are cfg-gated (empty/refused
  surfaces elsewhere); `liteinst-inprocess` is `compile_error!` off
  Linux x86-64 and `liteinst-launch` exposes its API only there. The
  fact-only crates (`liteinst-x86`, `liteinst-artifact`, and the
  admission model) carry no such gate — decode facts alone buy no
  execution authority anywhere.
* **Kernel:** no SUD required. ptrace is required only where a
  controller drives another process (`liteinst-launch`, hybrid
  clients); pure in-process use needs none.
* **Binaries:** caller-certified regions. General static/PIE/musl
  turnkey support is not claimed; static `ET_EXEC` has an opt-in
  per-product bootstrap (`liteinst-bootstrap`, unpublished).
* **Dynamic code:** JIT and self-modifying code are not discovered.
  Gates admit *certified* pages lazily; uncensused code stays gated
  and refuses on first touch.
* **Threads/signals:** as above — quiescent entrypoints require total
  exclusion for the call; handlers see only pre-published translations.

If your program sits outside this envelope, the correct outcome is a
named refusal and a different mechanism (see
[Interception mechanisms compared](mechanisms.md)), not a workaround
inside LiteInst. At the Reverie layer, this library's refusals surface
under the shared `R-*` names — an uncensusable region or a
`TrapRequired` with no trap cell becomes `R-CODE`, a SIGTRAP-ownership
conflict `R-SIGNAL`, a strict-W^X policy `R-WX` — so a tool author
sees one taxonomy no matter which layer refused.

> 🚧 **Under construction — refusal catalogue.** TODO: a per-refusal
> reference: every public refusal/error variant,
> what triggers it, and the supported remedy — generated or checked
> against the source so it cannot go stale. External users will hit
> envelope refusals first; they deserve product-quality guidance, not
> bare enum names. <!-- UC: safety-catalogue -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`safety-catalogue`).
