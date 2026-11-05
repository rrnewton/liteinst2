# The patching tactics

"Patch this site" is not one operation. Depending on what you can prove
about the program at publication time, LiteInst offers four tactic
families. Choosing among them is the main API decision a client makes,
and the repository's
[patch-site decision tree](https://github.com/rrnewton/liteinst2/blob/main/PATCH_SITE_DECISION_TREE.md)
states the choice exhaustively. This chapter introduces each family
and when to reach for it.

## Quiescent publication

If you can exclude every other thread, signal handler, instruction
fetch, and code writer for the duration of the call, use the quiescent
entrypoints. They prefer generalized short-instruction puns —
install-once, no guarded splits — under a held `QuiescenceLease`.
Publication still prepares Linux sync-core and reserves trap routing
internally; "quiescent" removes the *concurrency* proof burden, not
all machinery. This is the right default at launch time, under a
stopped-task controller, or in a single-threaded preload constructor.

Planning is safe (`plan_install`); the *publication* entrypoints are
`unsafe`: the exclusion is your proof to uphold, and the lease type
exists to make that proof explicit and scoped. They must not be used
as a faster default for threaded applications.

## Concurrent publication (WordPatch++)

If the program keeps running while you patch, use the ordinary
`LiveJumpPatch` / `InstalledHook` entrypoints. Publication is
concurrent-safe: single-store puns where geometry allows, WordPatch++
guards across cache-line splits, and a process SIGTRAP router that the
library owns for the duration. Requirements that surprise people:

* Installation refuses a pre-existing custom SIGTRAP handler (prior
  `SIG_DFL`/`SIG_IGN` only), unless the host supplies exact
  installation/redelivery callbacks through
  `prepare_live_patching_with_signal_runtime`.
* Split sites need a machine/topology-qualified `StalenessBudget`.
  Without one, route the site to your trap fallback.
* Neighbouring sites may share the unchanged tail of their 8-byte
  stores when their displaced intervals are disjoint; overlapping
  writers fail with `Contended` rather than racing.

## Rapid toggles

Some probes must turn on and off millions of times (profilers,
sampling instrumentation). Re-planning a five-byte patch per toggle is
far too slow. The **rapid** family plans an exact one-byte pun once —
the original bytes must encode a free trampoline destination — and then
toggles with a single atomic opcode-byte store. Measured toggle costs
are in [Performance](performance.md).

Rapid puns are also the least general tactic: when the exact pun does
not exist, the planner says so and you pick another family. There is no
approximate rapid mode.

## Synchronized (sync-core) publication

The experimental `patcher::synchronized` API publishes words and
batches behind sync-core barriers. Note precisely what changes:
split members still publish `0xCC` front-fragment guards
(`GuardsPublished` phase) — the barriers replace the *staleness
waits*, not the guards. Its
supported geometry, caller obligations, and terminal-failure behaviour
are narrower than WordPatch++'s; treat it as a specialist tool and read
its contract before use.

## Choosing

| Situation | Tactic |
|---|---|
| All fetchers/writers excluded (launch, stopped task, single thread) | Quiescent |
| Live multithreaded program, install-once or rare changes | Concurrent (WordPatch++) |
| Same site toggled at very high frequency | Rapid (`RapidProbe::install` is standalone; no prior general install needed) |
| Batched split-site publication without caller staleness budgets | Synchronized (experimental; front guards still published — barriers replace the waits) |
| No tactic's preconditions hold | **Trap fallback** (`PunPlan::TrapRequired`) — your controller (e.g. ptrace) handles the site |

The last row is load-bearing: refusing to patch and trapping instead is
a supported, expected outcome, not an error path to hide. Clients that
keep a ptrace slow path follow the decision tree site by site.

> 🚧 **Under construction — per-tactic listings.** TODO: one runnable
> listing per family (quiescent install, concurrent install, rapid
> toggle loop with timing, synchronized batch), each compiled in CI
> from `examples/` or `tests/` sources. <!-- UC: tactics-listings -->
> Tracking: [liteinst2#38](https://github.com/rrnewton/liteinst2/issues/38) (`tactics-listings`).
