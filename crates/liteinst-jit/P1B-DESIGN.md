# liteinst-jit P1b design note (draft, awaiting the external review verdict)

Status: **DESIGN ONLY.** P1b implementation is gated on an
adversarial review of the P1a code + §6 invalidation design, plus
a project go-ahead. Nothing here is built, selectable, or claimed. Layering
rule carried over: liteinst owns translation primitives; a complete
loader/tool belongs in Reverie. P1b target is architecture cell V10
remains **unbuilt until M4 is met**, and merging to liteinst2 main
remains barred under the owner's DBT hold regardless of this note.

**Scope decision recorded 2026-11-05 in project review:** for **P1a**, the
disclosed asynchronous-signal reduction is accepted (admission
refuses installed async handlers; poll-bounded `AsyncSignal`
stops; no transparency claim). That acceptance is **for P1a only**.
Transparent asynchronous delivery per original §6.3 is a required
gate before any P1b whole-program claim and is therefore item 1
below. The genuine Linux signal-frame, compiled-C static/dynamic/
PIE variant, and SINGLEBLOCK-corroboration gaps remain disclosed;
none is satisfied by this note.

Goal (M4 shape, final wording is the owner's): the standalone driver
counts every retired conditional branch (then every instruction) of
a real dynamically-linked program (`/bin/ls` or a review-approved equivalent),
with the refusal list explicit and costs reported per the owner
rule (DR-null ratio, run count, machine; dense counting labelled
vs a DR counting client). Everything P1a refuses that P1b still
cannot do keeps refusing by name.

## 1. Required gate: transparent asynchronous delivery

No P1b stage may be presented as a whole-program result — including
any `/bin/ls`, M4-shaped, or staged-driver claim — until this gate
is implemented and independently validated. Indirect control flow,
mapping discovery, and driver work below do not bypass it.

Required behavior, at the level frozen for P1b authorization:

- An asynchronous signal may arrive at any guest-live generated PC,
  including copied instructions, counter/poll stubs, call/exit
  machinery, common exit, and the entry bridge. The executor first
  reconstructs exact source state: next source PC, registers,
  flags, stack effects, and pending versus committed branch and
  instruction credit, with no lost or double credit.
- Delivery uses a genuine Linux signal frame at the recovered
  source PC with source-faithful `siginfo` address semantics. No
  cache/generated PC, machinery register, spill value, or
  executor-private address may be exposed as guest state.
- The guest handler itself executes under the same counting,
  syscall/nondet exit, mapping-admission, and refusal contract as
  other guest code. Signal masks, alternate-stack ownership,
  nested and real-time signal ordering/coalescing, restart of
  interrupted syscalls, and `rt_sigreturn` resume to the recovered
  source PC each need an explicit rule before implementation is
  claimed complete.
- Synchronous faults retain precise source PC/state and
  signal-specific address semantics; asynchronous provenance is
  never relabelled by the emitted location at which it arrives.
- Acceptance evidence must include asynchronous interruption at
  copied and machinery boundaries, a guest loop that progresses
  only when its handler runs, a handler that mutates architectural
  state and returns through `rt_sigreturn`, source-PC/siginfo
  assertions inside the handler, and full-state/count comparison
  against the independent native oracle. Genuine-frame evidence is
  currently absent and remains an explicit gap until those tests
  exist.

This gate changes the driver sequence in §4: its staged programs
may be used as development fixtures, but no stage is a
whole-program claim while asynchronous delivery is only blocked,
reported, or confined to dispatcher boundaries.

## 2. Indirect control flow

Two stages, separately landable:

- **P1b.1 dispatcher-resolved indirect (correctness first).**
  Indirect `jmp`/`call` keep P1a's exit stub, but the dispatcher
  gains a resolve step: evaluate the target from the exported state
  **in the dispatcher** (register or memory operand read via
  `GuestMemory`, including the `call` return-address push done
  dispatcher-side so guest-stack effects are exact), then: target in
  an admitted region → translate on demand (discovery by execution)
  or enter the existing block; target outside every admitted region
  → `Refuse::IndirectUnresolved` as today. `ret` already resolves
  this way in P1a and is unchanged. Cost: one dispatcher exit per
  indirect transfer — acceptable as the correctness-first
  development stage, measured honestly, removed only by P1b.2;
  any resulting whole-program claim still requires §1.
- **P1b.2 in-cache hash-lookup exit stub (speed).** An
  allocation-resident open-addressing table `orig_pc → gen_pc`
  (power-of-two, linear probe, generation-stamped entries). The
  stub sequence must be flag-neutral and spill-exact like the count
  stub (SETO/LAHF save, hashed probe loop with its own internal
  branches **excluded from both counters by construction** — they
  are machinery, recorded as a new PC-map phase so fault recovery
  still names the source indirect instruction), and must miss to
  the P1b.1 dispatcher path without having mutated guest state.
  Hit-path chaining (patching the indirect site to a direct jump
  after a hit) is explicitly **deferred**: it creates the
  incoming-link bookkeeping §6 of the first report reserves for
  after quiescence is proven. Table invalidation is whole-table
  flush on any generation advance (P1a's flush discipline).
- PLT/GOT and jump tables need no special case under either stage:
  the target is whatever value memory/register holds at run time.
  Lazy binding means the dynamic linker's resolver is itself
  reached by an indirect transfer and gets translated like any
  other code once its mapping is admitted (§3). `jmp *GOT` through
  a not-yet-bound slot therefore works or refuses by the same rule
  as every other indirect edge — there is no PLT-aware shortcut.

Counting reminder: indirect and unconditional transfers never
increment the RCB counter; only the conditional branch that retires
does (unchanged from P1a). The lookup stub's internal conditional
branches are machinery and are not guest branches.

## 3. Code discovery: dlopen, ld.so, fresh mappings

P1a admits one immutable private region up front. P1b admits
**lazily, on first control transfer in**, under these rules:

- The handler sees every syscall (blocks still exit before
  syscall-class instructions). `mmap`/`mprotect` making pages
  executable, `munmap`/`mremap`, and `execve` are **generation
  events**: the driver records mapping identity + generation and
  calls `Executable::invalidate` equivalents before the guest
  resumes. No region is scanned or translated at syscall time —
  translation happens only when control actually transfers into
  the mapping (discovery by execution), from a byte snapshot taken
  at admission and hashed into the cache key.
- Admission requires the same proof as P1a: private, non-writable,
  file-backed or provably immutable; writable/shared/memfd
  executable mappings keep refusing `SelfModifyingOrWritableCode`.
  That refuses JIT-emitting guests by name in P1b (M5 territory);
  ordinary `dlopen`ed shared libraries (RELRO, RX after relocation)
  are the intended admittees. A library whose text is still being
  relocated (writable during `ld.so` relocation) is admitted only
  after the `mprotect` that seals it — control cannot legitimately
  transfer in before then, and if it does, refusal is correct.
- Multiple regions need the cache index keyed per (mapping
  identity, generation) rather than one global generation; the
  `CacheKey` already carries generation, so the change is to stop
  assuming a single current generation in `Executable` and key
  validity per region. Invalidation of one mapping must not flush
  unrelated regions' translations, but **must** flush the indirect
  hash table entries pointing into it (whole-table flush is the
  P1b-simple correct choice).
- Saved-context retention across `dlclose`/`munmap` is unchanged
  from the first report's §6 design: return/signal PCs into an unmapped library
  remain recorded; resuming to one faults/refuses by name, never
  silently lands in a reused mapping (generation, not address,
  decides).

## 4. The `/bin/ls` driver (standalone, no Reverie binding)

Recommended shape: **ptrace-launched child with an injected cache**
(reusing the exec-stop ideas from `crates/liteinst-launch` at the
design level, not its code):

1. `fork` + `PTRACE_TRACEME` + `execve(/bin/ls)`; stop at
   `PTRACE_EVENT_EXEC` before the first guest instruction.
2. In the stopped child, remote-`mmap` the cache arena + data page
   (syscall injection at the stop, registers restored exactly),
   copy translations in as they are produced, and redirect the
   entry RIP into the cache. The dispatcher lives in the tracer;
   exit stubs `int3` to it (the resident-tracee shape), handler
   syscalls are served by single-stepping the **original** syscall
   instruction in the child so the kernel sees a genuine guest
   syscall with genuine state.
3. Threads: `clone` exits name the new thread; P1b admits
   additional threads only with per-thread `JitData` (spill slots
   and counters are per-thread; counters sum at exit) and a shared
   cache that is append-only between quiescent points. If the
   rendezvous proof is not ready, multi-threaded guests keep
   refusing `ThreadLifecycle` — `/bin/ls` is single-threaded in
   practice, and P1b must say so rather than imply coverage.
4. Signals: §1 is a hard gate, not a later transparency upgrade.
   Dispatcher-boundary delivery, signal blocking, poll-bounded
   `AsyncSignal` stops, or a state rewrite without a genuine Linux
   frame may be used while developing the mechanism, but none
   satisfies §1 and none supports a whole-program claim. The
   driver cannot call a stage complete until arbitrary-PC async
   interruption, genuine-frame delivery, handler execution under
   the counting contract, and `rt_sigreturn` resume are validated
   as specified in §1. Synchronous faults keep precise source
   PC/state and signal-specific address semantics.
5. `execve` from the guest refuses `ExecSuccessor` in P1b
   (successor retranslation is named future work), as do `ptrace`
   by the guest, personality changes that alter decode, and
   32-bit compat execution (`Arch`).

Staging inside the driver: static hello → dynamic hello (ld.so
translated) → `/bin/true` → `/bin/ls -d .` → `/bin/ls` on a real
directory. Each stage's counts validate per §5 before the next is
used as a development fixture, but **no stage may be claimed as a
whole-program result until §1 also passes on that stage**.

## 5. Oracles for P1b (freeze before implementation)

- **§1 async-delivery evidence (new, required):** an independent
  native oracle must observe handler-visible source PC/`siginfo`,
  full state, counts, and resume behavior at copied and machinery
  boundaries, including a loop that progresses only through its
  handler. A genuine Linux frame is not currently demonstrated;
  this remains a gap until those tests exist and pass.
- **O1 (existing)** keeps covering every P1a fixture plus new
  indirect/call/ret/jump-table fixtures at fixture scale, exact
  equality, no tolerance. P1b.2's hash stub must produce
  bit-identical counts to P1b.1's dispatcher path on the same
  corpus (stub on/off differential).
- **O4 guest-visible equivalence:** stdout/stderr/exit code of the
  driver vs native `ls` on identical directory state, byte-equal.
- **O3 DynamoRIO counting client** on the same workloads, reported
  only as "vs DR with a counting client": branch counts should
  match the driver's; wall times reported with medians+IQR.
- **O2 PMU** stays a skid-caveated trend witness only.
- Negative controls: stale-hash-entry mutant (invalidation of the
  lookup table disabled) must be caught by a dlopen/dlclose/reopen
  fixture; stub-branch-counting mutant (machinery branches leaking
  into the RCB count) must be caught by O1 equality.
- Still-disclosed evidence gaps: compiled-C static/dynamic/PIE
  variants and SINGLEBLOCK corroboration are not established by
  the current corpus and must either be added to the frozen P1b
  corpus or explicitly carried as non-claims in every result.

## 6. Explicit non-goals and refusals carried into P1b

Self-modifying/JIT code (M5), `execve` successors, attach (A4),
external-debugger coexistence (the P1b driver *is* the tracer),
CET shadow-stack call rewriting, aarch64, any Reverie core change,
and any V10-selectable or product claim before M4 exit is declared
by the project owner. Cost guardrail from the admission work: steady state does no
per-page or per-admission work — discovery is per first-transfer
into a block, and every reported number carries DR-null ratio +
exactly-10 median + IQR + machine or is labelled UNMEASURED.

## 7. Open questions for the external review

1. Is dispatcher-side indirect resolution (P1b.1) an acceptable M4
   shape if its measured cost is honest, with the hash stub as a
   pure optimization? (This note assumes yes.)
2. Per-region generations vs one global generation with
   flush-on-any-mapping-event: is the simpler global flush
   acceptable for M4 if `dlopen`-heavy reruns retranslate?
3. **Resolved 2026-11-05 in project review:** mid-cache transparent
   async delivery **does** gate every P1b whole-program claim
   (§1). The remaining questions are mechanism-specific: exact
   genuine-frame construction and resume rule, nested/RT ordering
   and coalescing rules, interrupted-syscall restart semantics,
   and how much of that surface must be validated before the first
   staged `/bin/ls` result may be called whole-program.
4. Remote-arena injection at exec-stop vs a preload-shaped child
   bootstrap: any objection to ptrace syscall injection as the
   *driver-only* mechanism (explicitly not the future V10 loader)?

Estimated against L10 §6.4's P1b stage (15–30 agent-days, estimate):
transparent delivery is now scope item 1 and a claim gate, so
that stage estimate must be repriced after the external review verdict and
P1b authorization rather than treated as already covering §1.
Within the remaining scope, P1b.1 + driver staging is the bulk of
the work; P1b.2's hash stub is the tail risk if flag-neutral
probing resists the simple template.

## 8. Item-1 staging: I1-A through I1-H

Staging source: the P1b scoping report's stage map (I1-A
recovery core through I1-G RT/payloads/restart, plus I1-H gate
evidence), committed here so the staging survives outside the
untracked report. This section sequences §1's gate only; it does
not weaken §1, and no stage below — including I1-D — is a
whole-program, `/bin/ls`, or M4 claim. In the mini-JIT plan
(`ai_docs/2026-11-05-minijit-plan.md`) this is stage S1; S2 driver
work (§§2–4 above) may use these stages as development fixtures
but may not be claimed whole-program until I1-H review passes.

Status at this section's commit (liteinst2 `main`
`c4217e8965eaff5a209dbd9902cf3d64dfc7e2b5`), updated for I1-E
through I1-G2 on `main` `ca1152214e221b437caa11fb48c3e36d5069da21`:

- **I1-A landed** (`2b46ed54a14839513ebc122246e7926333c6f499`):
  backend-neutral recovery core in `src/recovery.rs`.
- **I1-B landed** (`a0db922be1295f467be54fb812d7dce9dc173bd6`,
  with provenance/restart hardening): remote ptrace substrate in
  `src/remote.rs`; async signals still stop as recovered outcomes,
  custom-handler delivery absent.
- **I1-C landed** ([PR 50](https://github.com/rrnewton/liteinst2/pull/50), head
  `0f3f569fcac677d4c2b25b683f14a4052b749e43`, from
  `983b2029a31770322eea096b62b5600a7bffd3a5`): guest signal
  registry **mirror** — stepped genuine registry syscalls with
  post-call kernel readback reconciliation. Landed I1-C does
  **not** install the common signal-entry stub and does not
  virtualize old-action results; that half of the mechanism
  below belongs to I1-D.
- **I1-D landed** ([PR 65](https://github.com/rrnewton/liteinst2/pull/65),
  `db60f1d1f421337406e3281fab06ecf45e9a5d6c`): stub install +
  old-action virtualization, genuine frame delivery at
  recovered block starts, translated handler, kernel
  `rt_sigreturn` resume, native-child differential — bounded
  exactly to the admitted shape in the I1-D detail below.
- **I1-E landed** (`cbd319d83fb006d8866d8541c7bb913893f20af1`,
  then `2edcd80eab955e476b1c281dbbd680a37dd175c5`): arbitrary
  generated-phase async recovery with exact mid-block
  generated re-entry (raw precredit re-based, not a new
  translation), synchronous SIGSEGV/SIGFPE delivery at
  copied insns with source-form instruction addresses, same
  admitted flag/mask/restorer bounds. Async stops in
  common-exit spilled stages and at generated PCs with no
  pcmap entry (entry-loader bridge class), stepped-syscall
  and original-step async stops, blocked-poll delivery,
  sync faults outside copied insns, and handler-mutated
  mid-block resume PCs still stop by name (see I1-E detail).
  I1-H H2b later closes the common-exit stages (except an
  INDIRECT exit's) and the original-step stop; the
  stepped-syscall stop before syscall entry stays open.
- **I1-F landed** (`736454bcaff828689cc7f97ec962d495d3015399`):
  masks, alternate stack, capped nesting (see its detail).
- **I1-G split** (project decision 2026-11-10): **I1-G1**
  (RT ordering, RT retention vs standard coalescing,
  `rt_(tg)sigqueueinfo` payloads and sender words, kernel
  back-to-back frame setup) **landed**
  ([PR 76](https://github.com/rrnewton/liteinst2/pull/76),
  merge `4210776c6485989dfb6ead7e61c745912d04e191`).
  **I1-G2** (syscall restart, `SA_RESTART`) **landed**
  ([PR 77](https://github.com/rrnewton/liteinst2/pull/77),
  merge `ca1152214e221b437caa11fb48c3e36d5069da21`).
- **I1-H** (scope approved in design review 2026-11-10) runs as four
  PRs in order: a standalone poll fix (W4: a blocked pending
  signal stopped the run at a poll exit; **landed**,
  [PR 78](https://github.com/rrnewton/liteinst2/pull/78),
  merge `ec2a98f8eaf0b959b1acb6430abd0c7e578a051d`; see I1-F
  below), then H1 evidence (an O1 signal oracle, deterministic
  arrival at any generated PC, a differential sweep, the frozen
  corpus), H2 (deliver arrivals in common-exit stages and
  original-instruction steps; W5; plus the `kill` gate's NSpid
  proof; the entry-bridge class W2 turned out empty, see below;
  H1 landed as [PR 79](https://github.com/rrnewton/liteinst2/pull/79),
  merge `e207a8ea`; H2 runs as two PRs, H2a = W5, the NSpid
  proof, the poll-budget fix and the H1 review follow-ups, then
  H2b = W1 and W3), and H3 (the S1 overhead
  breakdown, a replay of every retained mutant, and the one
  bounded claim).
- **W5** (found in the W4 review, pre-existing; **closed in
  H2a**): the mirrored signal mask is refreshed after a stepped
  `rt_sigprocmask` and at sigreturn, but not at handler entry,
  so during a handler a signal blocked only by its `sa_mask`
  (or its own signal without `SA_NODEFER`) read as unblocked
  at a poll, and an ineligible one stopped the run early. The
  poll now takes `SigBlk` from the same `/proc/<pid>/status`
  text it reads for the pending sets, through the one
  fail-closed parser (`status_masks`, which also serves mirror
  seeding and `rt_sigprocmask` reconciliation), so the poll's
  mask is the kernel's at every poll; there is no handler-entry
  refresh. Discriminating tests (the old poll stopped inside the
  handler): SIGUSR2 in a USR1 handler's `sa_mask` with no
  handler, and the handler's own USR1 reset to `SIG_DFL` and
  self-sent; after sigreturn each stops where the native child
  dies. Regression tests (eligible signals were deferred under
  the old poll too): signal 34 in `sa_mask` and the handler's own
  USR1 with its handler, each delivered after sigreturn, equal to
  O1-S. Each crosses several polls inside the handler. Mutant:
  the poll reads the mirror again.
- **Poll budget 0 handed to a handler** (found reading the code
  in the H2 scope review; latent since I1-E; fixed in H2a). The
  poll stub is `dec qword [poll]; jnz`, so every stop on the
  poll path has a raw budget of 0. A delivery from there passed
  the 0 to the handler, whose first `dec` wrapped it to 2^64 - 1:
  no poll fired for the rest of the run. Every delivery from a
  raw 0 now restarts the full budget (`resume_budget`, a pure
  function of the stop state). The mid-block sigreturn re-base
  refuses a raw 0 by name instead (design review): every budget-0 stop
  recovers to its block start and resumes through the block
  index, so a 0 restored mid-block is a broken invariant, and
  resetting it would hide the bug; a test seam presents it. The
  seam counts poll exits so the fix is observable.
- **W1 and W3** (**closed in H2b**). W1: a common-exit stop of a
  RETURN, SYSCALL, NONDET or POLL exit is resumable. It recovers
  to the exit's source PC with the terminator not yet run and
  resumes through the exit stub's pristine entry (or the block
  index), so the terminator runs once after the handler; a POLL
  exit recovers to its block start. An INDIRECT (or unknown)
  kind keeps the named refusal, pinned by a `jmp rax` fixture.
  W3: a signal-delivery stop presented before the original
  `cpuid` step runs is delivered at the `cpuid`, nothing
  credited, and the `cpuid` is stepped once after sigreturn; a
  three-part provenance guard (RIP, GPRs, RFLAGS exactly, against
  the recorded pre-step copy, no TF exception) refuses any other
  asynchronous stop by name, shown per part through a seam. The
  restore invariant above extends to POLL-kind common-exit stops
  (they recover to a block start), pinned on the PC map. Still
  open: an asynchronous stop before a stepped syscall's entry
  (the W3 sibling), and kernel-generated signals during the
  original step. Liveness non-claim: W3 retries the `cpuid`
  where a native run progresses, if an asynchronous signal (a
  short-period timer, say) fires faster than the
  deliver-and-retry round trip; before H2b that case was refused
  by name. **Since H2c** the retry is bounded: after 64
  consecutive W3 deliveries with no completed original step, the
  next interrupt refuses by name (`BudgetExceeded`, "original
  step interrupted without progress"); fail-closed liveness,
  deterministic given the same delivery sequence. Ordering
  condition (H2b review P3-3): the H2c test-hygiene items, a
  one-shot `pre_redirected_step_signal` seam and the per-run
  deadline in the other six ptrace test binaries
  (remote_signal_rt, remote_signal, remote_registry,
  remote_compare, o1_compare, custody), land in or before the
  slice that closes the stepped-syscall stop. Closing that stop
  with the seam still persistent would bring back the H2b
  record-pass hang, in a binary with no deadline. **H2c lands
  both**, so the stepped-syscall slice (H2d) comes after it.
- **W2 is closed by evidence, not code** (H1). The scope named
  W2 as "generated PCs with no pcmap entry (the entry-loader
  bridge class)", but the remote substrate has no such PCs. The
  tracer enters every block by setting registers, so no
  generated entry bridge exists, and every byte the remote
  translation emits (exit style `TrapToDispatcher`) lies in
  exactly one PC-map entry, contiguously. The H1 test
  `w2_remote_translation_maps_every_generated_byte` checks this
  for both sweep fixtures and every corpus-v1 fixture that
  translates. The arena's only other code is the signal-entry
  stub, which only a kernel delivery enters; an arrival there is
  the I1-G1 back-to-back case. `resume_gen`'s unmapped-PC refusal
  therefore has no reachable input in this substrate.
- **H2 follow-ups from the H1 reviews** (recorded in H1; **done
  in H2a**: `rf_at_hits` asserted at every hit, R5 recorded as
  equivalent, and O1-S's handler entry pinned to `si_code ==
  SIGTRAP` with the `!= TRAP_TRACE` clause dropped; the pin is
  load-bearing, not redundant: an ignored signal re-injected over
  a step whose registers happen to have the handler-argument
  shape reports TRAP_TRACE, and a regression test covers it):
  - The arrival seam's "ensure RF" step on non-final hits is
    defence in depth. For an execute breakpoint the kernel's
    `hw_breakpoint_handler` already sets `X86_EFLAGS_RF`
    (`arch/x86/kernel/hw_breakpoint.c`, about line 562) before
    the tracer reads RFLAGS, so a mutant that drops the step is
    **equivalent** on this kernel (the design review's R5 passes every
    test). H2 records it as equivalent, and may assert that the
    recorded `rf_at_hits` are all set, as a pin of the kernel
    rule rather than of the seam.
  - O1-S recognises the handler-entry stop without pinning its
    `si_code`. Per the kernel source, `signal_delivered` calls
    `ptrace_notify(SIGTRAP, 0)` when the tracee is stepping, and
    `ptrace_do_notify` sets `si_code` to the exit code, so the
    stop reports `si_code == SIGTRAP` (5), distinct from
    `TRAP_TRACE` (2) and `TRAP_BRKPT` (1). H2 pins
    `si_code == SIGTRAP` there; today's `si_code != TRAP_TRACE`
    clause is redundant with the `rdi`/`rdx` frame tests (R3
    survives).

Each stage is its own branch off then-current liteinst2 `main`,
signed, with exact-head `fmt`, Clippy, locked debug/release
package tests, and mutants as applicable. Signal-frame stages
(I1-D onward) keep two approving reviews.

### Mechanism for the genuine frame

Delivery substrate is the remote ptrace guest of §4, not the
in-process bridge. The tracer intercepts `rt_sigaction`: for a
custom handler it records the guest's source handler, flags,
restorer, and mask as the guest-visible action, then installs
one common cache-resident signal-entry stub as the kernel
handler (querying an existing action is virtualized back to the
recorded source values). When a signal stops the guest before
delivery, the tracer reads `PTRACE_GETSIGINFO` and the
interrupted registers, reconstructs exact source state from the
PC map through the I1-A recovery core, writes that recovered
state back as the tracee registers, and injects the signal —
so the **kernel** builds the real `rt_sigframe` with visible
ucontext RIP at the recovered source PC and enters the stub.
At the stub trap the tracer records the frame address, leaves
frame and handler arguments intact, and redirects RIP to the
translated entry for the recorded source handler. At handler
return it intercepts the restorer's `rt_sigreturn`: reads the
(possibly handler-modified) frame resume state, ensures a
block starts exactly at the resume source PC, rewrites only
the frame resume RIP to that translated entry, and lets the
kernel execute `rt_sigreturn`. Frame layout, restorer,
siginfo, alternate-stack selection, and restoration stay
kernel-produced and kernel-consumed; synthesizing a frame in
the tracer or invoking the handler as a host callback is
rejected for exactly that reason.

### Stage map

| PR | Exit witness | Still refused / not claimed |
|---|---|---|
| I1-A Recovery core | Existing suites byte/semantics-stable | Any delivery |
| I1-B Remote substrate | Direct fixtures match in-process/O1 | Indirect, async delivery, whole program |
| I1-C Signal registry | Install/query matrix matches native | Custom-handler delivery |
| I1-D One-signal round trip | Handler sees source PC/state; resume exact | Nesting, RT, altstack, mutation edge cases |
| I1-E Arbitrary phases + sync faults | Boundary matrix matches native oracle | Nested/RT/restart completion |
| I1-F Masks, altstack, nesting | Signal-state matrix matches native | RT queue payload/restart gaps named |
| I1-G1 RT, payloads, back-to-back | Ordering/coalescing/payload matrix matches native | Syscall restart, `SA_RESTART` |
| I1-G2 Syscall restart | Restart matrix matches native | Only undisclosed gaps block claim |
| I1-H Gate evidence | Differential + fuzz + mutants causal | Item-1 claim only after review |

### Stage detail

**I1-A — Pure recovery core (landed, no behavior change).**
Generated-PC recovery behind a backend-neutral input record
(raw interrupted registers, counters/spills, fault provenance)
with the in-process `Fault` output unchanged, so the remote
tracer consumes the same authored rules. Exit was existing
package, custody, oracle, and mutant suites unchanged and
green, plus unit tests pinning the extracted boundary.

**I1-B — Remote direct-block substrate (landed).** Remote
fixture child and tracer-side cache allocation, entry, common
trap exit, and direct-block dispatcher reusing `translate()`
blocks/PC map (emission differs only in exit/entry style).
Admitted syscalls pass through at the original instruction
under ptrace or refuse by the existing named envelope; async
signals remain stopped/reported under the accepted P1a
reduction. Exit was direct-corpus and synchronous-fault
equality with in-process and native O1 counts/state.

**I1-C — Guest signal registry mirror (landed).** Stepped
`rt_sigaction`/`rt_sigprocmask`/`rt_sigpending`/`sigaltstack`
for the single remote thread; per-signal source dispositions
for catchable signals (1–64 excluding SIGKILL, SIGSTOP, and
glibc-reserved 32/33) mirrored only from verified kernel
readback — including copy-out `EFAULT` after a real mutation —
never from raw guest input. Exit was the
install/query/default/ignore matrix matching a native guest
(flags/mask/restorer words exact), with custom-handler
delivery still stopping as a recovered async outcome.

**I1-D — One standard signal, genuine round trip.** The frame
flow above for one non-fault standard signal — the tested
and admitted set in the implementation is exactly SIGUSR1 —
with an
`SA_SIGINFO` handler, default mask, no alternate stack, no
nesting, and no handler mutation of the ucontext except a
scratch register explicitly covered by the test. This stage
adds the common-stub install and old-action virtualization
I1-C did not land. The guest witness records signal number,
`si_code`, handler-visible RIP/register values, and a value
only reachable if the handler ran; the main guest loop
progresses only through that handler. Exit: native-child and
translated runs agree on the witness fields and the recorded
final-state words the native child actually returns (result
RAX plus the witness buffer; flags compared on status/DF
bits), on fault/no-fault outcome, and on the exact resume
block; translated counts are pinned separately to the
fixture's enumerated instruction/branch semantics — the
native child is not a count oracle, and no native
count/full-register-image agreement is claimed at this stage
(that completion belongs to I1-H evidence).
Still refused: synchronous custom-fault delivery beyond
existing recovered outcomes, alternate stack, nested and
real-time delivery, handler `longjmp`/`siglongjmp`, any second
thread, and any delivery shape outside the tested set — no
asynchronous-transparency claim beyond what I1-D tests.

**I1-E — Arbitrary phases, synchronous faults, partial
blocks.** Generalize I1-D across copied instructions,
branch/count/poll stubs, call sequences, exit stubs, common
exit, entry loader, and syscall entry/exit. Resume-PC
splitting as implemented: a mid-block resume re-enters the
already-emitted generated insn exactly (copied/call-pristine/
exit-pristine entries only) with the interrupted raw
counters — which already carry the block precredit —
re-based by the handler delta, so the retired prefix is
never re-credited and no new translation is published; a
handler-mutated resume PC must land on a block start or it
fails closed. Synchronous delivery as implemented admits
SIGSEGV/SIGFPE guest faults at copied insns only, preserves
original fault fields (instruction-address `si_addr`
rewritten to source form via `PTRACE_SETSIGINFO`, data
addresses raw). Still refused in this stage's
implementation: async stops in common-exit spilled stages
or at generated PCs with no pcmap entry (entry-loader
bridge class), async stops while stepping original/syscall
insns, blocked-signal poll delivery, sync faults outside
copied insns and other sync signals, nested delivery,
alternate stack, real-time queueing semantics, uncovered
restart cases.

**I1-F — Masks, alternate stack, nesting.** Guest kernel
state authoritative, mirror proven after every relevant
syscall: `rt_sigprocmask` block/unblock/setmask, handler-entry
mask (`sa_mask` plus delivered signal unless `SA_NODEFER`),
`sigaltstack` on both stacks, nested standard signals and
same-signal reentry where Linux permits, dispositions changing
under a live frame. Active frames form an explicit tracer
records stack; `rt_sigreturn` pops exactly one. Still refused:
queued RT payload ordering beyond one pending instance,
multi-threaded guests, uncovered restarted syscalls.
As implemented in commit `736454bc`: async set is
exactly SIGUSR1/SIGUSR2 (sync stays SIGSEGV/SIGFPE, empty
frame stack only); flags are the I1-D base plus optional
`SA_NODEFER`/`SA_ONSTACK` only, `sa_mask` arbitrary; the
frame stack is capped at 8; `SA_ONSTACK` onto an enabled
altstack needs size ≥ 8192 (disabled altstack keeps the
kernel normal-stack fallback); poll deferral picks the
lowest-numbered unblocked eligible pending signal (a pending
signal the kernel shows as blocked does not stop the run at a
poll: it stays pending, as natively, until the guest unblocks
it and the kernel presents it; fixed after I1-G2 as the I1-H
"W4" PR, whose test blocks SIGUSR1, receives it, runs past two
poll exits, probes `rt_sigpending`, and then unblocks it. The
blocked mask is the kernel's `SigBlk` at every poll since
I1-H H2a, which closed W5: before, the poll used the mirror,
which is not refreshed at handler entry, so a signal blocked
only by a running handler's `sa_mask`, or by its own signal
without `SA_NODEFER`, read as unblocked and, if ineligible,
stopped the run early); and the self-send syscalls
`getpid`/`kill` pass through with `kill` gated to the traced
child's own pid (proven through `NSpid` since I1-H H2a). Evidence: mask matrix
with in-handler mask query (NODEFER on/off), altstack frame
placement, distinct-signal nesting and `SA_NODEFER`
same-signal reentry by self-send with LIFO order words, and
disposition change under a live frame, each translated vs
the native child.

**I1-G — Real-time ordering, payloads, syscall restart.**
`SIGRTMIN..SIGRTMAX` kernel ordering (lowest first, FIFO
within a number), standard coalescing vs RT queue retention,
`sigqueue`/`rt_tgsigqueueinfo` payload and sender fields, and
signals during pass-through syscalls with and without
`SA_RESTART`. The kernel queue remains authoritative; guest
signals are not dequeued into tracer custody as the normal
mechanism. Still refused: multi-threaded guests, `execve`
successors (separately scoped), any unadmitted signal feature.
Split into I1-G1 (everything but restart) and I1-G2
(syscall restart).

As implemented for I1-G1 in
[PR 76](https://github.com/rrnewton/liteinst2/pull/76)
(kernel citations are `kernel/signal.c` in the Linux 7.1.3
source at `199c9959d3a9b53f346c221757fc7ac507fbac50`, the
running kernel's version; the native child confirms each
behaviour on the host):

- *Delivery set.* Async delivery admits SIGUSR1/SIGUSR2 and
  the RT range 34..=64 (glibc SIGRTMIN..SIGRTMAX) under the
  unchanged I1-F flag/mask/altstack/8-frame bounds. 32 and 33
  (reserved by glibc/NPTL) stay outside, for delivery and for
  queueing: one predicate serves both. `SA_RESTART` actions
  stay ineligible (admitted by I1-G2, below).
- *Ordering is the kernel's.* The tracer only injects the
  signal the kernel presents at each delivery stop, with the
  kernel's own siginfo (no rebuild, no rewrite for async
  signals), so lowest-first, FIFO within an RT number,
  private-before-shared dequeue (`:629`, `:632`), and
  standard-signal coalescing (`legacy_queue`, `:1061`, which
  keeps the first payload and still returns 0) all come from
  the kernel.
- *Back-to-back frames.* With several unblocked signals
  pending, the kernel builds the next frame before the
  stub runs and reports that delivery stop at the stub entry.
  The tracer validates the frame just built, records it, and
  injects the next signal over that frame's guest-visible
  handler entry (the source handler, never the stub), so the
  second frame's ucontext names the first signal's source
  handler exactly as natively. An ineligible next signal is a
  recovered `AsyncSignal` stop at that source handler entry.
- *Queueing gate.* `rt_sigqueueinfo` and `rt_tgsigqueueinfo`
  pass through, stepped over a tracer-staged copy of the guest
  siginfo, so the kernel copies exactly the bytes classified.
  The gate reads and stages the whole 128-byte record as a
  conservative policy; the kernel copies the 48-byte
  `kernel_siginfo` prefix and checks the rest only for unknown
  layouts (`__copy_siginfo_from_user`, `:3535`). Every
  returned guest state — including a recovered asynchronous
  stop before syscall entry — carries the guest's own pointer
  argument, never the staging address. The I1-D
  `rt_sigaction` stub redirect shares that restore path; it
  previously leaked the scratch address in `rsi` on the same
  stop (fixed here, pre-existing on `main`). A failed scratch
  restore is a named refusal.
  Calls the kernel provably refuses with no side effect step,
  so the guest sees the kernel's own errno, equal to native:
  a forged code (`si_code >= 0` or `SI_TKILL`) whose compared
  target (`pid`, or `tid` for the tg form, as a 32-bit
  `pid_t`) is not the caller gets `-EPERM` before any lookup
  (`:4199`, tg `:4246`, after the tg form's `-EINVAL` for a
  non-positive id at `:4240`); and the tg form with the
  caller's own TID but a foreign TGID gets `-ESRCH` from
  `do_send_specific` (`:4124`, `:4128`) whatever the code.
  `si_signo` is not checked: the kernel overwrites it with the
  requested signal (`:3540`), as natively.
  **Deliberate divergences from native, all failing closed by
  name (`NoHandler`):** (1) a forged code aimed at the caller
  itself (own pid, or own TID and TGID) is accepted by Linux
  but refused here, because delivering it would forge kernel
  provenance (`SI_KERNEL` SIGTRAP reads as an exit trap, a
  positive SIGSEGV code as a synchronous fault); (2) a
  non-forged call aimed at another task (foreign pid, or a
  foreign TID) is refused even where native would fail (a
  nonexistent pid gets `ESRCH`), because nothing proves the
  kernel would not queue it; (3) an unreadable 128-byte
  siginfo is refused, though native could succeed when only
  the tail beyond the 48-byte prefix is unreadable. Otherwise
  only the tested shape steps: `SI_QUEUE`, an admitted
  signal, and every target word (full 64-bit register) equal
  to the child's own pid, proven to be its own-namespace pid
  through `NSpid` (the guest is single-threaded, so its TID
  and TGID equal its pid).
  *Invariant:* staging is sound only while `mprotect` and
  `pkey_*` are not passed through. The kernel reads the
  tracer-written copy, so readability of the guest buffer is
  decided by the tracer's `process_vm_readv` (which applies no
  protection keys), not by the guest's `copy_from_user`;
  recheck when either syscall family is admitted.
- *Follow-ups (not blockers):* (a) **closed in I1-H H2a**: the
  I1-F `kill` self-send gate compared the target with the
  tracer's view of the child pid without the `NSpid` proof the
  queueing gate uses; it now takes the same proof (exactly one
  `NSpid` entry, ours), shown through a test seam that presents
  a nested namespace to the proof only. (b) For native `EFAULT`
  parity on an unreadable siginfo, a later stage may step
  with the guest's original pointer only when the first 48
  bytes are unreadable to the tracer, require `-EFAULT` as
  the result (named stop otherwise), and never step when 48
  bytes are readable but 128 are not.
- *Evidence* (`tests/remote_signal_rt.rs`, translated vs the
  native child): the RT order/retention/coalescing matrix
  with kill-sent and forged-sender entries; back-to-back
  frames for standard and RT pairs with a distinct handler
  per signal (the second frame names the first signal's
  handler, not its own); private-first `rt_tgsigqueueinfo`
  with a 64-bit `sival_ptr`; kernel-refused calls with the
  native errno (`EPERM`, `ESRCH`); a mismatched `si_signo`
  overwritten as natively; the pointer argument registers
  (`rsi`, `rdx`, `r10`) after every redirected syscall
  compared with native; named refusals for forged self-sends,
  foreign `SI_QUEUE` targets (including a tg call with both
  ids naming a real process the test spawns, with nothing
  queued in it), 32/33, an unmodelled flag word (`SA_RESTART`
  at I1-G1, `SA_RESETHAND` since I1-G2 admitted `SA_RESTART`),
  unreadable siginfo, and unadmitted signals; and, through a
  test seam compiled only
  with the test-only `test-seams` cargo feature (enabled for
  the crate's own tests through a self dev-dependency, inert
  unless a test sets it, and restoring scratch before it
  reports its own failure) that signals the traced child
  between staging and the step, the guest pointer argument in
  recovered pre-entry stops for both queue forms and
  `rt_sigaction`. No claim beyond the tested shapes.

As implemented for I1-G2 in
[PR 77](https://github.com/rrnewton/liteinst2/pull/77), from
`main` `4210776c6485989dfb6ead7e61c745912d04e191` (kernel
citations are `arch/x86/kernel/signal.c` in the same Linux
7.1.3 source unless another file is named; the native child
confirms each behaviour on the host):

- *Interruptible set.* The pass-through set adds
  `rt_sigsuspend`, `futex` and `nanosleep`. `futex` steps only
  as `FUTEX_WAIT_PRIVATE` (128) with a NULL timeout, comparing
  the full 64-bit `rsi` and `r10`; any other operation and any
  timeout is refused by name before it runs (`NoHandler`),
  because a timed wait returns `-ERESTART_RESTARTBLOCK`
  (`kernel/futex/waitwake.c:728`) and would restart through
  `restart_syscall`. `nanosleep` is the plain relative sleep;
  `clock_nanosleep` is not passed through. Delivery at a
  restart exit applies to these three calls only, classified
  by the low 32 bits of `orig_rax` as the kernel dispatches
  and as pass-through admission classifies (`0x1_000000ca`
  runs futex and is delivered like it; the full `orig_rax`
  stays the provenance check and a restart's frame RAX). Any
  other pass-through call whose exit carries a restart code
  keeps the named stop `syscall restart pending at exit stop`.
  This is tested with a blocking `write`: the test harness
  hands the child a pipe it has already filled to
  `F_GETPIPE_SZ`.
- *Delivery at the syscall exit.* An exit stop carrying
  `-ERESTARTSYS`, `-ERESTARTNOHAND` or `-ERESTART_RESTARTBLOCK`
  is not completion. The tracer resumes once with
  `PTRACE_SYSCALL` and requires the interrupting signal's
  delivery stop, with the restart code, `orig_rax` and RIP
  (just after the syscall) unchanged. It injects an eligible
  action with RAX still holding the code, so the kernel's own
  `handle_signal` (`:264`-`:283`) applies the rule:
  `NOHAND` and `RESTARTBLOCK` become `-EINTR`, and `SYS`
  restarts (`ip -= 2`, `ax = orig_ax`) only under
  `SA_RESTART`. The tracer predicts the outcome and the frame
  must match it: ucontext RIP at the syscall (restart) or just
  after it (`-EINTR`), and ucontext RAX the syscall number or
  `-EINTR`. A mismatch is a named substrate refusal. With a
  handler, `handle_signal` sets RIP and RAX together, so a
  wrong prediction already fails the frame-RIP check; the RAX
  check is defence in depth (it turns a tracer that corrupted
  RAX before injection into a named stop instead of a wrong
  syscall result).
  `rt_sigsuspend`'s saved mask lands in the frame's
  `uc_sigmask` and sigreturn restores it. That is the kernel's
  doing, compared with native. On this path the tracer writes
  only its own data page and, at sigreturn, the frame's saved
  RIP (rewritten to the generated re-entry). `nanosleep`'s
  remainder, like every syscall result, is written by the
  kernel through the guest's own pointer.
- *Restart resume and counts.* A restarted frame resumes at
  the syscall and the call steps again. When the syscall is
  mid-block, the resume is the I1-E exact mid-block re-entry:
  the syscall's exit stub at its pristine stage, which retires
  nothing, and the dispatcher re-bases the counters at
  sigreturn (`tot = raw + (tot - resolved)`, with `raw` the
  count before the syscall). When the syscall starts its own
  block, the resume goes through the normal block index with
  no re-base. The syscall instruction is credited once, at
  completion: an `-EINTR` return credits it at delivery, a
  restarted attempt is not credited, and the completed
  restart is. A wrong restart credit is invisible on the
  mid-block path (the re-base cancels it), so the block-start
  path is tested too.
- *Back-to-back.* With several unblocked signals pending at
  the exit (for example, `rt_sigsuspend` unblocking two), the
  I1-G1 loop builds back-to-back frames. The first frame
  records the restart outcome; the next names the first
  signal's source handler, with RAX 0 as the kernel leaves it
  at handler entry. This widens the I1-G2 scope as first
  proposed (several signals at a restart exit refused); the
  design review acknowledged the widening explicitly. Tested only
  with an `-EINTR` bottom frame: a restarting bottom frame
  under another frame is untested, because nothing makes two
  signals reliably pending at a futex exit natively
  (`rt_sigsuspend` has a mask but never restarts).
- *Flags.* `SA_RESTART` joins the admitted flag words. Outside
  a syscall restart it changes nothing, which is tested for an
  RT handler. `SA_RESETHAND` and `SA_NOCLD*` stay ineligible.
- **Not modelled, failing closed by name:** an interrupting
  signal with no eligible action (no handler, default-ignored,
  or otherwise ineligible) at a restart exit stops as
  `syscall restart: signal not eligible for delivery`, with
  nothing injected. Natively the kernel would restart the
  call: a rewind for `SYS`, `NOHAND` and `NOINTR`, and
  `restart_syscall` for `RESTARTBLOCK`
  (`arch_do_signal_or_restart`, `:344`-`:359`). A
  default-ignored signal reaches this stop only because the
  child is traced (`sig_ignored`, `kernel/signal.c:121`);
  natively it would be discarded at send.
  `-ERESTARTNOINTR` (it always restarts, and no admitted
  syscall produces it) and any unknown code are named stops.
  So is a restart exit followed by a syscall stop instead of a
  delivery stop.
- *Evidence* (`tests/remote_signal_rt.rs`). Interruption is
  external, and the signal lands only while the call sleeps.
  A test thread polls until the child (translated or native)
  is asleep in the expected syscall: `/proc/<pid>/syscall`
  names it, the scheduler state is `S`, and `wchan` names a
  kernel sleep site. The syscall number alone is not enough,
  since it is already visible at a ptrace syscall-entry stop
  (state `t`); a test holds a child there and checks that it
  is not taken for asleep. The thread then waits 50 ms,
  checks that the child is still asleep there, and signals
  it through a pidfd opened while the child was known alive
  and unreaped, so a reused pid cannot be hit. A 5 s bound on
  sleeping and a 10 s bound after the send each fail the test
  by name.
  Translated vs native:
  - `rt_sigsuspend` interrupted returns `-EINTR`, with and
    without `SA_RESTART`, and the saved mask is restored;
  - two pending signals released by `rt_sigsuspend` build
    back-to-back frames;
  - `FUTEX_WAIT_PRIVATE` restarts under `SA_RESTART` (the
    handler changes the word, so the restarted wait returns
    `-EAGAIN`) and returns `-EINTR` without it;
  - `nanosleep` returns `-EINTR` even under `SA_RESTART`
    (`RESTARTBLOCK` is not `RESTARTSYS`). Each child's
    kernel-written remainder is bracketed by that child's
    measured times: at most the request plus timer slack and
    clock resolution minus the time from first seeing the
    child asleep to sending (at least 50 ms), and at least the
    request minus the whole run. A copied request fails;
  - the futex wait issued as `0x1_000000ca` restarts like
    native, with the full value as the frame's RAX;
  - every case compares the frame's ucontext RIP, RAX and
    saved mask;
  - an interrupted blocking `write` (outside the delivery set)
    keeps the named stop translated, while native shows the
    handler and `-EINTR`.

  A record-only test seam (`test-seams` feature) logs every
  call to `write_mem`, the tracer's only guest-memory write
  path. Every differential test asserts that the tracer wrote
  nothing into the guest's data buffer. The `nanosleep` test
  also asserts that the remainder pointer reaching the kernel
  is the guest's own, so the remainder is the kernel's value,
  never rewritten or synthesized.

  Named refusals: the no-handler restart (SIGWINCH) for
  `nanosleep` and for `futex`, the `futex` shapes outside the
  bound, and `clock_nanosleep`. Counts are pinned to the
  fixture formula, with each interrupted syscall credited
  once. No claim beyond the tested shapes.

**I1-H — Gate evidence and envelope rewrite.** Freeze the
signal corpus, run the assigned differential/fuzz slices, and
replace per-stage statements in `README.md`, `src/lib.rs`, and
dispatcher documentation with one positive claim bounded
exactly by the admitted matrix. Only after this stage's
review may any result be called whole-program under §1.
