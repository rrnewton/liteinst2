# liteinst-jit P1b design note (draft, awaiting Astra verdict)

[who-am-i: musejit, host withheld. Owner: musejit (muse, devbig030) since 2026-11-05T12:03:34Z]

Status: **DESIGN ONLY.** P1b implementation is gated on hl-ff-a's
adversarial review of the P1a code + §6 invalidation design, plus
coord7's go. Nothing here is built, selectable, or claimed. Layering
rule carried over: liteinst owns translation primitives; a complete
loader/tool belongs in Reverie. P1b target is architecture cell V10
remains **unbuilt until M4 is met**, and merging to liteinst2 main
remains barred under the owner's DBT hold regardless of this note.

**Scope decision recorded 2026-11-05 via coord7:** for **P1a**, the
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
a real dynamically-linked program (`/bin/ls` or coord7 equivalent),
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
by coord7/owner. Cost guardrail from li2adm: steady state does no
per-page or per-admission work — discovery is per first-transfer
into a block, and every reported number carries DR-null ratio +
exactly-10 median + IQR + machine or is labelled UNMEASURED.

## 7. Open questions for the Astra review

1. Is dispatcher-side indirect resolution (P1b.1) an acceptable M4
   shape if its measured cost is honest, with the hash stub as a
   pure optimization? (This note assumes yes.)
2. Per-region generations vs one global generation with
   flush-on-any-mapping-event: is the simpler global flush
   acceptable for M4 if `dlopen`-heavy reruns retranslate?
3. **Resolved 2026-11-05 via coord7:** mid-cache transparent
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
that stage estimate must be repriced after the Astra verdict and
P1b authorization rather than treated as already covering §1.
Within the remaining scope, P1b.1 + driver staging is the bulk of
the work; P1b.2's hash stub is the tail risk if flag-neutral
probing resists the simple template.
