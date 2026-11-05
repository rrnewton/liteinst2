# liteinst-jit P1b design note (draft, awaiting Astra verdict)

[who-am-i: musejit, host withheld. Owner: musejit (muse, devbig030) since 2026-11-05T12:03:34Z]

Status: **DESIGN ONLY.** P1b implementation is gated on hl-ff-a's
adversarial review of the P1a code + §6 invalidation design, plus
coord7's go. Nothing here is built, selectable, or claimed. Layering
rule carried over: liteinst owns translation primitives; a complete
loader/tool belongs in Reverie. P1b target is architecture cell V10
remains **unbuilt until M4 is met**, and merging to liteinst2 main
remains barred under the owner's DBT hold regardless of this note.

Goal (M4 shape, final wording is the owner's): the standalone driver
counts every retired conditional branch (then every instruction) of
a real dynamically-linked program (`/bin/ls` or coord7 equivalent),
with the refusal list explicit and costs reported per the owner
rule (DR-null ratio, run count, machine; dense counting labelled
vs a DR counting client). Everything P1a refuses that P1b still
cannot do keeps refusing by name.

## 1. Indirect control flow

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
  indirect transfer — acceptable for M4 correctness, measured
  honestly, removed only by P1b.2.
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
  other code once its mapping is admitted (§2). `jmp *GOT` through
  a not-yet-bound slot therefore works or refuses by the same rule
  as every other indirect edge — there is no PLT-aware shortcut.

Counting reminder: indirect and unconditional transfers never
increment the RCB counter; only the conditional branch that retires
does (unchanged from P1a). The lookup stub's internal conditional
branches are machinery and are not guest branches.

## 2. Code discovery: dlopen, ld.so, fresh mappings

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
  from the §6 design: return/signal PCs into an unmapped library
  remain recorded; resuming to one faults/refuses by name, never
  silently lands in a reused mapping (generation, not address,
  decides).

## 3. The `/bin/ls` driver (standalone, no Reverie binding)

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
4. Signals: asynchronous signals are delivered only at dispatcher
   boundaries in P1b.1 (state is at a source PC there by
   construction); a signal arriving mid-cache in P1b.2 requires the
   §6 frame-rewrite (PC-map translation of the interrupted PC plus
   spill-phase resolution) before mid-cache delivery is enabled.
   Synchronous faults keep P1a's rewind-to-source-PC rule.
5. `execve` from the guest refuses `ExecSuccessor` in P1b
   (successor retranslation is named future work), as do `ptrace`
   by the guest, personality changes that alter decode, and
   32-bit compat execution (`Arch`).

Staging inside the driver: static hello → dynamic hello (ld.so
translated) → `/bin/true` → `/bin/ls -d .` → `/bin/ls` on a real
directory. Each stage's counts validate per §4 before the next is
claimed.

## 4. Oracles for P1b (freeze before implementation)

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

## 5. Explicit non-goals and refusals carried into P1b

Self-modifying/JIT code (M5), `execve` successors, attach (A4),
external-debugger coexistence (the P1b driver *is* the tracer),
CET shadow-stack call rewriting, aarch64, any Reverie core change,
and any V10-selectable or product claim before M4 exit is declared
by coord7/owner. Cost guardrail from li2adm: steady state does no
per-page or per-admission work — discovery is per first-transfer
into a block, and every reported number carries DR-null ratio +
exactly-10 median + IQR + machine or is labelled UNMEASURED.

## 6. Open questions for the Astra review

1. Is dispatcher-side indirect resolution (P1b.1) an acceptable M4
   shape if its measured cost is honest, with the hash stub as a
   pure optimization? (This note assumes yes.)
2. Per-region generations vs one global generation with
   flush-on-any-mapping-event: is the simpler global flush
   acceptable for M4 if `dlopen`-heavy reruns retranslate?
3. Mid-cache async signal delivery: gate P1b exit on it, or is
   dispatcher-boundary delivery (with the bound stated) enough
   for the `/bin/ls` M4 claim?
4. Remote-arena injection at exec-stop vs a preload-shaped child
   bootstrap: any objection to ptrace syscall injection as the
   *driver-only* mechanism (explicitly not the future V10 loader)?

Estimated against L10 §6.4's P1b stage (15–30 agent-days, estimate):
this note's P1b.1 + driver staging is the bulk of it; P1b.2's hash
stub is the tail risk if flag-neutral probing resists the simple
template.
