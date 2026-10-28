# liteinst2

`liteinst2` is a Rust library for **hooking machine code in a running program**.
It lets you intercept a chosen point in already-loaded x86-64 code — redirecting
execution into your own function and then back — by rewriting instructions in
place while the program keeps running, with no recompilation and no need to stop
every thread. This is a form of *dynamic binary instrumentation*: you would reach
for it to trace, profile, intercept, or modify a program's behaviour at runtime.
A common use is hooking a `syscall` instruction to observe or redirect the call.

It is a standalone library: you link it into your own program (or into an
`LD_PRELOAD` shim) and drive it yourself. It has no runtime framework and makes
no policy decisions about processes, signals, or syscalls — those belong to the
client that embeds it.

## Instruction punning

Overwriting live code is dangerous: another thread can fetch an instruction
mid-edit and execute half of the old bytes and half of the new. `liteinst2`
avoids this with *instruction punning* — a technique for x86-64 where a patch is
published as a single atomic store that reuses ("puns") existing bytes so that
every possible concurrent instruction fetch sees either the complete old
instruction or the complete new one, never a torn mix. Split sites that cannot be
covered by one atomic store use the guarded cross-modification protocol
(WordPatch++) instead.

The techniques come from two papers and from the original C++ library that
introduced them:

- Original implementation (C++): [iu-parfunc/liteinst](https://github.com/iu-parfunc/liteinst).
- *Living on the Edge: Rapid-Toggling Probes with Cross-Modification on x86*
  (PLDI 2016,
  [doi:10.1145/2908080.2908084](https://doi.org/10.1145/2908080.2908084)) — the
  guarded split-site word-patching protocol.
- *Instruction Punning: Lightweight Instrumentation for x86-64* (PLDI 2017,
  [doi:10.1145/3062341.3062344](https://doi.org/10.1145/3062341.3062344)) —
  instruction punning and the generalized WordPatch++ protocol.

`liteinst2` is a Rust reimplementation of that work.

## A first hook

`replace_first` installs a hook over a two-byte instruction, mutates the saved
register context, relocates the rest of the five-byte patch window, and toggles
the hook off again:

```console
cargo run --example replace_first
```

The `preload_consumer` cdylib example shows how a consumer can own `LD_PRELOAD`
delivery while depending on the policy-free core:

```console
cargo build --example preload_consumer
```

For a standalone stop/resume client with an owned buffer, see
[`owned_loop_clock`](tools/software-preemption/README.md#owned-loop-client).
Run `cargo run --example owned_loop_clock` without arguments.

## How the crate is organised

Each module owns one correctness boundary:

- `contracts`: immutable plans, legal entries, mapping generations, scoped leases,
  publication receipts, and separate interception/profiling lifetimes.
- `quiescent`: generalized short-instruction puns preferred for install-once,
  bounded same-block upstream selection, logical-PC hooks, qualified
  displaced-entry routing and generation retirement under a held lease. See the
  [standalone interface](INTERFACES.md) and [quiescent contract](A1-QUIESCENT.md)
  for its supported envelope and explicit refusals.
- `composition` and `bundle`: ordered virtual source images, persistent byte
  locks and quiescent transactions spanning several generated images. The
  [composition contract](A2-COMPOSITION.md) describes staging, retirement,
  aggregate allocation limits and the remaining tactic-engine work.
- `emission`: explicit target descriptions and symbolic same-module hooks for
  offline plans. The [offline tool](A3-OFFLINE.md) produces ELF candidates,
  metadata and sparse overlays through the same tactic engine; it records
  outstanding runtime requirements separately from structural success.
- `cache_line`: overflow-safe patch-span classification.
- `scanner`: fail-closed x86-64 decoding and cache-line crossing discovery.
- `patcher`: multi-instruction jump planning and all-front-byte WordPatch++ publication.
  The separate experimental `patcher::synchronized` API uses sync-core barriers
  for word publication and batches; its [contract and required native gate](A4-SYNCHRONIZED.md)
  define the supported geometry, caller obligations and terminal failure behavior.
- `planner`: rapid, relocated, and client-trap fallback selection.
- `rapid`: exact instruction-pun planning and atomic opcode toggling.
- `probe`: idempotent probe lifecycle state.
- `trampoline`: near dual-mapped allocation, relocation, hook dispatch, CET-safe
  return, exact extended-state preservation, controller-owned stop points, and
  async-signal-safe reverse-PC lookup.

Clients that keep a ptrace slow path follow the exhaustive
[patch-site decision tree](PATCH_SITE_DECISION_TREE.md): choose quiescent or
concurrent publication, then select a direct pun, a proved relocation, a safe
straddler bailout, or an explicit ptrace fallback.

## Safety invariants

The implementation maintains six invariants:

1. A cross-cache-line patch must use guarded publication unless the caller
   proves that no concurrent instruction fetch or data access is possible.
2. Probe installation publishes state only after planning and allocation pass.
3. Trampoline sizing and emission use the same checked plan.
4. Signal handlers use only async-signal-safe, pre-published data.
5. Trampolines never use one RWX mapping; arena mode instead retains separate
   RW and RX aliases and therefore does not provide strict W^X.
6. Trampoline continuation uses a direct jump when reachable, with a CET NOTRACK
   indirect fallback, so an application continuation need not begin with ENDBR64.

## What clients must provide

These checks do not establish arbitrary-binary or probe-anywhere support.
Generic hooks can displace several complete instructions, replace a short first
instruction such as `syscall`, mutate the saved integer context, and use a
dual-mapped arena prepared before signal-driven registration. Exact one-byte
rapid puns still require the original bytes to encode a free trampoline
destination. Clients must provide a trustworthy code region, writable access to
the live patch word, mapping-lifecycle ownership, proof that no control-flow
entry can target the interior of a relocated window, and a trap fallback when the
planner returns `PunPlan::TrapRequired`.

Installed trampolines publish immutable generated-to-application PC ranges.
Signal handlers and unwind front ends can call
`trampoline::translate_program_counter` without allocation or locks before
reporting or unwinding a relocated fault. This translates the logical PC; it
does not install a signal handler or synthesize DWARF call-frame metadata.
Existing `InstalledHook` entrypoints continue to publish these ranges
automatically. The explicitly controller-owned ptrace-stop entrypoint leaves
process-global publication opt-in; its owner can call
`ExecutableTrampoline::publish_program_counter_mappings` after binding when it
needs the global lookup and accepts process-lifetime metadata.

Callbacks can inspect `HookContext::saved_extended_state` together with the
authenticated `TrampolineLayout::saved_extended_state` to locate the exact
FXSAVE64 or standard XSAVE64 image. The layout includes every admitted
non-legacy component extent and fails closed if the enabled x86 state cannot be
represented exactly. The controller-owned trampoline form brackets the callback
with entry and post-restore `INT3` stops and requires the external controller to
perform both documented RSP pivots; using that entrypoint without such a
controller is unsupported.

Concurrent WordPatch++ installation owns the process SIGTRAP router. Standalone
installation admits only prior `SIG_DFL` or `SIG_IGN` dispositions and refuses a
custom SIGTRAP handler without replacing it. A filtered host can instead call
`prepare_live_patching_with_signal_runtime` with exact installation and default
redelivery callbacks, subject to the same prior-disposition rule. The host
installer retains a blocked SIGTRAP mask until LiteInst2 publishes the prior
action and asks the host to restore the exact mask. This avoids pretending that
a direct Rust call can reproduce kernel signal-mask,
alternate-stack, reset, and restart semantics. The preparation entrypoint is
unsafe because the host callbacks must initialize their outputs and uphold
those signal and no-unwind contracts.

Trampoline arenas retain their original RW alias but seal the memfd against new
writable mappings, positional writes, resizing, and policy changes. Arena
creation therefore fails closed when the backing store cannot provide the
required seal set. Near-allocation discovery also bounds `/proc/self/maps` at
2 MiB and refuses malformed, oversized, or unreservable input.
The ordinary `LiveJumpPatch` and `InstalledHook` entrypoints use concurrent-safe
publication. WordPatch++ guards every byte before a cache-line split as
specified by PLDI 2017, but callers must still supply a
machine/topology-qualified `StalenessBudget`. A consumer without that
calibration should route split sites to its ptrace/trap fallback instead of
selecting `GuardedSplit`.

Concurrent single-cache-line jump patches may share the unchanged tail of their
8-byte stores when their complete displaced instruction intervals are disjoint.
For example, two 5-byte sites five bytes apart no longer conflict solely because
their stores overlap. Registration authenticates shared snapshot bytes; each
publication compares all eight live bytes with an exact image containing the
neighbor's committed jump bytes, then preserves those bytes in its store.
Overlapping writers and registration fail with `Contended` while a publication
is in progress. Split-word, Rapid, pending, and actual displaced-instruction
conflicts remain refused. Concurrent-bound objects also maintain this state
when used through the unsafe quiescent publication methods.

The unsafe `bind_quiescent`, `install_replacing_first_quiescent`, and matching
activation entrypoints retain the same planning and relocation but skip trap
registration and guarded split publication. They are valid only when the caller
can exclude every other thread, signal handler, instruction fetch, and code
writer for the complete publication call. They must not be used as a faster
default for threaded applications.

## Development

```console
cargo test --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo package --locked
```

GitHub Actions runs these blocking checks on Linux x86-64:

- `cargo fmt --all -- --check` and Clippy with warnings denied check source
  formatting and every library/test target.
- Debug and release `cargo test --all-targets --all-features` cover decoding,
  cache-line planning, jump publication, trap routing, relocation, context
  preservation, and concurrent toggling using synthetic dual-mapped functions.
- `relocated_fault_pc_translation` runs in the normal suite but delegates its
  intentional SIGSEGV to a bounded child process so it cannot mutate the test
  harness's signal state.

The following host-scale checks are opt-in rather than part of the blocking
workspace runs:

- `live_probe_stress_matrix` exercises 128 rapid probes, one million opcode
  stores, 16 guarded jump probes, 10,000 activation cycles, and concurrent
  signal delivery at its default scale.
- `probe_overhead_benchmark` is used only as a functional active-hook loop. When
  run, it requires one callback per call but does not enforce host-dependent
  timing.
- `benchmark_single_byte_toggle_latency` is the separate host-timing benchmark
  for the one-byte rapid-patch operation.

```console
cargo test --release --test stress live_probe_stress_matrix -- --ignored --exact --nocapture
cargo test --release --test stress probe_overhead_benchmark -- --ignored --exact --nocapture
cargo test --release --lib rapid::tests::live::benchmark_single_byte_toggle_latency -- --ignored --exact --nocapture
```

`LITEINST_STRESS_RAPID_FUNCTIONS`, `LITEINST_STRESS_RAPID_ITERATIONS`,
`LITEINST_STRESS_GENERAL_FUNCTIONS`, `LITEINST_STRESS_GENERAL_CYCLES`, and
`LITEINST_STRESS_SIGNAL_ROUNDS` scale the matrix without changing source.

## Admission development

The workspace also contains [liteinst-admission](crates/liteinst-admission/README.md),
a standalone all-start instruction scanner, versioned entry facts and a mock
page/dependency ledger. It exports facts through `liteinst2::contracts`. The
model never changes executable memory and is not a live admission gate.

[liteinst-inprocess](crates/liteinst-inprocess/README.md) provides a singleton
in-process NX page gate with no ptrace supervisor. It prepares genuine core
CPUID, RDTSC and returning read/write/getpid/gettid replacements before execution,
then handles first-touch admission on a guarded signal stack. The caller owns
the immutable region and certifies complete entries and instruction extents.
Its release probe separates publication, first touch and steady-state cost.

[The first-entry launcher](tools/page-entry/README.md) uses a freestanding ELF
interpreter bridge to run the original dynamic linker and application under an
in-process NX gate. Its explicit sealed dependency namespace supports real
mapping, relocation and TLS initialization. This backend uses kernel traps for
CPUID, timestamps and syscalls, with `source_patches=0`; the owned-region library
above supplies actual source patches. An opt-in raw-fork profile rearms the
child's gate before resuming its original signal frame and forwards bounded
wait4 calls with their actual results. Each process remains single-threaded;
unsupported signal, process and mapping operations refuse. Its documented
identity and loader-search restrictions apply.

[liteinst-launch](crates/liteinst-launch/README.md) captures an ELF process at
its exec stop before the executable/interpreter's first instruction. Its
restricted controller gates initial executable mappings and admits scanned
pages under a held task stop. A native CPUID trap reference and an A1 remote
generalized-pun adapter are separate paths. The concurrent gate registers a
fixed group of real workers, holds every task before publication, and admits
competing first faults once. Both envelopes require caller-certified immutable
code and complete instruction heads. Broader instruction coverage and general
thread, signal and mapping lifecycle support remain open.
