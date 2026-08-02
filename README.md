# liteinst2

`liteinst2` is a Rust implementation of online x86-64 instrumentation using
the instruction-punning techniques from PLDI 2016 and PLDI 2017.

The crate is a standalone patching engine. It has no Hermit or Reverie
dependency and contains no syscall, process-lifecycle, or tool policy. Its
modules separate the main correctness boundaries:

- `cache_line`: overflow-safe patch-span classification.
- `scanner`: fail-closed x86-64 decoding and cache-line crossing discovery.
- `patcher`: multi-instruction jump planning and all-front-byte WordPatch++ publication.
- `planner`: rapid, relocated, and client-trap fallback selection.
- `rapid`: exact instruction-pun planning and atomic opcode toggling.
- `probe`: idempotent probe lifecycle state.
- `trampoline`: near dual-mapped allocation, relocation, hook dispatch, CET-safe
  return, and async-signal-safe reverse-PC lookup.

Clients with a ptrace slow path follow the exhaustive
[patch-site decision tree](PATCH_SITE_DECISION_TREE.md): choose quiescent or
concurrent publication, then select a direct pun, proved relocation, safe
straddler bailout, or explicit ptrace fallback.

The implementation preserves six invariants established before the port:

1. A cross-cache-line patch must use guarded publication unless the caller
   proves that no concurrent instruction fetch or data access is possible.
2. Probe installation publishes state only after planning and allocation pass.
3. Trampoline sizing and emission use the same checked plan.
4. Signal handlers use only async-signal-safe, pre-published data.
5. Trampolines never use one RWX mapping; arena mode instead retains separate
   RW and RX aliases and therefore does not provide strict W^X.
6. Trampoline continuation uses a direct jump when reachable, with a CET NOTRACK
   indirect fallback, so an application continuation need not begin with ENDBR64.

## Examples

`replace_first` installs a hook over a two-byte instruction, mutates its saved
register context, relocates the rest of the five-byte patch window, and toggles
the hook off again:

```console
cargo run --example replace_first
```

The `preload_consumer` cdylib example shows how a consumer can own LD_PRELOAD
delivery while depending on the policy-free core:

```console
cargo build --example preload_consumer
```

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
- `live_probe_stress_matrix` exercises 128 rapid probes, one million opcode
  stores, 16 guarded jump probes, 10,000 activation cycles, and concurrent
  signal delivery at its default scale.
- `probe_overhead_benchmark` is used only as a functional active-hook loop: CI
  requires one callback per call but does not enforce its host-dependent timing.

These checks do not establish arbitrary-binary or probe-anywhere support.
Generic hooks can now displace several complete instructions, replace a short
first instruction such as `syscall`, mutate the saved integer context, and use
a dual-mapped arena prepared before signal-driven registration. Exact one-byte rapid
puns still require the original bytes to encode a free trampoline destination.
Clients must provide a trustworthy code region, writable access to the live
patch word, mapping-lifecycle ownership, proof that no control-flow entry can
target the interior of a relocated window, and a trap fallback when the
planner returns `PunPlan::TrapRequired`.

Installed trampolines publish immutable generated-to-application PC ranges.
Signal handlers and unwind front ends can call
`trampoline::translate_program_counter` without allocation or locks before
reporting or unwinding a relocated fault. This translates the logical PC; it
does not install a signal handler or synthesize DWARF call-frame metadata.
The ordinary `LiveJumpPatch` and `InstalledHook` entrypoints use concurrent-safe
publication. WordPatch++ guards every byte before a cache-line split as
specified by PLDI 2017, but callers must still supply a
machine/topology-qualified `StalenessBudget`. A consumer without that
calibration should route split sites to its ptrace/trap fallback instead of
selecting `GuardedSplit`.

The unsafe `bind_quiescent`, `install_replacing_first_quiescent`, and matching
activation entrypoints retain the same planning and relocation but skip trap
registration and guarded split publication. They are valid only when the caller
can exclude every other thread, signal handler, instruction fetch, and code
writer for the complete publication call. They must not be used as a faster
default for threaded applications.

The live stress matrix and overhead benchmark are opt-in:

```console
cargo test --release --test stress live_probe_stress_matrix -- --ignored --exact --nocapture
cargo test --release --test stress probe_overhead_benchmark -- --ignored --exact --nocapture
```

`LITEINST_STRESS_RAPID_FUNCTIONS`, `LITEINST_STRESS_RAPID_ITERATIONS`,
`LITEINST_STRESS_GENERAL_FUNCTIONS`, `LITEINST_STRESS_GENERAL_CYCLES`, and
`LITEINST_STRESS_SIGNAL_ROUNDS` scale the matrix without changing source.
