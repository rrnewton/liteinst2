# liteinst2

`liteinst2` is a Rust implementation of online x86-64 instrumentation using
the instruction-punning techniques from PLDI 2016 and PLDI 2017.

The repository is at the foundation stage. Its modules separate the main
correctness boundaries:

- `cache_line`: overflow-safe patch-span classification.
- `scanner`: fail-closed x86-64 decoding and cache-line crossing discovery.
- `patcher`: direct-jump planning and atomic WordPatch++ publication.
- `rapid`: exact instruction-pun planning and atomic opcode toggling.
- `probe`: idempotent probe lifecycle state.
- `trampoline`: near W^X allocation, relocation, hook dispatch, and return.

The implementation will preserve five invariants established before the port:

1. A cross-cache-line patch must never fall back to a tearing store.
2. Probe installation publishes state only after planning and allocation pass.
3. Trampoline sizing and emission use the same checked plan.
4. Signal handlers use only async-signal-safe, pre-published data.
5. Executable mappings follow W^X rather than remaining writable and executable.

## Development

```console
cargo test
cargo clippy --all-targets --all-features -- -D warnings
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

These checks do not establish arbitrary-binary or probe-anywhere support. The
live fixtures engineer five-byte `mov eax, imm32` sites and free exact
trampoline destinations. In particular, rapid installation currently validates
only the opcode byte rather than the complete five-byte pun window; this is
tracked in [issue #2](https://github.com/rrnewton/liteinst2/issues/2).

The live stress matrix and overhead benchmark are opt-in:

```console
cargo test --release --test stress live_probe_stress_matrix -- --ignored --exact --nocapture
cargo test --release --test stress probe_overhead_benchmark -- --ignored --exact --nocapture
```

`LITEINST_STRESS_RAPID_FUNCTIONS`, `LITEINST_STRESS_RAPID_ITERATIONS`,
`LITEINST_STRESS_GENERAL_FUNCTIONS`, `LITEINST_STRESS_GENERAL_CYCLES`, and
`LITEINST_STRESS_SIGNAL_ROUNDS` scale the matrix without changing source.
