# liteinst2

`liteinst2` is a Rust implementation of online x86-64 instrumentation using
the instruction-punning techniques from PLDI 2016 and PLDI 2017.

The repository is at the foundation stage. Its modules separate the main
correctness boundaries:

- `cache_line`: overflow-safe patch-span classification.
- `cfg`: function-range CFG construction and same-block site backtracking.
- `scanner`: fail-closed x86-64 decoding and cache-line crossing discovery.
- `patcher`: direct-jump planning and atomic WordPatch++ publication.
- `rapid`: exact instruction-pun planning and atomic opcode toggling.
- `probe`: idempotent probe lifecycle state.
- `trampoline`: near W^X allocation, relocation, hook dispatch, and return.

The implementation will preserve six invariants established before the port:

1. A cross-cache-line patch must never fall back to a tearing store.
2. Probe installation publishes state only after planning and allocation pass.
3. Trampoline sizing and emission use the same checked plan.
4. Signal handlers use only async-signal-safe, pre-published data.
5. Executable mappings follow W^X rather than remaining writable and executable.
6. CFG-selected patches remain inside one caller-declared function and basic
   block; selection fails closed rather than searching predecessor blocks.

## Development

```console
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

The live stress matrix and overhead benchmark are opt-in:

```console
cargo test --release --test stress live_probe_stress_matrix -- --ignored --exact --nocapture
cargo test --release --test stress probe_overhead_benchmark -- --ignored --exact --nocapture
```

`LITEINST_STRESS_RAPID_FUNCTIONS`, `LITEINST_STRESS_RAPID_ITERATIONS`,
`LITEINST_STRESS_GENERAL_FUNCTIONS`, `LITEINST_STRESS_GENERAL_CYCLES`, and
`LITEINST_STRESS_SIGNAL_ROUNDS` scale the matrix without changing source.
