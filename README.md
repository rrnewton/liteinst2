# liteinst2

`liteinst2` is a Rust implementation of online x86-64 instrumentation using
the instruction-punning techniques from PLDI 2016 and PLDI 2017.

The repository is at the foundation stage. Its modules separate the main
correctness boundaries:

- `cache_line`: overflow-safe patch-span classification.
- `patcher`: atomic publication strategy and, later, WordPatch state machines.
- `probe`: idempotent probe lifecycle state.
- `trampoline`: checked planning and, later, relocation-aware code generation.

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
