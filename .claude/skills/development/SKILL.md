---
name: development
description: "Build and test a LiteInst change at the correct crate and evidence level. Use when selecting local checks, reproducing a failure, or validating a package or documentation change."
---

# Develop and test LiteInst

The root package is `liteinst`; `liteinst2` is the repository name. Read
[Cargo.toml](../../../Cargo.toml) for workspace membership and features. The
manifest requires Rust 1.94; [CI](../../../.github/workflows/ci.yml) selects
1.94.1. Core native instrumentation targets Linux x86-64; architecture fact
crates and the AArch64 runtime patcher have their own scopes.

Use [patching-contracts](../patching-contracts/SKILL.md) for executable writes,
trampolines, publication and lifetime changes. Use
[instrumentation-frontends](../instrumentation-frontends/SKILL.md) to choose
between scanners, offline artifacts, page gates and the JIT.

## Select the test layer

From the repository root, these focused commands exercise decoder facts or
mock contract checks without publishing native patches:

```sh
cargo test --locked -p liteinst-x86 --lib
cargo test --locked -p liteinst-aarch64 --lib
cargo test --locked -p liteinst --lib contracts::tests
cargo fmt --all -- --check
```

The last test filter is deliberate: the complete root library test suite also
contains native publication tests. Inspect the executed test names and count;
a filter matching nothing establishes nothing.

For a native core change on Linux x86-64, build the main-thread oracle drivers
and point the tests at those exact binaries. This runs the debug core group:

```sh
liteinst_test_target="$PWD/target"
cargo build --locked -p liteinst --bins --all-features --target-dir "$liteinst_test_target"
env \
  LITEINST_BOUNDARY_SIGNAL_MAIN_THREAD_DRIVER="$liteinst_test_target/debug/boundary-signal-oracle-driver" \
  LITEINST_CHAIN_MAIN_THREAD_DRIVER="$liteinst_test_target/debug/eviction-chain-oracle-driver" \
  LITEINST_CHAIN_EXTENSION_MAIN_THREAD_DRIVER="$liteinst_test_target/debug/eviction-chain-extension-driver" \
  LITEINST_SYNC_CORE_MAIN_THREAD_DRIVER="$liteinst_test_target/debug/sync-core-capability-driver" \
  LITEINST_T2_MAIN_THREAD_DRIVER="$liteinst_test_target/debug/successor-eviction-oracle-driver" \
  cargo test --locked -p liteinst --all-targets --all-features --target-dir "$liteinst_test_target"
```

For release evidence, add `--release` to both Cargo commands and use the
`release/` driver paths. Missing drivers or required host facilities are
failures to qualify that run. Do not replace them with a smaller passing test.
Current CI separates the core, launcher, JIT and smaller crates; reproduce the
relevant group and its prerequisites from the workflow. Older whole-workspace
recipes are not an exact description of that coverage.

## Test what the patch promises

Compare the same workload uninstrumented and instrumented. Check observable
results, exit status, required register/flags/extended-state preservation and
actual hook activity. A matching result with no hook invocation is insufficient.
Exercise refused sites and failures before and after a write, including the
resulting custody state. Keep deliberate fault/signal tests in bounded child
processes as the existing native oracles do.

For concurrency changes, the release stress entrypoint is:

```sh
cargo test --locked --release -p liteinst --test stress live_probe_stress_matrix -- --ignored --exact --nocapture
```

This is separate from the ordinary test selection; CI invokes it explicitly.
The synchronized publication API additionally requires the native procedure in
[tools/word-sync-oracle](../../../tools/word-sync-oracle/README.md).
That adapter currently still selects `liteinst2@0.1.0` and `cargo -p liteinst2`,
while this workspace names the root package `liteinst`. Repair and revalidate
that adapter binding before claiming its native qualification; the linked
procedure is not currently an executable qualification recipe for this revision.
An ordinary Cargo pass does not discharge that API's qualification contract.

For packaging changes, use `cargo package --locked` and the workflow's extracted
package `preload_consumer` build: a workspace build can hide missing package
files. Keep generated binaries, captures and machine-specific tool inventories
outside source changes. Report the command, revision, profile, host capability,
executed/refused cases and remaining limits; timing alone proves no correctness.
