# Grouped successor-chain validation

From a clean checkout of the reported revision, with Rust 1.97.1, GCC, the locked offline Cargo dependencies, and Linux x86-64 with ptrace permitted for owned children:

```sh
python3 -B evaluation/chain-grouping/reproduce.py \
  --raw "$PWD/ignored/chain-grouping-reproduction" \
  --toolchain "$RUST_TOOLCHAIN" --user-home "$HOME" --cargo-home "$CARGO_HOME"
```

The script invokes the unchanged required workspace dispatcher once: formatting, Clippy with warnings denied, workspace tests, and the all-target/all-feature check. The test command includes the new contract and native grouped-chain tests and all existing tests. Limits remain 180/180/360/180 seconds, four build jobs and four test threads, one target directory, and no incremental compilation. The native cohort retains the existing isolation and trace limits. A required placement or assertion failure fails the run; no case becomes a skip or an accepted refusal.

The authored depth-two B2 chain must retain four virtual pages while sharing one sealed 4 KiB backing page. Every declared original entry runs with both existing state seeds in original, installed, and retired phases. The existing full-state oracle compares registers, flags, extended state, application memory and stack. This cohort also checks exact source/image bytes, shared RX mapping ownership, rejected writable permission changes, and rollback after a late alias collision. The cohort's JSON contains observed counters after all assertions. Machine-state comparisons are executed assertions; individual state snapshots are not serialized by this fixture.

Raw logs, mapping captures, command/environment records, source digests, hardware and tool observations remain under `ignored/`. Publish the small cohort JSON and command/result CSV with path coordinates normalized, exact tested revision and hardware label. Preserve failures and distinguish operational elapsed times from performance measurements. This supports one bounded chain-grouping slice of claim 4; broader chain families, full A2 and claims 1–3 remain open.
