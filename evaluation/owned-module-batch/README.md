# Owned module batch reproduction proposal

This unexecuted adapter builds the fixed CSV/strnlen subject DSO and the real C
four-call caller, then runs exactly one fresh release libtest invocation:
`owned_module_native_four_call_batches_epochs_and_close`. The native control
exercises three safe batch calls, two sampled epochs, the removed state, real
outer-return checkpoints, and close. It retains the existing assertions; it is
not the separate hardware single-step oracle, a performance comparison, or A5
qualification.

The eventual tracked location is `evaluation/owned-module-batch/reproduce.py`.
Until root applies it, use this private script path. From the repository root,
inside a root-owned **one-CPU HARD reservation**, the complete interface is:

```sh
python3 -I -B evaluation/owned-module-batch/reproduce.py \
  --root "$PWD" --revision "$(git rev-parse HEAD)" \
  --toolchain "$(rustc --print sysroot)" \
  --user-home "$HOME" --cargo-home "${CARGO_HOME:-$HOME/.cargo}" \
  --output "$PWD/ignored/owned-module-batch-run-v1"
```

Root owns the reservation and an overall bounded outer process; the script does
not acquire/release CPUs or introduce a dispatcher. The output directory and
matching `target/evaluation/<output-name>` capture directory must both be fresh.
The adapter records actual inherited single-CPU affinity, load, CPU flags, boot,
cgroup, kernel, source revision, source hashes, tool hashes/versions and selected
GCC subtool hashes. No external admission document or metadata approval is
required. The reservation evidence remains with the outer owner.

Each fixed command uses `evaluation/admission/processes.py` around the existing
`tools/unwind-oracle/bounded_command.py`. C builds have 60 CPU seconds, 90 wall
seconds and 128 MiB per file; the release libtest build has 120/180 seconds and
128 MiB. Metadata and the single native invocation have 20/30 seconds and 1 MiB.
The native test also retains its original absolute 15-second deadline. Each
outer helper has wall+25 seconds and a 1 MiB private log. Root should use the
existing 1200-second outer owner; this is a fixed sequence with no retry.

The script reuses the unchanged module recipe's symbol, complete-body CFG and
123-byte/40-head/four-CALL/four-store/outer-RET caller checks. It captures full
readelf headers/segments/dynamic symbols/relocations and actual disassemblies,
refuses init/fini/dependencies/IFUNC, and creates full-byte equal, distinct-inode
candidate copies. Cargo's JSON artifact identifies the actual optimized libtest
with debug/overflow checks retained; no filename glob selects a binary.

Native safety is the fixed source/test's explicit integration envelope: known C
semantics cover every accepted input, exact caller and selected body geometry,
private sealed source/retained loader and installed owners, actual thread stack
and callback state checks, blocked asynchronous signals, no foreign entry or
unsafe mapping writer, and genuine ordinary returns. The existing loader checks
actual SHSTK status and runtime code detects xstate/clock support. The adapter
requires RDTSCP advertised on its CPU and refuses advertised IBT. Those flags
are trusted running-kernel evidence, not independent physical CPUID/MSR proof;
absence of an ELF CET property is not used as evidence. Arbitrary hostile
in-process unsafe code, nonlocal exits and foreign mapping changes are outside
this finite integration profile. Blocking or refusal never fabricates return.

All command requests, outer closures, inner receipts and raw logs remain private
and numeric values are retained in JSON. Owner closure is authenticated before
child output is interpreted. A failure stops dispatch, stays failed and leaves
later stages unexecuted; reuse of the same output namespace refuses. Success
requires exactly the named test to pass with no skipped test or stderr. No
compilation, test or native invocation has been run by the author.
