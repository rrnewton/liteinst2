# Owned module batch reproduction

The adapter builds the fixed CSV/strnlen subject DSO and real C four-call caller, then dispatches exactly one fresh release invocation of `owned_module_native_four_call_batches_epochs_and_close`. [Recorded results](result-v1/README.md) preserve the caller-format failure, the later SIGABRT and unsuccessful GDB diagnostic, and the passing fixed integration control at `5b90ed28c1145bb721edb2da58cf052e21feb260`.

From a clean checkout of the chosen exact revision, inside an externally owned **one-CPU HARD reservation** and a 1200-second outer owner with an 8 MiB log bound:

```sh
python3.9 -I -B evaluation/owned-module-batch/reproduce.py \
  --root "$PWD" --revision "$(git rev-parse HEAD)" \
  --toolchain "$(rustc --print sysroot)" \
  --user-home "$HOME" --cargo-home "${CARGO_HOME:-$HOME/.cargo}" \
  --output "$PWD/ignored/owned-module-batch-run-v1"
```

Use the recorded tool versions and exact revision for a comparable reproduction. Both the output directory and `target/evaluation/<output-name>` must be fresh. The caller owns reservation/release and overall containment; the adapter records inherited singleton affinity, CPU flags, load, boot/cgroup, source and tool identities. It neither allocates CPUs nor retries.

Each stage uses the existing `evaluation/admission/processes.py` and `tools/unwind-oracle/bounded_command.py`. C builds allow 60 CPU/90 wall seconds and 128 MiB per file; release libtest build allows 120/180 seconds and 128 MiB. Metadata and native invocation allow 20/30 seconds and 1 MiB. Stage owners add 25 wall seconds with a 1 MiB private log. The native test retains its absolute 15-second deadline. Release opt-level 3, debug 0, debug assertions/overflow checks, offline Cargo, one build job and disabled incremental compilation are fixed by the adapter.

The existing module recipe checks complete selected-body CFGs and the actual 123-byte/40-head/four-CALL/four-store/outer-RET caller, full ELF headers/dynamic symbols/relocations, and forbidden dependencies/constructors/IFUNC. Fresh candidate copies must match the complete trusted bytes and have distinct inodes. Cargo JSON selects the exact release libtest artifact.

The passed control exercises three safe application batches, two sampled epochs, removed outcomes, twelve ordinary returns/stores and final close. It retains the fixed test's unsafe setup obligations: known semantics for every admitted 0..=64-byte input, exact geometry and retained sealed/installed owners, actual thread stack/callback state, no foreign entry/writer/unload/reentry or nonlocal exits, and genuine ordinary returns. Asynchronous signals are blocked while reserved synchronous SIGILL remains unblocked; an inherited blocked SIGILL mask refuses. Existing SHSTK and xstate/clock guards still execute. The adapter requires advertised RDTSCP and refuses advertised IBT; these are trusted kernel observations, not physical CPUID/MSR proof.

Authenticate each outer closure before reading child evidence. Failure stops the sequence and remains failed; success requires exactly the named test to pass, with no ignored test or stderr. `native_attempts` counts dispatch intent, not a PID/reap observation. Requests, receipts and raw logs remain private. This fixed integration result does not establish performance, accuracy, full A5 qualification, the separate hardware single-step oracle or safety against arbitrary hostile in-process unsafe code.
