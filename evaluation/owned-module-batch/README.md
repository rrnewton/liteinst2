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


## Fixed-work batch cost mode

After the integration control succeeds, the same adapter can select one separate
ignored release experiment with `--mode batch-cost` and a fresh output directory.
All other CLI arguments, build/geometry checks, CPU ownership, command bounds and
cleanup rules above stay the same. The default `--mode control` still selects the
original integration test; the new mode does not replace that test or any gate.

The experiment runs exactly five pairs in order B/O, O/B, B/O, O/B, B/O. Each arm
runs 64 warm-up and 256 measured batches, with four ordinary target calls per
batch. B uses independent sealed, unpatched module/caller instances; O uses the
safe owned batch API and its outer-return checkpoint. Both use the same complete
C inputs and compiled caller body. Four fixed input pairs cover empty, quoted
CSV/embedded NUL, full 64-byte inputs, and 64-byte CSV/NUL-at-32 inputs.

Each wall interval covers the 256-batch loop and preallocated outer result
retention. O includes the existing callback, admission, checkpoint and transfer
allocation costs. It excludes setup, warm-up, epoch control, full-file/map
verification, result/report/history inspection and formatting; these stay
outside both timers. There are no per-call clocks, changed capacities, adaptive
repetitions or noisy-result retries. Wall time includes observer and scheduling
costs; it is not exclusive CPU time or a causal attribution of individual costs.

`batch-cost.jsonl` retains ten raw timing rows and, only after all semantic,
record/report/history, reclamation and close assertions pass, a final validation
summary. A failed prefix stays failed even if timing rows exist. The successful
process and command-owner closures are also required. Each owned epoch accounts
for 1,280 calls (640/function), within unchanged K1000; final owned totals are
6,400 balanced sampled calls and ten history actions. Per-arm measured totals
are 1,280 batches / 5,120 target calls; warm-up adds 320 batches / 1,280 calls.
The small data set supports descriptive wall times and paired ratios only, not a
precision, general-application, speedup-causality or A5 qualification claim. The
separate strict 2 ms / 2,048-row / 520 ms consumer and all its failures remain
unchanged. This addition is source-only until its explicitly reserved run.
