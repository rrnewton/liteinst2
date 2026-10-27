# Reachable allocation under contention

The allocator now tries the remaining page-aligned starts in each captured free
gap after an `EEXIST` collision. Previously it tried one address per gap, so a
concurrent winner could make it report `NoReachableMapping` while most of that
gap remained free. The search is lazy, finite (at most 2^32 / page-size starts),
and retains `MAP_FIXED_NOREPLACE`. Other mmap errors stop immediately with their
errno. The complete mapping, including its last byte, must fit signed rel32
reach. Existing ownership tests and their default parallel execution are unchanged.

The source fix is `48f22252ca010c5ed7da130f494bee4eaf9c028d`. The merged checks
ran at `16ae829d8dfad08b74dad326f1129181601473d7`, which includes main
`4f4e39bf9f1ab7efd4858ef0c3796829f71e61aa`; all three allocator source files are
byte-identical between those revisions. These results support claim 4's bounded
regression coverage.

On the **AMD EPYC Zen 5 dev host**, with 316 CPUs available to libtest and Rust
1.97.1, all 62 campaign commands passed. The seven merged-tree checks passed across an
initial attempt and an unchanged retry; the first serial-launch failure remains
recorded below.
No affinity reduction or `RUST_TEST_THREADS` setting was used. Serial-launch and
the 20 focused interrupt-diagnosis commands explicitly request one test thread;
the other test commands retain default parallelism.

| Check | Result |
| --- | --- |
| Forced contention, geometry and error controls | 4 passed |
| Default-parallel core library | 25 runs, each 241 passed / 0 failed / 1 ignored |
| Default-parallel exec admission B3 | 25 runs, each 7 passed (five original native cases and two parser controls) |
| Launch library | 742 passed |
| Workspace, at each tested revision | 2,517 passed / 0 failed / 4 ignored |
| Formatting, strict Clippy, workspace check, historical allocation checks | Passed |
| Merged serial launch | Initial failure; unchanged retry passed |

The native regression opens an owned, guarded gap after preparing its aliases
and worker. A competing thread claims the first candidate. The real allocator
then observes `EEXIST` and claims the next page, preserving the competitor and
guard bytes. Filling the gap requires a real exhaustion refusal. The test also
checks exact-address refusal and cleanup of a real alias returned at an unexpected
address. The new regression alone uses a bounded child to own this deliberate
gap; the existing reported tests retain their original execution and assertions.

Five baseline core runs at `b5091935451c053f8e877a8ebaeccae435ba9912` all passed
(237 passed / 1 ignored each), so this experiment did not reproduce or attribute
every historical flake. The forced schedule demonstrates the source defect and
its correction. A precommit strict-Clippy failure remains recorded: an equivalent
modulo check replaced a helper newer than the declared minimum Rust version.

The first merged serial-launch attempt exposed a separate fixture race in
`dynamic_control::active_interrupt_preserves_seeded_state_and_rejects_stale_or_foreign_tokens`:
only kernel `orig_rax` changed, from 39 at the first stop to -1 at the second;
seven later tests failed on the poisoned lock. The command supervisor reaped two
remaining descendants after that failure; cleanup completed. The immediate interrupt after
getpid exit can observe a different kernel phase at the same RIP as the user
self-jump. This mechanism is source-consistent, not a traced kernel proof.
All 20 focused repetitions and the full unchanged serial-launch retry passed.
The two later allocation checks were unrun in the failed attempt; both passed
in the retry.
No source or comparator was changed. The first attempt remains FAILED and this
separate fixture race remains unresolved.

The exec map-count fix is already in ancestor `b26c900be977d176e791fdc38cc19dcd3fc32147`.
Its earlier root-cause evidence is [separate](../exec-identity-b26c900/README.md).
This campaign again passed 128 exact-VMA queries plus one baseline with 553 total
maps, 516 deliberately owned maps and 179 unrelated protection-change cycles.
The originally reported unexpected abort was not reproduced.

[commands.csv](commands.csv) contains individual command results and operational
durations, including the five baseline runs. [receipt.json](receipt.json) records
revisions, hardware, source hashes, command recipes and limitations. Raw logs and
captures remain ignored. Workspace totals use 99 outer groups and exclude five
nested summaries; the custom cleanup harness is separate. No throughput or
profiler-accuracy claim is made here.

Reproduce the complete campaign at the source revision:

```sh
python3 -B evaluation/admission/check_exec_identity.py \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/NEW_CAMPAIGN" --include-reachable-allocation
```

At the merged revision, reproduce its seven checks with the same command and
`--checks-only` in place of `--include-reachable-allocation`. Compiler jobs stay
at four; incremental compilation is disabled. The script keeps bounded logs
private and requires command completion and complete child cleanup.

The baseline recipe at its recorded revision is five invocations of
`cargo test -p liteinst2 --lib` with the recorded environment. The separate
interrupt diagnosis repeats the exact filtered command in commands.csv twenty
times at the merged revision, then reruns the serial-launch command unchanged.
