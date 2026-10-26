# Exec backing cleanup: qualified validation

The fixed six-command protocol and both default-parallel repetition recipes passed at source `87028fcf5e7dd7c8959151a721a46485a212aa85`. The three receipts bind the same 1,421 source files, manifest SHA-256 `5d496ab6329ca5cc6bc12ddd961b8cdc26729355820eb2fef96fe9c5a78aa375`, and unchanged configuration:

- [Six-command qualification](results/20261026T154403.210003Z-87028fcf5e7d.json), SHA-256 `7ba33c7e36af03f38148c2248d3b5357c466f3664f0941b91ae3157b6242b8d7`.
- [Four default unit repetitions](results/20261026T155314.180540Z-default-parallel-87028fcf5e7d.json), SHA-256 `4cc9134269a1674104f62d3ea1c2ca2e150fb7a62209f5d5f5938d9d36598249`.
- [Four default fork repetitions](results/20261026T155359.711173Z-default-parallel-fork-87028fcf5e7d.json), SHA-256 `80ee3433a3e40c63aa0e3765b2ea5444be76cf1714f4796a20f42b10b63c0bc8`.

The new ordinary-main Cargo helper runs the actual admitted-exec owner and executable-backing probe code. Before probing, it joins its raw-reference worker, authenticates a singleton process and blocks catchable signals. It preallocates its observations. Immediately after the real unmap, a full-page `mincore` requires `ENOMEM` while the exact executable descriptor remains live; immediately after close, `F_GETFD` requires `EBADF`. No allocating assertion or parsing operation intervenes between each release and its observation. The [helper recipe](backing-cleanup.md) describes the closed protocol and independent aggregate gates.

Both workspace and serial runs authenticated all three controls and four trajectories:

| Trajectory | Actual probe count | Observed result | Cleanup |
| --- | ---: | --- | --- |
| Complete admitted exec | 6 | Exit 0; exact owned resources released | Owner and physical cleanup |
| Backing read error | 1 | Actual `EFAULT` (14); exit 0 after refusal | Owner and physical cleanup |
| Injected unwind | 1 | Explicit panic after map acquisition; exit 0 after handling | Owner and physical cleanup |
| Invalid unmap leaf | 1 | Actual `EINVAL` (22), followed by `SIGABRT` | Parent-authenticated physical teardown; `owner_cleanup=false` |

The abort leaf contains no application tracees. Its result establishes the failed-release branch's fail-stop behavior; it does not establish successful unmapping. The parent requires the original process pin, exact private receipt, signal and authoritative reap before publishing the observation. The six observations emitted per helper run comprise begin, four trajectories and complete. These are typed control records, not additional libtest methods.

| Fixed command | Seconds | Result |
| --- | ---: | --- |
| `python3 -m unittest discover -s evaluation/admission -p 'test_*.py'` | 8.400 | 254 passed |
| `cargo fmt --check` | 2.931 | Passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 14.721 | Passed |
| `cargo test --workspace` | 344.554 | 1,727 passed; 4 unchanged ignores; 89 libtest harnesses; helper complete |
| `cargo check --workspace --all-features --all-targets` | 10.478 | Passed |
| `cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture` | 89.498 | 647 passed; 27 libtest harnesses; helper complete |

The old 355 launcher unit cases, 56 named native fixtures, 50 static cases, 15 dynamic fixtures and 388 matrix rows remain required and passed. These are separately counted collections, not additive instruction totals. Fourteen additive Python calibrations increased the recorder inventory from 240 to 254. The new helper target is separately required in both commands; its transcript cannot hide an old libtest failure or qualify a failed command.

Four complete default unit runs each passed all 355 cases in 3.726/3.696/3.688/3.699 seconds. Four complete default fork runs each passed all seven cases in 0.277/0.288/0.273/0.260 seconds. These recipes retain the original targets and do not run the cleanup helper. Neither sets a libtest thread override. The reset deadline regression has six saved exact “ok” outcomes across workspace, serial and unit repetitions; the fork interruption regression has six across workspace, serial and fork repetitions. These are repetitions of existing cases, not measured concurrency or new cases.

All 14 commands reported cleanup complete and zero adopted descendants. Recorded hardware was AMD EPYC 9D85, Linux 7.1.3, Rust/Cargo 1.97.1, non-root with zero effective capabilities. The main protocol observed 316 CPUs in its affinity; each extra recipe certifies unchanged inherited eight-CPU affinity. Commands, bounds, hardware details, toolchain and source bindings are retained in the JSON. Raw logs remain private with their hashes recorded.

Reproduce from the clean tested checkout. Run each extra under an externally established eight-CPU affinity:

```sh
python3 evaluation/admission/run.py --expect-revision 87028fcf5e7dd7c8959151a721a46485a212aa85
python3 evaluation/admission/default_parallel.py --expect-revision 87028fcf5e7dd7c8959151a721a46485a212aa85 --cohort unit
python3 evaluation/admission/default_parallel.py --expect-revision 87028fcf5e7dd7c8959151a721a46485a212aa85 --cohort fork
```

Five unsuccessful attempts remain unchanged, each committed before its correction:

| Receipt | Retained result | SHA-256 |
| --- | --- | --- |
| [20261026T152713.311109Z-31c76ad19298.json](results/20261026T152713.311109Z-31c76ad19298.json) | Strict Clippy rejected repeated enum prefixes | `84ad118c7e84afcee71e3682b7ad33c004e7db63662ca1c7a4ffc44f697b09b1` |
| [20261026T152911.674465Z-0f0897b218af.json](results/20261026T152911.674465Z-0f0897b218af.json) | Strict Clippy failed on an ambiguous counter import | `56dec5182bb207f7e3fbdc286b7ec64f30545b5331334029e8b2cc7a145ea58a` |
| [20261026T153103.853088Z-5ce6c82290e9.json](results/20261026T153103.853088Z-5ce6c82290e9.json) | Strict Clippy rejected an item after a test module | `28334310b2400e736a0b3ef0a98ee0b7bc7156b8fe5cd9b2f5d37ba75db58367` |
| [20261026T153223.723009Z-44e0aa867190.json](results/20261026T153223.723009Z-44e0aa867190.json) | Workspace linking failed on duplicate assembly globals | `ec16841f8e61c9a3979ff86d68c27a2902cd5fe7d1c885dc5a5e1af5c7f77d52` |
| [20261026T153705.711129Z-b51028de91b9.json](results/20261026T153705.711129Z-b51028de91b9.json) | Renaming the self dev dependency did not fix the same linking failure | `83938053a4964f827aca165e2be53b13042d901ae45e418b41d80e5d866b2b46` |

The final link correction gives the unit-test build distinct assembler symbol names through Rust `sym` operands. All 26 production global names remain unchanged; substituting those names reconstructs both original assembly files byte-for-byte. Instructions, fault branches and reset controls remain. No duplicate-symbol allowance, weak symbol, removed assertion or widened deadline was added. The unsuccessful dependency-alias change was reverted.

This finite B3 increment supports claim 4's systematic validation and strengthens the executable-identity custody underlying claims 1 and 2. It does not establish those whole claims, extend the previous exec CPU coverage beyond CPUID, complete ordinary-application support/B3/B4, or provide claim 3 preemption-clock evidence. Validation durations are not hook latency or application throughput. Earlier admitted-exec results and their unsuccessful receipts remain separate historical evidence.
