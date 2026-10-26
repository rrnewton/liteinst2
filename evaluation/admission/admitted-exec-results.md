# Finite admitted exec: qualified validation

The fixed six-command protocol passed at source `47865dd078a1e24c4f025dd42a872757c3e3647e`. The two separate default-libtest recipes also passed. These receipts bind the same 1,412 source files and unchanged configuration:

- [Six-command qualification](results/20261026T145620.370694Z-47865dd078a1.json), SHA-256 `188dff8d898b3e9b0afa8a19ede5fc87c73e208fd0aaddff08152edf807ac7bf`.
- [Four default unit repetitions](results/20261026T150333.481240Z-default-parallel-47865dd078a1.json), SHA-256 `49c28b51bf48a0e6f1536ed3507ecd1d1665b3695b22d737e7ab8abd595150f8`.
- [Four default fork repetitions](results/20261026T150356.979470Z-default-parallel-fork-47865dd078a1.json), SHA-256 `8ae7a5f0afbb43af7f35bf3baf1605a5b1000e880ff18043be1aeb615baf42c1`.

This increment adds one bounded original native `execve` through the same owner: exact filename/argv/envp capture and ENTRY recheck, actual ENTRY → EXEC → EXIT, fresh task/mm, first-user state, NX quarantine and runtime source capture. The resolver supplies complete heads, not source bytes or publication authority. The owner retains old domain/census history and one six-dimensional lifetime account. The replacement-ready state keeps source pages NX; subsequent admission separately authorizes execution. Original deadlines, fixed capture bounds, the default 64 MiB cap and nonrefundable reservations remain. See [admitted-exec.md](admitted-exec.md) for the mechanism and unsafe profile contract.

Independent raw references and private same-tracer controls compare full architectural state at matching boundaries, fixed memory, original inputs, source bytes, mapping and identity facts, retained history and cleanup. Kernel-random initial stack data receives independent per-lane ABI validation. The new exec CPU trajectories cover CPUID; the existing seven selected classes remain separate baseline evidence.

Executable identity now respects two exact kernel ABI projections: stat metadata and VMA metadata derived from the same owned executable descriptor. The public oracle independently compares six stat observations and full raw/admitted EXEC/EXIT mappings in their respective namespaces. No alternate device value or relaxed identity comparator is accepted.

| Fixed command | Seconds | Result |
| --- | ---: | --- |
| `python3 -m unittest discover -s evaluation/admission -p 'test_*.py'` | 8.464 | 240 passed |
| `cargo fmt --check` | 3.052 | Passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0.412 | Passed |
| `cargo test --workspace` | 322.139 | 1,727 passed; 4 unchanged ignores; 89 harnesses |
| `cargo check --workspace --all-features --all-targets` | 0.273 | Passed |
| `cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture` | 91.411 | 647 passed; 27 harnesses |

The launcher has 355 unit tests: 77 additions comprise 68 pure controls and nine private native controls. Five public exec cases are additional integration tests. All 56 named native cases passed in both workspace and serial runs, preserving the old 42 and adding 14. The 50 static cases, 15 dynamic fixtures and 388 matrix rows remain unchanged, separately counted collections; they are not additive instruction totals.

Four complete default unit runs each passed 355 cases in 3.708/3.693/3.700/3.706 seconds. Four complete default fork runs each passed all seven cases in 0.261/0.262/0.264/0.266 seconds. Neither recipe overrides libtest threads. The reset deadline regression has six exact saved “ok” outcomes across workspace, serial and four unit runs; the corrected fork interruption regression likewise has six across workspace, serial and four fork runs. These are repeated executions of existing cases, not new distinct cases or measured concurrency.

All 14 commands reported physical cleanup complete and zero adopted descendants. The host was AMD EPYC 9D85, Linux 7.1.3, Rust/Cargo 1.97.1, non-root with zero effective capabilities. The main protocol observed affinity to 316 CPUs; each extra receipt certifies unchanged inherited eight-CPU affinity. Allocator implementation and cgroup placement are not receipt-certified claims. Log hashes, bounds, configuration observations and exact source bindings remain in the JSON.

Reproduce from the clean tested checkout; run each extra under an externally established eight-CPU affinity:

```sh
python3 evaluation/admission/run.py --expect-revision 47865dd078a1e24c4f025dd42a872757c3e3647e
python3 evaluation/admission/default_parallel.py --expect-revision 47865dd078a1e24c4f025dd42a872757c3e3647e --cohort unit
python3 evaluation/admission/default_parallel.py --expect-revision 47865dd078a1e24c4f025dd42a872757c3e3647e --cohort fork
```

Eleven unsuccessful receipts remain byte-identical to their original additions. One refused before commands; ten failed. No failed attempt was relabelled or removed:

| Receipt | Retained result | SHA-256 |
| --- | --- | --- |
| [20261026T135027.643284Z-d1c24fa801e9.json](results/20261026T135027.643284Z-d1c24fa801e9.json) | Preflight refused; zero commands | `828db060b514ca5b0f71aa1751f2dcdc4c8a39c4ce0220c3806156322dd04cde` |
| [20261026T135050.103389Z-7c8db24aa123.json](results/20261026T135050.103389Z-7c8db24aa123.json) | clippy: exit 101 | `6d19361c4bfd850451ecaa9d1842fd9fb25e7e6bb4a9c8200387b32ab31766ea` |
| [20261026T135200.700772Z-8875e919e758.json](results/20261026T135200.700772Z-8875e919e758.json) | clippy: exit 101 | `43e7c48b67069887b3de631a386e6535be181a88232170ead4377f9390a8ca1a` |
| [20261026T135430.635194Z-1ea66498f9bc.json](results/20261026T135430.635194Z-1ea66498f9bc.json) | workspace_tests: exit 101 | `da0a81ad9c359584c0ee12c399cc7d027cbb553022055f5d2ec93e6086aebd58` |
| [20261026T135912.476458Z-e93aacccec5e.json](results/20261026T135912.476458Z-e93aacccec5e.json) | workspace_tests: exit 101 | `33a1aef2f0179eaf17bf601399bda61880071a7d52dd5b73996c698e699b7298` |
| [20261026T140818.789380Z-4789b6bef1e3.json](results/20261026T140818.789380Z-4789b6bef1e3.json) | clippy: exit 101 | `5f4412705f334e6a7b74fc90d0e42eb4d41e33eabfcc6355c202a2711c9913c0` |
| [20261026T141813.617701Z-691edd07d89d.json](results/20261026T141813.617701Z-691edd07d89d.json) | workspace_tests: exit 101 | `f487e3df1554412ba3a6d74a9511f521ecdfd6fc4fe397f4456f18f86c897b65` |
| [20261026T142140.063422Z-79d6522307aa.json](results/20261026T142140.063422Z-79d6522307aa.json) | workspace_tests: exit 101 | `e94de5211c2b768a4c38162a0fb618abdf353012d19b7ccd6457ad729ffcd1dc` |
| [20261026T142529.988427Z-c416d9ae7c63.json](results/20261026T142529.988427Z-c416d9ae7c63.json) | workspace_tests: timeout, exit −9 | `206e8c7e18aa9537259342e0b8061c17b299887866f41b545eb37574892f78f6` |
| [20261026T143305.105829Z-e53cd9369b63.json](results/20261026T143305.105829Z-e53cd9369b63.json) | serial_launch: exit 101 | `98c215bdfb2fecf118e8d6739bd0c288a17d599e533a00bd859bb6ecd28c8cc7` |
| [20261026T145403.619342Z-d3b002dbc1a8.json](results/20261026T145403.619342Z-d3b002dbc1a8.json) | recorder_tests: exit 1 | `6148eddd36c658b74e0efd91960be5664ef92196b873d192bb71da667251ac5e` |

This is finite single-exec evidence. It does not establish ordinary arbitrary-application support, general head discovery, PIE/interpreter validation, unrestricted thread/signal/mapping composition, full B3, B4 hybrid release, or claim 3 preemption-clock coverage. The proposed local backing-cleanup helper remains unpromoted and contributes no credit. Validation duration is not hook latency or application throughput.
