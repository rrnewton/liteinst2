# Actual-PC runtime: finite native qualification

The six-command protocol and both default-parallel repetition recipes passed at source `acf7c3e421d05819d9ebb522529d3b34cae7f916`. The three receipts bind the same 1,478 source files, manifest SHA-256 `bcf3a34d86ac638c42155a0e5e53e31931ae6c3f03f2d6d4e62883db2c8899c6`, and unchanged configuration:

- [Six-command qualification](results/20261026T184000.457629Z-acf7c3e421d0.json), SHA-256 `77ab47e007896002949e3cb14b895c96f26665618b45a4f25d5c5f2ff93ca992`.
- [Four default unit repetitions](results/20261026T184800.086791Z-default-parallel-acf7c3e421d0.json), SHA-256 `3f6e894fb73701c3fe26f58d4cd753c440bbc05be217ab9ad90226517301c06e`.
- [Four default fork repetitions](results/20261026T184835.524905Z-default-parallel-fork-acf7c3e421d0.json), SHA-256 `ae191a1a49ec64fa542832195802bbc233864347ccf95c7a041b107cc87c3a07`.

The [runtime profile](actual-pc-runtime.md) describes the production contracts. `launch_runtime` captures the actual executable/interpreter and follows the held program counter without caller-supplied bytes or a complete head list. Original mappings remain NX between operations. Qualified ordinary instructions execute through an owned native single step with six private calls, seven actual waits, complete source/state checks, exact fetch-page RX/NX transitions and a consumed census origin. Scripted selected CPU results use a separate neutral private trap and keep original source NX. Unsupported memory, stack, native-selected and syscall operations refuse before original execution.

The increment adds 136 Rust methods: 120 pure controls and 16 native methods (six startup, five ordinary, five selected/refusal). The native controls cover real initial boundary state and cleanup, one-short/expired/unwind paths, literal register operations, taken/untaken branches, same-PC origin consumption, an independent raw NOP single-step comparison, scripted CPUID/RDTSC/RDTSCP/RDRAND/RDSEED/RDPID, selected-to-ordinary lineage and actual enabled-debug-register refusal. Several methods contain multiple trajectories; these are not additional method counts or independent samples. Native ordinary fixtures in this revision use one fetch page. Two-page geometry has pure controls; native cross-page fixtures are separate future evidence.

All 16 original native bodies now execute in exact-filter child processes. The outer libtest suite remains parallel. Each outer success requires an exact one-test child result, an independently owned parent/child-bound receipt written after the complete body, and physical child reaping. Original assertions, operation deadlines and production map parsing remain unchanged. Three additive pure controls check malformed results, receipts and roles. The separate process watchdog bounds fixture execution; it does not renew an inner deadline. This removes unrelated test activity from the tracer map table while retaining actual public client/provider and owner threads. It does not establish atomic production map reads or single-threaded runtime execution.

| Fixed command | Seconds | Result |
| --- | ---: | --- |
| `python3 -m unittest discover -s evaluation/admission -p 'test_*.py'` | 8.621 | 265 passed |
| `cargo fmt --check` | 2.971 | Passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 17.387 | Passed |
| `cargo test --workspace` | 336.759 | 1,863 passed; 4 unchanged ignores; 89 libtest harnesses |
| `cargo check --workspace --all-features --all-targets` | 11.925 | Passed |
| `cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture` | 94.865 | 783 passed; 27 libtest harnesses |

The serial recorder authenticated all 72 named native fixtures, including the 16 new runtime methods. The original 56 rows, 50 static cases, 15 dynamic fixtures and 388 matrix rows remain required and passed. The existing executable-backing helper separately passed all three controls/four trajectories in both workspace and serial commands. These collections have separate denominators and must not be added into an instruction total. Eleven additive Python controls increased the recorder inventory from 254 to 265.

Four default unit runs each passed all 491 cases in 4.176/4.191/4.198/4.244 seconds. Four default fork runs each passed all seven cases in 0.272/0.265/0.266/0.266 seconds. Both recipes retain the original targets, certify unchanged eight-CPU affinity and set no libtest thread override. Child isolation changes the execution boundary of the 16 runtime bodies, not the outer test inventory or original deadline/fork regressions. Four successful repetitions are finite regression evidence, not a proof that every possible schedule succeeds.

All 14 commands reported cleanup complete and zero adopted descendants. Hardware was AMD EPYC 9D85 (family 26, model 17, stepping 0, microcode `0xb101066`), Linux 7.1.3, Rust/Cargo 1.97.1, non-root with zero effective capabilities. The main protocol observed 316 CPUs in its affinity and fixes four build/test workers; each extra recipe used eight-CPU affinity and Cargo's default test parallelism. Exact commands, limits, hardware, toolchain and source bindings are retained in JSON. Raw logs remain private with their hashes recorded.

Reproduce from the clean tested checkout. Establish an eight-CPU affinity externally before each extra recipe:

```sh
python3 evaluation/admission/run.py --expect-revision acf7c3e421d05819d9ebb522529d3b34cae7f916
python3 evaluation/admission/default_parallel.py --expect-revision acf7c3e421d05819d9ebb522529d3b34cae7f916 --cohort unit
python3 evaluation/admission/default_parallel.py --expect-revision acf7c3e421d05819d9ebb522529d3b34cae7f916 --cohort fork
```

Five earlier receipts remain unchanged, committed before subsequent corrections:

| Receipt | Retained result | SHA-256 |
| --- | --- | --- |
| [20261026T180150.224193Z-53c7e5dd5ae1.json](results/20261026T180150.224193Z-53c7e5dd5ae1.json) | Strict Clippy failed on private re-exports and unused imports; later commands not run | `900ccbe22c300d15946f61a2cb9330b1155e34610edc825b9c7accf5cb7a70a6` |
| [20261026T180330.852414Z-4b43252e11b9.json](results/20261026T180330.852414Z-4b43252e11b9.json) | Strict Clippy failed on unused diagnostics and style errors; later commands not run | `3ec9ea148cdbde24c1752de5af5be5e8660533eebb9c7078ed9f9a636cf5aeaa` |
| [20261026T181011.311003Z-4ec230a66210.json](results/20261026T181011.311003Z-4ec230a66210.json) | Strict Clippy failed on seven test-style diagnostics; later commands not run | `836cbb97412eb512072d742e4191b6fefb046416b51d9bef857d98a94716323b` |
| [20261026T181157.486277Z-1a1be3ba50c2.json](results/20261026T181157.486277Z-1a1be3ba50c2.json) | All six commands passed: 1,860 workspace passes plus 4 ignores, 780 serial passes, 72 native fixtures | `b6387b4878040d4128ba5e26bf740f7994756b6522636a73aeab6ffe73219892` |
| [20261026T182020.398732Z-default-parallel-1a1be3ba50c2.json](results/20261026T182020.398732Z-default-parallel-1a1be3ba50c2.json) | First default unit run failed: 487 passed, 1 failed; remaining repetitions not run | `d696de2085d91431807286eafcf25eed60816e2a4594c00634278f3a005b34c2` |

The failed default run refused source maps during the ordinary NOP control's source reauthentication. Concurrent unrelated tests can change tracer VMAs between reads of the whole map table; source inspection found a concrete mechanism for a correctly strict parser to refuse such a stream. The saved result lacks a specific parse subtype, so this is a source-supported explanation, not proof of that occurrence's precise cause. Isolation preserves the complete map comparator and the failed observation. It introduces no production parser exemption.

Lint corrections scoped diagnostics to their actual consumers and repaired private visibility and test style. Seven narrow dead-code expectations retain intentionally stored negative-control and attempt fields; no broad lint suppression was added. The initializer unwind path now records an explicit aborted capture, and the existing native unwind case checks it before and after cleanup. Original retained evidence, comparisons, limits and cleanup assertions remain.

This finite B3 increment supports claims 1 and 2 through page confinement, first-instruction custody and selected delivery, and claim 4 through explicit native and negative controls. It does not establish any whole candidate claim, implement cross-modification-free in-place publication or the claim 3 software clock, qualify arbitrary ordinary applications, complete B3/B4, or supply performance measurements. Loader/syscall, memory/stack, general thread/signal/fork/exec and dynamic module/JIT composition remain unfinished. Validation durations are not application throughput or hook latency.
