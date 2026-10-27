# Saved selected-constructor frame inspection

The retained `260338fa41073f67f88f451d1de3548955dc94c3` ELF contains a concrete stack-size risk before the expected selected-Native refusal. Eleven functions on a directly verified nested constructor path reserve **1,519,736 bytes**. Five additional, source-connected ancestor frames raise the conditional partial sum to **2,100,032 bytes**, **2,880 bytes above** the matching Rust sources' normal 2 MiB libtest worker request. These are conditional lower sums if the named path reaches its deepest constructor. They omit intervening catch/closure frames, return addresses, unlisted callers and further callees; they are not upper estimates or measured historical high-water marks.

The saved failure does **not** establish the fault PC, actual worker stack extent, deepest reached function, or SIGSEGV cause. In particular, the source-connected extension is not a fully machine-reconstructed chain. This evidence supports the allocation-preserving explicit-array correction; it does not turn the failed run into a pass.

## Saved run and artifact

The exact failed receipt is `20261026T233947.790400Z-260338fa4107`, SHA256 `4ceb4285d31309e2c3f94a332346514b7db221f8041539d0cd861d036aff9738`. Recorder 302, formatting and strict Clippy passed. Workspace tests exited 101 after 20.364766262 seconds; the remaining two commands did not run. Outer cleanup completed and reaped **five adoptees**. The child diagnostic reports SIGCHLD / CLD_DUMPED / SIGSEGV for `runtime_kernel_default_native_and_cpu_refusals_keep_current_state`, an exact expected pid, and empty captured stderr. The isolated parent reaped that direct child and failed closed. The test's three sequential refusal trajectories are not separately identified by the crash output.

The original command log names `liteinst_launch-11d49a8d76592146`. Its retained 140,564,200-byte ELF was copied before rebuilding and hashes to `e9f45affbb2c348d1857d2d5137c6151635a705c2be57540fc8aeb5c65fbcc43`. The original receipt did not hash the ELF; this later inspection binds the preserved artifact. The log SHA is `23a78f94c861436ff9c1bad937160ea22e737480f5e071da4dd49e57334fd4c1`. RLIMIT_CORE was zero. No core or historical fault PC is supplied by this report.

## Exact path and limits

`old_refusal → with_owner → action/pending → Owner::execute → execute_admission → execute_runtime → catch closure → RuntimeOwner::execute → advance → prepare_selected` is the source ancestry. The ELF directly verifies the three ancestor edges listed in the JSON and all ten constructor edges from `prepare_selected` through `PreparedNativeSelected::allocate`, `array::from_fn`, `try_from_fn`, `try_from_fn_erased`, its wrapper and allocation closures, `ControlProfile::default`, `BoundedCet::default`, the two-element `CetStatus` array default and `CetStatus::default`. All reported reservations are checked against their actual probe/subtraction prologues. Each restoration has the exact corresponding add, optional saved-register pop, and return; other stack-pointer writes refuse the reproduction.

| Function role | Reserved bytes |
| --- | ---: |
| with_owner | 123,416 |
| execute_admission | 159,576 |
| execute_runtime | 291,720 |
| runtime_execute | 2,760 |
| advance | 2,824 |
| prepare_selected | 444,440 |
| selected_allocate | 222,376 |
| array_from_fn | 104,808 |
| array_try_from_fn | 314,392 |
| array_erased | 279,624 |
| wrap_mut | 34,968 |
| allocate_closure | 24 |
| control_default | 34,936 |
| cet_default | 34,744 |
| status_array_default | 32,968 |
| status_default | 16,456 |

The two `CetStatus::default` calls in its array constructor are sequential, so only one such frame is added. The eight-byte `push %rbx` in `prepare_selected` is included. The 24-byte allocation closure is included. Earlier informal subtotals that omitted this closure are superseded by the JSON.

The matching installed Rust sources show `test::run_test` using `thread::Builder::new().name(...)` without `.stack_size`, Builder's `None`, the `RUST_MIN_STACK`/default selection, and Linux's 2 MiB default. The official recorder inherits only its explicit location whitelist and fixed environment; `RUST_MIN_STACK` is excluded. The isolated child supplies no override. Libtest also has a synchronous WouldBlock fallback, and neither worker identity nor actual pthread stack geometry was recorded. Consequently 2 MiB is the source-supported normal worker request, not an observed historical extent.

## Source triage and correction

The old refusal body and its helpers are byte-identical across the coalescence integration. `Fixture::code` supplies one 8 KiB RX PT_LOAD. It cannot select the new lower-R/upper-RX 4 KiB pair, so the coalescence sidecar allocation, native producer and descriptor-transfer branch do not run for this fixture. New no-pair preflight uses the existing read-only original map/backing mechanisms and borrowed parsed rows. This review found no concrete new ownership, mapping or unsafe-memory defect on that no-pair route; that is not a proof excluding every possible defect.

`prepare_selected` creates its retained native attempt before the provider decision. The old array combinator constructs three inline `ControlProfile` values, each containing large fixed CET diagnostic arrays. The expected `Native` refusal is later. Root's committed one-file candidate `6c79cacf74f470a451f3cdcc31cc827c36c2d1dd` replaces only that combinator with three explicit defaults in the same order. It preserves field type and values, heap allocation, size-based accounting, checks, first-error handling, deadlines and all tests. Candidate manifest `41eafdcc9e6e1f6e4f8c7980788b2773e96598a91380c6e4ad4444d805064e8f` and inverse review are separate. This report makes no candidate frame-size or qualification claim.

## Reproduction and custody

`inspect_runtime_selected_frames.py` is a closed inspector for this one hash-pinned ELF, not a generic stack analyzer. It pins the failed receipt, workspace log, GNU nm and objdump binaries; bounds each tool at 30 seconds and its captured output; invokes only those tools against a held read-only ELF; checks unchanged file/tool identities; keeps raw disassembly in a fresh private directory; and atomically publishes a fresh normalized JSON target. It never invokes the ELF, Cargo, rustc, tests or project parsers. Inputs and output paths are command arguments, not host paths embedded in the public result.

The [authored summary](results/runtime-selected-stack-260338fa.json) preserves the prior source inspection and explicitly says `reproduction_script_executed: false`. Following independent source review, the read-only inspector exited zero and produced the separate [generated summary](results/runtime-selected-stack-reproduction-260338fa.json), SHA256 `7741b7ad86dba13fa608ff3bd6ed2aa2eb0fe49baebed91f6cedc89b98bd3aab`. All 16 frame records, 13 direct edges, artifact identities and numeric sums match exactly. Their origin/executed metadata intentionally distinguish the authored inspection from the script run. Neither summary replaces the failed native receipt.

The recipe requires the retained private ELF/log and matching inspection tools. Those raw inputs are not distributed in the public repository; this is a saved-artifact inspector, not a portable rebuild recipe or dynamic crash reproducer. Use the saved ELF, not the rebuilt deps pathname. The separately qualified correction is reported in [initial coalescence results](initial-coalescence-results.md); that success does not recover the earlier fault location.

Example invocation after review, with all paths relative to the repository:

```text
python3 evaluation/admission/inspect_runtime_selected_frames.py \
  --elf target/b3-bootstrap-map-coalescing-kernel-crash-analysis-v1/private/inspected.elf \
  --receipt evaluation/admission/results/20261026T233947.790400Z-260338fa4107.json \
  --workspace-log target/evaluation/admission/20261026T233947.790400Z-260338fa4107/workspace_tests.log \
  --private-dir target/runtime-selected-static-reproduction \
  --summary target/runtime-selected-static-reproduction.json
```

No old receipt, raw artifact, test assertion, catalog identity, resource cap, deadline, or native success criterion is modified. The evidence has no native qualification or benchmark credit.
