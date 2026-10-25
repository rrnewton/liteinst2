# Public frontend ownership and model records

The focused public suite passed all eight commands at source `9098a3d74309fd445fd6f56a6048c1ce517bb81f`: 60 unit/model cases and eight exact compile-fail documentation cases. The table keeps repeated executions, workspace counts and tool observations separate.

| Record | Actual result | Reproduction |
| --- | --- | --- |
| Focused public suite, `9098a3d7` | [Eight commands, 60 unit/model cases and eight documentation cases](results/frontend-public-9098-20261025/summary.json); zero failed, ignored or filtered cases | [Exact requests and artifact-review procedure](frontend-public/README.md) |
| Required workspace, `9098a3d7` | [Four gates passed](results/required-9098a3d7-20261025/summary.json); 984 top-level passes, zero failures, four existing ignores, 61 outer groups; five nested guard passes separate | [Recorded exact command/environment coordinates](results/required-9098a3d7-20261025/summary.json) and [existing runner](required-gates.py) |
| Preserved required workspace failure, `3f87ac90` | [Format and Clippy passed; test exited 101; check unrun](results/required-3f87ac90-20261025-failed/summary.json). Observed 560 passes, one failure and one ignore across 28 groups; five nested passes separate. Thirty-two prior groups, including A5 model/docs groups, were unreached. | [Recorded failed-attempt request context](results/required-3f87ac90-20261025-failed/summary.json) |
| Tool-version observations | [Six separate successful queries](results/frontend-tool-versions-20261025.json): Cargo, rustc and rustdoc for Rust 1.97.1 and 1.85.0 | [Six request and wrapper templates](reproductions/frontend-tool-versions-20261025/README.md) |

The required workspace counts already include its own execution of the 60 public unit/model tests and eight docs. The focused repetition is additional execution evidence, not additional unique case coverage. The earlier required failure remains failed: child comparison successes did not override its failing parent cleanup. None of these denominators are summed.

The focused run paused after its normal-library and test compilation for review of the actual executable, dependencies and source owners. Its first three phases used admission v2; the remaining five used a separately reviewed v3 after `/etc/ld.so.cache` inode/timestamps changed with identical bytes. Both immutable records remain. A wrong field lookup stopped an intermediate caller before it launched any child; that event has no helper receipt and is separate from the eight command outcomes. The documentation command revalidated the previously compiled ordinary-library artifacts before its unchanged 1 MiB cap.

The earlier v1 cache-admission checks also stopped before request/workload creation. Their differing read values were not serialized, and later metadata observations do not backfill those missing values. These preparation events remain separate from the eight completed focused commands.

The 60-case inventory comprises 17 inherited generation tests, four owned-ticket tests, 31 frontend models, one reference-ledger test and seven inherited interval/PMU tests. The single expected caught registry-poison panic preserves the required assertions. The eight docs require E0599 twice, E0382 twice and E0616 four times. The separate private TLS proposal is excluded.

These are ownership/controller-model and regression records, not native frontend or performance results. Linked assembly-byte checks and conditional legacy PMU tests do not establish runtime PMU availability, machine-return-slot transparency, native entry/exit, TLS activation, a preemption clock, full A5 or claims 1–4. Selected tool/runtime evidence and phase-relative hardware snapshots do not claim complete dynamic-loader closure or continuous hardware attestation. Raw captures, full stat maps and binaries remain private; elapsed times are operational diagnostics.
