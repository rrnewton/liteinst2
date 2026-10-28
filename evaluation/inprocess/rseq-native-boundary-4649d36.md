# Registered native boundary execution

At revision `4649d361f5fa3c2e30957f9cd6cf9f7475011d51`, page mode completes the real dynamically linked `/bin/true` with rseq enabled. The new boundary owner retains the original kernel-selected PC through a genuine second NX event, verifies zero-word/pin/TLS state, closes the first page, and then forces the original instruction owner. A CALL ending at the page boundary can push a return address pointing to the never-executed next page; that address does not imply a split CALL or authorize replaying it.

All 20 native/gated pairs pass: 40 subjects, 26 completed operations and 14 required failed operations, including six signal terminations. The original 6 publication owners, 49 negative controls and 17 inactive-rseq pairs also pass. The four new pairs cover split MOV, split CALL, CALL ending at the boundary, and a genuine rseq abort redirect. They retain full UC/FP/register/flag/source/data checks, both actual close records and single-push CALL checks. Their 24 recorded events include three completed gated boundary retries. See the [finite receipt](results/20261028T202357.143548Z-page-selected-rseq-native-boundary-4649d361f5fa.json) and [fixture contract](../../tools/page-entry/selected/tests/rseq_native_boundary/FIXTURE.md).

The release application matrix is **failed overall: four of five cases pass**. These are single samples on one reserved AMD EPYC 9D85 CPU; the receipt records kernel identity, input/library/build hashes, exact command and unchanged 30 CPU-second/60 wall-second limits.

| Program | Native seconds | Gated seconds | Result |
|---|---:|---:|---|
| true, default rseq | 0.003481447 | 6.330147263 | exit 0, equal output |
| true, rseq disabled | 0.003904412 | 6.528538848 | exit 0, equal output |
| ls, default rseq | 0.003900556 | 19.714495952 | exit 125, missing output |
| ls, rseq disabled | 0.004769289 | 20.227672053 | exit 0, equal output |
| boundary, rseq disabled | 0.003395829 | 1.218266335 | exit 0, equal output |

Default true completes 974 registered native epochs and 23 boundary retries. Its first recorded admission service takes 77,677 ns; the median of 16 recorded revisit services is 77,952.5 ns. These measure admission service only, excluding application work; they do not establish steady-state application throughput or a speedup. The [release receipt](results/rseq-native-boundary-release-4649d36.json) retains all raw numeric samples and all five outcomes.

Default ls reaches the registered syscall guard and refuses syscall 16 (`ioctl`, code 1207). It closes all 5,485 native admissions, including 4,346 registered epochs and 39 boundary retries. The terminal report lacks the request, FD, output pointer and syscall PC; these are not inferred. Full-program source patches remain zero. Ordinary-program syscall/RDTSC publication and broader B2/B3/B4 coverage remain separate work.

The two earlier boundary attempts remain failed: [c2e](results/20261028T195649.867812Z-page-selected-rseq-native-boundary-c2e1bb04f1a0.json) lacked typed siginfo-alias authentication; [7bc](results/20261028T201019.328603Z-page-selected-rseq-native-boundary-7bc9c2d9e96b.json) missed a required continuation observation. The corrections authenticate actual siginfo pointers and add identity NOPs that force the existing NX fallback. No state comparator, required event count, native outcome or bound was relaxed.

Reproduce at the recorded revision using `evaluation/inprocess/page_selected_oneshot.py`, `page_selected_oneshot_failure.py`, and `page_selected_rseq_application.py --fast-memset`, then pass their exact same-revision private receipts to `page_selected_rseq_native_boundary_run.py`. Each takes `--expect-revision`; the finite receipt records all arguments. Run the release matrix with the exact `native_pages.py` command in its receipt. Use one reserved CPU, `PYTHONDONTWRITEBYTECODE=1`, `CARGO_INCREMENTAL=0`, and `CARGO_BUILD_JOBS=1`.

All six [required checks](results/20261028T202806.872845Z-checks-4649d361f5fa.json) pass at the same revision: 350 recorder tests; formatting; strict workspace/all-target/all-feature Clippy; 2,987 workspace tests (36 ignored); all-feature/all-target check; and 1,039 serial launch tests. Original 180-second command and 900-second workspace limits remain unchanged. Run `python3 evaluation/inprocess/checks.py --expect-revision 4649d361f5fa3c2e30957f9cd6cf9f7475011d51` with four reserved CPUs and `CARGO_INCREMENTAL=0`.
