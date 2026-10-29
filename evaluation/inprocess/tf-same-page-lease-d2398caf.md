# Same-page lease with real application execution

The opt-in page lease keeps the actual RX permission owner and held fetch reference across eligible plain instructions on one page. It still authenticates every TRACE event, architectural frame, instruction byte, backing object, VMA/alias observation and rseq write footprint. Branches, selected instructions and page boundaries retain the existing close/reopen path. This evidence supports claims 2 and 4; it does not establish general B2/B3 coverage.

Native qualification and release measurements use exact revision `d2398caf15225303f0c9f1332f46722c324c85f2`, which includes main `781209b92dbe17010a9777da86e769245f88197e`. The runtime is an unprivileged in-process gate without a ptrace supervisor. The measured profile supports registered rseq, with inactive-word checks at instruction/syscall handoffs, and trusted regular btrfs stdout; it performs zero source patches. The separate temporary syscall/RDTSC publication result remains documented in [the combined publication report](oneshot-cpuid-cf8c1de.md).

All five fixed alternating native/page-mode `/bin/ls -d .` pairs completed with identical `2e 0a` output. The build used C `-O2` and the locked Rust release archive on one reserved CPU of an AMD EPYC 9D85 (family 26/model 17/stepping 0, microcode `0xb101066`), Linux 7.1.3.

| Measurement | Minimum | Median | Maximum |
| --- | ---: | ---: | ---: |
| Native process, five samples | 4.694796 ms | 5.107213 ms | 5.496487 ms |
| Gated process, five samples | 15.631291604 s | 15.868017566 s | 16.325655768 s |
| First admission work, five samples | 81.762 us | 82.825 us | 122.644 us |
| Revisit admission work, 80 samples | 78.818 us | 81.402 us | 117.587 us |

Each gated process recorded 117,810 actual lease transfers, 211,471 completed generic instructions, 5,732 native-page admissions and closures, and one validated `-ENOTTY` result for each of TCGETS and TIOCGWINSZ. No samples were discarded. The process interval starts immediately before parent `Popen` and ends at leader reap; it includes launch, namespace/carrier setup, execution, terminal reporting and pre-reap cleanup. Parent FD queries, later descriptor closure and custody checks are outside it. Admission-work intervals exclude fault/handler entry, the final registered-publication hook, native execution and close. The raw clock queries invalidate maps reuse; no instrumentation overhead is subtracted. These are component costs, not complete first-touch or steady-state latency. Separate baseline and lease batches do not establish a controlled speedup.

Qualification passed all 148 finite subjects and fresh 6/49/17 prerequisites. Of the 148 subjects, 88 complete their operations, two zero-exit controls stop before the operation, and 58 are required failures. The new lease cohort contributes five native/gated pairs, an old-owner reference, an unobserved production comparison and five required failures. Independent replay retained exact full-frame/FP comparisons and rejected six raw-record corruptions. Five separate companion oracles passed: chain (23 subjects), generic full-state (21 pairs and three required failures), maps (27 native subjects), query reuse (120 checks), and write footprint (38 cases).

The earlier `e4903d67` lease attempt failed the strict predecessor snapshot comparison. The production correction saves fetch progress before validation changes it; the comparator is unchanged. An additional legacy stream/ls diagnostic at d239 passed its 20 finite cases but failed when ls exited with signal 9 and empty output under its unchanged three-second CPU limit. Its kill cause and terminal PC were not observed. The private orchestration had invoked this older diagnostic for a step labelled full-state; the actual full-state oracle was run separately. Both the diagnostic and the original sequence remain failed. The required-check attempts at d239 and `8598f9ca` also remain failed: recorder hit its unchanged 180-second deadline in both runs; the other five checks were not run. The 8598 change only hoisted fixed mutation paths within a recorder test, preserving every read and assertion.

All six required checks passed at `d2a3a71c287ef193176b9222a491d49d6ddaa9cd`: 350 recorder tests, formatting, strict all-target/all-feature Clippy, 3,088 workspace tests (36 ignored across 103 harnesses), the all-feature/all-target check, and 1,039 serial launch tests across 27 harnesses. Recorder completed in 166.543 seconds under its unchanged 180-second limit. The entire source difference from measured d239 is two recorder-test files: 16 fixed mutation-path constructions moved outside synchronous read callbacks. All 384 original assertions and 350 recorder identities remain. Runtime and in-process evaluator sources are identical to measured d239; measurements remain attributed to d239.

Numeric results: [finite qualification](results/20261029T021420.056177Z-page-selected-tf-same-page-d2398caf1522.json), [companion and failed-attempt summary](results/tf-same-page-validation-d2398caf.json), [release receipt](results/tf-same-page-release-d2398caf.json), [all ten process samples](results/tf-same-page-release-d2398caf.csv), and [six required checks](results/20261029T025027.882138Z-checks-d2a3a71c287e.json).

The tracked numeric receipts and CSV retain exact revisions, hardware, command counts, reproduction commands, all samples and hashes of private captures. Complete command records and raw logs remain private. Reproduce from this measured revision using the committed evaluators below, with one CPU reserved for native runs. Use the actual fresh private receipt paths emitted by the prerequisite drivers for the three receipt variables. Use a fresh output directory for each performance attempt.

```sh
LEASE_REVISION=d2398caf15225303f0c9f1332f46722c324c85f2
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 PYTHONDONTWRITEBYTECODE=1
python3 -B evaluation/inprocess/page_selected_oneshot.py --expect-revision "$LEASE_REVISION"
python3 -B evaluation/inprocess/page_selected_oneshot_failure.py --expect-revision "$LEASE_REVISION" --positive-receipt "$LEASE_POSITIVE_RECEIPT"
python3 -B evaluation/inprocess/page_selected_rseq_application.py --expect-revision "$LEASE_REVISION" --fast-memset
python3 -B evaluation/inprocess/page_selected_tf_same_page_run.py --expect-revision "$LEASE_REVISION" --positive-receipt "$LEASE_POSITIVE_RECEIPT" --negative-receipt "$LEASE_NEGATIVE_RECEIPT" --rseq-receipt "$LEASE_RSEQ_RECEIPT" --tiocgwinsz-btrfs
python3 -B evaluation/inprocess/page_selected_chain_oracle.py --expect-revision "$LEASE_REVISION"
python3 -B evaluation/inprocess/page_selected_generic_oracle.py --expect-revision "$LEASE_REVISION"
python3 -B evaluation/inprocess/page_selected_maps.py --expect-revision "$LEASE_REVISION"
python3 -B evaluation/inprocess/page_current_lookup.py --expect-revision "$LEASE_REVISION" --maps-query-reuse
python3 -B evaluation/inprocess/page_selected_write_footprint.py --expect-revision "$LEASE_REVISION"
python3 -B evaluation/inprocess/page_default_ls_release_performance.py --expect-revision "$LEASE_REVISION" --qualification-receipt "$LEASE_FINITE_RECEIPT" --qualification-sha256 "$LEASE_FINITE_SHA256" --tf-same-page-lease --output "$LEASE_NEW_OUTPUT"
```

The failed legacy diagnostic is reproducible separately with `python3 -B evaluation/inprocess/page_selected_generic.py --expect-revision "$LEASE_REVISION"`; its result is not a prerequisite pass or an application-completion claim.

Reproduce the required checks at their exact revision with four reserved CPUs:

```sh
env CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 PYTHONDONTWRITEBYTECODE=1 python3 -B evaluation/inprocess/checks.py --expect-revision d2a3a71c287ef193176b9222a491d49d6ddaa9cd
```
