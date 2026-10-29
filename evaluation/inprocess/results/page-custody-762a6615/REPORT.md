# Sealed-page custody: qualification and release measurements

At `762a66157c4c0103acd59605554c216ac5e8db18`, the original lease prerequisites, sealed-page custody cohort, both interval cohorts and all four timing batches passed. Independent saved-data reviews accepted the complete finite records and all 60 timing samples. All six [repository checks](checks.json) passed separately at current revision `1acb42c4e95fc210c6a627104b18ad2189aa7d4d`, which includes main `2754cbfff93960913a08a71fe62d2d8b4c37df93`. Independent saved-check replay also passed. Later upstream `9c70b1af4c10cbf66d1cab26c66561d03bb463fb` is outside that check result. Measurement attribution remains 762a; the complete page runtime and in-process evaluator trees are byte-identical to that measured revision.

The optional custody mode retains one managed sealed page's VMA and negative-alias proof across eligible same-owner, same-page plain-instruction TF handoffs. It still checks descriptor identity, seals, extent, live source bytes, owner/frame and registered-rseq authority. It does not retain a global maps snapshot. A fresh transfer establishes the proof; invalidating events discard it, and final closure still performs the actual revoke/release.

The baseline here is the existing same-page TF lease with custody disabled, built at the **same revision**. The reported finite and timing sequence used one reserved CPU (43), AMD EPYC 9D85, x86-64 family 26/model 17/stepping 0, microcode `0xb101066`, Linux 7.1.3. The four batches have separately authenticated artifacts and namespace instances. The comparison review joined shared source, hardware, system executable/interpreter/dependency bytes and environment; it did not require independently built ELF path metadata to be identical.

| Median, five samples per lane | Baseline native | Baseline gated | Custody native | Custody gated |
| --- | ---: | ---: | ---: | ---: |
| N=1 operation interval | 34.973 us | 3.686480 ms | 85.319 us | 3.352497 ms |
| N=256 operation interval | 40.711 us | 11.339562 ms | 37.266 us | 5.628661 ms |
| `/bin/ls -d .` process path | 5.390248 ms | 16.164177998 s | 15.979929 ms | 14.661278832 s |

The interval fixture executes N=1 or N=256 `ADD $1,%r8` operations. Its parent clock starts immediately before GO write and stops after complete DONE read, including IPC, scheduling, remaining read return, first fault/handler, body, closure and notification. Process creation, setup/READY, subsequent output/record handling and reap are outside this interval. Acceptance still requires their complete protocol, state, output and custody checks. Thus **11.340 ms versus 5.629 ms is a workload round-trip comparison**, not isolated steady-state execution. N=1 is likewise a first-entry workload round trip, not isolated fault latency or cache/TLB coldness.

The ls clock runs immediately before `Popen` through successful leader reap, including launch/exec, gated namespace/carrier setup, target execution and terminal reports. Parent descriptor queries and custody checks are outside it. The original admission-work timers in the receipts cover narrower runtime validation work; they exclude fault/handler entry, final registered publication, native execution and close. They are not complete first-touch or revisit execution latency.

All four batches retain their original alternating order, with no discarded warmup, retry, sample filtering, overhead subtraction or pooling. The native ls medians differ substantially—**5.390 ms versus 15.980 ms**—while gated medians are **16.164 s versus 14.661 s**. These separately timed batches do not isolate a causal ls speedup. No application-specific custody-retention count is observed for ls. Default application rseq registration remains enabled, with zero source patches, 5,727 actual native admissions and closes per gated process, and one actual `TCGETS` and one `TIOCGWINSZ` result validation each. There is no low-overhead or complete generic B2/B3 claim.

Finite evidence preserves the original 6 selected sites across two processes, 49 failure-cohort processes, 17 rseq pairs and all 148 lease subjects (88 completed operations, 58 required failed operations and two pre-operation prefixes). The new custody cohort has 69 commands and 17 subjects: seven completed operations, ten required exit-125 failures, six successful native/gated pairs and five retained native references. It includes actual stack growth and retained-proof failure/cleanup cases.

Each interval mode additionally accepted eight successful targets, five required protocol failures and four actual pre-exec descriptor refusals, with two native/observed full-state pairs. The observed custody N=256 body had one fresh stage, 255 retained stages, 509 retained checks, 255 commits/transfers and one real close. N=1 had one fresh stage, no retained transfer and one real close. Full initialized FP state is checked at endpoints; compact per-TRACE records make no full-FP claim. Timing uses the exactly qualified unobserved bridge with empty FD3, so these BODY counts belong to observed qualification, not inferred timing-lane observations.

Subject limits remain 5 CPU seconds/15 wall seconds for custody and interval cases, and 30 CPU seconds/60 wall seconds for ls, with 512 MiB address space and 16 MiB file limits. Original protocol, output, state, source, descriptor, namespace and cleanup predicates remain mandatory.

Seven actual run failures remain failed in [validation.json](validation.json): 59af stopped at rseq source-pin preflight with zero commands/subjects; 5f stopped after the first custody child when the reader rejected its historical registration proof; ea930 stopped after 12 custody subjects on the stack-ingress history reader; ea930's recorder separately timed out at 180.384 s, the post-merge d366 recorder timed out at 180.071 s, the 68cf recorder timed out at 180.059 s, and the f8c7 recorder timed out at 180.059 s. All four recorder attempts exited -9 under the unchanged 180-second cap, reaped five descendants with complete cleanup, and left five later checks not run. The reader corrections follow source-defined registration, partial backing-view and exact stack-selector contracts. Saved replay or later success does not convert those attempts into qualification. Three failed comparison-review scaffolds are also retained as review-only failures; their corrections did not alter production predicates.

At revision `68cf178b0c6c117f7c27dcaf74e8996df9d13139`, the library-only compiled list passed with 475 unique names and all 14 newly added session/history test identities in 9.133 s. Those Rust/Cargo inputs and the corpus are unchanged through 1acb. The current [six-check receipt](checks.json) records 350 recorder tests in 40.312 s, formatting in 7.091 s, strict all-target/all-feature Clippy in 8.771 s, 3,179 workspace tests passed plus 36 existing ignores across 103 harnesses in 354.323 s, the all-target/all-feature workspace check in 21.331 s, and 1,039 serial launch tests across 27 harnesses with no ignores in 133.794 s. All exits were zero, source/configuration stayed unchanged and cleanup completed with zero descendants requiring reap. Original limits remain 180 s per check except the 900-second workspace test limit.

The prior ba5f checks remain a compact historical success in [validation.json](validation.json): all six passed, including 350 recorder tests in 176.148 s, 3,165 workspace tests plus 36 existing ignores in 330.054 s, and 1,039 serial launch tests in 132.813 s. Formatting, strict all-target/all-feature Clippy and the all-target/all-feature workspace check passed, with source/configuration and cleanup gates intact. The earlier d366 three-harness compiled list remains bound separately; its 815 names and 29 additions describe that revision. No prior failure is relabelled.

The recorder still assigns the complete main813 inventory module to one existing worker and all other complete modules to the remaining three, retaining all 350 identities, prior assertions, fixture semantics and the original 180-second/8-MiB limit. From measured 762a to current 1acb, the complete `tools/page-entry` and `evaluation/inprocess` Git trees are identical. Eight admission paths update exact inventory, recorder scheduling and controls. The splice-only f8c7 attempt remains failed. The additional 1acb source precheck rebuilds current expectations and reads the files freshly so mutations can reject earlier; successful prechecks still run the complete original historical/source validation. All prior assertions, bounds and negative controls remain. Only exact immutable splice results can be reused; checks and expectations are never cached. The passed current check duration does not isolate an individual optimization's contribution or change measurement attribution.

To repeat the required checks at 1acb, reserve four CPUs and run `PYTHONDONTWRITEBYTECODE=1 CARGO_INCREMENTAL=0 python3 -B evaluation/inprocess/checks.py --expect-revision 1acb42c4e95fc210c6a627104b18ad2189aa7d4d`. The compiled-list command is `CARGO_INCREMENTAL=0 cargo test -p rapid-profiler --lib -- --list`; the retained helper used the evaluator-controlled environment and original 180-second/8-MiB ownership limits.

Use a clean checkout at the measurement revision, Python 3.12, the repository's locked offline build inputs, a supported btrfs capture filesystem and fresh output directories. Hold the entire sequence to one reserved CPU. Keep the same system ls/interpreter/libraries and environment for the separate batches. The committed runners enforce these prerequisites and stop on failed evidence. The first four runners print a public receipt location: for `evaluation/inprocess/results/STEM.json`, the corresponding private receipt is `target/evaluation/inprocess/STEM/receipt.json`. Assign the variables below to those actual private paths. All output directories below must be new.

```sh
set -eu
REVISION=762a66157c4c0103acd59605554c216ac5e8db18
export PYTHONDONTWRITEBYTECODE=1
run() { module=$1; shift; python3 -B "evaluation/inprocess/$module.py" --expect-revision "$REVISION" "$@"; }
sha() { sha256sum "$1" | cut -d ' ' -f 1; }

run page_selected_oneshot
# Set POSITIVE_RECEIPT using the printed public-to-private mapping above.
run page_selected_oneshot_failure --positive-receipt "$POSITIVE_RECEIPT"
# Set NEGATIVE_RECEIPT using the same mapping.
run page_selected_rseq_application --fast-memset
# Set RSEQ_RECEIPT using the same mapping.
run page_selected_tf_same_page_run --positive-receipt "$POSITIVE_RECEIPT" --negative-receipt "$NEGATIVE_RECEIPT" --rseq-receipt "$RSEQ_RECEIPT" --tiocgwinsz-btrfs
# Set LEASE_RECEIPT to the complete 148-subject private receipt using that mapping.
LEASE_SHA=$(sha "$LEASE_RECEIPT")

run page_selected_tf_custody --qualification-receipt "$LEASE_RECEIPT" --qualification-sha256 "$LEASE_SHA" --output target/custody-finite
run page_selected_tf_interval --qualification-receipt "$LEASE_RECEIPT" --qualification-sha256 "$LEASE_SHA" --output target/interval-baseline
run page_selected_tf_interval --sealed-custody --qualification-receipt "$LEASE_RECEIPT" --qualification-sha256 "$LEASE_SHA" --custody-receipt target/custody-finite/receipt.json --custody-sha256 "$(sha target/custody-finite/receipt.json)" --baseline-interval-receipt target/interval-baseline/receipt.json --baseline-interval-sha256 "$(sha target/interval-baseline/receipt.json)" --output target/interval-custody

# Review the complete closed finite evidence before measuring.
run page_tf_interval_performance --qualification-receipt target/interval-baseline/receipt.json --qualification-sha256 "$(sha target/interval-baseline/receipt.json)" --output target/timing-baseline
run page_tf_interval_performance --sealed-custody --qualification-receipt target/interval-custody/receipt.json --qualification-sha256 "$(sha target/interval-custody/receipt.json)" --output target/timing-custody
# Set LIBRARY_ROOT to the system library root (the measured run used /usr/lib64).
run page_default_ls_release_performance --tf-same-page-lease --qualification-receipt "$LEASE_RECEIPT" --qualification-sha256 "$LEASE_SHA" --library-root "$LIBRARY_ROOT" --output target/ls-baseline
run page_default_ls_release_performance --sealed-custody --qualification-receipt target/interval-custody/receipt.json --qualification-sha256 "$(sha target/interval-custody/receipt.json)" --library-root "$LIBRARY_ROOT" --output target/ls-custody
```

Exact receipts and all raw samples are retained here: interval [baseline receipt](interval-baseline.json)/[20 samples](interval-baseline.csv), interval [custody receipt](interval-custody.json)/[20 samples](interval-custody.csv), ls [baseline receipt](ls-baseline.json)/[10 samples](ls-baseline.csv), and ls [custody receipt](ls-custody.json)/[10 samples](ls-custody.csv). [Required checks](checks.json) retain their complete public receipt. [Validation](validation.json) binds finite successes, failed attempts and independent reviews by hash. Private host paths, raw logs and binary records are not published.
