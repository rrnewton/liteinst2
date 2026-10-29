# Default-rseq ls under in-process page admission

ADDS end-to-end `/bin/ls -d .` execution under unprivileged in-process page admission, with the application's ordinary rseq registration and actual TCGETS/TIOCGWINSZ results. The new gates admit these two queries on trusted normal-open btrfs stdout after checking descriptor identity, registration ownership and the actual `-ENOTTY` result. This evidence supports claims 2 and 4 within that profile.

The merged source revision is `db0bec0be13df1bc2aed23347aa8aa9f0f786d6c`, including main `83b119027bb205c0ce860f8213f6a3aee9e04b49`. The preceding measured source is `c2a1ceb1f6a1fbcf545e5adb34bc9988bc8f2a7f`. Their page-runtime, admission and evaluator sources are identical. The final publication commit adds documentation and numeric results only.

Both runs use the qualified unobserved C `-O2` bridge and locked Rust release archive, one reserved CPU, AMD EPYC 9D85 (family 26/model 17/stepping 0, microcode `0xb101066`), and Linux 7.1.3. Each consists of five fresh native/page-mode pairs, alternating order, without discarded samples. All twenty processes exited 0 with identical two-byte output. Every gated process recorded 38 CPUID, 10 RDTSC, 100 syscalls, 5,721 native-page admissions and closures, 4,582 registered native epochs, and one validated request of each new type. Execution starts at the dynamic interpreter's first instruction; no ptrace supervisor is used. This workload uses the supported registered-inactive rseq and regular captured-stdout profile. It performs zero source patches; active-rseq publication and general application coverage remain outside this result.

| Source | Native process median | Page-mode process median | Native range | Page-mode range |
| --- | ---: | ---: | ---: | ---: |
| c2a1ceb | 4.976011 ms | 18.728153847 s | 4.674–5.144 ms | 18.570–19.167 s |
| db0bec0 | 5.261456 ms | 18.676642469 s | 4.085–7.962 ms | 17.981–18.997 s |

Process timing begins immediately before `Popen` and ends at leader reap, including launch/exec, the gated carrier and sealed namespace, target execution, terminal reports and process-group cleanup. Parent descriptor queries and custody checks are outside it. These measurements expose substantial remaining overhead; they do not establish a low-overhead runtime.

At db0bec0 the five first-admission-work samples have median 82.904 µs (range 82.745–113.741 µs); the 80 retained same-page/allocation/generation revisit-work samples have median 82.2035 µs (range 77.666–117.897 µs). These timers cover admission work through verified RX/maps/source checks. They exclude fault/handler entry, final registered publication, native execution and close, so they do not measure full first-touch or steady-state execution latency. Their raw clock queries invalidate maps reuse. The next performance change is a same-page TF lease, which has no execution evidence in this result.

Fresh 6/49/17 prerequisites and all 131 registered/query subjects passed at both revisions: 32 registered-native, 8 boundary, 56 TCGETS and 35 TIOCGWINSZ. Each finite run executed 653 commands; 78 subjects exited 0 and 53 retained required failures, including six signal terminations. The checks cover full native/gated frames and FP state, actual subvolume identity, memfd wrong-filesystem refusal, and supplied query/parser/result faults. The four preceding full qualification attempts remain failed in the compact attempt table. No failed prefix earns qualification credit.

All six [required checks](results/20261029T013444.715706Z-checks-a483d9091507.json) pass at `a483d9091507b2975d7d6166640d3ee20dbb929b`, which includes main `781209b92dbe17010a9777da86e769245f88197e`: **350 recorder tests; formatting; strict workspace/all-target/all-feature Clippy; 3,088 workspace passed / 0 failed / 36 ignored across 103 harnesses; workspace check; and 1,039 serial launch passed / 0 failed across 27 harnesses**. Recorder/workspace/serial times are 169.578/360.544/146.062 seconds under the unchanged 180/900/180-second caps. Source, configuration and process cleanup remain intact.

The measured page-runtime and in-process evaluator code at db0bec0 is identical at a483d909. The intervening changes are admission inventory/tests, two fixture documents and nine separate core perf-tool/evidence additions. Required-check results belong to a483d909; the application measurements above remain attributed to db0bec0. The inventory now includes the 32 added core tests and caches only native SHA256 calculations for identical immutable source bytes, retaining fresh file reads, every live expected-value comparison and all previous assertions.

The [earlier c2a1ceb six-check pass](results/20261029T003704.200930Z-checks-c2a1ceb1f6a1.json), [db0bec0 preflight failure](results/20261029T010536.935471Z-checks-db0bec0be13d.json), and [a96c20b recorder timeout](results/20261029T011740.529759Z-checks-a96c20bba7d8.json) retain their original outcomes. The preflight failed before any check command ran; the recorder later reached its 180-second cap and the remaining five commands did not run. Neither failure is relabelled by the subsequent pass.

Raw numeric samples and receipt identities:

- [c2a1ceb JSON](results/default-rseq-ls-c2a1ceb.json), [CSV](results/default-rseq-ls-c2a1ceb.csv).
- [db0bec0 JSON](results/default-rseq-ls-db0bec0.json), [CSV](results/default-rseq-ls-db0bec0.csv).
- [Qualification attempts](results/default-rseq-ls-qualification-attempts.csv), including exact revisions, outcomes and receipt hashes.
- [c2a1ceb finite result](results/20261029T001841.197816Z-page-selected-rseq-tiocgwinsz-btrfs-c2a1ceb1f6a1.json), [db0bec0 finite result](results/20261029T005114.993774Z-page-selected-rseq-tiocgwinsz-btrfs-db0bec0be13d.json).

Use a clean checkout at the exact 40-hex source revision and a shell bound to one reserved CPU. Run these tracked evaluators in order. For each prerequisite, use its complete private `target/evaluation/inprocess/<emitted-stem>/receipt.json`, not its compact public result. Do not pass `--case` to the failure evaluator.

```sh
REVISION=db0bec0be13df1bc2aed23347aa8aa9f0f786d6c
python3 -B evaluation/inprocess/page_selected_oneshot.py --expect-revision "$REVISION"
python3 -B evaluation/inprocess/page_selected_oneshot_failure.py \
  --expect-revision "$REVISION" --positive-receipt "$POSITIVE_PRIVATE_RECEIPT"
python3 -B evaluation/inprocess/page_selected_rseq_application.py \
  --expect-revision "$REVISION" --fast-memset
python3 -B evaluation/inprocess/page_selected_rseq_native_boundary_run.py \
  --expect-revision "$REVISION" --tiocgwinsz-btrfs \
  --positive-receipt "$POSITIVE_PRIVATE_RECEIPT" \
  --negative-receipt "$FULL49_PRIVATE_RECEIPT" \
  --rseq-receipt "$FULL17_FAST_RSEQ_PRIVATE_RECEIPT"
```

The finite run requires the fresh 6/49/17 prerequisites, then sixteen registered-native pairs, four boundary pairs, twenty TCGETS pairs plus sixteen supplied refusals, and seventeen TIOCGWINSZ pairs plus one supplied refusal. Required failures remain failed operations. Case 5 creates a unique unprivileged subvolume in each lane and proves it using the actual capture FD; case 19 retains the observed memfd mount ID 0 as a fixed fixture condition, not a universal memfd promise.

After the complete finite receipt passes review, set `QUALIFICATION_PRIVATE_RECEIPT` to that receipt, `QUALIFICATION_SHA256` to its actual SHA256, and `NEW_PRIVATE_OUTPUT` to a nonexistent path under `target`. Keep the same committed revision; run the complete performance invocation under one reserved CPU:

```sh
python3 -B evaluation/inprocess/page_default_ls_release_performance.py \
  --expect-revision "$REVISION" \
  --qualification-receipt "$QUALIFICATION_PRIVATE_RECEIPT" \
  --qualification-sha256 "$QUALIFICATION_SHA256" \
  --output "$NEW_PRIVATE_OUTPUT"
```

Performance uses five fixed alternating native/gated `/bin/ls -d .` pairs with no discarded samples. Process latency runs from immediately before Popen through leader reap, including launch/exec, target and reports; parent FD queries and custody checks are outside it. First/revisit admission-work timers cover only the runtime admission work, excluding fault/handler entry, final registered publication, native execution and close. Their raw clocks invalidate maps reuse. These component intervals do not establish full first-touch or steady-state execution latency, low overhead, or B2/B3 completion. Actual revision, hardware, reproduction commands and all sample values remain in the public numeric receipts; complete command and capture evidence remains private.
