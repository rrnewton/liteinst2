ADDS execution across two immutable generated images during one held source/rseq lifetime, including cold publication and warm reuse with no interior signals in the observed loop. This experiment provides loop-only mechanism evidence relevant to claims 1 and 4. It does not establish whole-program coverage or the 10×DynamoRIO target: the release `/bin/ls -d .` experiment was killed at its unchanged CPU limit.

The native source is `a215c3aa8ab20bedc3900157f744d574ea46d230`, including main `34c47f5b8bdbeb5a7c73db067cf5b4aee36fc37f`. All four stages ran sequentially on reserved CPU 1 of an AMD EPYC 9D85 (family 26/model 17, microcode 0xb101066), unprivileged on Linux 7.1.3. The actual group bridge uses `-O2`; the decoder archive is a release build. The public JSON pins source and hardware plus the complete private input, artifact and command manifests; raw captures remain private.

The new owner shares two original source pages across two 32-KiB generated images. Protected read-only link slots connect them through immutable six-byte indirect stubs. All 17 code pages close before link reset, reference release and source/rseq release. Warm entry consumes the completed generation's exact permit. The group accepts 65–128 supported heads, with at most eight total directed capacity links and unsupported exits. Graphs with at most 64 heads remain classified misses in this separate experiment; the original single-image profiles retain their existing tests and contracts. Unsupported frontiers still drain into ordinary execution.

The [fresh group comparison](results/20261031T044944.336651Z-persistent-group-loop-a215c3aa8ab2.json) ([CSV](results/20261031T044944.336651Z-persistent-group-loop-a215c3aa8ab2.csv)) passed. Its real 65-head loop traverses both images, with one cold publication, one warm entry and zero interior signals in the two focal executions. Full native/generated architectural state agrees against the original 267-step reference. Six link traversals follow from that reference's control flow; no inserted counter independently measured those traversals. All 16 application, 79 owner, 4 pair and 63 terminal negative controls pass. Group fault, asynchronous-entry and replacement qualification remain open; the earlier single-image fault tests do not establish those group properties.

Fresh prerequisites also pass: [fixed five cases](results/20261031T044706.084175Z-persistent-epoch-a215c3aa8ab2.json) and [dynamic five cases](results/20261031T044818.366258Z-persistent-dynamic-a215c3aa8ab2.json), with the same revision, CPU, hardware and decoder archive. The group pure oracle additionally checks 1,458 recoveries, 296 MOV boundaries, ten link boundaries and 38,024 rejected PCs; it executes no generated instructions. Native and gated fixture process durations were 0.163685638 and 7.667949710 seconds. They include validation machinery and are not performance comparisons.

The subsequent [canonical release ls result](results/20261031-group-ls-a215c3aa.json) ([CSV](results/20261031-group-ls-a215c3aa.csv)) is FAILED: exit -9 after 30.189787353 seconds, with empty stdout and stderr. Terminal event, publication, admission and maps counts are unavailable, not zero. The complete four-stage sequence therefore failed. Its individually passing loop stage remains useful mechanism evidence. No completed-program time, speedup, aggregate timing or event savings are inferred from the failed prefix. Every subject was reaped; source and artifacts remained unchanged.

This result reinforces the structural gap identified by the [earlier CPU profile](persistent-dynamic-cost.md). The current owner still requires the original entry PC for warm reuse, rebuilds at other proved heads, and drains at unsupported frontiers. The next experiment must dispatch among retained, authenticated fragments and broaden useful frontier coverage while preserving original CALL return PCs, exact indirect-target membership, protected writes and fault recovery. Another increase in cold graph capacity cannot justify the approximately 263-ms target. Relative to this failed 30-second prefix, even an entirely event-proportional model would require over 99% of that overhead to disappear; that is a requirement, not a measured prediction.

Three preceding attempts remain failed in their original records:

| Source | Failure | Correction |
| --- | --- | --- |
| `cf1e888bfd42` | Build metadata omitted a decoder symbol that was present in the actual retained `nm` output; no subject launched. | Authenticate that provider from the complete retained symbol output. |
| `3039ab8b5db0` | The 89-page proof exceeded the existing 64-page private-query limit; gated target exited 125 before guest execution. | Retain two actual query receipts for 64 and 25 pages, preserving the API cap and complete proof coverage. |
| `4370711c27e8` | Both subjects exited zero, but the reader expected eight-byte alignment for three actual four-byte-aligned arrays. | Correct precisely those three alignment expectations; retain every offset, width, extent and state comparator. |

The failed [provider attempt](results/20261031T042130.611662Z-persistent-group-loop-cf1e888bfd42.json), [proof-query attempt](results/20261031T042926.517830Z-persistent-group-loop-3039ab8b5db0.json) and [layout attempt](results/20261031T043842.603119Z-persistent-group-loop-4370711c27e8.json) retain their complete prerequisite joins and CSVs. A subsequent [portable offline replay](results/20261031T045505.097942Z-persistent-group-layout-replay-d938497cad87.json) at `d938497cad87ed0f85ec02dd6576494ab78953c9` rereads the historical layout attempt, passes all complete-state readers and 162 negative controls, and launches zero targets. Its 4.821547971-second duration is reader time. It does not change the original failed receipt or substitute for the fresh native pass.

Reproduce on one externally reserved CPU, from a clean checkout at the stated source revision and fresh private output directories. Run `evaluation/inprocess/persistent_epoch.py`, then `persistent_dynamic.py` with its fresh fixed receipt, then `persistent_group.py` with both fresh prerequisite receipts, each using `--expect-revision a215c3aa8ab20bedc3900157f744d574ea46d230`. The exact argv is recorded in each JSON. After those stages:

```sh
python3 -B evaluation/inprocess/persistent_group_experiment.py \
  --revision a215c3aa8ab20bedc3900157f744d574ea46d230 \
  --output target/page-region-next/fresh-group-ls
```

For the historical reader diagnostic, first reproduce the failed group capture at `4370711c27e893a631cf246c496df26648e067ea`, preserving its private receipt and inputs, then checkout the replay revision and run:

```sh
python3 -I -S -B evaluation/inprocess/persistent_group_layout_replay.py \
  --root . --receipt "$closed_group_receipt" \
  --output target/page-region-next/fresh-group-layout-replay \
  --expect-revision d938497cad87ed0f85ec02dd6576494ab78953c9
```

Subject and reader limits remain 30 CPU seconds, 60 wall seconds, 512 MiB and 16 MiB output. The complete protected group capture remains below its original 4-MiB limit at 4,183,488 bytes. No failure, limit or qualification predicate was relaxed.

All six [required checks](results/20261031T045517.776955Z-checks-d938497cad87.json) passed at `d938497cad87ed0f85ec02dd6576494ab78953c9`: recorder 363; formatting; strict Clippy; workspace 4,089 passed, 0 failed and 37 ignored across 109 harnesses; all-targets/all-features check; serial 1,039 passed, 0 failed across 27 harnesses. Workspace and serial checks took 577.907843479 and 130.333981582 seconds. Rust/Cargo were stable 1.97.1, with four reserved CPUs. Source, configuration and cleanup checks passed. This revision adds only the standalone replay script to the native-tested source; runtime and qualification sources are unchanged. The subsequent hand-back commit contains only this report and result summaries.
