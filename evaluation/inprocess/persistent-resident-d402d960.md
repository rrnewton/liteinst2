# Resident register-jump experiment

Claims 1 and 4: generated execution now dispatches register-indirect jumps to exact proved heads within one held source/rseq lifetime. Unknown targets drain before the original JMP executes. This opt-in resident profile accepts 1–128 heads; the previous two-image profile and its qualification remain available unchanged.

At revision `d402d96052fcdcdf1d3b0857b0bbd64d16cc06e3`, all four fresh native stages passed on reserved CPU 3 of an AMD EPYC 9D85 (family 26, model 17, stepping 0, microcode 0xb101066): fixed5, dynamic5, original group2 and resident2. The resident pair matched the full 271-instruction reference, including six architectural links, one known-head dispatch and one unknown-target exit. It observed one generated activation, zero interior signals, all 17 code pages closed, and the genuine next ordinary TRACE. All 20 application, 81 owner, 6 pair and 63 terminal controls passed. Existing group267 retains all 162 controls. Source and cleanup checks passed.

This establishes the finite mechanism. It does not qualify resident faults, nested signals, partial cleanup, or whole-program execution. Architectural dispatch counts come from the original program and complete state/event comparison; they are not inserted runtime counters. The two pure component checks at `4cd09ba2` are separately recorded in `results/20261031-resident-pure-4cd09ba2.json`.

The canonical release `/bin/ls -d .` still failed: exit -9 (SIGKILL) after **30.159144221 seconds process wall**, under the original 30 CPU-second limit, with empty stdout/stderr. The original 60-second wall, 512 MiB address-space and 16 MiB file limits are unchanged. Its usable sealed counter mapping supplies the following final per-cell prefix; terminal counts remain null.

| Final prefix event | Count |
|---|---:|
| Events | 47,625 |
| TRAP / SEGV / ILL | 33,040 / 14,474 / 111 |
| Fresh maps acquisitions / maintained-view hits | 18,879 / 847,489 |
| Cold attempts / cancelled | 7,830 / 3,917 |
| Publications / warm hits | 3,912 / 853 |
| Entries / completed | 4,765 / 4,765 |
| Retirements / permit claims | 3,911 / 4,764 |
| Root unsupported / outside pair / link limit misses | 3,148 / 202 / 567 |
| Native admissions / closed | 250 / 250 |
| Differential comparisons | 0 |

An in-flight operation can split counter relationships; these values are not normalized. The earlier failed group run and this resident run stopped at different guest progress, so their count differences are not completed-work reductions or a speedup. The target within 10× DynamoRIO remains unmet. Publication frequency suggests a useful question for the next profile, but event counts alone do not attribute CPU time.

Reproduce on the exact revision using one `cpuset-alloc run --cores 1` reservation throughout: run `evaluation/inprocess/persistent_epoch.py --expect-revision REV`, then `persistent_dynamic.py` with that fixed receipt, `persistent_group.py` with both receipts, and `persistent_resident.py` with all three. Finally run `persistent_resident_experiment.py --revision REV --output target/page-region-next/NEW --fixed-receipt F --dynamic-receipt D --group-receipt G --resident-receipt R`. Invoke each with `python3 -B`. Each committed JSON provides the reproduction argv, hardware, original bounds and exact artifact identities; the scripts verify all prerequisite joins. The release build uses the source-owned `build-persistent-resident-counters.sh` recipe and the four-feature release decoder archive.

The preceding `1d34ca3` attempt remains failed before any guest launched: the unchanged namespace test rejected unsolicited `None` counter keywords. The carrier correction restores the original ordinary invocation and retains explicit counter validation. No test or bound changed.

Repository checks on d402d960: fmt, strict workspace/all-target/all-feature Clippy, workspace tests (4,089 passed, 0 failed, 37 ignored), all-feature/all-target check and recorder (363 passed) passed. The extra serial check first timed out at its unchanged 180-second deadline after 804 observed passes and 0 assertion failures; the complete attempt remains failed in `results/20261031T062601.675979Z-checks-d402d96052fc.json`.

One focused rerun of the identical full serial command passed all 1,039 tests across 27 libtest harnesses, with 0 failures/ignored/filtered, in 154.346965997 seconds. It used four reserved CPUs (15, 35, 50, 80), unchanged source/toolchain/configuration and all 28 executable hashes stable before/after. Child CPU accounting was 38.012584 seconds user and 49.431630 seconds system; cleanup passed. The earlier eight-harness subtotal was 105.26 seconds versus 80.56 in the previous successful revision; this run's subtotal was 79.47 seconds. These observations establish variability, not its scheduler or kernel cause. No source, test, timeout, assertion or corpus changed for the rerun. `results/20261031-serial-d402d960.json` preserves the separate diagnostic and exact command; it does not relabel the first six-check attempt.
