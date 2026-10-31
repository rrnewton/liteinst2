The cached `ls` startup still failed its original CPU bound. A fresh profile of the exact revision `22613d9b26f8be5438fe389d690feb221f62d3db` identifies repeated planning and validation as substantial costs. It does not establish a completed-program speedup.

The observer reused the actual release bridge, carrier and libraries from the [failed real-program run](20261031T185004.241929Z-direct-frontier-program-22613d9b26f8.json), on the same hard-reserved CPU 3. The target ended with signal 9. Its process-start-to-reap interval was 30.396641702 seconds, including held-preexec observer setup; `wait4` reported 29.032132 user and 0.962291 system CPU seconds. Its original limits remained 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB file/capture size.

All 2,895 samples at 99 Hz were loss-free and inside the observed exec-to-exit envelope. That envelope includes the launch Python process. The exact sampled user-IP partition is:

| Leaf group | Samples | Share |
| --- | ---: | ---: |
| Explicit planning/decode functions | 771 | 26.63% |
| `pe_bytes` | 680 | 23.49% |
| Compact-plan `project` | 479 | 16.55% |
| Other or unknown | 965 | 33.33% |

These are sampled user-CPU shares. Ancestor-based phases are retained separately and are not substituted for leaf costs or wall-time attribution. The raw sample, mapping and ELF joins were independently checked. The [JSON](20261031-real-ls-profile-22613d9.json) and [CSV](20261031-real-ls-profile-22613d9.csv) preserve the counts, exact revision, hardware, executable hashes and limits; [reservation evidence](20261031-real-ls-profile-22613d9-exact-cpu.json) records the actual hard CPU reservation and release. Raw perf data remains private.

The post-reap counter prefix records 18,944 linked ingress events, including 12,540 TRAP events; 9,606 cold attempts; 3,603 publications; 3,601 retirements; 5,497 completed generated entries; and 1,375 fresh maps reads out of 545,671 queries. These are independent prefix cells, not completed transactions or all kernel traps. Sampling changes the run, and this interrupted prefix cannot be compared with another interrupted prefix as completed work.

For the same sampled work mix, an idealized model making every `pe_bytes` operation free gives only `1 / (1 - 680/2895) = 1.307` times user-CPU improvement. Removing all three named groups would model 3 times improvement. Both calculations assume unchanged remaining work; neither predicts full-program completion or wall time. Consequently the reviewed word-load-only optimization is deferred. The next architecture experiment should retain compiled graphs across more working-set entries and dispatch typed cached calls/returns without draining and trapping at each such boundary. Stack effects, fault recovery, source/lifetime authority and all original qualification limits remain required.

The historical 10× DynamoRIO yardstick is 263.061 ms. There is no measured model placing this implementation within that budget. Original 392/522-instruction qualification, completed real programs and the same-host ten-run comparison remain unmet.

The [reproduction scripts](../real_ls_profile/README.md) distinguish the observed fixed-input run from a fresh input-binding successor. The observation used source packet `33872022293d805d792cb14c784408f67ba44d2bb2275231323d30a5ff32b1ed`, exact-CPU packet `7226b90e14f82b0637d8c137edfcfc3b6a24572d0bb285ee498e896f016fdfbd`, and closed private receipt `35ac01edad2518111df53ea4c4bab40347fda2ef0174f9da9ea3dcbdb49f7587`. Publishing an adapter does not change those observed identities or grant it execution credit.
