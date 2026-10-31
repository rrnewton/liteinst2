# Resident construction cost and the next cache experiment

A loss-free per-thread profile at observer revision `cff913e09d4c225ec924323764f901797a640d90` sampled the retained `d402d96052fcdcdf1d3b0857b0bbd64d16cc06e3` release. `/bin/ls -d .` still failed with SIGKILL at its unchanged 30 CPU-second limit: **30.355201540 s wall, 27.958698 s user, 2.036903 s system**. This failed prefix is not a completed-program benchmark. The target within 10× DynamoRIO remains unmet.

The observer retained all 2,796 user samples across the complete command exec/exit envelope, including carrier startup, at 99 Hz on reserved CPU 16 of an AMD EPYC 9D85. Three leaf functions account for 53.11% of sampled user time:

| Function | Samples | Share | Observed operation |
| --- | ---: | ---: | --- |
| `li2_pg_plan_pages` | 574 | 20.53% | Includes clearing its 981,312-byte output. |
| `project` | 568 | 20.31% | Includes temporary guard clearing, unused-guard checking and compact output clearing. |
| `pe_bytes` | 343 | 12.27% | Full retained code/proof byte comparison. |

The source operations were located from actual sampled instruction pointers against the exact release ELF and its DWARF. These are leaf/source observations; the stored automated phase partition remains unchanged. Three leaf samples are unknown, and bounded observed callchains are not complete stacks. User sampling does not allocate kernel or wall time. The preceding lossy capture remains a separate failed observation.

The final sealed counter prefix records **47,904 events: 33,175 TRAP, 14,618 SEGV, 111 ILL; 18,749 fresh maps acquisitions, 850,167 maintained-view hits; 3,888 publications, 853 warm hits and 4,740 completed generated entries**. Terminal counters remain unavailable. This prefix reaches different guest progress from earlier failures, so the count differences are not completed-work reductions.

The measured cost motivates retaining compiled certificates across more than one root. The next experiment keeps two independent fixed-address certificates, permitting A→B→A construction reuse. Each actual additional hit avoids three cold planner calls, two compact projections and cold publication. Initial construction and replacement still perform every validator; every activation retains fresh source/rseq authority, permission closure and each full-byte comparison. Cache hit frequency and speedup are unmeasured, and unsupported-frontier traps remain. Even removing all three profiled functions could not close the remaining performance gap.

The compact JSON/CSV record exact hardware, commands, artifact identities, original limits, phase counts and timeline. Reproduce with `evaluation/inprocess/persistent_resident_profile.py` and the recorded closed resident release receipt under one external CPU reservation. `evaluation/inprocess/persistent_profile_controls.py --receipt <closed-v3-receipt.json> --output target/<fresh-private-output>` reproduces five exact binary-reader refusals without running the target or perf. Use the Python executable matching the recorded identity. Raw perf data and process logs stay private.

At observer revision `cff913e`, all six repository checks passed: 363 recorder tests; formatting; strict workspace Clippy; 4,089 workspace tests with 0 failures and 37 ignored; all-feature/all-target checking; and all 1,039 serial launch tests in 140.896 seconds under the unchanged 180-second limit. The portable reader-control run passed all five exact refusals. Source, configuration and cleanup checks passed. See `results/20261031T070353.202226Z-checks-cff913e09d4c.json` and `results/20261031-resident-profile-controls.json`.
