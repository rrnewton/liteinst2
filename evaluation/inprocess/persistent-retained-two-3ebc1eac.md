# Two retained translated certificates

The opt-in retained-two profile keeps two immutable translated certificates, each with its own generation and completed permit. Every activation still reacquires source/rseq authority. Reusing an exact root avoids rebuilding its certificate; a classified miss preserves both slots.

At revision `3ebc1eacace8983bc8fe8a71d6b692d2c183d66b`, fresh fixed5, dynamic5, group2 and resident2 prerequisites passed before the new native/gated pair. The new pair compares 13 native frames across 12 instructions: A cold, B cold, two genuine ordinary misses, then A warm at the same generation. It observed two publications, one warm activation and zero interior signals. All 24 application, 109 owner, 10 pair and 70 terminal reader controls rejected their mutations. The extracted authority component passed its 5 positive, 40 refusal, 8 selection, 2 blocked-selection and 2 byte-corruption controls; these are separate from native execution.

The release `/bin/ls -d .` run **failed**, ending with SIGKILL after **31.477009822 s** Popen-to-reap wall time. Original limits remained 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB output. Source and cleanup checks passed. The sealed post-reap prefix contains:

| Event | Count |
|---|---:|
| Ingress | 45,835 |
| TRAP / SEGV / ILL | 31,854 / 13,870 / 111 |
| Fresh maps acquisitions / view hits | 16,541 / 794,513 |
| Offers / publications / warm entries | 7,516 / 3,385 / 736 |
| Classified cancellations / completed regions | 3,394 / 4,121 |

The prefix can stop between counter updates. It is not a completed terminal record; terminal and per-slot fields remain null. Different failed prefixes do not establish throughput or speedup. The target of completion within 10 times DynamoRIO remains unmet.

Both experiments used reserved CPU 3 on an AMD EPYC 9D85. Build recipes use `-O2`; exact hardware, archive/policy identities, bounds and commands are in [the numeric receipt](results/20261031-retained-two-ls-3ebc1eac.json), with [CSV counts](results/20261031-retained-two-ls-3ebc1eac.csv). Its reproduction command invokes `persistent_retained_two_experiment.py` with all five fresh qualification receipts; run each prerequisite on the same externally reserved CPU and revision. The separate native collector is `persistent_retained_two.py`.

Main was subsequently merged as `5ab09efb4c697c7f4f091e7efb52319ba0538c88`, with the identical tree `b06770ff7b8881bf59932ec38c03121b9741ffb5`. Two-slot retention alone leaves repeated traps and source/rseq, byte-check and protection work at activation boundaries. The next structural experiment is an active dispatcher lifetime across authenticated blocks; no performance estimate is claimed here.

All required checks passed on that merged tree: formatting, strict Clippy, workspace tests (4,113 passed, 37 ignored across 110 harnesses), and the all-feature/all-target build check. The recorder suite passed 364 tests; the serial launch suite passed 1,039 tests across 27 harnesses in 145.246 seconds under its unchanged 180-second limit. Source, configuration and cleanup checks passed. [Exact check receipt](results/20261031T075044.993785Z-checks-5ab09efb4c69.json).
