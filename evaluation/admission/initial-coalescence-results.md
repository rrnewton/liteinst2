# Initial coalescence and compiler consumer results

Revision `6c79cacf74f470a451f3cdcc31cc827c36c2d1dd` passes the fixed qualification and the first compiler-produced C consumer. The new native controls require an actual original R/RX pair to merge after quarantine, preserve original RX source authority, and split/reclose the complete mapping table when an instruction runs. The compiled consumer uses the public runtime API and the unchanged generated ELF.

This is finite evidence for candidate claims 1 and 4, with the existing first-instruction and selected-instruction controls supporting claim 2. It establishes neither full B3/B4 nor the software-preemption claim 3. One freestanding static artifact is not evidence for general applications, thread/signal/JIT lifecycle coverage or useful-scale performance.

## Qualification

All four receipts bind the same 1,566-file source manifest, `f3be647338cc997c94ee46a376d1aacbb2dfb74420507fac007cc2c2257bdab7`, unchanged configuration and hardware. The full sequence inherited one unchanged eight-CPU reservation. Cargo build jobs were four, workspace test threads four, and the separate serial cohort used one; default-parallel repetitions supplied no test-thread override. Incremental compilation was disabled.

| Check | Result | Seconds |
| --- | --- | ---: |
| Recorder controls | 302 passed | 12.294 |
| Formatting | passed | 3.594 |
| Strict workspace Clippy | passed | 23.469 |
| Workspace tests | 1,984 passed; four unchanged ignored; 89 harnesses | 359.830 |
| All-feature/all-target check | passed | 13.074 |
| Serial launcher cohort | 904 passed; 27 harnesses | 99.947 |
| Default-parallel unit repetitions | 612 passed in each of four runs | 4.762, 4.714, 4.675, 4.721 |
| Default-parallel fork repetitions | seven passed in each of four runs | 0.285, 0.267, 0.273, 0.280 |

All 86 named native validation identities passed in the required workspace and serial cohorts. Each of the three new coalescence methods also passed in the four default-parallel unit repetitions. This does not mean every named native identity ran in that narrower unit cohort. All 14 qualification command cleanups completed with zero adoptees. Workspace elapsed time was only 0.170 seconds below its unchanged 360-second limit; this pass supplies no timing-margin or performance claim.

| Receipt | SHA256 |
| --- | --- |
| [Fixed six checks](results/20261026T234710.247009Z-6c79cacf74f4.json) | `df6415cf886a1de5906de15f10e4e92c0fb4d59562c9fa6245d39e1d7dc81137` |
| [Default-parallel unit](results/20261026T235543.184570Z-default-parallel-6c79cacf74f4.json) | `1226f1d7b3ba45fccdeb2d6db5b9182208781f01f4b03f25d1d8a18d684d885d` |
| [Default-parallel fork](results/20261026T235604.793095Z-default-parallel-fork-6c79cacf74f4.json) | `35d0354fe45ec2acbf3264450e9e2a3672d072c852e9dd4e17c92e093e884697` |
| [Compiler C consumer](results/20261026T235608.658654Z-runtime-consumer-6c79cacf74f4.json) | `6d7b99e919c81dcffa719fcbb11afc27a7f805f2ffb6d5cf71f3940a3389c8f7` |

## Compiler-produced C

Clang 22.1.3 and LLD 22.1.6 produced an 8,864-byte static native64 ELF, SHA256 `37a69af5dd1e0cc1ef6372f154ee91aa9a13980fce547569bdc609a27a160eff`. Its file-page-zero R segment and file-page-one RX segment are distinct original identities. The 31-byte text and linker padding were not patched. This is the same artifact hash as the earlier failed consumer.

The uninstrumented reference exited 7. Admitted execution made three provider calls: real getpid (39), gettid (186), and terminal exit_group (231), ending with code 7. Two returned-state comparisons and the identity chain passed. The retained journal contains three attempts, 24 raw waits, 15 state copies and fact counts 25/25/20, with zero journal failures. Archive preservation, unchanged artifact and physical writer cleanup all passed. The consumer process completed in 0.291 seconds; its eight commands all completed cleanup with zero adoptees, for 22 zero-adoptee command cleanups across the complete sequence.

| Consumer observation | Charged source bytes | Retained source bytes | Retained origins | History records |
| --- | ---: | ---: | ---: | ---: |
| Initial ready | 5,996,620 | 5,896,205 | 1 | 0 |
| First returned syscall | 12,496,941 | 12,372,096 | 3 | 15 |
| Second returned syscall | 21,324,859 | 21,175,584 | 6 | 37 |

These are the runtime's managed evidence-accounting metrics, not RSS or allocator metadata. The default 64 MiB lifetime source-fact ceiling and three-second operation/cleanup deadlines were unchanged. Retaining this much evidence for a small program is a scaling limitation.

## Preserved failures and interpretation

Five preceding qualifications remain failed in their original receipts:

| Source | First failure |
| --- | --- |
| `db0d90934fbe937e7803509125ac2aa6ee149372` | Six incorrectly qualified GateError paths during compilation |
| `d69f8a7684d0a3577e63c8ede367748425802506` | Two strict-Clippy manual_bits lints in byte accounting |
| `3ae69dd3d8da50b7975c201cb4c4a3419065ceb5` | New refusal oracle used a success-only observer after cancellation |
| `1c24ada14f296d10c8627f51ca731a8a65fb6ce5` | New prospective capture profile exceeded its own window-product limit |
| `260338fa41073f67f88f451d1de3548955dc94c3` | Existing kernel-refusal isolated child died with SIGSEGV |

Corrections preserved existing assertions, capacities, deadlines and cleanup gates. The cancelled-owner observer retains the original absolute deadline and independently checks the held stop, full state, whole maps/stack/pair and live pins. The capture refusal remains exactly one byte short: 20,479 versus a prospective 20,480. The final correction constructs the same three inline control profiles explicitly, avoiding generic array-construction temporaries. [Saved-binary inspection](runtime-selected-stack-inspection.md) documents a conditional stack-pressure risk; the fault location and historical crash cause remain unproved.

The earlier compiler [startup refusal](runtime-consumer-cleanup-results.md) also remains failed. Its actual post-quarantine maps were not retained, so the new actual-merge controls and successful same-artifact run do not retrospectively establish that old failure's cause.

## Reproduction and limits

Use the unchanged four-driver sequence in [initial coalescence](initial-coalescence.md#reproduction), with the exact revision above and the fixed-six receipt/digest in this report. The [consumer recipe](runtime-kernel-consumer.md) records the C source, compiler/linker commands and public API example. Receipts retain relative argv, tool/artifact/source hashes, typed observations and cleanup outcomes; raw logs and host paths remain private.

The recorded machine was an AMD EPYC 9D85 (family 26, model 17, stepping 0, microcode `0xb101066`), Linux upstream 7.1.3, Rust/Cargo 1.97.1, with eight visible/reserved logical CPUs and no effective capabilities. Exact tool and sanitized kernel identities are in the receipts. No Intel/topology breadth, general mapping support, complete source-head knowledge, fault transparency or throughput claim follows from this run.
