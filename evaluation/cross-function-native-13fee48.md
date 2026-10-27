# Synthetic cross-function native check

The focused two-owner T3 fixture passed at `13fee48dad74409e401dce4943de7dc6dc416625` on the AMD EPYC Zen 5 dev host. Its first attempt at `b11870928d88cfcb63499e24bfba6268ee15712d` failed compilation: the existing `deny(warnings)` rejected a direct function-item-to-integer cast. No native test ran in that attempt. The sole source correction inserted the compiler-recommended `as *const ()`; no warning suppression or test weakening was used.

| Attempt | Cargo / parent exit | Named test | Other tests | Operational time |
| --- | --- | --- | --- | --- |
| b118709 | 101 / 1 | Unrun: compilation failed | No harness execution | Cargo 1.671 s; parent 2.519 s |
| 13fee48 | 0 / 0 | 1 passed, 0 failed, 0 ignored | 70 filtered out | Test 0.21 s; Cargo 2.191 s; parent 3.022 s |

The exact named test uses synthetic JNZ/NOP/RET and MOVABS/RET functions with five complete original heads and two seeds. Its assertions require ten original, ten installed and ten restored traces, 27 ordered original visits, two selected-relay checks and eight installed entries with no callback. Including ten seed-initialization children gives 40 children by the executed source contract. There are no independent per-child capture files in this reporting packet. The shared oracle retains full GPRs, logical PC, defined flags except TF/RF, canonical XSAVE, data, application-stack/redzone and source/event-log checks; its existing lower private stack reserve remains explicit. This is not full common-app 87-head/176-case evidence.

Both attempts retain complete source/tools/config equality before and after, process cleanup completion and zero reaped descendants. Commands ran with four CPUs and four Cargo jobs, offline dependencies, 180-second command bounds and 8-MiB logs; their direct parents used 240-second bounds. Debug information was disabled; debug assertions and strict warnings remained enabled. Durations describe these operations and are not performance measurements.

The failed attempt remains failed. The successful focused case does not rerun or replace the earlier complete workspace/parallel validation. Full A3, live publication, arbitrary loader/CET behavior and global qualification remain incomplete.

[Exact data and failure retention](data/cross-function-native-13fee48/summary.json), [complete normalized commands](data/cross-function-native-13fee48/commands.json), [all source pins](data/cross-function-native-13fee48/source-files.json), [CSV](data/cross-function-native-13fee48/attempts.csv), and [reproduction instructions](reproductions/cross-function-native-13fee48/README.md) accompany this report. Raw logs and private inverse maps remain private.
