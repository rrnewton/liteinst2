# Compact read-ledger corpus

**All three attempts FAILED.** At revision `fd50d5ef02fd042fa4282cb83224d1b60900723c`, `read-chunks256-v1` completed all three LI2 reports under unchanged limits. No LI2 executable was produced: all 27 native rows remain **18 original/E9 PASS, nine LI2 UNOBSERVED**.

| Program | Selected jump/push/pop | LI2 core refusals / atomically withheld / emitted | E9 coverage / misses |
| --- | --- | --- | --- |
| cat | 751/111/146 | 88 / 920 / 0 | 936/1008 / 72 |
| head | 870/143/201 | 80 / 1134 / 0 | 1130/1214 / 84 |
| wc | 1228/177/240 | 135 / 1510 / 0 | 1544/1645 / 101 |

WC's canonical ledger is 69,541,898 bytes, streamed and hashed without an expanded file. Its compact plan and final ledger are each 2,408,844 bytes, plus a 767,933-byte table. The prior inline WC SIGXFSZ attempt remains FAILED_UNVERIFIED with unknown counts. Cat/head canonical hashes and complete ordered report rows equal their prior inline attempts; this storage change grants no additional emission or qualification.

[receipt.json](receipt.json) records physical/canonical identities, refusals, source, tools, commands and bounds. Shared grouping/storage fields apply to every program. In commands, replace each `argv_fragment` object with its named array from `commands.fragments`; all other arguments retain their order. [results.csv](results.csv) retains every case and input/expected identity: PASS requires exit zero, exact stdout and empty stderr; blank observed fields are unrecorded. E9's native matches do not satisfy full structural coverage. External CPU reservations are root-attested.

From a clean exact-revision checkout, follow the [corpus protocol](../CORPUS.md) and receipt commands: one release, one attempt per program, each with an external one-CPU reservation. Substitute local directories, fresh work/unit names and recomputed receipt hashes. Keep `--rewrite-profile jumps-gpr-stack64-block-upstream-v1 --ledger-storage read-chunks256-v1`, the complete base selection, all bounds, and the `li2core-direct-cat-` unit prefix. The 64 MiB file cap, 128 MiB aggregate ledger/staging envelope, 160 MiB functional reserve and slot ceilings are unchanged. Bootstrap wire use is unsupported.

[Prior failures](../grouped-upstream-result/README.md) and [correctness history](../ledger-chunks-validation/README.md) remain separate. Caller complete-code/ownership, helper scratch and zero-bias loader premises remain unproved. No broad native, complete-CFG, page-exemption or performance claim follows.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
