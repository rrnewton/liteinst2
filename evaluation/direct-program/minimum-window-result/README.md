# Minimum-window corpus

**All three attempts FAILED; no LI2 executable.** Revision `26cc9b7fc1760e1e63f38c3b4079dd9a76f19656` ran the min5 upstream profile with `read-chunks256-v1`: **18 original/E9 PASS, nine LI2 UNOBSERVED**, all 27 cases retained.

| Program | LI2 refused / accepted but withheld / emitted | Prior accepted | E9 coverage / misses |
| --- | --- | --- | --- |
| cat | 89 / 919 / 0 | 920 | 936/1008 / 72 |
| head | 86 / 1128 / 0 | 1134 | 1130/1214 / 84 |
| wc | 137 / 1508 / 0 | 1510 | 1544/1645 / 101 |

Some sites became locally accepted, but total acceptance fell by nine: **no aggregate improvement**. Atomic withholding and E9's 257 missing sites remain failures.

[receipt.json](receipt.json) retains identities, class/refusal counts, transitions, bounds, CPU/load and walltimes. Join every [cases.csv](cases.csv) row to its unique `(program,case)` fixture for input/expected identities; blank observed fields are unrecorded. PASS requires zero exit, exact stdout and empty stderr.

Shared JSON pointers resolve through the pinned [prior receipt](../ledger-chunks-result/receipt.json). Command parameter objects expand to literal per-program strings; member aliases and column tables are explicit. From a clean exact checkout follow the [protocol](../CORPUS.md), exact receipt commands and pinned recipes, reserve one external CPU, and use fresh work/unit names and receipt hashes. One release and one attempt per program ran; no retry/subset. All original limits and comparators remain.

[Correctness](../minimum-window-validation/README.md) is separate. Prior failures/unknowns, including inline WC SIGXFSZ, remain unchanged. Complete-code/ownership, helper scratch and zero-bias premises remain unproved; no complete-CFG, runtime exemption, broad native or performance qualification. Walltimes are correctness costs.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
