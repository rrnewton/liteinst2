# Stopped common-corpus run at 8bbf302

Revision `8bbf302e25d3af99dcba0adf465a691204d2ee0c`, AMD EPYC Zen 5 dev host, `dev-debug0-v1` (assertions and overflow checks enabled). These are correctness results, not performance measurements.

The completed work comprises 74 production stages, 192 whole-program output/journal cases, and two heap-write core-null cells: 352 instruction pairs, 704 children and 1,056 live state comparisons. Independent saved-content audits also passed for both cells. Units are reported separately in `numbers.csv`.

The run stopped before launching the third native cell: its valid candidate has generated ELF load segments before the original segments, exposing an obsolete prefix requirement in the validation runner and native replay helper. The four failed attempts remain in `receipt.json`, including an audit killed by SIGKILL (origin unproven), an exact signal-frame padding mismatch, and two preparation failures. Later passes do not replace those records.

Only 352 of 704 core-null pairs completed. All 2,112 recording pairs and the separate 1,408 E9-null pairs remain unrun in this cohort. This is neither full A3 qualification nor normal-loader evidence.

`invocation.json` records the report-generation command. `collect.py` regenerates these compact results from the retained, hash-pinned private metadata; raw captures and logs remain ignored. It does not rerun native validation. A fresh corpus reproduction must build the corrected native helper at its own recorded revision.
