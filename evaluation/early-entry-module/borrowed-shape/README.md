# Optional entry: borrowed shape checks

The strict 20,000-step qualification remains FAILED. The separately named 80,000-step profile is reported independently; it does not replace the strict result.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.

This owned selected-module profile keeps all four physical calls and mandatory returns while optional entry gates control sparse interval observations. The change reuses validated metadata only within one callback's exclusive borrow and preserves fresh journal reads and post-call checks.

At `32733a47e465a0109407c852ba7314cca5640e4a`: native: PASS (4 attempted); strict: FAILED (1 attempted); wide: PASS (12 attempted). Source/library checks: PASS. Full workspace gate: PASS. See [receipt.json](receipt.json) for exact statuses, including failed and undispatched cases, actual CPU model, tools, commands, reservations, load and capacity. This is correctness evidence on an AMD EPYC Zen 5 dev host, with no timing or completed A4/A5 claim.

Each state profile has a planned denominator of 12 cohorts, 288 pairs and 576 children. Successful pairs retain all 640 witness words and the original comparisons, 15-second pair deadline and 2-second cleanup. The two profiles differ explicitly in their instruction budget. Literal CSVs are retained for every CLOSED cohort that produced them, including failed cohorts; absence is not a pass. The receipt's file table is the complete produced-file list.

Reproduce at the recorded source revision with [the native recipe](../reproduce.py), [strict state recipe](../state.py), [separate 80,000-step recipe](../state_wide_80k.py) and [workspace recipe](../workspace.py). Use the exact normalized commands and environments in the receipt with fresh output directories and the recorded reservations. [WORKSPACE.md](../WORKSPACE.md) and [WIDE-80K.md](../WIDE-80K.md) describe those distinct scopes. Public recipes and historical private owners are identified separately by their source hashes; no new execution is attributed to a documentation commit.

Earlier failed attempts, full-gate failures and resource non-admission outcomes remain at the receipt's history links. Raw logs and binary witnesses remain private with their original pinned authorities; they are not replaced by this projection.
