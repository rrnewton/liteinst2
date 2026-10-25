# Fixed A3 common-corpus reproduction

The [source and request recipe](../tools/e9-common-reproduce/README.md) stages the
exact historical inputs for the separately reported six-file B1 corpus. It
requires explicit local prerequisite artifacts with fixed hashes; it does not
fetch or publish the GPL reference implementation. The script writes requests
for the existing bounded helper and launches no workload itself.

Use the corrected `sparse-v4` variant for the 12 tool calls, 4 + 36 OS-loader
runs and separate 144-trace / 360-point / 768-page manual body oracle. Use fresh
`legacy-v1` and `untyped-v3` stages to retain the earlier calibration and compiler
failures. Their nonzero exits stay failures and prohibit later phases. The held
v2 source has no execution result.

This proposal has not executed the public recipe. Historical results remain
private source snapshots with null tested revisions, and the loader and manual
body measurements remain separate evidence. The bounded B1 subset is partial
support for systematic tactic validation; it does not establish full A3,
bootstrap/body state continuity, unwind, a preemption clock, page-admission
cross-modification freedom, or a general first-instruction capability claim.

The v2 source correction retains the held v1 proposal, requires the actual
unused-import/deny(warnings) compiler failure for untyped-v3, and pins operational
configuration/Python/runtime lookup owners instead of accepting unrelated copies.
Original preparation4/16 and added owner3/10 are separate controls, not new native
coverage. Full historical outcomes and source epochs remain unchanged.
