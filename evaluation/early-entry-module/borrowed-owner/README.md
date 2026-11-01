# Optional-entry borrowed-owner result

This checkpoint records the optional-entry owned-module implementation at
`e99b78a76d4e7162291f59aea74ffa0843b1d876`. The source change borrows an
already-owned interval owner while validating the callback boundary. It
preserves the four physical calls, optional entry admission, mandatory
authenticated returns and the existing comparisons.

native: PASS (recipe EARLY_ENTRY_MODULE_NATIVE_PASS; 4 attempts). strict: FAILED (recipe FAILED; 1 attempts). wide: PASS (recipe EARLY_ENTRY_MODULE_80K_QUALIFICATION_PASS; 12 attempts). Full workspace gate: UNRUN_NOT_ADMITTED.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.

The strict and separately named 80,000-step profiles share a planned
denominator of twelve cohorts, 288 pairs and 576 children. Both retain
640 witness words, a shared 15-second pair deadline and two-second cleanup.
Each campaign has its own recorded result and completed comparison count.
Produced CSVs are copied literally, including partial files from a failed
cohort; undispatched cohorts remain unobserved. The default-feature native
integration has four separate cases. This packet makes no timing or complete
A4/A5 claim.

[receipt.json](receipt.json) records the actual revision, command and recipe
pins, complete source-manifest hashes and counts, artifact profiles, tools,
AMD EPYC Zen 5 dev host model, affinity, load, capacity and all outcomes.
Reservations reported by the launcher are distinguished from observed
affinity. Raw logs and binaries remain private, with their complete receipt
authorities retained. Earlier [strict results](../receipt.json) and
[presence/80k results](../presence-80k/receipt.json), including their failures,
remain unchanged.

Reproduce on the recorded source checkout with the existing
[native recipe](../reproduce.py), [strict recipe](../state.py) and
[separate 80k recipe](../state_wide_80k.py), using fresh output directories
and one externally reserved CPU for each sequential campaign. The recipes
record their exact release profile and preparation commands. See
[WORKSPACE.md](../WORKSPACE.md) for the separate twelve-CPU workspace gate;
the receipt binds prospective commands and, only when the gate was
dispatched and CLOSED, its actual owner. Otherwise it records the sampler,
artifact absence and UNRUN_NOT_ADMITTED. No failed campaign is replaced by
a later result.

The receipt records the current fixed resource-admission decision separately
from the older denied admission. If the current sampler reports
NOT_ADMITTED, the full gate is UNRUN_NOT_ADMITTED: all five commands are
unobserved, with no execution, census, validation or landing credit.
ADMITTED alone is insufficient; a full-gate result requires its own CLOSED
evidence. Neither branch changes the strict-profile failure.
