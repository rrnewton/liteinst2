# Bounded search evidence

The detailed relocation, generalized/prefixed pun, successor, neighbor and
coalesced planners report `SearchEvidence` alongside their existing metrics and
ordered attempts. The tactic engine retains this evidence for every attempted
leaf, including a leaf that succeeds before the outer bundle budget refuses it.
Candidate order, selected plans and raw refusal precedence are unchanged.

`AllocationUnavailable` alone does not identify why a search stopped. A policy
can reject a placement, a mapping budget can be insufficient, or a bounded
candidate schedule can end before examining another target. Clients should
report the raw refusal and the scoped evidence separately.

## Scope and termination

Each `SearchRun` names its domain: physical sites, victims, selected images,
victim images or joint pairs. Its scope identifies the source PC, fixed victim
target and prefix count when known. `examined` counts entered slots, including
duplicate or unavailable targets. `limit` is the configured bound; equality
between those two fields does not establish exhaustion.

| Stop | Established fact |
|---|---|
| `Accepted` | This domain found a result; an enclosing composition can still fail. |
| `DomainComplete` | The defined finite candidate schedule was covered. |
| `BudgetLimited` | A positive lower bound on omitted scheduled work is known. |
| `UnclassifiedBoundedStop` | The loop ended without a sufficient completion or omission certificate. |
| `Interrupted` | Qualification, another domain or a backend decision ended this run. |

The relocation generator preserves its original indexed slots. Its certificate
uses checked seed arithmetic to derive a permanent exclusive endpoint, and a
bounded search for an exact later `Some(target)` witness. That endpoint can be
later than the actual final usable slot. Failure to find a witness before the
endpoint remains unclassified. An omitted duplicate address still proves an
omitted slot, not a new feasible placement.

Pun target evidence covers the preferred address and the existing caller-ordered
page-boundary walks. It preserves both candidate caps, range order and
deduplication. An omitted distinct target is authenticated against that schedule;
otherwise the finite returned set covers it. It does not cover every byte address
in the displacement window. Neither certificate proves that a witnessed address
can be mapped, emitted or accepted by ownership policy.

Local `RefusalEvidence` separates established unsupported semantics, prerequisite,
resource-capacity, address-policy and backend decisions. Other decisions remain
unclassified. Failed earlier runs and reasons survive a later successful plan.

## Limits and validation

`classification_complete` is **false** in this implementation. Local certificates
are not a whole-tactic proof that no valid patch exists. Some nested searches
remain interrupted, and some early mixed resource/qualification gates lack a
narrower classification. Clients must retain these unknowns in coverage reports;
they must not count a refusal as a successful rewrite or infer complete address
exhaustion from a raw error.

Seventeen additive tests cover finite-domain equality versus cutoff, indexed
endpoint and witness boundaries, pun schedules, coalesced zero-work evidence,
leaf-success/outer-budget refusal and real T2/T3 search geometry. The eviction
cases preserve selected `NoPatchWindow` precedence, require the original ordered
attempts, and distinguish one-versus-two victim/pair budgets using required
positive controls. Forced-singleton completion is scoped only to its victim
domain. The earlier native contracts, oracle comparators and required outcomes
remain unchanged.
