# A2 successor eviction — 2026-10-25

This partial A2 milestone qualifies T2 on an AMD EPYC Zen 5 dev host. It adds
successor eviction to the previously reviewed T1, composition and immutable
grouping foundation. A2 remains open for T3, independent runtime coalesced
controls, the unified tactic search and the generated/sampled campaign.
Raw commands, logs, source hashes and review records remain under ignored/.

`eviction::plan_successor` preserves one whole 5–15-byte original successor in
a callback-free image, with E9 at its original entry. The selected 1–4-byte
instruction is then punned against that redirect. B2 and T1 are separately
forceable; success must use the requested tactic. The successor can lie beyond
the selected basic block, but must stay within the certified function and entry
scope. Both images and all dependencies form one quiescent bundle transaction.

Instruction identities come from one authenticated original decode. The second
member reads the preceding byte overlay; unchanged tails of evicted instructions
remain locked and are never redecoded as new application instructions. Publishing a
three-byte selected instruction uses one four-byte store that preserves the
preceding overlay's padding. Reverse-order retirement restores the selected
instruction before the victim redirect.
Both complete mapping extents and backing charges count against the budgets.

The bounded contract corpus has nine child scenarios. Required positives cover
all eleven victim lengths and all ten B2/T1 selected geometries, followed by all
64 cache-line offsets for those geometries: 620 successful offset cases and
20 crossing refusals. Twenty-one additional cases cross two executable pages.
Collision, stale-byte, lease and budget retries plus a separate replacement
case bring the total to 758 install/retire cycles, 9,093 native calls and 758
callbacks, with zero mismatches. There are 42 required planning refusals and
eight BeforeWrite refusals. Subprocess summaries are not extra Rust tests.

Every ordinary positive executes four declared body entries before publication,
while installed and after retirement. The replacement case executes its three
original heads in all three phases: INC RAX yields 43 from input 42 originally,
the replacement yields 99 while installed, and retirement restores 43. Executing
the replaced INC would instead yield 100 and fails the assertion. Direct victim
and RET entries preserve 42 without invoking the selected hook.

The independent native oracle has four normal fixtures with fifteen original
heads. Both fixed seeds enter every head: 30 installed and 30 retired
full-state/event comparisons. These include separate B2/T1 geometries, a victim
conditional backedge with exactly 32/31 selected visits, and a RIP-relative load
from controlled data outside the scanner's function snapshot. Eight direct
victim-entry executions add no selected hook. A separate seven-byte load victim
requires SIGSEGV/SEGV_MAPERR at address zero in two installed and two retired
comparisons, including logical fault PC and full state. That fault fixture stops
before its unreachable RET and does not claim hook-event counting at the fault.

The oracle's original masks, comparison code, six rejection calibrations,
20,000-step limit and 15-second per-trace deadline are unchanged. The SHR fixture
retains the stricter native full-flags comparison, including its ISA-undefined AF;
no mismatch was masked. Callbacks deliberately clobber scratch integer, flags,
SIMD and x87 state. Exact publication bytes, original tails, private storage,
ordered logical visits and event prefixes remain checked.

Review found two diagnostic defects, both corrected without changing expected
outcomes. Later unavailable victim placements must not erase a selected-site
NoPatchWindow refusal. Also, a victim placement failure now records no prefix
count, rather than falsely claiming a B2 attempt. Dedicated regressions retain
the exact intermediate inventory and final refusal. The initial failing receipt
is preserved privately. Callback documentation also distinguishes the hook-free
victim image from an original branch that naturally returns to the selected PC.

The bounded runner is `evidence/a2/run-checks.py`: four Cargo jobs, incremental
compilation disabled, one target directory, offline dependencies, and a
180-second limit per command. The four required workspace checks and nine
focused commands pass. Workspace results are 252 passed, zero failed and four
pre-existing ignores. Source and log hashes bind the local receipts to the
reviewed code. Independent review covers production and the oracle; the
contract author does not review their own fixtures.

This is finite native evidence under the existing unsafe caller certification,
quiescence and lifetime contracts. It does not establish recursive eviction,
all supported instructions or arbitrary control flow, concurrent toggle
visibility, Intel/CET qualification, asynchronous signal transparency or unwind
support. T2 reuses the bundle's existing postwrite poison/retention tests; it does
not add a T2-specific postwrite fault injection. Code and metadata remain retained
for process lifetime. An evicted instruction's fallthrough adds an entry redirect
and a generated continuation jump even on paths without a selected hook; original
taken branches may bypass the continuation. These are transfer counts, not timing
or workload performance measurements.
