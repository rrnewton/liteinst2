# A2 composition and tactic engine

`composition::Composition` is a pure virtual overlay for ordered source rewrites.
It authenticates every member's reads against the preceding overlay, retains
original snapshots separately, and locks writes, displaced instructions, consumed
pun bytes and actual-store padding. A routed `0x62` marker also locks its entire
qualified 15-byte fetch span, including successor bytes outside the displaced
interval: changing those bytes could invalidate its illegal-encoding proof.
Later changes to locked bytes refuse; an
identical padding write is permitted. This makes a successor redirect available
to a later pun without treating already-modified bytes as original input.

`bundle::PlannedBundle::compose` accepts only trusted `PlannedInstall` values.
The resulting immutable `BundlePlan` records the original snapshots, ordered
member contracts, final snapshots, byte locks and aggregate memory accounting.
Members share one `CodeIdentity`. A cross-mapping identity set is not implemented.
Version 3 of the single-plan interfaces adds the distinct T1 prefixed-pun kind.

Full snapshot validation and lease coverage are separate from persistent byte
ownership. Publication still checks every consulted original byte and holds its
range. Persistent locks cover the bytes whose later modification would invalidate
the installed rewrite. Adding an overlapping probe requires replanning its whole
dependent bundle; composition does not silently replace a previous hook.

Publication stages every executable image and route before writing source bytes.
An allocation or route failure releases all staged images and reservations. The
publisher rechecks snapshots and the lease after staging. Each generalized or prefixed pun
still uses its explicit single byte/word/dword MOV, including authenticated
unchanged padding. All stores precede final permissions, sync-core and the bundle
receipt. A postwrite failure poisons the lease and retains the entire reachable
bundle. Source byte ownership is shared with the existing publishers.

Retirement requires all original dependencies and generated allocations to be
held with execution and saved references drained. It checks the final snapshots,
restores stores in reverse order, finalizes permissions and synchronizes before
releasing source ownership. Active-handle drop retains the bundle. Generated code
and immutable metadata remain allocated for process lifetime, as in A1.

Aggregate limits separately bound steps, mappings, virtual bytes, physical backing
bytes and virtual span. Ordinary composition uses one private allocation per
image. `PlannedBundle::compose_grouped` uses `grouping::GroupingPlan` to place
immutable images with disjoint page offsets into one sealed backing page,
mapped at every image's dictated address. Overlapping offsets receive separate
backing groups; multi-page images have explicit dedicated backing. Overlapping
virtual mapping extents refuse, including disjoint images in the same virtual
page. Arena packing within one virtual page remains later work.

Grouping is deterministic first fit and never re-encodes an image. Every input
image remains present. It counts mappings, virtual pages/bytes, backing
pages/bytes and virtual span separately. Both bundle and grouping budgets apply;
sharing cannot reduce the virtual mapping or page charges. Mapping count
describes allocation requests, not measured kernel VMA merging or RSS/PSS.

Backing files are initialized without a writable mapping, then sealed against
writes, growth, shrinking and further seal changes before RX shared aliases
are created with `MAP_FIXED_NOREPLACE`. Descriptors close after staging. Any
prewrite failure removes all staged aliases and reservations. Commit transfers
their lifetime to the same retained-code policy as ordinary bundles. Each alias
publishes only its own image's PC maps; another member's bytes appearing at that
alias have no authenticated execution entry. Mutable probe state is excluded
from these immutable backing pages.

`eviction::plan_successor` forces T2 successor eviction. It relocates one whole
5–15-byte successor into a callback-free image, preserving its original entry
through E9. The selected 1–4-byte instruction is then punned against that
redirect's bytes; T1 is available for lengths 2–4. The successor may lie beyond
the selected basic block but must remain inside the certified function and
entry scope. Both allocations, entries and dependencies join one bundle.

T2 decodes the authenticated original snapshot once. Its selected pun retains
that instruction identity while authenticating the preceding byte overlay,
including the successor's new E9. Unchanged tails of a long evicted instruction
are locked and never decoded as new application instructions. The original
successor instruction executes in its own image without adding a selected hook.
An original control-flow visit back to the selected instruction still invokes
that hook. Retirement restores the selected store first, preserving
any overlaid E9 padding, then restores the victim redirect.

Selected and victim allocation policies have separate bounds; aggregate bundle
budgets charge both mappings and backing. Detailed planning retains every
candidate/prefix outcome. A specific selected-site refusal survives later
unavailable victim placements. Each fallthrough traversal of the evicted
instruction adds its entry redirect and generated continuation jump, including
calls that never visit the selected hook. Timing measurements are later work.
The T2 API still evicts exactly one long successor and refuses shorter victims.
The separate chain API below does not change that contract or the ordinary
single-image planner.

`eviction_chain::plan_successor_chain` adds explicit bounded successor chains.
One selected 1–4-byte instruction is followed by at least one immediate original
1–4-byte successor and then the first whole 5–15-byte anchor. The anchor is
redirected first; each predecessor is punned against that preceding overlay.
One original decode supplies every instruction identity, and each member
authenticates the full current overlay. Auxiliary images add no hook; only the
selected instruction observes or replaces. Original branches can revisit the
selected instruction and therefore invoke its hook again.

`ChainSearch` bounds the number of short successors and total candidate work,
including suffix backtracking. A forced successor list must name the exact
immediate original path. Separate allocation policies apply to each successor,
while all images pay the existing aggregate bundle budget. Complete instruction
spans, consumed pun bytes and actual store padding remain locked. Publication
and retirement use the existing bundle transaction and process-lifetime code
retention. The five-tactic engine order remains unchanged; chains use this
explicit API rather than an implicit fallback.

Local search evidence retains failed suffixes and original refusal reasons.
A global cutoff requires a witnessed unentered candidate; reaching the cap
alone is insufficient. `classification_complete` remains false. The initial
qualification covers genuine depth-two/depth-three straight-line chains,
all declared original entries, and transaction failures. See
`evidence/a2-eviction-chains-20261025.md`. A separate 72-record legacy planner/emitter
parity gate passes with exact bytes, maps, contracts and diagnostics; the
integrated workspace passes its required checks. Additive native fixtures now
cover a short conditional backedge and a readable/protected-page load anchor;
see `evidence/a2-chain-branches-faults-20261025.md`. Chain grouping and broader
branch/memory families remain open.

`neighbor::plan_neighbor` forces T3. A selected 2–4-byte instruction receives
EB rel8 to a private relay at V+5 inside a whole 10–15-byte victim at V. The
victim's first E9 enters its callback-free image; the relay's E9 enters the
selected hook image. Original victim entries retain their behavior, and both
whole original instructions, including unchanged tails, remain locked. The
legal victim-start interval is S−131 through S+124, inclusive. The displacement
is measured from S+2 to V+5; the two E9 displacements are measured from V+5
and V+10, respectively.

T3 builds both images from the authenticated original decode. It composes source
members in descending physical-address order, with later reads authenticating
the preceding overlay. Both members use the internal Relocation contract;
the outer PlannedNeighbor and immutable geometry identify the multi-member T3
tactic. Publication stages both images and uses the existing quiescent bundle
transaction. Its two edits do not claim single-store atomic publication. The
source relay is generation-bound plan metadata, not an original legal entry or
process-lifetime reverse-PC registration. Existing asynchronous signal/unwind
limitations remain in force.

NeighborSearch independently bounds victim heads and total joint image-placement
candidate slots. Forced victim selection never substitutes another head.
Stage-specific attempt records distinguish qualification, victim placement,
selected placement and composition. Selected fallthrough adds EB, relay E9 and
a generated continuation transfer; victim fallthrough adds its entry E9 and
generated continuation. Original taken branches may bypass a continuation.

`engine::plan` provides one bundle result for all five install-once tactics.
Its preferred order is generalized pun, same-site/upstream relocation, prefixed
pun, successor eviction and neighbor eviction. A forced policy invokes exactly
one tactic. Every result pays the bundle budget, including single-image plans;
leaf successes that fail aggregate limits remain engine failures. The complete
ordered leaf attempt inventories and winning geometry/cost metrics remain
inspectable. Selected and victim allocation policies are separate. The outer
search performs at most five bounded leaf invocations and may repeat original
validation; it does not claim decode sharing or improved search performance.
RapidProbe remains the separate exact-byte toggle interface.

Detailed planners and the engine retain scoped search evidence separately from
raw refusal reasons. Finite completion and omitted-work certificates apply to
the existing candidate schedules; unresolved stops remain explicit. No
whole-tactic exhaustion claim is made. See `SEARCH-EVIDENCE.md`.

`quiescent::plan_coalesced` adds independent observing controls to one shared
relocation window. The existing certified-basic-block and entry rules apply.
`controls::ProbeControl` changes data outside immutable generated code and grouped
backing; disabling preserves every original instruction. Executable allocators
retain each control for the same lifetime as its code. The fork-shared arena
explicitly refuses controlled plans. A Boolean store requests enable state and
does not drain in-flight callbacks. See `COALESCED-CONTROLS.md` for the API,
ownership and process-local boundaries.

A2 is not complete at this foundation. T1 and grouping have forced native and
architectural-oracle fixtures recorded in `evidence/a2-20261025.md`. T2 qualification is recorded in
`evidence/a2-successor-20261025.md`. T3 and unified selection are recorded in
`evidence/a2-neighbor-20261025.md`. Coalesced controls are recorded in
`evidence/a2-controls-20261025.md`. Scoped search diagnostics are implemented;
whole-tactic classification remains incomplete. The fixed generated/sampled
campaign completed all 544 required outcomes; its successes, refusals, preserved
failed attempt and resource/memory observations are recorded in
`evidence/a2-campaign-20261025.md`.

Additional native entry fixtures execute actual direct branches and every
jump-table case into displaced heads, and witness kernel signal-frame restoration
to enumerated resumes. Exact signed rel32 endpoints execute; targets one byte
outside each endpoint refuse unchanged. See `evidence/a2-entry-paths-20261025.md`.
Five four-byte mandatory-prefix move forms now have forced B1/B2/T1 normal and
synchronous-fault evidence, with exact code/operand qualification and nearby
refusals. See `evidence/a2-mandatory-prefixes-20261025.md` for the bounded envelope.

A real prepublication signal frame now survives child-side publication and
returns through the kernel into every enumerated head. Actual CALL/RET paths
also preserve return addresses inside unchanged generalized-pun displacement
bytes. These bounded fixtures and their explicit lifecycle/relocation limits
are recorded in `evidence/a2-parked-call-20261025.md`.

An authored C++ exception now reaches its literal LSDA landing entry in the
original, installed and retired phases. The fixture also compares architectural state
across the relocated landing prefix and requires exact prepublication refusals.
See `evidence/a2-exception-landing-20261025.md` for the bounded envelope and the
fixture package's C++ compiler requirement.

Real kernel SIGUSR1 delivery and rt_sigreturn now have a bounded witness at
every restored-state instruction visit and owned return terminal of same-site
and upstream relocation fixtures. The physical kernel RIP is preserved, while
logical-PC lookup is checked separately. See
`evidence/a2-boundary-signals-20261025.md` for the exact native inventory and the
remaining asynchronous-delivery and unwind limits.

The full A2 exit gate remains open. Required gaps include broader exception
and generated-unwind support, active CET and Intel evidence, broader chain
qualification/grouping, arbitrary asynchronous signal delivery and generated
unwind qualification. Existing unsupported refusals and finite AMD results do not
substitute for those required fixtures. Generalized puns retain first priority
for install-once clients; ordinary relocation precedes T1. Concurrent toggle
visibility remains A4 work.
