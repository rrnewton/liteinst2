# A2 composition foundation

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

A2 is not complete at this foundation. T1 and grouping have forced native and
architectural-oracle fixtures recorded in `evidence/a2-20261025.md`. T2/T3, coalesced independent
probe controls and the generated/sampled campaign remain pending. Generalized
puns retain first priority for install-once clients; ordinary relocation precedes
T1. Concurrent toggle visibility remains A4 work.
