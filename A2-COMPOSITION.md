# A2 composition foundation

`composition::Composition` is a pure virtual overlay for ordered source rewrites.
It authenticates every member's reads against the preceding overlay, retains
original snapshots separately, and locks writes, displaced instructions, consumed
pun bytes and actual-store padding. Later changes to locked bytes refuse; an
identical padding write is permitted. This makes a successor redirect available
to a later pun without treating already-modified bytes as original input.

`bundle::PlannedBundle::compose` accepts only trusted `PlannedInstall` values.
The resulting immutable `BundlePlan` records the original snapshots, ordered
member contracts, final snapshots, byte locks and aggregate memory accounting.
Members share one `CodeIdentity`. A cross-mapping identity set is not implemented.
The underlying version-2 single-plan interfaces remain unchanged.

Full snapshot validation and lease coverage are separate from persistent byte
ownership. Publication still checks every consulted original byte and holds its
range. Persistent locks cover the bytes whose later modification would invalidate
the installed rewrite. Adding an overlapping probe requires replanning its whole
dependent bundle; composition does not silently replace a previous hook.

Publication stages every executable image and route before writing source bytes.
An allocation or route failure releases all staged images and reservations. The
publisher rechecks snapshots and the lease after staging. Each generalized pun
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
bytes and virtual span. This foundation uses one private allocation per image;
physical grouping is still pending. Mapping count describes allocation requests,
not measured kernel VMA merging or RSS/PSS.

A2 is not complete at this foundation. T1/T2/T3, coalesced independent probe
controls, immutable backing groups and the generated/sampled campaign each need
forced positive native and architectural-oracle evidence before their exit gates
can be reported as passing. Generalized puns retain first priority for install-once
clients. Concurrent toggle visibility remains A4 work.
