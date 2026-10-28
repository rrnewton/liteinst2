# Coalesced observing controls

`controls::ProbeControl` owns an immutable callback and a mutable atomic Boolean.
Clones share one identity and enable state. `ControlledAction` pairs that control
with an original instruction head. Distinct actions in a coalesced image require
distinct control identities, so changing one callback's state cannot implicitly
change another callback's state.

`quiescent::plan_coalesced` plans one relocation window containing every action.
It requires observing semantics, a nonempty action list in strictly increasing
original-PC order, and a first action at the request's logical PC. Every action
must lie inside the caller-certified basic block and function. The usual source,
entry, saved-resume, ISA, allocation and byte-ownership checks still apply. The
window cannot contain an interior control transfer. The planner may search
upstream within the existing bounds; it cannot cross a block boundary to fit an
additional action. The actions supply callbacks, and this forced relocation API
does not use the request's single callback or tactic-selection preference.

The resulting trusted `PlannedInstall` uses the existing bundle composition,
quiescent publication and retirement path. Overlapping additions still require
replanning the entire dependent bundle under a new lease. Runtime controls do
not authorize rewriting a byte owned by an earlier probe. Conditional replacement
is outside this API: the original instruction executes whether its observing
callback is enabled or disabled.

The lower-level `TrampolinePlan::from_controlled_actions` also supports internal
direct branches under its existing caller contract. A branch to a logical action
visits that control on every visit, including backedges. This does not certify
the branch-containing region as a basic block for `plan_coalesced`.

## Complete scalar functions

The explicit unsafe `plan_whole_function_controlled_detailed` API accepts a
`WholeFunctionRequest` for one complete read-only scalar function of 5..=80
bytes. Its actions are the entry followed by every reachable ordinary `RET`,
with distinct controls. It checks a closed CFG with direct internal branches,
no calls, no entry backedge, no falloff, and only original NOPs in unreachable
padding. It relocates the complete function into one image, retaining all
internal entry routes and source obligations. The existing 256-candidate,
one-mapping and 8192-byte limits apply.

The caller must independently authenticate the complete function and sole
external entry, exclude saved or foreign interior entries, and satisfy the
existing callback, signal, lifetime and quiescence contracts. Decoding cannot
prove those premises or termination. The `_after` variant authenticates the
predecessor's original bytes and current overlay before searching. Internal
branches enter the generated destination before its control; returns execute
their original `C3`. The appended end stub is retained and checked unreachable
from the admitted entry. The basic-block APIs retain their original refusals.

For an admitted profiler owner, `OrdinarySitePreparation::new_whole_function`
selects this policy and supplies permanent entry/RET observers. The constructor
retains the same complete source-page, gate, publication and ownership checks.

## Enable state and completion

`set_enabled` performs a release store; dispatch reads the Boolean with acquire
ordering. The emitter saves the complete supported application state before the
dispatcher reads the control. Disabled actions therefore still pay the full
save, dispatch and restore cost. This is not a measured cheap inactive path.

The store requests the state used by a future dispatch. A dispatch that already
read `true` may invoke or finish its callback after disabling returns. Reading
`is_enabled` reports the Boolean; it does not drain a callback, establish
quiescence, or provide a completed sampling-epoch receipt. A4 must separately
qualify concurrent visibility, in-flight intervals and completion.

## Immutable code and lifetime

Controls occupy separate heap storage. All emitted code, original/generated PC
maps and sealed grouped backing remain unchanged as controls change. Grouped
images contain their own control pointers even when their disjoint image offsets
share a physical backing page. Each alias retains only its own authenticated
entries and PC maps.

Pure plans and images retain ordinary reference-counted handles and release them
on drop. The supplied private and grouped executable allocators retain controls
for the same process lifetime as their executable code, including active-handle
drop, retirement and postwrite failure. Unpublished rollback releases those
references only after successfully unmapping the code. A custom allocator that
copies `TrampolineImage::bytes()` must itself retain the image's controls for
the entire executable-code lifetime.

Controls are process-local. Fork inherits a snapshot; the parent and child do
not share later enable stores. The fork-shared `TrampolineArena` refuses controlled
plans before reserving a slot or writing bytes, because it can publish newly
created heap pointers into a process that never inherited those objects. Static
arena plans remain supported. Controlled private or grouped code must not be
published into another process through an external alias.

`ProbeControl::payload_bytes()` reports the control payload only. It excludes
reference-count bookkeeping and allocator overhead, and each distinct identity
must be counted once. It is separate from executable virtual/backing charges.

The finite native and architectural qualification is recorded in
[`evidence/a2-controls-20261025.md`](evidence/a2-controls-20261025.md).
