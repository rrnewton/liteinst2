# A2 bounded successor chains

This increment adds an explicit successor-chain API beside the
existing five-tactic engine. It does not change T2's one-long-successor contract
or the engine's preferred order. The source-bound private package and legacy
runtime parity pass on an **AMD EPYC Zen 5 dev host**. The integrated source
also passes formatting, warnings-denied workspace Clippy and all 28 focused
tests. Exact committed-head workspace receipts are recorded separately.

A genuine chain contains one selected 1–4-byte instruction, one or more
immediate original 1–4-byte successors, and the first whole 5–15-byte anchor.
The anchor is redirected first, then each preceding pun consumes the resulting
overlay. Original short-node windows miss their permitted target pages; the
successor edits enable those targets. These are dependent chains, not separate
T2 pairs. One original decode supplies instruction identity throughout.

Only the selected node has a hook. Every auxiliary image preserves its whole
original instruction without adding a hook. Original branches may still revisit
the selected instruction. Complete original spans, consumed bytes and actual
store padding remain locked. All images share the existing checked bundle,
generation and lease requirements, prewrite rollback, postwrite retention and
retirement rules. Generated code remains allocated for process lifetime.

`ChainSearch` bounds short successors and total candidate work; separate
per-node allocation policies retain candidate, mapping and byte caps. The hard
maximum is eight short successors. Forced lists
must name each immediate original successor through the anchor exactly once;
there is no alternate-path substitution. Failed suffix searches remain in the
attempt inventory. A global cutoff requires evidence of a next unentered slot;
local schedule completion does not establish whole-site impossibility, and
`classification_complete` remains false.

The private package passes compilation, scoped Clippy, **13 contract tests and
15 oracle-target tests**. The contract tests require nine accepted chain plans,
54 chain refusals and six separately counted legacy leaf refusals. They cover
local/global/depth/capacity limits, exact forced paths, entries and saved resumes,
CET/unsupported semantics, replacement planning and suffix backtracking.

The oracle target contains two native cohorts and all 13 inherited shared-helper
calibrations. Three required install/retire cycles exercise depth-two B2,
depth-three B2 and depth-two T1 with P1 at every short node. Every one of the
19 declared original heads runs under both fixed seeds: **38 original captures,
38 installed comparisons and 38 retired comparisons**, with six authenticated
selected-hook events and 20 auxiliary-entry comparisons without a selected
callback. Complete source pages and all 13 generated images are checked. The
callback deliberately clobbers flags, GPR, x87 and XMM state; the existing strict
architectural/memory comparator, masks and trace limits remain unchanged.

Separate failure cases require four `BeforeWrite` results, one occupied-address
planning refusal, and one `KeepGated` postwrite failure with a poisoned lease and
all five reachable images retained. The occupied owner bytes and staged-image
rollback are checked. These refusals are not counted as successful execution.
The postwrite case executes no source entry after failure.

Each cohort runs once in a fresh executable's main thread, with exact one-thread
censuses before and after. Bounds remain 20 CPU seconds, 30 wall seconds,
two seconds for cleanup and 16 MiB output; each trace retains its 15-second and
20,000-step caps. Cleanup retains the unreaped leader until owned process-group
cleanup completes and requires the final child inventory to be empty. This is
a scoped guarantee for the fixture's same-group fork tree, not arbitrary
escaping descendants. No retry, skipped positive or enlarged native bound was
used.

The private focused receipt is bound by audit SHA-256
`62e0c8f4090f7462475bd2b554b8028be3057431db8e4e2edcfd80dbf691dbc9`.
The integrated focused run repeats all 13 contract and 15 oracle-target tests;
its audit SHA-256 is
`52218b0b5250e80fe4515e6aa86d898390ed42f18d0ff74566823bea47874925`.
Independent semantic, documentation and boxed-error source reviews remain
separate from execution evidence; the final error-size review is bound by
`f15c506e4f5caa886330528146599ac582ecb93df1590b8b3911e169815624ab`.
The first Clippy failure for the new large error type is preserved. Boxing its
complete metrics fixed that gate without dropping diagnostics or adding a lint
allowance; it adds one allocation on failed planning. No performance improvement
is claimed.

Mechanical reversal recovers the complete original `quiescent.rs` and `lib.rs`.
The existing pun wrapper keeps callbacks enabled, no forced target and the same
search scope. The active exception-extended oracle and signal helpers are
preserved; the private helper's earlier snapshot is not an integration payload.
The separate runtime parity gate also passes 72 exact records: 45 required
successes and 27 exact refusals across B1/B2/T1/T2/T3, upstream relocation,
Observe/ReplaceFirst, leaf/engine APIs and preferred ordering. Both libraries
emit 59 images; all 334 capture files per side compare byte-for-byte, including
raw generated bytes, PC maps, complete contracts and search/attempt/error
inventories. Both use the same actual observer pointer, with zero observer
calls and no generated-code execution or pointer normalization. One positive
and 11 negative comparator calibrations remain required. This is planner/emitter
compatibility, not a substitute for the native chain oracle or active-head gates.
The parity audit SHA-256 is
`b31a2f22aa2648d6c0fce60dd5b41cefe40ddbad4e7b8eb7aa4ddaae46836237`.
Two harness compiler failures remain preserved: a dependency-directory binding
error and a denied function-pointer cast lint. Corrections changed the binder
and made the pointer conversion explicit; the planner fixture rows, expected outcomes
and comparator assertions stayed unchanged.

This finite straight-line cohort does not qualify native branch/fault chains,
chain grouping, generated unwind, asynchronous relocation boundaries, concurrent
publication, active CET, Intel execution or general search completeness. Those
requirements remain open. This increment does not complete A2.
