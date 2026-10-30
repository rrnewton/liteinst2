# Offline ELF rewriting

The `liteinst-rewrite` tool uses the core tactic engine to produce an ELF
candidate, metadata and a sparse source overlay from one authenticated selection.
It accepts accurate original instruction locations and entry facts; it does not
infer those facts from arbitrary binary bytes.

```console
cargo build --locked -p liteinst-rewrite
./target/debug/liteinst-rewrite prepare program selection.txt new-output
```

The output directory must be new. The tool preserves the input file and writes a
complete result for every requested site. Exit 0 means a complete structural
candidate, exit 2 means a reported site or carrier refusal, and exit 1 means
invalid input, identity or I/O failure. `COMPLETE` is written last and binds the
output index. A directory without that marker is incomplete. Output files have
mode 0600; making a candidate executable does not discharge its runtime
requirements.

The [selection format](tools/elf-rewrite/SELECTION.md) describes the original
content digest, immutable source snapshots, legal entries, symbolic hook,
target state and finite search/allocation limits. The same engine chooses
B2, B1, T1, T2 or T3, or honors an explicitly forced tactic. A bounded search
failure remains a search failure. A conflicting selected site makes the whole
candidate incomplete and remains in the report.

For successive sites, the tool calls `engine::plan_with_emission_after` with
the original snapshot and the preceding `Composition`. The core authenticates
that snapshot against the composition's immutable originals, then uses current
overlay bytes for read expectations, pun suffixes and store padding. Instruction
heads, entries and relocated operations still come from the original decode.
Each candidate refuses to displace an instruction whose bytes an earlier step
changed, including for a replacing hook. The tool appends all returned steps to
a temporary composition and retains the existing byte-lock, allocation and
whole-selection checks before accepting them. Sparse expectations remain
relative to the original ELF.

The core also provides `quiescent::plan_adjacent_b2_with_emission_after` for
explicit joint planning of two adjacent observing, forward two-byte Jccs. It
tries an upper placement and then derives the lower pun window from that actual
overlay. Upper and lower image allowances remain cumulative, with a separate
continuation bound. Its ordered evidence retains refused attempts and omitted
targets; bounded failure does not establish global impossibility.

This artifact-only API accepts the original sites in lower/upper order and
returns two opaque members in upper/lower append order. Callers must commit both
members together, supply every external pending instruction, and check resources
for the complete predecessor plus pair. The returned memory and bundle budget
cover only the two new members. The explicit
`elf-disassembly-null-jumps-adjacent-b2-short-t3-pending-v1` frontend supplies
that transaction, pending ownership and whole-composition resource checking.
It tries each baseline once and publishes only a complete selection. Existing
frontend profiles remain available with their original limits.
[The validation receipt](evaluation/adjacent-b2/README.md) records frontend
controls and native state comparisons for two authored adjacent-Jcc layouts;
whole-program adjacent coverage remains unqualified.

## Three outputs from one plan

`candidate.elf` preserves the original entry and LOAD mappings, applies the
planned source edits, and adds a read-only program-header carrier and executable
trampoline LOADs. These file-backed images are mapped by the normal ELF loader.
The current carrier supports ET_EXEC and common-bias ET_DYN geometry. The
default places new pages above all original LOAD pages; explicit owned-neighbor
and adjacent-pun ET_EXEC profiles also admit images in unoccupied gaps. It uses
separate backing for each image; grouped aliases and signed or absolute
placement bridges remain open.

The dynamic inventory bounds relocation destinations and loader metadata before
source edits. Its COPY profile accepts ET_EXEC `DT_RELA` records with a named,
defined global object, zero addend, checked symbol/version metadata and a unique
readable, writable, nonexecuting destination. The symbol's `st_size` reserves the
destination footprint; it does not establish the external provider's copy length
or successful dynamic linking. Other COPY profiles remain explicit refusals.
Known GNU x86 ISA requirement bits remain unchanged in their original read-only
note. CET feature bits and unknown or malformed properties remain unsupported.

`metadata.li2meta` binds original-content identity, compatibility and every
selected-site outcome. Its chunk checks authenticate exact original ranges;
a checksum is not a verdict that an instruction is safe to execute.

`source.li2sparse` reconstructs the exact original-relative edits. Its validator
authenticates original identity, expected source bytes and complete affected
pages. Metadata validates compatibility and site outcomes; image ownership and
bytes are checked separately against the candidate ELF. Original identity is separate from patched-artifact identity.
A consumer must keep code gated and fall back to `RuntimeScan` when validation
fails. These codecs do not themselves install an overlay or grant admission.

The sidecars retain the shared plan's source dependencies, image bytes, fixups,
entry routes, PC mappings, limits and outstanding requirements. The symbolic
emitter uses target coordinates and a same-module hook; it does not serialize
build-process callback pointers or copy a live trampoline into the file.

## Static executable startup profile

The optional `offline-router` feature adds a bounded producer for the authored
checksum and RLE programs. `liteinst_rewrite::offline_router::prepare_programs`
requires both complete inputs, with 80/16 and 107/26 original heads/selected
instructions respectively. It retains the existing planning limits, prepares
each program once, and withholds both products if either preparation fails.
The `offline_router_sites` example publishes the pair with a complete directory
marker only after all bounded input rereads and member writes succeed.

The startup carrier retains the original entry and LOAD layout while adding a
checked interpreter and absolute bootstrap DSO dependency. Each product includes
`catalog.li2boot`, compiled from the accepted opaque plans and final ELF bytes.
It retains consumed-successor obligations for generalized/prefixed puns,
selected/victim neighbor relays, image ownership and unresolved requirements.
The catalog does not grant execution authority.

`crates/liteinst-bootstrap` is a separate per-product build, outside the default
workspace. Its normal build script requires a complete canonical catalog through
`LITEINST_BOOTSTRAP_CATALOG`; the main's final bytes precede the DSO build, avoiding
a content-hash cycle. The constructor uses the production router and sync-core
implementation, checks current file/map/target ownership, and exits with status
125 on error or panic without writing diagnostics. Its hidden completion object
and exported status function indicate constructor completion only.

The core activation API is explicitly unsafe. Its contract requires independent
artifact qualification and an admitted loader/dependency/constructor history,
unreachable main code before initialization, supported signal/stack/ISA behavior,
and unchanged mapping ownership through process exit. Current observations
cannot prove those historical or future conditions. Package verification must
check the actual linked DSO and dependency graph before native execution; these
source interfaces alone do not qualify that package or a whole-program run.

## Execution contract and remaining qualification

Every emitted image currently records `qualification_complete=false`. A target
state description specifies what the emitter saves; it does not prove that the
CPU and XCR0 permit those instructions on entry. The hook's ABI, readiness,
owned stack, entry completeness, code-as-data assumptions, router readiness,
CET and unwind requirements must also be satisfied before execution.

The initial native oracle uses an authored freestanding ET_EXEC fixture with
fixed application addresses, a null hook and a hook that records its logical PC
and call count. Its normal kernel-exec path and seeded CALL/RET window are a
bounded test, not admission for arbitrary programs or early dynamic-loader
execution. Results and exact commands belong in `evaluation/`; a source test
alone is not a result.

Full A3 still requires the fixed common E9Patch corpus with each successful site
retained or explicitly reported as a miss, all five tactics, physical grouping,
PIE/non-PIE and mixed shared-library loading, and native output, ABI, state and
unwind checks. Trap outcomes remain separate from trampoline successes. The
[site comparison tool](tools/elf-rewrite/compare-sites.py) checks an exact
inventory and pinned policy; its report does not certify that release gate.
