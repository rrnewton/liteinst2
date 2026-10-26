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

## Three outputs from one plan

`candidate.elf` preserves the original entry and LOAD mappings, applies the
planned source edits, and adds a read-only program-header carrier and executable
trampoline LOADs. These file-backed images are mapped by the normal ELF loader.
The current carrier supports ET_EXEC and common-bias ET_DYN geometry and places
new pages above all original LOAD pages. It uses separate backing for each
image; grouped aliases and signed or absolute placement bridges remain open.

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
