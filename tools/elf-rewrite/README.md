# ELF rewrite frontend

`liteinst-rewrite` applies the shared liteinst2 planner and artifact emitter to
explicitly selected sites in an ELF64 x86-64 input. It emits an inspectable ELF
candidate, its exact source edits, and complete per-site reports. The planner
handles B2, B1, T1, T2, and T3 through the same API; this tool does not replace
core instruction decisions with a fixture-specific instruction grammar.

## Prepare a candidate

From the repository root, after the workspace dependencies are locked:

```sh
cargo run --offline --locked -p liteinst-rewrite -- prepare INPUT_ELF SELECTION NEW_DIRECTORY
```

[SELECTION.md](SELECTION.md) specifies the strict input format. It binds the
complete original SHA-256, exact source and hook ranges, original entry facts,
target state layout, common load-bias domain, and prospective search/allocation
limits. A complete-entry declaration is a caller assumption, not a CFG proof
created by this tool. Unknown entry coverage refuses. Target state is explicit;
the build host does not supply implicit CPU or XCR0 authority.

The output directory must be new. The CLI rereads both inputs before creating
it, uses exclusive file creation with mode 0600, and writes `COMPLETE` last.
Exit 0 means a complete structural candidate; exit 2 means requested sites or
carrier placement refused and a report was written; exit 1 means invalid
input, format, identity, or I/O failure. A partial directory without its final
marker cannot be consumed. The CLI neither marks the candidate executable nor
runs it or overwrites the input.

The library entrypoint is `liteinst_rewrite::prepare(original, selection)`.
Its immutable `Product` exposes `files()`, `reports()`, and
`candidate_complete()`. `qualification_complete()` remains false. It performs
no executable mapping, live callback conversion, host probing, router
registration, or publication. It depends on the workspace's shared core and
[liteinst-artifact](../../crates/liteinst-artifact/README.md).

## Output records

`selection.txt` retains the exact selection bytes. `report.tsv` retains every
selected ID and its source geometry, tactic, candidate status, refusal code,
stage, and hexadecimal diagnostic text. Global input failures instead retain
all valid selected IDs in `input-failure.tsv` with the observed original hash.
No selected failure is removed from the denominator.

`target.tsv` records the explicit target state. `plan-ledger.tsv` retains source
reads/writes, original entry assumptions, actual store spans, allocations,
images, symbolic hook routes, restored boundaries, reverse-PC ranges, producer
address fields, and outstanding requirements. `ledger.tsv` records carrier
placement, original loader/dynamic ownership, and header/source changes.
`metadata.li2meta` binds original and selection identities; `source.li2sparse`
binds original identity and exact edit declarations.
Generated image files, the candidate ELF, and sidecars are hashed by
`bundle-index.tsv`; `COMPLETE` binds that index. Hashes provide integrity, not
trusted producer signatures or runtime approval.

The carrier preserves the original entry point and LOAD geometry, with
explicitly recorded ELF-header and selected-source edits. It appends a read-only carrier with a relocated
program-header table and separate RX image LOADs. The kernel or dynamic loader
can map these before entry without a new manual file mapper. ET_EXEC and
ET_DYN layouts are structurally supported; load-bias, early IFUNC/hook readiness,
CPU/XCR0, unwind/router integration, code-as-data assumptions, and actual
execution remain separate obligations. Artifact grouping and coalesced contexts
are not implemented by this frontend. Cross-site planning uses authenticated
original snapshots and refuses incompatible composition; it does not invent
new original decoding from already patched bytes.

Hooks must be authenticated original RX bytes in the same bias domain. The
emitter uses the symbolic hook ABI and producer field ledger, with bounded
relative-address checks. No address-like byte scan manufactures fixups. Every
emitter requirement remains explicit; structural success is not full A3
qualification. Normal-kernel-exec evidence must join the emitted artifact,
actual hook effect, native ABI, and full state under the intended load regime.

## Common-corpus site comparison

```sh
python3 -B tools/elf-rewrite/compare-sites.py SELECTION REPORT E9_SITES POLICY NEW_OUTPUT --policy-sha256 TRUSTED_POLICY_SHA256
```

The preserved comparator consumes one exact selection, this tool's complete
report, a complete machine-readable E9 inventory, and a separately pinned
policy. It retains E9 revision `0d5d36e4c4edcac37ca2499694d64302a391136f` and
strict original/selection identity, instrumentation, and selection-style
semantics. `POLICY` has exactly six fields: integer `schema: 1`,
`original_sha256`, `selection_sha256`, `e9_revision`, `instrumentation`
(`null` or `real-hook`), and `selection_style` (`jump-site`, `heap-write`, or
`forced-puzzle`). Duplicate, missing, or unknown fields refuse. The trusted
policy digest is supplied independently, not learned from the E9 report.

Every missing, extra, duplicate, or geometrically relabelled site refuses.
Lost E9 trampoline sites are listed and cause exit 2; traps remain a distinct
outcome. The output is a structural inventory, never an E9 or A3 execution pass.
The script does not launch E9, create a baseline, or certify application output.
Common-corpus production and native/runtime evidence remain separate.

The unchanged comparator calibration source is
`tests/compare_sites.py`: three positives and 24 required refusals, including
the original one-positive/five-refusal cohort. It can be run separately with
`python3 -B tools/elf-rewrite/tests/compare_sites.py` under the project's
bounded validation process. The Rust source retains all 62 carrier/parser and
11 frontend integration test functions, including every old assertion. These
source inventories do not claim a new test run. Historical outcomes and new
exact-source qualification are recorded separately.
