# Trusted disassembly: null jump sites

`elf-disassembly-null-jumps-v1` is an additive artifact-only frontend. It accepts
an exact original ELF, a separately trusted complete instruction ledger, and
fixed target/search/allocation policy. It selects every decoded `j*` instruction
in address order, including indirect and unreachable jumps. CALL, RET and LOOP
are not `j*`; this matches the existing common-sites classifier. Unsupported
selected or displaced instructions remain in the denominator and face the
unchanged core refusal rules.

This route does not recover functions or a whole-program CFG. It does not need
symbol names, one `.text`, an acyclic call graph, a 64 KiB enclosing kernel, or a
whole-function RSP proof. It does require accurate complete code locations with
no overlapping streams and no code-as-data. Hashes and decoding cannot establish
those external premises. Omitted code not contradicted by a known original
entry/branch cannot be discovered by this importer.

## Inputs and exact scope

The ledger is ASCII, single-space separated, LF terminated, at most 1 MiB. Its
first three lines are exact (SHA values are lowercase):

```text
LI2DISASM 1
original WHOLE_ORIGINAL_SHA256
contract complete-code no-overlap no-code-as-data private-image
```

They are followed by one or more region groups:

```text
region VA FILE_OFFSET BYTE_LENGTH
head VA LOWERCASE_INSTRUCTION_HEX
head NEXT_VA LOWERCASE_INSTRUCTION_HEX
```

Regions are nonempty, ordered by VA and disjoint. Each is uniquely backed by
original RX, non-writable file bytes with exact inverse translation. Heads must
cover each region contiguously, with 1..15 bytes each. Every byte and boundary is
checked against an independent iced-x86 scan of the entire region. The full
original SHA includes headers, data and gaps; data gaps are preserved, never
invented as padding or decoded code. Regions may be separated and need not
follow symbol/function boundaries. Every original executable stream must be in
the trusted ledger. A nonzero ELF entry, and every known direct target inside
an original executable LOAD, must be a declared head. External targets and
indirect control flow require no whole-program recovery.

Each region is lowered to an **artifact code-region ownership scope**. The
legacy `function` columns in the generated LI2TOOL projection name that scope,
not a recovered function. Every verified head is a legal entry, with ENDBR
requirements retained. In memory the sealed selection uses
`EntryCompleteness::AllInstructionHeads`; the projection spells the equivalent
exhaustive all-head list with the unchanged parser's `complete` token. Resumes
are `NoneExist` only under the declared private, unexecuted-image contract.

Blocks are conservative straight-line intervals, cut after every non-Next
instruction and at every declared direct target. All-head entry obligations
still apply at other heads; unknown indirect entries are not omitted. The
artifact core uses the region for source and eviction containment. No
foreign-function catalogue, coalesced/whole-function API, live InstallRequest,
publication receipt or callable address is exposed by this frontend.

## Fixed policy

Policy is also ASCII/single-space/LF, at most 1 MiB. Header order is fixed:

```text
LI2DISASM-POLICY 1
original WHOLE_ORIGINAL_SHA256
ledger TRUSTED_LEDGER_SHA256
target fxsave64
domain DOMAIN
carrier CARRIER_VA
limits INPUT SITES IMAGES IMAGE_BYTES LOAD_PAGES OUTPUT ADDED PHDRS SPAN
null-hook ORIGINAL_C3_VA
```

`target xsave64 ...` is also available with the unchanged
[selection format](SELECTION.md). The hook must be an independently verified
one-byte original C3 head. No hook is synthesized or appended. Its exact bytes
are authenticated again, checked against dynamic writes, and protected by the
existing complete composition/hook-write check. Its eventual ABI, CPU/CET,
loader and writable-stack readiness remain external obligations.

After the header supply exactly one search record and two allocation records
per jump ID (IDs are 1..N in ascending VA). Their syntax and limits are exactly
those in SELECTION.md:

```text
search ID TACTIC UPSTREAM DISPLACED SITES FORCED_VICTIM_OR_none VICTIMS PAIRS
allocation ID selected PREFERRED_OR_none CANDIDATES MAPPED_BYTES START:LENGTH ...
allocation ID victim PREFERRED_OR_none CANDIDATES MAPPED_BYTES START:LENGTH ...
```

No `site`, entry, function, block, resume, replacement or subset override exists
in this policy. Missing, duplicate and extra records refuse. Search/placement
permits and their independently supplied policy digest must be fixed before
planning; no retry, result-selected permit, or alternate batch is performed.

All existing hard ceilings remain: input 256 MiB, generated selection 1 MiB,
1024 sites, 4096 images, 64 MiB image bytes, 65536 new pages, output 512 MiB,
4096 PHDRs, 16 ranges per allocation, and the original search/placement caps.
Repeating region heads in the legacy projection may reach its existing 1 MiB
cap first. Exceeding any whole-program limit is a whole-program refusal, not a
reason to omit sites, split batches or claim corpus fit. A zero-jump program is
explicitly refused by the existing nonempty selection contract.

## Library and one-attempt example

`disassembly::import(original, ledger, expected_ledger)` returns sealed verified
locations and the complete jump inventory. `Disassembly::bind(policy,
expected_policy)` derives the selection and invokes the unchanged strict
LI2TOOL parser. `prepare_disassembly(original, &selected)` uses the same
post-parse planner, source composition and carrier body as `prepare`. It adds
hash-bound profile/input/inventory files to the output index. Both old prepare
entrypoints, parser, common_sites and comparator remain unchanged.

After review and under the repository's bounded build procedure:

```sh
cargo run --offline --locked -p liteinst-rewrite --example disassembly_sites -- ORIGINAL LEDGER LEDGER_SHA256 POLICY POLICY_SHA256 NEW_DIRECTORY
```

This example is one preparation attempt, not a corpus runner. It rereads all
inputs before dispatching the result, exclusively creates a private directory,
writes non-executable files and a distinct `LI2DISASSEMBLY-DIRECTORY` COMPLETE
index last. A partial directory is not consumable. A verified inventory survives
policy/global refusal; invalid ledgers retain the program refusal and attempted
inputs without pretending to have a verified denominator. Argument/read or
input-drift errors exit 1 without a COMPLETE marker. Callers must retain those
failed program attempts as well. No automatic retries occur. Exit 0 denotes
only a structural candidate; exit 2 retains a refusal. Both remain explicitly
`qualification_complete=false`.

The generated `selection.txt`/`report.tsv` can use the unchanged exact-site
comparator with an independently frozen null/jump-site policy and complete E9
inventory. The new profile and input hashes must remain attached; old heap-sort
runtime recipes do not become general-corpus validators.

Eight additive `disassembly::tests` controls use fabricated ELF/ledger bytes and
actual importer/binder/shared preparation helpers. All old tests stay required.
Their prospective command is `cargo test --offline --locked -p liteinst-rewrite`;
source proposal authoring did not run it. Actual loader execution, output/ABI/
full-state/unwind preservation, real hooks, heap writes, grouping, broader
corpus fit and performance remain unqualified.
