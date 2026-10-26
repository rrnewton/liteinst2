# Reproduce the fixed consumer ordinary-planner parity comparison

These materials prepare requests, bind fresh artifacts and audit captures for the
same 72-row comparison as the published consumer parity result. They do not launch
a process. The five files under `harness/` are unchanged from that actual run.
The unchanged public `tools/unwind-oracle/bounded_command.py` owns every workload
and its descendant cleanup. There is no added supervisor, retry or case selector.

The required outcome remains 45 successes, 27 exact refusals, 59 generated images
per library, 334 corresponding raw files compared byte-for-byte, and 672 capture
files in total. One accepted comparator control and eleven required comparator
refusals remain separate. Both libraries receive the same actual observer pointer;
the observer and generated machine code are never called. This tests pure planning
and emission parity, not native publication, unwind behavior or performance.

## Fixed inputs and distinct source checkouts

Use a historical consumer checkout at
`be782c88f9f30581d67aa43aa20aa0a49062cd69` as `${REPO}`, and a baseline checkout at
`6e99b849513799a35e6be3827ad484e4c5521e6d` as `${BASELINE}`. The reporting checkout
may be newer: `${MATERIALS}` is the absolute directory containing this README and
need not lie in `${REPO}`. Do not substitute the reporting checkout for either
historical source epoch. `source-inputs.json` binds all selected original bytes.

The baseline's 29 README/source files remain exact. Only its Cargo manifest and
lockfile are replaced with the provided, previously used standalone overlays:
same package version and four dependency declarations, unique library name,
no workspace members or automatic tests/binaries. Its isolated build therefore
has `tested_revision: null` and the recorded original revision, not a fabricated
Git identity for the overlay. The entire 31-file input map is checked.

First obtain a new source admission, freeze and reviewed build in `${CONSUMER_RAW}`
using the existing instructions in `${REPO}/tools/unwind-oracle/README.md`. This
recipe requires that admission to name the exact clean consumer commit and its
70 selected files. No consumer runtime execution is required for the archive
input. Use the public adapter's existing tool/configuration freeze; do not replace
it with unrecorded PATH lookup. Retain its actual build audit and whole archives.
The historical result used retained old and new library archives; this fresh
reproduction records its own Cargo `fresh` values and artifact hashes, including
reuse within the new build. It does not inherit the historical result's credit.

`${RAW}` is a fresh absolute path under `${REPO}/ignored`, disjoint from
`${CONSUMER_RAW}`. Create only its sibling `${RAW}-control` before the first phase.
All new requests, copied sources, artifacts, receipts and captures stay within
that ignored root. The original input checkouts and materials remain read-only.

## Prepare and execute the fixed serial sequence

Independently authenticate `files.json` and use its SHA-256 as
`${MATERIAL_SHA256}`. Every invocation rechecks that exact material inventory.
Select `${PYTHON}`, `${TIMEOUT}` and `${HELPER}` from the actual consumer freeze's
`helper_python`, `timeout` and `helper` roles. Recheck the tool/runtime and Cargo
configuration records before and after each launch. Their recorded finite scope
is not a complete toolchain-closure claim. A permission-denied configuration
observation remains an explicit operation/errno observation, never hidden-content
or absence evidence.

`request-templates.json` contains fixed outer templates for `init`, the three
dependent preparation/binding phases, `audit`, and the separate pure controls. Substitute only the declared placeholders, as
JSON strings or whole environment objects, preserving all other fields and order
of argv elements. The environment for `init` is exactly the consumer freeze's
`environment` object. The environment for all later phases is exactly the
`environment` object written to `${RAW}/inputs.json`; its sole change is TMPDIR.
Do not shell-expand JSON text. Materialize `init.request.json` under the control
sibling and retain its reviewed hash before launching it.

| Order | Request | Purpose | CPU / wall seconds | Per-file cap |
| --- | --- | --- | --- | --- |
| 1 | control `init` | Check inputs; copy old sources; prepare requests | 20 / 30 | 16 MiB |
| 2 | `old-cargo` | Offline, locked standalone old library build | 60 / 90 | 128 MiB |
| 3 | `archive-old` | Copy/bind whole old artifacts and depfile sources | 20 / 30 | 128 MiB |
| 4 | `compile-request` | Bind both distinct dependency directories | 20 / 30 | 1 MiB |
| 5 | `compile` | Compile the unchanged parity harness | 60 / 90 | 128 MiB |
| 6 | `bind` | Bind the actual ELF, depfile and once-only request | 20 / 30 | 1 MiB |
| 7 | `run-once` | Execute all 72 required planner rows and controls | 20 / 30 | 16 MiB |
| 8 | `audit` | Compare all raw captures and earlier receipts | 20 / 30 | 1 MiB |

The first phase writes only the phase-2 Cargo request. Its captured result prints
the actual whole `inputs.json` SHA-256 and Cargo-request SHA-256. Wait for its
completed actual helper receipt and independently admit that receipt, request and
result. Only then materialize the fixed phase-3, phase-4 and phase-6 templates,
carrying `${INITIAL_INPUTS_SHA256}` from the original result and
`${ACTUAL_INIT_RECEIPT_SHA256}` from the actual receipt. No future receipt digest
is guessed and no extra executable stage is introduced. Phase 4 writes phase 5;
phase 6 writes phase 7. Phase 8 carries the same original tokens and the reviewed
actual binary record. Files are created exclusively; existing outputs refuse.
No phase runs the next one.

Every later state read authenticates the inputs before and after parsing, checks
the exact initial receipt/result/request, and repeats the authority check after
state-dependent work. Old-archive, compile, binary, independent-review and final
audit records retain that whole authority. A different otherwise acceptable
consumer freeze/build cannot replace the initial epoch: a changed input fails the
original digest; supplying a newly computed digest also fails the original init
result. Never refresh either initial token to make an intervening change pass.

For each row, `launch-contract.json` gives the exact existing-helper invocation,
output filenames and finite parent wait. The executable command has this shape:

```text
${TIMEOUT} --signal=TERM --kill-after=10s ${WALL_PLUS_10}s \
  ${PYTHON} -B ${HELPER} --request ${REQUEST} --receipt ${RECEIPT}
```

Use the existing finite caller with the contract's parent wait (`wall + 25`), the
exact request environment and cwd, and exclusive helper stdout/stderr captures.
For example, the 30-second phases have a 40-second outer timeout and a 55-second
parent wait; compiler phases retain 100/115. This is the same helper/caller
contract used by the recorded parity phases. No new waiting, signal or process
ownership implementation is supplied. Serial execution and pre/post admission are
mandatory; do not run a concurrent Cargo writer against the shared target.

Compiler flags, offline/locked mode, jobs=4, incremental=0, shared `${REPO}/target`,
profile/features and the absence of a CARGO_ENCODED_RUSTFLAGS override are retained.
The new archive-copy phase uses the existing build's 128 MiB file cap because it
copies complete rlibs; it is declared before any execution, adds no comparison
credit, and does not widen the 1 MiB binding/audit or 16 MiB planner limits.
Old/new Cargo records, exact full package IDs, locked ownership, target `src_path`,
depfile targets/prerequisites/environment records, build-script files and all whole
copied artifacts are retained and checked. No raw artifact is shipped here.

## Actual binary review and final closure

After phase 6, independently inspect the actual binary, ELF interpreter and needed
libraries, tool/runtime identities, all source/archive/dependency joins, and the
exact run request. Fill `binary-review.template.json` only after that review; its
report is hash-bound. This separate admission is required before phase 7. A
`INDEPENDENT_ACTUAL_BINARY_REVIEW_REQUIRED` binding is not permission to run.

After phase 7, materialize the exact audit request. The auditor retains the full
historical capture predicate block and adds whole-byte comparison and preparation
receipt checks. It cannot certify its own future helper receipt: its output status
explicitly leaves final helper closure pending. Independently inspect that final
receipt, helper stdout/stderr, request, parent result, output map and source/tool
pre/post observations before reporting the new reproduction as complete. Any
failed phase remains failed with its original request and captures; no retry,
missing-row exemption or pointer normalization is permitted.

Keep raw binaries, paths, captures and loader observations under ignored storage.
A new sanitized report must identify its own source admissions, actual artifacts,
commands, hardware observation scope, bounds and results. The existing historical
summary is immutable and is not retroactively rewritten by a fresh reproduction.

## V2 correction and separate pure controls

V1 was held before execution for two source findings: its header predicate omitted
the historical ET_EXEC/ET_DYN requirement, and the whole initial inputs file was
not carried as immutable authority. V2 restores that exact ELF type requirement
while retaining the existing ELF64/little-endian/x86-64 checks. It adds the initial
receipt/digest chain above. No old run is relabeled and no capture assertion,
corpus case, comparator control or existing stage/cap is removed or relaxed.

`calibrate.py` exercises the actual restored header predicate and authority-reader
functions using explicitly synthetic files/receipts. Its fixed inventory is three
acceptances and ten refusals: executable/shared-object headers plus the exact
initial authority; relocatable/core headers, changed coordinates/build digest,
replacement epoch, attempted digest refresh under the original receipt, mutation
during read or after a phase, and changed original receipt/request. These controls
run separately under 20/30/16 MiB and the same helper/caller. They neither claim a
real consumer build/helper invocation inside the fixtures nor add native/planner
credit. Preserve the original 72 rows and comparator 1+11 controls unchanged.
