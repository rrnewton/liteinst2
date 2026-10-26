# Saved original-observation content audit

`audit_originals.py` reads a closed `observe_originals.py` run. It never launches
a program, imports repository code, accesses live `/proc`, or reads `target`.
It writes three new private files and returns zero only when all sixteen
mandatory cases pass every saved-content check. This source proposal has not
been executed. Original observation, audit execution, and caller admission are
separate events.

The finite subject is the two original ELF files prepared at
`ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05`. The observer originated at
`bab4df624f6ff51e0ae0c6c10cc5f4629fd1d4c8`; the actual observation and build
revisions are taken from their authenticated saved source maps. They must agree
with each other, while the preparation revision remains separate. The script
pins the reviewed observer, recipe, helper, build and complete original fixture
sources. It also rehashes every member of the observation's full source map,
checking saved owner identity and Git mode. It does not run Git or infer a
commit from the current working tree.

## Invocation and caller evidence

Run with assertions enabled, using a selected Python interpreter with Python
3.9 or later:

```text
PYTHON -B MATERIALS/evaluation/e9-common-app/audit_originals.py \
  --inputs /absolute/pinned-audit-inputs.json \
  --inputs-sha256 SHA256 \
  --raw /absolute/REPO/ignored/new-original-content-audit
```

The output path must be absent, have a canonical existing parent, lie under
`REPO/ignored`, and neither contain nor be contained by the observation run.
The input JSON has exactly these keys:

```json
{
  "schema": 1,
  "repo": "/absolute/REPO",
  "observation": "/absolute/REPO/ignored/closed-observation",
  "files": {
    "/absolute/named/input": {"bytes": 123, "sha256": "WHOLE_FILE_SHA256"}
  },
  "evidence": {
    "source_review": ["/absolute/closed-source-review-binding.json"],
    "build_review": ["/absolute/closed-driver-build-review-binding.json"],
    "parent_closure": ["/absolute/actual-parent-closure-observation.json"]
  }
}
```

`files` is a complete finite map, assembled before invocation. It must include
every record subsequently read: the observation summary/results/stage list,
hardware and whole source map; its original input JSON and all named inputs;
every mandatory stage's saved request, command, receipt, helper streams,
snapshots, result and capture index; every indexed capture; all eight static
inventories and their requests/receipts; selected independent build archives
and source members; preparation source/result/review records and originals;
selected runtime-owner files; and each explicitly named evidence record.
The original caller input file named by the observation's initial snapshot
must be retained as well as the observation's `inputs.json` copy. Unknown
read paths are refused. The same selected original runtime files must remain
available; no target product is substituted for an independent archive.

Each read opens a regular file without following a final symlink, checks its
canonical parent, records the opened-file and pathname device/inode/mode/size/
mtime/ctime identity, and verifies the whole bytes against the caller's pin.
Repeated reads and the final complete reread must preserve the identity and
bytes. Historical capture/input/source owner records are compared where the
protocol saved them. The auditor's own script and input JSON are checked
before and after the audit. Existing files are never overwritten.

The three evidence lists are explicit caller records, not self-issued
authority. The build review binding must equal the one in the original
driver-build admission. The caller must separately authenticate the meaning
of the source/build reviews, the actual closed-and-reaped parent observation,
and this audit's invocation and independent review. Matching a result or a
script hash alone does not prove which script ran. No particular future review
verdict is fabricated by this script.

## Independently checked saved content

All cases remain mandatory, in the recipe's exact order: unstripped then
stripped, each with empty, singleton, pair-reverse, equal-17, sorted-17,
reverse-17, duplicates-17 and mixed-64. No dynamic visit count can remove a
static site. The complete 87-head table is checked against three whole
original byte ranges, exact instruction bytes/lengths, transfer targets,
selection flags and static stack depths. Its two unreachable padding heads
remain present. Decoder mnemonic labels not used for selection remain bound
to the reviewed decoder and saved execution; this is not a general x86 decoder.

For every case the audit checks:

- The exact command, environment and limits; the strict thirteen-field helper
  receipt, whole streams, parent result and complete saved input/source maps.
  Eight complete static inventories retain both styles and both hook policies,
  with exact COMPLETE hashes and unchanged selected sites in `selection.txt`.
- The exact capture filename set, consumed input copies and owner records.
  There are `54 + selected_runtime_owners` regular capture files per completed
  case. The owner count is admitted separately and lies between two and sixteen.
- Every 40-byte ptrace event against the complete ordered PC stream: exec stop,
  breakpoint stop, each numbered single-step stop, successful exit event and
  terminal wait. There are exactly `steps + 4` events. Unexpected statuses,
  requests, step numbers, messages or extra events cannot disappear from a
  passing result.
- Both original marker CALL encodings and destinations, the exact finite
  original main bridge, the complete eight-byte breakpoint word with exactly
  one RET-to-INT3 byte substitution, and all 27 trapped/restored register words
  with RIP as the sole difference. Both raw XSAVE captures must be identical.
- Every legal next-PC relationship using the complete fixed instruction table,
  the real nested CALL/RET record sequence, callee return destinations and
  reconstructed stack movement, recorded callee RSP values, static frame depths,
  stack/red-zone bounds, per-head visit limits and the original formula bound.
  Conditional edges must take an original legal successor; intermediate flags
  are not saved and are not invented here.
- Exact ordered jump and heap projections, including repeated PCs; complete
  coverage rows, including zero visits; every store's call, base, index,
  effective address, value and old/new word. Replaying all store records over
  the captured before-middle page must produce the entire captured after-page,
  including every guard byte, and the exact complete sorted dataset.
- Complete before/after run and journal records. Both marker-entry records have
  phase 1 and an active empty journal; phase 2 and deactivation occur after
  `after_sort` returns. The final journal is exactly the inactive zero journal,
  stdout is the complete fixed dataset output, and stderr is empty.
- All saved exec/before/after maps, raw map-files path witnesses, FD provider
  records and selected mount records. Every file VMA joins an admitted ELF
  owner, device, inode, raw path, LOAD offset/bias and allowed permissions.
  Every main file-backed LOAD page joins the original owner and offset;
  anonymous BSS and all three guarded array pages retain their exact ownership
  and permissions. RWX and extra file owners are refused.

The observer's 60-second application deadline, per-dataset formula and
1,048,576 hard step ceiling are unchanged. Each observation request retains
60 CPU seconds, 90 wall seconds and 64 MiB output; its outer timeout is 100
seconds with ten seconds to kill and a 115-second parent backstop. The fixed
helper still has its original five-second descendant cleanup and the observer
its original two-second Drop cleanup. These are the separate application
observer's existing limits. The earlier tactic driver's 15 seconds and 20,000
stops are untouched.

## Saved evidence versus live assertions

The observer compared live RX mapping bytes and the bytes read at each
executed instruction PC against the original, but did not serialize those
reads. It also checked the actual restored eight-byte breakpoint word live;
only the original and installed words were saved, not a third restored-word
capture. These checks are not claims about arbitrary data-operand reads.
Intermediate complete registers, actual RSP and actual stack return words are
also absent. The saved callee-RSP and store-value rows are observer reports,
not extra raw register captures. This audit independently checks their
arithmetic, control-flow and memory-stream relationships. It does not pretend
to reconstruct the absent raw values. Live single-task and `/proc/exe`/FD
identity checks are likewise authenticated through the unchanged source and
closed execution; saved maps/provider records support the explicit content
joins above. These distinctions are carried in every output binding.

## Results and failure retention

`audit.json` retains all sixteen case names and their original recipe result
objects. A case can be `PASS_SAVED_CONTENT`, `CONTENT_MISMATCH`, the original
`FAILED` or `UNRUN`, or `UNCHECKED` following a global input error. Partial
capture indexes are retained when available. A failed or unrun mandatory case
cannot satisfy the denominator, and no retry or reduced selection is offered.

Top-level `PASS_SAVED_CONTENT` requires all sixteen case contents, exact
successful recipe closure and stable final owners. It records the separate
observation/build/preparation revisions, source-map and hardware hashes,
build/runtime admission hashes, all eight inventory COMPLETE hashes and
per-case capture-index, jump-stream, heap-stream and coverage hashes. On
failure the audit remains incomplete and exits nonzero while preserving the
known case rows. `read-inputs.json` records all opened input owners and hashes;
`binding.json` binds that map, the report, script identity and input JSON.
These files contain private raw coordinates and must remain ignored.

A later caller can construct its `CONTENT-AUDIT` admission from a successful
report, the actual audit invocation/review and the separate parent authority.
The report itself is not that admission. It supplies original observation
stream/memory evidence only: no architectural equivalence, manually mapped
replay, ordinary rewritten/E9 execution, performance result, exhaustive tool
qualification or full A3 claim is made.
