# Ordinary candidate execution

`run_candidates.py` runs the fixed common application's candidate files as ordinary processes. It checks exact sorted stdout, empty stderr, and every byte of the bounded journal against independently audited original observations. It does not attach a tracer, seed registers, repair state, compile, query a target, or claim architectural equivalence. Actual process mappings and complete dynamic-loader/configuration closure are outside this recipe's scope. Durations are operational diagnostics, not benchmarks.

Commit this recipe with the build and observation recipes before collecting their evidence. The active tracked tree, actual reviewed build, original observations, production, and this runner must have the same clean committed revision. The original prepared application remains separately pinned to `ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05`; all 17 files from that preparation under this directory must remain byte-identical.

```sh
python3 -B "$REPO/evaluation/e9-common-app/run_candidates.py" \
  --inputs "$INPUTS" --inputs-sha256 "$INPUTS_SHA256" --raw "$NEW_RAW"
```

All coordinates are canonical absolute paths. `NEW_RAW` is an absent child of the checkout's `ignored` directory, outside previous evidence trees. All its parent directories must already exist. The recipe creates its output exclusively. The selected Python must be the running interpreter's resolved owner. Optimized Python is refused. Root records the actual enclosing process's closed/reaped status separately; a script summary is not that observation.

The command above keeps the legacy profile: every attempted core production
request must use `prepare`, and its input, admission and summary must omit
`planning_profile`. Production must have no `planning-profile.json`; core
bundles must have no `planning-profile.tsv`.

To consume production from the explicit owned-neighbor frontend, append
`--planning-profile owned-foreign-neighbors-v1`. The ordinary input envelope
and the production admission must each add the literal
`"planning_profile": "owned-foreign-neighbors-v1"`. The producer input must
carry that same field. Its summary and indexed `planning-profile.json` must
equal the exact profile record described below. Omission does not select this
profile implicitly. This option changes the core production identity joins;
it supplies no native router, signal-handler or architectural qualification.

## Fixed inventory and limits

There are 24 artifact cells, each with all eight datasets, yielding **192 mandatory named rows**. Order is null then journal; jump-site then heap-write; unstripped then stripped; core then stock-algorithm then bootstrap-patched-reference; then `empty`, `singleton`, `pair-reverse`, `equal-17`, `sorted-17`, `reverse-17`, `duplicates-17`, and `mixed-64`. This order is fixed before the first helper.

Each executed case uses the existing `tools/unwind-oracle/bounded_command.py`: **20 CPU seconds, 30 wall seconds, and 16 MiB per-file limit**, with a 40-second `timeout` backstop, `--kill-after=10s`, and a 55-second enclosing wait. The existing helper's five-second cleanup remains unchanged. Execution is serial with no retry. The exact environment is `PATH=/usr/bin:/bin`, `LC_ALL=C`, `PYTHONDONTWRITEBYTECODE=1`, and a fresh case-specific `TMPDIR`; cwd is the checkout. The child argv is precisely `EXECUTABLE_COPY DATASET NEW_JOURNAL`.

Every actual helper must retain its exact eight-field request, outer command, full streams, and typed 13-field receipt. Receipt closure requires `ECHILD`, no unexpected descendants or cleanup events, no timeout/abort/cleanup error, unchanged request/helper, exact stream hashes, and the expected helper JSON stdout. Input, source, selected runtime, copy-owner, or closure drift stops later launches. A cleanly closed nonzero child or output/journal mismatch is retained as a failed case; independent later cases continue. Dependent unrun cases remain in the 192-row denominator.

## Inputs and real admissions

For legacy mode the caller supplies one JSON input record with exactly these
keys. Owned-neighbor mode adds only the matching `planning_profile` field:

- `schema`: integer 1.
- `source_epoch`: path to the caller's current full `source()` observation (`revision`, complete tracked `files`, and all six-stat `owners`). It must equal the recipe's fresh Git/blob/owner observation.
- `preparation`: the original recipe's `summary`, `source`, `source_after`, `review_binding`, and `originals` object with unstripped/stripped paths.
- `build_admission`: the actual `CALLER_AUTHENTICATED_OBSERVER_BUILD` record documented in [OBSERVE.md](OBSERVE.md). Its actual artifact/archive review supplies the separate driver authority; production's named core/common-sites products cannot substitute for it. The recipe joins all archived Cargo products, the three selected executables, depfiles, source bindings, exact dev profile, and the complete eight-cell static inventories.
- `observation_content_admission`: the caller's admission of an **actual independent capture-content audit**, with the shape below. Successful observer commands or `PASS_COMMAND_AND_CAPTURE_SCHEMA` alone are insufficient.
- `production_admission`: the caller's actual artifact-review admission below. The production traversal may have failed ordinary structural predicates or lost-site comparisons. Its original summary and every one of its 74 rows remain preserved.
- `runtime_admission`: the current selected interpreter/library/cache owner epoch below. This is an explicit limited epoch, not an attestation of the child's actual process maps.
- `tools`: canonical executable paths for `python`, `helper_python`, `timeout`, and `git` (the latter exactly `/usr/bin/git`).
- `files`: every consumed input path mapped to `{ "sha256": HEX, "bytes": INTEGER, "stat": [dev, ino, mode, size, mtime_ns, ctime_ns] }`. This includes admission/review/provenance records and all original, build, observation and production files consumed by their indices. No metadata or digest is refreshed implicitly.

`observation_content_admission` has `schema: 1`, `authority: "CALLER_ADMITTED_ORIGINAL_OBSERVATION_CONTENT_AUDIT"`, `scope: "all-sixteen-original-capture-contents-and-ordered-pc-streams"`, the current `source_revision`, actual observation `directory`, actual `build_directory`, `review_binding`, `evidence_files`, `parent_closed_reaped: true`, `parent_observation`, `architectural_equivalence_claim: false`, and `cases`. Both the actual content-review binding and the separately recorded root parent observation belong in `evidence_files`. They are explicit caller authorities, not facts inferred from a marker or a fabricated receipt.

`cases` has exactly the 16 keys `observe-VARIANT-DATASET`. Each row contains `capture_directory`, `capture_files_sha256`, `jump_pcs_sha256`, and `heap_pcs_sha256`. The first digest binds that case's full `capture-files.json`; the other two bind the complete raw little-endian u64 streams. Every indexed capture is authenticated. Every decoded static head remains in `coverage.tsv`, including zero-visit heads. The full per-style stream's PC multiplicities must equal all corresponding coverage rows, and its order and duplicates are retained literally. This additional join does not replace the independent content audit.

`production_admission` has `schema: 1`, `authority: "CALLER_ADMITTED_COMMON_PRODUCTION_ARTIFACTS"`, `scope: "closed-production-artifacts-only"`, current `source_revision`, actual production `directory`, `review_binding`, `evidence_files`, `parent_closed_reaped: true`, and `parent_observation`. Both authority records are in `evidence_files`. Actual `raw-files.json`, complete source before/after, all attempted strict receipts and all 74 planned rows are authenticated. A fatal production cleanup or owner failure is not admissible; ordinary producer, adapter, comparison or complete-candidate failures remain explicit and may leave independently eligible artifacts.

For the owned-neighbor profile, this admission also carries the same explicit
`planning_profile`. The summary and indexed producer profile record have
exactly `schema: 1`, `planning_profile: "owned-foreign-neighbors-v1"`,
`core_subcommand: "prepare-owned-neighbors"`, `marker: "planning-profile.tsv"`,
the SHA-256 and byte length of the marker below as `marker_sha256` and
`marker_bytes`, and `qualification_complete: false`.

Every attempted core production request, including a failed attempt, must be
exactly `CORE prepare-owned-neighbors ORIGINAL SELECTION OUTPUT`. `CORE` is the
same admitted build product; `ORIGINAL` is the producer's variant path with the
whole admitted original bytes; `SELECTION` is that cell's same complete build
inventory; `OUTPUT` is that production root's `CELL/core`. No additional argv
element is accepted. Legacy requests make the identical join with `prepare`.

`runtime_admission` has `schema: 1`, `authority: "CALLER_PINNED_ORDINARY_RUNTIME_EPOCH"`, `scope: "selected-interpreter-library-cache-owners-only-not-process-maps"`, current `source_revision`, `owners`, `interpreter_lookups`, and `evidence_files`. `owners` contains 2–32 unique canonical selected files, including the actual PT_INTERP owner and `/etc/ld.so.cache`; caller-selected libraries remain explicit. Each owner uses the full descriptor/pathname/provider identity documented in OBSERVE.md: path, SHA, byte length, both eight-field stats, raw pathname hex, and exact mount-provider row. `interpreter_lookups` maps each literal PT_INTERP path to its complete lexical symlink/lstat lookup record and selected resolved owner. Every eligible candidate's PT_INTERP is checked against this table. These same selected owners and lookup records are reread before and after every launch. No library owner or process map is guessed from an executable hash.

## Per-artifact eligibility and immutable copies

A core artifact needs the exact original `COMPLETE`, full `bundle-index.tsv`, complete report and selection joins, and `candidate_complete=true`. A refusal or absent candidate leaves all eight rows unrun. A partial directory cannot manufacture a replacement selection.

After those whole bundle checks, owned-neighbor mode requires one exact
indexed `planning-profile.tsv` with these bytes (tabs between fields and a
final newline):

```text
LI2PLANNING\t1
profile\towned-foreign-neighbors-v1
qualification_complete\tfalse
```

The index row must have the exact filename, length and SHA-256. This applies
to both complete and withheld core bundles; a profile marker cannot make a
withheld candidate eligible. The ordinary raw output retains a watched
`planning-profile.json` and the matching summary field only in owned-neighbor
mode. The added record participates in the same immutable owner snapshots and
complete raw index. Fresh caller capacity must include it.

An E9 artifact needs its actual successful transport, producer and adapter stages, the exact successful adapter request, envelope/input identities, candidate hash, complete actual-site TSV and `producer-binding.json`. The structural comparator's exit or lost-site result is retained and does **not** gate that independently authenticated E9 artifact. A failed adapter or unauthenticated output leaves all its rows unrun. All complete site rows and their `trampoline`, `trap`, or `refused` classifications are retained. Ordinary success never converts traps or refusals into successful trampolines or proves unvisited sites.

For each eligible artifact, the recipe reads the admitted bytes, creates one exclusive independent file under `NEW_RAW/executables`, verifies full byte equality and distinct inode, and changes only that new copy from mode 0600 to 0500. It then rechecks both source and copy, records the copy's descriptor/provider identity, and pins the copy for every subsequent case. The frozen producer candidate is never chmodded or modified. Each copy comes from the complete original artifact/adapter/index admission, not a newly selected pathname or an unreviewed executable.

## Exact ordinary checks and outcome reporting

Every passing case requires child exit 0, the complete dataset stdout, empty stderr, and an exactly **131,144-byte** journal. Null mode requires the complete zero journal. Journal mode requires the complete corresponding audited original jump/heap PC stream, in order with duplicates; there is no successful-site or visited-site filter. The 8-word header is guard `0x6c69326a6f75726e`, version 1, capacity 16,384, active 0, exact count, and zero overflow/fault/reserved. Every unused PC word is zero and the final guard is `0x7265636f72647321`. Expected counts above 16,384 leave that case unrun, with the full count and reason preserved; capacity and predicates are never relaxed.

`PASS_ORDINARY_OUTPUT_AND_JOURNAL` describes only that case. `artifact-prerequisites.json` retains full structural site rows; `production-status.json` retains the unchanged producer summary and 74 rows. `results.json` always keeps all 192 case identities. `ordinary_cases_complete` requires all 192 ordinary passes and unchanged final owners. The overall `successful` also requires the original producer's own success; finishing a traversal cannot relabel a failed production campaign. `qualification_complete`, `full_a3`, `architectural_equivalence`, and `process_maps_attested` stay false.

Raw requests, full journals/stdout, indices, copies, snapshots, and runtime identities remain in the ignored tree. This recipe does not publish them or produce a performance result. Any later publication must preserve the exact source revision, separate scope and failures, and sanitize coordinates without changing command meanings.

`test_candidate_profile.py` contains prospective synthetic saved-record
controls for both profiles, all 74 production rows, complete and withheld
two-site bundles, exact core argv, marker mutations, caller/profile mismatch,
and unchanged owner/source/history refusals. It never invokes recipe main or
an application. These tests do not substitute for a fresh reviewed build,
original observation/content audit, production, selected runtime admission or
ordinary execution. Those records must describe the final same source epoch;
historical records are not re-labelled for this option.
