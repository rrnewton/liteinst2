# Report one original-derived placement build

`collect_placement_build.py` reads one closed, independently reviewed
`build_inventory.py --allocation-profile original-derived-v1` run. It never
builds, executes a product, imports a recipe or opens live target products.
The existing historical `collect_build.py` and its published cohorts remain
unchanged. The build recipe remains the workload reproducer.

Commit the reporter before collecting. Its own exact Git revision and source
hash are recorded separately from the tested build revision:

```sh
/usr/bin/python3.9 -B evaluation/e9-common-app/collect_placement_build.py \
  --repo "$REPO" --inputs "$INPUTS" --inputs-sha256 "$INPUTS_SHA256" \
  --new-output "$NEW_OUTPUT"
```

All coordinates are absolute. Input, raw, launch, review and new-output records
are beneath this checkout's `ignored/`. Raw and launch roots must be distinct,
non-nested canonical directories. New output must not exist, cannot overlap
either input root, and has an existing canonical parent. The collector refuses
optimized Python before parsing arguments. No caller record creates review or
parent authority: the caller authenticates those actual records first.

## One caller envelope

The exact top-level keys are `schema` (integer 1), `authority`
(`CALLER_SELECTED_ONE_CLOSED_PLACEMENT_BUILD`), `attempt`, `test_review`, `roles`,
`privacy_literals`, and `files`.

`attempt` has exactly these keys:

- `revision`: full tested Git SHA, distinct from historical cbb189d.
- `recipe_sha256`: exact SHA256 of the new build recipe at that tested Git SHA.
- `raw`, `launch`: the existing closed build and enclosing launcher directories.
- `review_binding`, `review_references`: the independently authenticated actual
  build review and its whole saved-reference map. Both are sibling files;
  `binding.files` must bind the named map's bytes/hash.
- `review_revision_key`: the existing binding's `revision`, `tested_revision`
  or `source_revision` key.

The review must preserve `findings: []` and the actual closed outcome:
`CLOSED_BUILD_AND_STATIC_INVENTORIES_PASS_EXECUTION_RECORD_SCOPE` or
`FAILED_BUILD_RETAINED_NO_LATER_STAGE_CREDIT`. Every consumed raw/launch record,
and every reported archived product's hash/length, must match its complete
reference map. The reporter reads the saved archive/Cargo/source records;
product bytes and original owner authentication remain the named actual
review's authority. It does not reopen binaries, depfiles inside artifact
storage, or target files, nor claim a full dependency/loader closure.

`test_review` is null if the workspace-test gate did not pass. When that gate
passed, it contains `binding`, `checks`, `groups`, `baseline_binding` and
`baseline_groups`. The first three use the existing saved-log review format:
`PASS_SAVED_TEST_LOG_ACCOUNTING_ONLY`, its bound `checks.json`, and complete
`test-groups.json`. `checks.raw_log_sha256` must match this exact test log.
The final two are the immutable cbb189d log binding f0acc3a8 and complete
case inventory cec143ad. All 1,689 old outer case names/statuses and all old
group identities must survive. Added tests are listed, not guessed. Counts are
recomputed from that reviewed whole inventory; the reporter does not reinterpret
ambiguous nested child lines. Nested terminal observations and starts without
separate terminals remain separately labelled and never enter outer pass totals.
A failed/unrun test receives no full-identity-retention claim.

`files` maps every explicitly consumed absolute saved-record path to exactly
`{sha256, bytes}`. Include the complete raw/launch metadata and streams required
by this recipe, both main review files, and the five named log-review files
when applicable. The map excludes raw `artifacts/` binary copies and live
`target`. Files outside raw/launch are allowed only at those explicitly named
review paths. Each record is regular, symlink-refusing and bounded to 64 MiB;
the indexed reporting records together are bounded to 256 MiB before reading.
The complete tested source byte/mode map is independently joined to Git blobs,
not substituted with the reporter checkout's newer sources.

`roles` maps 4–64 unique symbolic strings such as `${REPO}`, `${RAW}`,
`${LAUNCH}`, `${TOOLCHAIN}`, `${HOME}` and `${CARGO_HOME}` to explicit absolute
coordinate strings. `${REPO}` must equal the selected repository. Longer
coordinates are replaced first, once; literal-token collisions and any decoded
roundtrip mismatch refuse. `privacy_literals` lists private usernames, hostnames
and other strings that must not survive the public projection. `/home/` and
`/data/users/` are independently forbidden. Portable system path strings such
as `/usr/bin:/bin` remain the exact command values unless explicitly symbolized.

## Preserved checks and output

The exact launcher argv retains the existing six argument pairs followed by
`--allocation-profile original-derived-v1`; fixed-v1 is not relabelled.
The tested Git recipe hash, launcher hash, source map and saved prospective
policy must agree. The finite domain remains start 65,536 / bytes 1,073,741,824;
64 KiB selected/victim slots, 65,536 candidates, carrier 0x20000000, and all
old search/application limits stay exact. LI2COMMON 2 policy, placement and
arena lines are checked in every completed inventory.

All twelve stage rows, four gate rows and eight inventory rows are retained.
A fully successful run has seventeen recorded command contexts: one launcher,
twelve stages including the required dispatcher, and four nested gates. The
eleven strict helper receipts are distinct from those other records. Compiler
requests keep 60 CPU / 90 wall / 128 MiB per file; target/inventory requests
keep 20 / 30 / 16 MiB; outer waits, cleanup predicates, minimal environment,
source/tool/config before-after equality and gate limits are unchanged. Expected
nonzero commands remain failed; dependent rows remain UNRUN. The supported closed prefixes include at least the required-dispatch result and
its first gate record. An earlier launch/precondition failure, or a missing or
unsafe cleanup/closure record, makes reporting refuse while retaining all raw
evidence; this script supplies no synthetic terminal record.
The collector does not fabricate a successful summary from a partial directory.

Every archived Cargo-reported filename and selected alias depfile stays in the
artifact inventory; the selected development profiles and source bindings join
the actual Cargo rows. All eight complete inventory tables keep 87 heads and
9 jump or 1 heap site, with complete same-style IDs/tables across hooks and
strip forms. This is static coverage, not evidence of application execution.

Eight small public files are produced: `summary.json`, `commands.json`,
`stages.csv`, `gates.csv`, `inventories.csv`, `artifacts.csv`,
`source-files.json`, and `files.json`. The complete commands retain reversible
decoded argv/env/cwd/request/receipt/result values through symbolic paths.
Summary identifies exact tested/reporter revisions, recipe/profile, tools,
actual hardware labelled **AMD EPYC Zen 5 dev host**, counts, failures and
UNRUN rows. The full case inventory stays privately bound; additions and exact
retention counts are public. All seconds are operational diagnostics, never
benchmarks. `files.json` hashes the other seven outputs.

`private-binding.json` retains full input hashes/owners, path-role inverses,
reporter source/revision and public file identities. All consumed records,
source and input envelope are reread for continuity before exclusive creation.
Encoded per-file and aggregate output limits remain 64/256 MiB. Actual public
bytes still require transformation/privacy review. No run is claimed by this
source proposal. Build/static results provide no new original, rewritten,
paired-state, performance or full-A3 qualification; historical failures remain
unchanged.
