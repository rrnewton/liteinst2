# Common-corpus artifact production

`produce.py` runs a fixed structural comparison campaign. It never executes
an original application or a rewritten candidate. Candidate production, a
complete site inventory, and a successful structural comparison do not establish
application correctness, architectural equivalence, or full A3 qualification.

Commit the recipe first, then build and authenticate the core CLI and
`common_sites` at that same clean revision. Prepare all eight complete static
inventories using the separately reviewed `common_sites` protocol. The original
preparation remains tied to `ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05`;
the recipe checks that the five fixture C/header/data sources remain exact.
It does not transfer the original preparation's successful runs to candidates.

```sh
python3 -B evaluation/e9-common-app/produce.py \
  --inputs "$INPUTS" --inputs-sha256 "$INPUTS_SHA256" --raw "$NEW_RAW"
```

That command retains the legacy `prepare` frontend. The separate opt-in is:

```sh
python3 -B evaluation/e9-common-app/produce.py \
  --inputs "$INPUTS" --inputs-sha256 "$INPUTS_SHA256" --raw "$NEW_RAW" \
  --planning-profile owned-foreign-neighbors-v1
```

The opt-in envelope must also declare exactly
`"planning_profile": "owned-foreign-neighbors-v1"`. A CLI/envelope mismatch,
unknown profile or extra field is refused before production. This selects
`prepare-owned-neighbors` for all eight core cells; it does not change either
E9 lane, any selected site, allocation permit, budget or comparator. It is
independent of the fixed versus original-derived allocation profile below.
The frontend requires separately authenticated complete function/head/resume
declarations already carried by the full selection. A foreign victim is an
auxiliary original operation, never another requested hook. Any unsupported
owner, control-flow or placement remains a failed core cell. Selecting this
profile does not promise eight complete candidates.

The variables denote independently admitted absolute coordinates and the
SHA-256 of the entire input JSON. `NEW_RAW` must not exist, must have a canonical
existing parent, and must lie under the checkout's ignored directory. Input
paths and tools must be canonical regular files; supply resolved tool owners.
The recipe refuses optimized Python. Raw records are private and retain exact
paths, commands, environment, streams, and owners. The caller separately records
closure and reaping of the enclosing recipe process; there is no invented
parent receipt or automatic closure inference.

The original fixed-arena inventories remain accepted. The separately declared
`LI2COMMON 2` profile is also accepted with exactly the `original-derived-v1`
domain and unchanged caps specified in [BUILD.md](BUILD.md). It requires a new
build admission and input envelope. All sites, original entry heads and action
checks remain mandatory; a refusal remains a failed production row. These
core placement permits are not imposed on the E9 backend, so this comparison
does not establish identical allocation policy between the two implementations.

## Input contract

The legacy JSON has exactly `schema`, `preparation`, `build_admission`, `cells`,
`products`, `tools`, and `files`. `schema` is 1. `files` maps every admitted
absolute input pathname to `{ "sha256": HEX, "bytes": INTEGER }`.
It includes the complete caller-selected preparation, compiler, provenance,
product and static-inventory evidence, not just the two runnable product hashes.
All entries are read and retained with six-stat owner identities, then checked
before and after every helper. Extra evidence owners can be included in this
map without adding stages. The source tree is independently compared to every
tracked Git blob, its modes and complete content map, before and after each
helper; the initial and final complete observations are retained.

Only the owned-neighbor opt-in adds the single `planning_profile` key above.
Its build admission still names actual products and evidence from the same
clean committed recipe/source revision. A profile label or the older successful
builds cannot replace that admission. No new build or execution admission is
created by this documentation.

`preparation` has these keys:

- `summary`, `source`, `source_after`, `review_binding`: absolute paths to the
  closed original preparation's records. Its review must have verdict
  `CLOSED_ORIGINAL_PREPARATION_PASS_EXECUTION_RECORD_SCOPE` and the exact
  30-stage, 16-original-run, six-refusal denominators.
- `originals`: exactly `unstripped` and `stripped`, naming the original ELFs.

`build_admission` names a separately authenticated JSON record with exactly:

```json
{
  "schema": 1,
  "authority": "CALLER_AUTHENTICATED_BUILD_PRODUCTS",
  "scope": "core-cli-and-common-sites-build-only",
  "source_revision": "ACTUAL_40_HEX_BUILD_AND_RECIPE_REVISION",
  "source_files_sha256": "ACTUAL_64_HEX_MAP_DIGEST",
  "products": {"core": "ABS_CORE_CLI", "common_sites": "ABS_EXAMPLE"},
  "required_products": ["ALL_REQUIRED_AUTHENTICATED_PRODUCT_OWNERS"],
  "evidence_files": ["ALL_ACTUAL_BUILD_SOURCE_RECEIPT_AND_REVIEW_RECORDS"]
}
```

`source_files_sha256` hashes canonical compact JSON with sorted keys, mapping
every tracked relative path to `{sha256, bytes, mode}`. Modes are Git's
`100644`/`100755` strings. `required_products` contains both named executables
and the full required product/dependency set covered by the caller's actual
build review. `evidence_files` includes the full source observations, actual
commands/receipts/Cargo outputs, product/depfile joins, and actual review binding.
Every pathname is also independently pinned in `files`.

This admission is explicit external authority. The recipe checks its source,
product and evidence-byte joins; it does not prove compilation by accepting an
arbitrary executable hash, manufacture compiler provenance, or claim a complete
system-tool closure. The caller supplies the actual selected toolchain/config
owners in `files` according to the build and hook-compiler admission. Implicit
system inputs not covered by that admission acquire no continuity claim.

`cells` has exactly eight keys, in the fixed Cartesian product of
`null|journal`, `jump-site|heap-write`, and `unstripped|stripped`, joined with
hyphens. Each value has `directory` (the completed common-sites output),
`run_directory` (its strict helper records), and `provenance` (the independently
admitted policy-provenance file). All ten output files, original policy/target
input owners, and request/receipt/stdout/stderr records are pinned in `files`.
The actual archived argv must name the admitted `common_sites` product, original,
policy, target, style, hook, and exact output directory. The recipe authenticates
the actual policy/target input paths against the copied output bytes, every
selected site against the whole kernel inventory, and identical full kernel
and target records across all eight cells. No successful-site subset is made.

`products` names exactly `stock_frontend`, `stock_backend`, `stock_loader`,
`transport_frontend`, `abi_backend`, and `abi_loader`. Their six byte hashes are
fixed in the recipe and the unchanged E9 adapter. `tools` names exactly `gcc`,
`python`, `helper_python`, `timeout`, and `git`; `git` is `/usr/bin/git`.
These tool files, the existing bounded helper, the unchanged adapter and
comparator, and the two hook source/header files are pinned in `files`.

## Fixed execution and failure behavior

All null cells precede all journal cells. Within each hook group, styles are
jump-site then heap-write, with unstripped then stripped for each. Each cell
has one core prepare command, then four stock-algorithm stages and four
bootstrap-patched-reference stages: transport, producer, adapter, comparator.
The two hook compiler/linker stages occur between the hook groups. This is
exactly 74 possible helper launches: 36 null, two hook, and 36 journal.

Every core request retains the exact selected frontend verb and is checked
against its full saved argv. The old whole `COMPLETE`, bundle-index, selection
and per-site report checks run unchanged for both profiles, including withheld
candidates. Legacy bundles must omit `planning-profile.tsv`. Owned-neighbor
bundles must index exactly the full marker bytes
`LI2PLANNING\t1\nprofile\towned-foreign-neighbors-v1\nqualification_complete\tfalse\n`;
missing, unindexed, duplicate, truncated or differently named profiles refuse.
The marker's digest and length must match its bundle-index row, which is bound
by `COMPLETE`. A global input-failure directory stays a failed postcheck; the
recipe never manufactures a profile marker or successful bundle for it.

For the opt-in only, `planning-profile.json` records the profile, frontend verb,
marker identity and false qualification scope before the first helper. It is
included in the unchanged watched-owner checks and final raw index. The same
record appears in `summary.json` as `planning_profile`. Legacy output field
shapes and its `prepare` argv remain unchanged.

The hook compile and link use 60 CPU seconds, 90 wall seconds and a 128 MiB
per-file cap. Every other stage uses 20 CPU seconds, 30 wall seconds and 16 MiB.
The existing helper is unchanged. Its outer timeout remains `--kill-after=10s`
with 100/40 seconds and the parent wait is 115/55 seconds. Commands are serial.
Every child receives only `PATH=/usr/bin:/bin`, `LC_ALL=C`,
`PYTHONDONTWRITEBYTECODE=1`, and the declared `TMPDIR`; transport and producer
in a lane use the identical cwd, environment and limits. No compiler, helper,
cleanup rule or comparator is replaced.

The stock lane uses the pinned algorithm with its recorded include-only build
adaptation. The bootstrap-patched lane remains a distinct reference. Both
transport witnesses use the separately identified JSON-output frontend fix.
All retain reference commit `0d5d36e4c4edcac37ca2499694d64302a391136f`;
none is labelled an unmodified authors' binary. Producer stderr alone receives
`--option=--debug`; the transport and producer otherwise share the same action,
whole three-function range, executable mode and compression-9 policy.

Jump selection uses `asm=j.*`. Heap selection uses one exact address-regex set
derived from every heap-write site in the admitted complete static inventory.
The pinned frontend has no memory-write matcher. This address policy expresses
the proven authored store classification; it is not chosen from observed
rewrite successes. The independent adapter must match all selected IDs, PCs
and lengths in the RPC and producer records, including real refusals and traps.
It authenticates the emitted loader's mmap records; it does not mistake those
appended trampoline mappings for ordinary PT_LOADs.

Null uses the original passthrough action. Journal uses the exact
`call[clean,before]li2_e9_record(instrAddr)` action. The journal address is derived
from the authenticated unstripped symbol and checked against both originals:
`li2_journal = 0x4040a0`, size 131,144, exact initial whole bytes. The hook build
preserves `e9compile.sh`'s `-fno-stack-protector -fpie -O2 -c -Wall` and
`-pie -nostdlib -Wl,-z -Wl,max-page-size=4096 --export-dynamic --entry=0x0
--strip-all` linker policy (the latter three supplied with `-Wl,`). Only the
explicit journal define and exclusive object/output coordinates are added.
Before journal producers, the hook ELF's defined dynamic symbol, unique RX
owner, LOAD geometry, absence of external dependencies/relocations and
custom `init`/`mmap` hooks are checked. Its load base follows the pinned
frontend exactly: page-ceiling of the maximum original PHDR end plus 16 MiB
plus eight pages. This is artifact validation, not hook execution credit.

`stage-inventory.json` exists before the first helper. Every planned row is
retained in `results.json`, including dependent `UNRUN` rows. Failed producer
or adapter output is never replaced with a synthetic inventory. Independent
cells continue after ordinary command or schema failures; cleanup, receipt,
input-owner or source drift stops further launches. Core exit 2 remains a
failed core cell with its full refusal report available for comparison.
Comparator exit 2 for lost E9 trampoline sites remains a failed comparison.
No cap is enlarged and no smaller selection is retried.

Per-stage `result.json` reports the strict command/receipt outcome; a separate
`postcheck.json` and final `results.json` also include product/schema checks.
`cells.json` retains complete available adapter and comparison results.
`summary.json` distinguishes completed traversal from successful production;
any failed or unrun required stage makes `successful` false. `raw-files.json`
indexes retained files, including partial outputs, and excludes itself.
The enclosing parent closure remains separately observed. Operational times
are diagnostics, not benchmarks. Ordinary dataset and native execution counts
for this recipe are both zero; `qualification_complete` remains false.

The prospective `test_production_profile.py` controls exercise only synthetic
saved bundle/schema validation, including complete and refused two-site
reports. They execute no producer, compiler, application or native replay and
do not replace any existing validation. New ordinary/native admission and any
reporting consumer must explicitly join the actual profile, exact command and
indexed marker; structural production alone supplies no runtime credit.
