# Build tools and inventory the original common corpus

`build_inventory.py` builds the current committed tools and produces all eight
static inventories of the previously prepared heap-sort application. It does
not rewrite or execute the application. The driver is invoked only in `target`
mode to observe the machine's supported extended-state layout.

Commit this recipe, the selector and the other intended sources first. Run it
from that exact clean checkout with a new raw directory beneath `ignored/`:

```sh
/usr/bin/python3.9 -B evaluation/e9-common-app/build_inventory.py \
  --raw "$NEW_RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --inputs "$INPUTS" --inputs-sha256 "$INPUTS_SHA256"
```

All coordinates are absolute, canonical paths. `TOOLCHAIN` contains `bin/cargo`,
`rustc`, `rustdoc`, `rustfmt` and `clippy-driver`. The three directory arguments
already exist. `NEW_RAW` has an existing canonical parent and must not exist.
The recipe refuses optimized Python. The caller records the enclosing process's
actual closure separately; the recipe does not invent a parent receipt.

## Pinned original inputs

`INPUTS_SHA256` authenticates the entire input JSON. Its exact keys are
`schema`, `preparation`, `collector_binding`, and `files`, with `schema` equal
to 1. `files` maps every admitted absolute file path to `{sha256, bytes}`.
The caller supplies the closed records and their complete named dependency
set, including the collector's own input and public-output indexes. The recipe
reads every entry, retains its six-field file identity, and requires the same
bytes and owner at closure. Repeated reads cannot refresh an owner.

`preparation` contains `summary`, `source`, `source_after`, `review_binding`
and `originals`. The latter has exactly `unstripped` and `stripped` paths.
These records belong to the original preparation at
`ab443afc2f4d9b62a9d04d56c4ca78a10e48ec05`: 30 stages, 16 successful ordinary
original runs and six expected refusals. Its review verdict is
`CLOSED_ORIGINAL_PREPARATION_PASS_EXECUTION_RECORD_SCOPE`. All original
common-app fixture/preparation source files must remain byte-identical in the
current checkout.

`collector_binding` names the actual collector's private binding JSON. Its
`input_files` and all eight sibling `public/` files must also appear in `files`.
The collector's own recorded revision and source hash remain distinct from the
original application's revision. These inputs provide historical original
evidence; no original execution credit is transferred to the new tools.

The recipe independently decodes both original ELF headers, complete program
headers, `.text`, and the ten named function/object owners. The strip comparison
retains the original section-table-only mask at ELF file offsets 40–47 and
60–63; all other LOAD bytes and all selected bodies must match. Actual symbol
coordinates and body hashes, rather than guessed addresses, populate the
policies and observer layout. The store body must be exactly `488914f7c3`.

## Fixed sequence and limits

There are twelve top-level stages:

1. Run the unchanged `evaluation/required-gates.py` once: fmt, Clippy, workspace
   tests and workspace check, retaining their 180/180/360/180-second limits.
2. Build `elf-exec-oracle` and `liteinst-rewrite` with Cargo JSON output, and
   immediately archive the reported products and selected alias depfiles.
3. Build the `common_sites` example with Cargo JSON output and immediately
   archive its reported products and selected alias depfile.
4. Invoke the archived driver in `target` mode.
5. Run eight inventories: null before journal, jump-site before heap-write,
   and unstripped before stripped within each pair.

The dispatcher is the first stage; the remaining eleven commands use the
unchanged [bounded helper](../../tools/unwind-oracle/bounded_command.py).
Both Cargo requests use 60 CPU seconds, 90 wall seconds and 128 MiB per file.
Target and inventory requests use 20 CPU seconds, 30 wall seconds and 16 MiB.
The helper's outer timeout is 100/40 seconds with `--kill-after=10s`; parent
waits are 115/55 seconds. The dispatcher parent wait is 1,000 seconds without
changing its four internal limits. All commands are serial and Cargo uses
the checkout's single `target` directory with four jobs, offline/locked builds,
the default development profile and incremental compilation disabled.

These application limits are fixed before any common inventory result:

| Limit | Value |
| --- | ---: |
| Input bytes | 1,048,576 |
| Sites | 64 |
| Images | 256 |
| Image bytes | 8,388,608 |
| New LOAD pages | 2,048 |
| Output bytes | 16,777,216 |
| Added file bytes | 12,582,912 |
| Program headers | 512 |
| Virtual span | 1,073,741,824 |

Selected and victim arenas begin at `0x10000000` and `0x18000000` respectively.
Both use a 65,536-byte stride, 65,536-byte slots and 65,536 candidates. The
carrier is `0x20000000`. Search values, in the existing policy order, are
`64 256 64 256 4096`. A refusal never raises a bound or selects fewer sites.

The default `--allocation-profile fixed-v1` retains that policy. A separate
opt-in `--allocation-profile original-derived-v1` emits `LI2COMMON 2`, using
the original-byte placement rules in
[COMMON-SITES.md](../../tools/elf-rewrite/COMMON-SITES.md). Its declared domain
starts at 65,536 and contains 1,073,741,824 bytes. It must contain all original
LOAD pages and the carrier. Selected and victim slots remain 65,536 bytes with
65,536 candidates each. Every aggregate and search limit above is unchanged.
The chosen profile is recorded before execution, in the policy and provenance;
it is never changed after a refusal. Use a new output directory and evidence
epoch for this profile. Earlier fixed-arena results keep their original scope.

The new profile derives permits, not successful plans. For example, the common
corpus's two-byte-only jump block at `0x40186c` has a B2 target window beyond the
1 GiB span, no B1 window and a negative T1 target. A neutral permit keeps this
site in the complete selection so the unchanged core can report its refusal.
Neither choosing a profile nor completing all inventories establishes that all
selected sites can be rewritten. The E9 comparison retains the same original
sites and actions, but its backend does not consume these core arena permits;
the two lanes must not be described as having identical placement policies.

Every complete output must contain exactly the original ten files and match
its `COMPLETE` index, exact stdout, copied policy/target and status. Full
instruction, memory-write, basic-block and padding tables must be identical
across all eight cells. Each style's complete site table must also match across
both hook choices and strip forms. Counts come from complete generated tables;
the recipe contains no guessed application instruction or site count.

## Evidence and production handoff

Each helper retains its complete request, strict 13-field receipt, streams,
outer command and parent result. A failed command or postcheck stops the
sequence; partial outputs and dependent unrun names remain recorded. There is
no retry. A source, tool, configuration or input-owner drift prevents a complete
closure. Cargo configuration observations preserve denied metadata lookups as
`READ_DENIED` with unknown existence/content; denial is never labelled absence,
and a later open/read denial remains an error. Configuration consumption is
unattested; the compiler cwd and lookup owners are not changed.

The source map joins every tracked byte and mode to the actual Git revision.
Hardware and selected tools are observed before work, with complete source,
tool and configuration observations repeated at closure. Each compiler archive
retains every Cargo-reported product, full Cargo rows, and the exact selected
target/package/profile/source/depfile joins. Independent copies are made before
the next target writer and checked again at closure. This is not a whole-target,
system-header, loader or toolchain dependency archive.

`cells.json` supplies the producer's exact eight `directory`, `run_directory`
and `provenance` entries. `observer-layout.tsv` supplies the independently
derived original symbol coordinates for a later observer. Neither file grants
runtime equivalence or native qualification.

On success, `build-admission-proposal.json` has the source/product schema used
by [the production recipe](PRODUCTION.md). It lists both required executables,
every retained product/dependency copy, and the named build evidence. It remains
a proposal: the caller must authenticate the actual archives and create a
separate admitted record that also names the closed actual review binding.
The producer's input envelope then pins that record and every listed file.
Do not silently patch an old admission or treat executable hashes alone as
proof of compilation. Broader qualification and rewritten/native comparisons
remain separate; `qualification_complete` is false.


## Explicit debug-info=0 build profile

The historical command above keeps the development debug-info=2 profile. A
separate `--build-profile dev-debug0-v1` invocation requires the same literal
`build_profile` in its input envelope. New summaries, both artifact archives
and caller build admissions must retain that identity. Consumers refuse a
missing/mismatched identity or a Cargo row from the other profile.

This branch sets DEV and TEST profile DEBUG=0, OPT_LEVEL=0,
DEBUG_ASSERTIONS=true and OVERFLOW_CHECKS=true through the corresponding eight
`CARGO_PROFILE_*` environment variables. Selected executable Cargo profiles
must be exactly opt_level=0, debuginfo=0, debug_assertions=true,
overflow_checks=true and test=false. The required-gates script inherits these
settings; every existing command, case, stage, limit, archive and owner check
remains mandatory. No Cargo.toml profile or RUSTFLAGS override is introduced.

The allocation and planning/router profiles are independent. Fresh actual
source/build/tool/archive review and caller admissions are required; neither
historical debug-info=2 results nor prior native-only builds transfer. The
direct-rustc verifier uses the separate admission scope
`direct-rustc-canonical-input-epoch-dev-debug0-v1` and exact `-C debuginfo=0`
with all other compiler options and limits retained. Storage savings are
unmeasured. The historical build reporter must not be used unchanged for this
new command/environment/profile.
