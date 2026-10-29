# Whole authored-program offline rewrite attempt

This adds whole startup/kernel/hook coverage for the existing checksum and
RLE-roundtrip programs: 187 independently transported instruction heads and all
42 decoded jumps, including error paths. It is a claim-4 structural result.
Neither program yielded a LiteInst candidate under the fixed allocation profile.
No rewritten application execution or performance measurement occurred.

| Program | Heads | Jumps | NoPatchWindow | Other plans discarded atomically |
| --- | ---: | ---: | ---: | ---: |
| checksum | 80 | 16 | 11 | 5 |
| rle-roundtrip | 107 | 26 | 11 | 15 |

The remaining plans are **not successful rewrites**: any refused requested site
prevents publication of the entire candidate. `sites.csv` retains every row.
The original allocation profile, one page/candidate per role, all-head entry
obligations, search bounds and 32-image/16-MiB carrier caps were unchanged.

Materials use source `1f6c043ce679973cd62997e56871d8abd75c8ed5`; the actual release
executables were built at `85e49ae297fb994555e8e742271320dd1737b290` with opt-level3,
no debug information, assertions and overflow checks enabled. The Rust build
inputs did not change between those revisions. Hardware: **AMD EPYC Zen 5 dev
host**. Each execution owner reserved four disjoint CPUs; exact reservations,
available load averages, commands, hashes and all outcomes are in `receipt.json`.
Missing load observations remain null. Durations are diagnostics, not benchmarks.
Raw captures and logs stay in ignored storage.

Development outcomes are retained: the initial build preflight failed on denied
configuration lookup. The revised bounded capture ran all thirteen commands
successfully, but returned2 because two configuration observations remained
READ_DENIED. This is incomplete provenance, not absence or qualification. Initial
material policies used an invalid `auto` token; both importer calls returned2
before planning. The source correction uses the parser's existing `preferred`
token. Its fourteen controls passed; the subsequent sole call per program
produced the complete refusal tables above. No failed attempt was erased.

The four E9Patch program/lane productions all returned0, but the original
artifact checker rejected every output at its single-mapping trampoline-extent
assertion. The four comparisons were UNRUN. The pinned stock PLDI2020 algorithm
and separately identified bootstrap-ABI reference remain different lanes.
A producer's exit0 does not establish executable equivalence or an accepted
structural inventory.

Reader correction `92aa9151a8b9aa19d4d29e0eec39323e120b70de` validates unique
executable backing for every fragment. It preserves the complete loader,
gateway, provenance and ownership checks. Existing3 accepted/24 refused controls
and additive adjacent/aliased/override cases pass. Independent source review
approved the exact change. A single saved-artifact check then accepted all four
inventories, **without rerunning either producer**. Each candidate has one
trampoline crossing adjacent mappings. Both lanes have checksum tactics
B1/B2/T1/T3=4/4/5/3 and RLE=14/4/5/3; no T2 case occurs here.

All four subsequent comparisons still returned2: each lane loses all42 E9
trampoline sites because LiteInst emitted no complete candidate. The overall
comparison remains **FAILED**. `e9-sites.csv` preserves all84 program/lane rows;
there are42 distinct requested program sites. No trap was counted as a retained
trampoline. Recheck reservation40/91/112/141, load65.46/64.02/63.96 before and after;
all eight commands closed normally without rescue. No rewritten candidate ran.
Historical full-state readers retain their old source pins: reproduce them at
their recorded revision, or supply the exact saved reader where their CLI
supports it. This correction does not upgrade those older proofs.

## Reproduction

Use fresh ignored directories, the recorded pinned tools and an external process
owner under a disjoint four-CPU reservation. Keep CPU/wall/file limits in the
tracked scripts; do not repeat attempts until a favorable result occurs.

```sh
python3 -I -B evaluation/offline-corpus/disassembly_controls.py
python3 -I -B evaluation/offline-corpus/head_capture_controls.py
python3 -I -B evaluation/offline-corpus/build_whole.py \
  --raw "$CAPTURE" --toolchain "$TOOLCHAIN" \
  --cargo-home "$CARGO_HOME" --user-home "$USER_DIRECTORY"
python3 -I -B evaluation/offline-corpus/reproduce_whole.py \
  --capture "$CAPTURE" --capture-sha256 "$CLOSED_JSON_SHA256" --output "$OUTPUT"
```

The final helper is an additive reproduction of the transformations and bounded
importer invocations used here. Its CLI import/argument smoke passed; its full
workflow was not rerun to replace the existing importer failures. It
requires external custody of the closed capture and its sidecars, authenticates
all thirteen command/receipt joins, and preserves incomplete configuration as a
nonzero outcome. It does not execute candidates. Its conservative source-change
guard can reject reuse of an older capture; this is not permission to rebuild or
repin that historical result. `HEAD_CAPTURE.md` and `WHOLE_DISASSEMBLY.md` explain
the explicit completeness/source premises.

For each program and each pinned E9 lane, use the exact transport/producer argv
recorded in `receipt.json`: select `asm=j.*:passthru` across
`--start=0x401000 --end=0x403001`, with executable mode and compression9. Preserve
the real bounded-command receipts and bind their files in the existing E9
adapter envelope. Run the existing artifact-only script once:

```sh
python3 -B tools/elf-rewrite/e9-sites.py "$ENVELOPE" "$FRESH_INVENTORY" \
  --envelope-sha256 "$ENVELOPE_SHA256"
python3 -B tools/elf-rewrite/compare-sites.py "$SELECTION" "$CORE_REPORT" \
  "$FRESH_INVENTORY/sites.tsv" "$POLICY" "$COMPARISON" \
  --policy-sha256 "$POLICY_SHA256"
```

The envelope hash must come from the external capture owner. Tool/RPC/loader,
source-gateway, mapping/backing, statistics and receipt checks are mandatory.
Full offline-corpus support and native equivalence remain open; these two
programs do not qualify the upstream corpus.

The unchanged Rust source retains its prior validation outcome in
`evaluation/disassembly-import-59f6550/`: targeted160 passed; fmt, strict workspace
Clippy and check passed; workspace exceeded its original360s bound; serial
launch1039, staged3 and prefixed-pun36 passed. This publication does not turn that
workspace timeout into a pass, nor claim default316-thread validation.
