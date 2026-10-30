# Full-program adjacent-pun diagnostic

Source `21728d7aea329f36e34bb456d4ad90bfcf9c15c1` runs the complete authored
checksum and RLE programs through the adjacent-pun frontend. **Both producers
refuse; neither emits a candidate.** This supports claim 4's systematic tactic
validation, but does not establish whole-program rewriting or native correctness.

| Program | Instruction heads | Selected branches | Producer exit | Candidate images |
| --- | ---: | ---: | ---: | ---: |
| checksum | 80 | 16 | 2 | 0 |
| rle-roundtrip | 107 | 26 | 2 | 0 |

The separate `offline-whole-authored-adjacent-b2-short-t3-pending-2g-v1`
profile retains all 187 heads and 42 selected branches. It fixes the
upper/lower/joint budgets at 2/1/2, with one producer attempt per program per
revision. Existing 16 MiB and broader profiles and their failures remain intact.
No subset, placement expansion, alternate binary or identical retry was used.

Both producer reports identify selected site 6 as a pending-ownership conflict
and site 7 as a core ownership conflict. The checked scalar counters report
zero adjacent-pair calls. The authored startup sequence at those sites is
`jbe read_more; jmp fail`: a backward conditional branch and a forward short
unconditional branch. Source inspection shows two separate exclusions: the
current adjacent contract requires targets beyond the pair and accepts only
ordinary two-byte conditional branches. Supporting this mixed pair needs a
new implementation and correctness coverage. Opaque producer Debug diagnostics
are retained privately and are not independently verified classifications.

The first diagnostic at `6cf74f9` stopped before either producer because the
driver expected one allocation range while the existing broad profile emits
two. The correction requires both exact existing ranges, in order, retaining
the allocation count and page size. Its controls cover four actual material
configurations and refuse 1,176 single-field mutations. The failed attempt is
present in `programs.csv`; the second attempt uses the corrected source and the
same captured producer binary. Rust producer source and Cargo inputs are
unchanged between capture and use.

All 13 release-capture phases pass. Capture exits 2 because two ancestor Cargo
configuration observations are `READ_DENIED`; their contents and effect are
unknown. `configuration_complete` therefore remains false. The subsequent
diagnostics each exit 1. The corrected run completes bounded output collection
and stability checks, but **artifact verification, native correctness,
classification, corpus success and performance qualification all remain false**.
It does not execute rewritten programs.

Development controls preserve both failing runs: the first has 13 subtest
failures and one error; the second has 13 subtest failures. Fixture inputs were
completed, then a real directory-reader bug was fixed: duplicating a directory
descriptor shares its enumeration offset, so a later membership check could
see an empty listing. Opening a fresh descriptor relative to the retained
directory anchor makes independent checks reliable. A positive repeated-read
control and a later-mutation refusal control preserve the original guarantees.
Final Python suites pass 33 diagnostic, 14 reproducer, 25 material and six head
capture methods, 78 total. Frontend tests pass 133 library and three publication
tests. The control-source overlays and exact commands are recorded; these are
synthetic/source validation results, not whole-program execution evidence.

`receipt.json` records source revisions, environments, binary identity, fixed
budgets and qualification gates. `checks.csv` retains every development and
validation command, including the diagnostic-only probe; `capture.csv` records
all release preparation phases; `programs.csv` retains both programs in both
attempts; `producers.csv` records the two actual producer commands. CPU
reservations, load averages and raw-log hashes are included. Hardware is an
AMD EPYC Zen 5 dev host, with stable Rust 1.97.1. All elapsed times are operational
receipts, not throughput or latency measurements. Raw logs and captures remain
under ignored storage.

At this source revision the full parallel workspace passes 3,649 tests, with
zero failures and 37 ignored, in 825.997 seconds. Formatting, strict workspace
Clippy and all-target/all-feature checking pass; serial launch passes 1,039
tests in 130.219 seconds. All 21 short-neighbor tests and the staged-drop and
prefixed-pun allocation regressions pass. Five nested child summaries are
excluded from the workspace total; both custom harnesses complete separately.
Cleanup is complete, with no adopted descendants. This single passing run does
not erase an intermittent RapidProbe address-reuse failure observed elsewhere;
the subsequent test-only fix and its own validation are recorded separately.

Reproduce at the source revision, with a disjoint four-CPU reservation and
`CARGO_INCREMENTAL=0`. Set `REPO`, `TOOLCHAIN`, `CARGO_HOME`, `USER_HOME` and
`PYTHON` to the local checkout, toolchain, Cargo data, user directory and Python
executable. Use fresh output directories. The scripts record every fixed phase
before starting it and preserve failures.

```sh
"$PYTHON" -B evaluation/offline-corpus/build_adjacent_whole.py \
  --raw "$REPO/ignored/adjacent-corpus-capture" \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" --user-home "$USER_HOME"
```

Record the SHA-256 of that capture's `closed.json` as `CAPTURE_SHA256`. A
configuration-incomplete capture remains diagnostic-only; its result must not
be relabelled as passing.

```sh
"$PYTHON" -B evaluation/offline-corpus/reproduce_whole.py \
  --capture "$REPO/ignored/adjacent-corpus-capture" \
  --capture-sha256 "$CAPTURE_SHA256" \
  --output "$REPO/ignored/adjacent-corpus-diagnostic" \
  --placement-profile offline-whole-authored-adjacent-b2-short-t3-pending-2g-v1
"$PYTHON" -B evaluation/offline-corpus/adjacent_whole_controls.py -v
"$PYTHON" -B evaluation/offline-corpus/reproduce_whole_controls.py -v
"$PYTHON" -B evaluation/offline-corpus/disassembly_controls.py -v
"$PYTHON" -B evaluation/offline-corpus/head_capture_controls.py -v
```

For workspace checks use the receipt's debug environment and a disjoint 16-CPU
reservation. The tracked driver preserves 316 harness threads, the 900-second
workspace bound and every outcome; it does not serialize the workspace.

```sh
"$PYTHON" -B evaluation/short-neighbor-parallel/validate.py \
  --revision 21728d7aea329f36e34bb456d4ad90bfcf9c15c1 \
  --output ignored/adjacent-corpus-workspace
```
